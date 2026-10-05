"""Google Cloud: the network plumbing an environment's landing zone, or another party, keeps
(opsdir.domains.network.plumbing), rendered into their root (terraform/landing-zone/[<party>/]network.tf). What
already exists (a provider ref) is adopted with an import block; what doesn't is created. Everything lives in the
network's project (a Shared VPC's host project).

  NAT egress        a Cloud Router and its Cloud NAT for the environment's subnetworks: static addresses (MANUAL_ONLY,
                    the reserved addresses looked up by IP) or Google's (AUTO_ONLY); a private range is Private NAT,
                    named, not rendered
  route tables      Google Cloud's routes are network-wide: a route per route, its next hop the internet gateway, an
                    address or instance, an internal load balancer (an egress firewall's is an input), a VPN tunnel;
                    'for <roles>' becomes the roles' network tags. Peering, transit and NAT aren't next hops (said);
                    subnets can't be associated (said)
  network ACLs      Google Cloud has none: named
  interconnects     VPC peering (our half, with the other environment's network on Google Cloud), HA VPN to the peer's
                    gateway(s) with BGP (a Cloud Router with the local ASN, a tunnel, interface and BGP peer per peer
                    address; the shared secret and link-local addresses are inputs). Dedicated attachments, hubs and
                    transit are named, not rendered
  flow logs         a subnetwork's log_config (the landing zone keeps its subnetworks): named per subnet, with where
                    the logs go
  kept elsewhere    a PSC endpoint for Google's APIs and an egress firewall's FQDN rules someone else keeps
                    (opsdir_adapter_gcp.network, .firewall_policy), the rules in their policy for every instance
Pure.
"""
import ipaddress
import re
from typing import NamedTuple

from opsdir.core.directory import is_kind, one, rdn_value, values
from opsdir.core.environment import of_class, one_role
from opsdir.core.network import is_private
from opsdir.domains.network.plumbing import adopted, peer_cloud, peer_network, route_target
from opsdir.domains.network.routing import parse_route
from opsdir.domains.network.stack import subnets
from opsdir_adapter_gcp.firewall_policy import egress_rules, network_project, policy_ref
from opsdir_adapter_gcp.identities import project_of
from opsdir_adapter_gcp.names import NETWORK, label, name_parts, network_tag
from opsdir_adapter_gcp.network import private_endpoint
from opsdir_format_terraform.hcl import Block, block, import_block, ref, tf_name

# blocks: what the binding renders; variables: inputs only its keeper knows; shared: data sources and resources
# rendered once in the root, however many bindings use them
Rendered = NamedTuple("Rendered", [("blocks", tuple), ("variables", tuple), ("shared", tuple)])
COMPUTE = "https://www.googleapis.com/compute/v1/"
INTERNET = "default-internet-gateway"
# what a route of each kind is on Google Cloud when it isn't a next hop
NOT_HOPS = {"nat": "Cloud NAT isn't a next hop: egress to the internet takes the default internet gateway route",
            "peering": "a peering's routes are exchanged by the peering, not written as routes",
            "transit": "Google Cloud has no transit gateway: routes come from a hub (Network Connectivity Center)",
            "endpoint": "a Private Service Connect endpoint is an address in the network, not a next hop",
            "egress-only": "Google Cloud has no egress-only gateway",
            "none": "a blackhole route; Terraform doesn't create those"}
# what a link of each other kind is on Google Cloud
LINKS = {"dedicated": "a Cloud Interconnect attachment (VLAN) on a dedicated or partner interconnect, ordered with "
                      "Google or the partner. Named, not rendered.",
         "hub": "a Network Connectivity Center spoke on the hub its keeper runs. Named, not rendered.",
         "transit": "Google Cloud has no transit gateway: record a hub (Network Connectivity Center) or peering. "
                    "Not rendered."}


def _subnet(m, s):
    ref_ = one(s, "ciamProviderRef")
    path = name_parts(ref_)
    return block("data", ["google_compute_subnetwork", tf_name(rdn_value(s))], [
        ("name", path.get("subnetworks", ref_)), ("region", path.get("regions", one(m.cloud, "ciamRegion"))),
        *project_of(path)] if ref_ else [("#", "UNBOUND: the subnet has no provider ref")])


def network_data(m):
    """Data sources for environment m's network and subnetworks (by their provider refs; a Shared VPC host project
    read from them)."""
    net = one_role(m, "network")
    path = name_parts(one(net, "ciamProviderRef")) if net is not None else {}
    name = path.get("networks", one(net, "ciamProviderRef") if net is not None else None)
    return (block("data", ["google_compute_network", "main"],
                  [("name", name), *project_of(path)] if name else [("#", "UNBOUND: the network has no provider ref")]),
            *(_subnet(m, s) for s in of_class(m, "ciamSubnetBinding")))


def _var(name, description, sensitive=False):
    return block("variable", [name], [("type", ref("string")), ("description", description),
                                      *((("sensitive", True),) if sensitive else ())])


def _adopt(address, b, id_=None):
    """An import block for a binding that exists (its provider ref, or the id given), else ()."""
    return (import_block(address, id_ or one(b, "ciamProviderRef")),) if adopted(b) else ()


def _note(b, text):
    return Rendered((f"# {rdn_value(b)}: {text}",), (), ())


def _name(m, *parts):
    """A Compute Engine resource name: lowercase letters, digits and hyphens, a letter first, 63 characters."""
    return re.sub(r"[^a-z0-9-]+", "-", "-".join(("ciam", rdn_value(m.env), *parts)).lower())[:63].rstrip("-")


def _region(m, path=None):
    return (path or {}).get("regions") or one(m.cloud, "ciamRegion")


def _self_link(ref_):
    """A network reference as the self link peering takes (a resource name gets the Compute API's prefix)."""
    return COMPUTE + ref_ if ref_.startswith("projects/") else ref_


# ------------------------------------------------------------------ NAT egress
def _nat_path(m, b):
    """(project or None, region, router, nat) of a Cloud NAT: its provider ref as the importer records it
    (<project>/<region>/<router>/<nat>, or the projects/../regions/../routers/.. form), else names made here."""
    parts = [t for t in (one(b, "ciamProviderRef") or "").split("/") if t not in ("projects", "regions", "routers")]
    if len(parts) == 4:
        return tuple(parts)
    project = dict(network_project(m)).get("project")
    return project, _region(m), _name(m, rdn_value(b), "router"), _name(m, rdn_value(b))


def _nat_ips(m, b, n, project, region):
    """(nat_ips body items, data sources): each static address looked up by IP among the project's reserved
    addresses in the region."""
    addresses = tuple(str(a) for c in values(b, "ciamCidr") if not is_private(c)
                      for net in (ipaddress.ip_network(c, strict=False),) if net.num_addresses <= 16 for a in net)
    if not addresses:
        return (("#", "UNBOUND: static allocation, but no public address recorded (ciamCidr)"),), ()
    data = tuple(block("data", ["google_compute_addresses", f"{n}_{i}"], [
        *((("project", project),) if project else ()), ("region", region), ("filter", f"address:{a}")])
        for i, a in enumerate(addresses))
    return (("nat_ips", [ref(f"data.google_compute_addresses.{n}_{i}.addresses[0].self_link")
                         for i in range(len(addresses))]),), data


def egress(m, b, here=()):
    """A Cloud Router and its Cloud NAT for the environment's subnetworks: MANUAL_ONLY with its static addresses, or
    AUTO_ONLY; an existing NAT ignores changes to its subnetworks (which the record doesn't hold); a private range is
    Private NAT (named, not rendered)."""
    if values(b, "ciamCidr") and all(is_private(c) for c in values(b, "ciamCidr")):
        return _note(b, "a private range is Private NAT, which translates between networks through Network "
                        "Connectivity Center. Not rendered.")
    n = tf_name(rdn_value(b))
    project, region, router, nat = _nat_path(m, b)
    where = (*((("project", project),) if project else ()), ("region", region))
    static = one(b, "ciamNatAllocation") != "automatic"
    ips, data = _nat_ips(m, b, n, project, region) if static else ((), ())
    found = of_class(m, "ciamSubnetBinding")
    scope = (("source_subnetwork_ip_ranges_to_nat", "LIST_OF_SUBNETWORKS"),
             *(("subnetwork", Block((("name", ref(f"data.google_compute_subnetwork.{tf_name(rdn_value(s))}.self_link")),
                                     ("source_ip_ranges_to_nat", ["ALL_IP_RANGES"])))) for s in found)) if found \
        else (("source_subnetwork_ip_ranges_to_nat", "ALL_SUBNETWORKS_ALL_IP_RANGES"),)
    return Rendered((
        block("resource", ["google_compute_router", n], [("name", router), *where, ("network", NETWORK)]),
        *(_adopt(f"google_compute_router.{n}", b, f"{project}/{region}/{router}") if project else ()),
        block("resource", ["google_compute_router_nat", n], [
            ("name", nat), ("router", ref(f"google_compute_router.{n}.name")), *where,
            ("nat_ip_allocate_option", "MANUAL_ONLY" if static else "AUTO_ONLY"), *ips, *scope,
            *((("#", "the subnetworks an existing NAT serves aren't recorded: they stay as they are"),
               ("lifecycle", Block((("ignore_changes", [ref("source_subnetwork_ip_ranges_to_nat"),
                                                        ref("subnetwork")]),)))) if adopted(b) else ())]),
        *_adopt(f"google_compute_router_nat.{n}", b)), (), data)


# ------------------------------------------------------------------ route tables
def _hop(m, route, here):
    """((next hop attribute, value) or None, variables, why not) of a route on Google Cloud."""
    b = route_target(m, route)
    if route.kind == "internet":
        return ("next_hop_gateway", INTERNET), (), None
    if route.kind in NOT_HOPS:
        return None, (), NOT_HOPS[route.kind]
    if route.kind == "vpn" and b is not None and b.dn in here:
        return None, (), "routes over an HA VPN are learned by BGP, not written as routes"
    if route.kind == "firewall" and b is not None:
        name = f"{tf_name(one(b, 'ciamBindingRole'))}_ilb"
        return ("next_hop_ilb", ref(f"var.{name}")), (_var(name, f"The internal passthrough load balancer "
                                                                f"(forwarding rule) in front of {rdn_value(b)}"),), None
    target = one(b, "ciamProviderRef") if b is not None else route.target
    if not target:
        return None, (), (f"UNBOUND: its target {route.target} isn't rendered here and has no provider ref"
                          if route.target else "UNBOUND: it names no target")
    if route.kind == "vpn":
        return ("next_hop_vpn_tunnel", target), (), None
    if route.kind in ("gateway-lb", "firewall"):
        return ("next_hop_ilb", target), (), None
    if route.kind == "appliance":
        return (("next_hop_ip" if re.match(r"^[0-9.]+$", target) else "next_hop_instance"), target), (), None
    return None, (), f"Google Cloud has no {route.kind} next hop"


def route_table(m, b, here=()):
    """A route per route of the table (Google Cloud's routes are network-wide), tagged for the roles a route is
    for; what isn't a next hop on Google Cloud named."""
    n = tf_name(rdn_value(b))
    head = (*((f"# {rdn_value(b)}: Google Cloud's routes apply to the whole network (or to tagged instances), not to "
               f"subnets: {', '.join(values(b, 'ciamSubnetRole'))} aren't associated",)
              if values(b, "ciamSubnetRole") else ()),
            *((f"# {rdn_value(b)}: existing routes keep their own names: import each "
               "(projects/<project>/global/routes/<name>) or let these replace them",) if adopted(b) else ()))
    out = []
    for i, r in enumerate(x for x in map(parse_route, values(b, "ciamRoute")) if x and x.kind != "local"):
        hop, variables, why = _hop(m, r, here)
        if hop is None:
            out.append(Rendered((f"# {rdn_value(b)} {r.destination} {r.kind}: {why}",), (), ()))
            continue
        out.append(Rendered((block("resource", ["google_compute_route", f"{n}_{i}"], [
            ("name", _name(m, rdn_value(b), str(i))), *network_project(m), ("network", NETWORK),
            ("dest_range", r.destination), ("priority", 1000), hop,
            *((("tags", [network_tag(m, role) for role in r.roles]),) if r.roles else ()),
            ("description", f"{r.destination} {r.kind} ({rdn_value(b)})")]),), variables, ()))
    return Rendered((*head, *(x for p in out for x in p.blocks)), tuple(v for p in out for v in p.variables), ())


def network_acl(m, b, here=()):
    """Google Cloud has no network ACLs: named."""
    return _note(b, "Google Cloud has no stateless network ACLs (firewall rules and policies filter traffic). "
                    "Not rendered.")


# ------------------------------------------------------------------ interconnects
def _peering(m, b, n):
    cloud, net = peer_cloud(m.d, b), peer_network(m.d, b)
    if cloud is not None and one(cloud, "ciamCloudProvider") != "gcp":
        return _note(b, f"peering joins two Google Cloud networks, and the other end is on "
                        f"{one(cloud, 'ciamCloudProvider')}: record it as a vpn link. Not rendered.")
    peer = one(net, "ciamProviderRef") if net is not None else None
    if peer is None:
        return _note(b, "UNBOUND: the other environment's network has no provider ref to peer with. Not rendered.")
    ours = name_parts(one(one_role(m, "network"), "ciamProviderRef") if one_role(m, "network") is not None else "")
    name = (one(b, "ciamProviderRef") or "").rsplit("/peerings/", 1)[-1] if "/peerings/" in (
        one(b, "ciamProviderRef") or "") else _name(m, rdn_value(b))
    importable = "projects" in ours and "networks" in ours
    return Rendered((
        *((f"# {rdn_value(b)}: the other network adds its half (a peering from {peer} back to this network) in its "
           "project",) if one(b, "ciamPeerAccepted") != "TRUE" else ()),
        block("resource", ["google_compute_network_peering", n], [
            ("name", name), ("network", NETWORK), ("peer_network", _self_link(peer))]),
        *(_adopt(f"google_compute_network_peering.{n}", b, f"{ours['projects']}/{ours['networks']}/{name}")
          if importable else ())), (), ())


def _vpn(m, b, n):
    gateways, local, peer_asn = values(b, "ciamPeerGateway")[:4], one(b, "ciamLocalAsn"), one(b, "ciamPeerAsn")
    if not gateways:
        return _note(b, "UNBOUND: a VPN needs the other end's gateway address (ciamPeerGateway). Not rendered.")
    if not (local and peer_asn):
        return _note(b, "HA VPN routes by BGP: record both ends' ASNs (ciamLocalAsn, ciamPeerAsn). Not rendered.")
    path = name_parts(one(b, "ciamProviderRef") or "")
    where = (*network_project(m), ("region", _region(m, path)))
    name = _name(m, rdn_value(b))
    redundancy = {1: "SINGLE_IP_INTERNALLY_REDUNDANT", 2: "TWO_IPS_REDUNDANCY"}.get(len(gateways),
                                                                                      "FOUR_IPS_REDUNDANCY")
    advertised = tuple(("advertised_ip_ranges", Block((("range", c),))) for c in values(b, "ciamAdvertisedCidr"))
    secret = f"{n}_shared_secret"

    def tunnel(i):
        t = f"{n}_{i}"
        return (block("resource", ["google_compute_vpn_tunnel", t], [
                    ("name", f"{name}-{i}"[:63]), *where,
                    ("vpn_gateway", ref(f"google_compute_ha_vpn_gateway.{n}.id")), ("vpn_gateway_interface", i % 2),
                    ("peer_external_gateway", ref(f"google_compute_external_vpn_gateway.{n}.id")),
                    ("peer_external_gateway_interface", i), ("shared_secret", ref(f"var.{secret}")),
                    ("router", ref(f"google_compute_router.{n}.id")), ("ike_version", 2),
                    ("labels", {"role": label(one(b, "ciamBindingRole")), "managed_by": "opsdir"})]),
                *(_adopt(f"google_compute_vpn_tunnel.{t}", b) if i == 0 and path else ()),
                block("resource", ["google_compute_router_interface", t], [
                    ("name", f"{name}-{i}"[:63]), ("router", ref(f"google_compute_router.{n}.name")), *where,
                    ("ip_range", ref(f"var.{t}_bgp_range")),
                    ("vpn_tunnel", ref(f"google_compute_vpn_tunnel.{t}.name"))]),
                block("resource", ["google_compute_router_peer", t], [
                    ("name", f"{name}-{i}"[:63]), ("router", ref(f"google_compute_router.{n}.name")), *where,
                    ("interface", ref(f"google_compute_router_interface.{t}.name")),
                    ("peer_ip_address", ref(f"var.{t}_bgp_peer_ip")), ("peer_asn", int(peer_asn))]))
    accepted = values(b, "ciamAcceptedCidr")
    return Rendered((
        *((f"# {rdn_value(b)}: accepts {', '.join(accepted)} from the peer, learned by BGP",) if accepted else ()),
        *((f"# {rdn_value(b)}: one peer address: a tunnel from the gateway's second interface to it too gives the "
           "99.99% availability HA VPN offers",) if len(gateways) == 1 else ()),
        block("resource", ["google_compute_ha_vpn_gateway", n], [("name", name), *where, ("network", NETWORK)]),
        block("resource", ["google_compute_external_vpn_gateway", n], [
            ("name", f"{name}-peer"[:63]), *network_project(m), ("redundancy_type", redundancy),
            *(("interface", Block((("id", i), ("ip_address", g)))) for i, g in enumerate(gateways))]),
        block("resource", ["google_compute_router", n], [
            ("name", f"{name}-router"[:63]), *where, ("network", NETWORK),
            ("bgp", Block((("asn", int(local)), *((("advertise_mode", "CUSTOM"), ("advertised_groups", ["ALL_SUBNETS"]),
                                                  *advertised) if advertised else ()))))]),
        *(x for i in range(len(gateways)) for x in tunnel(i))),
        (_var(secret, f"The pre-shared key of {rdn_value(b)}'s tunnels (agreed with the peer; never in the record)",
              sensitive=True),
         *(v for i in range(len(gateways)) for v in (
             _var(f"{n}_{i}_bgp_range", f"Tunnel {i}'s link-local BGP range (169.254.x.x/30) agreed with the peer"),
             _var(f"{n}_{i}_bgp_peer_ip", f"The peer's BGP address in tunnel {i}'s link-local range")))), ())


def interconnect(m, b, here=()):
    """An interconnect by its kind: peering (our half), HA VPN with BGP; dedicated attachments, hubs and transit
    named."""
    n, kind = tf_name(rdn_value(b)), one(b, "ciamLinkKind")
    if kind == "peering":
        return _peering(m, b, n)
    if kind == "vpn":
        return _vpn(m, b, n)
    if kind in LINKS:
        return _note(b, LINKS[kind])
    return _note(b, f"{one(b, 'ciamInterconnectKind')}: what kind of link it is isn't recorded (ciamLinkKind). "
                    "Not rendered.")


# ------------------------------------------------------------------ flow logs
def flow_log(m, b, here=()):
    """A subnetwork's log_config, named per subnet (the landing zone keeps the subnetworks), with where the logs go."""
    found = of_class(m, "ciamSubnetBinding") if one(b, "ciamFlowScope") == "network" else subnets(m, b)
    if one(b, "ciamFlowScope") not in ("network", "subnet") or not found:
        return _note(b, f"Google Cloud's flow logs are subnetworks' ({one(b, 'ciamFlowScope')} named, no subnet "
                        "found). Not rendered.")
    dest = one_role(m, one(b, "ciamLogDestinationRole") or "")
    days = one(b, "ciamRetentionDays")
    goes = (f"to Cloud Logging, routed to {rdn_value(dest)}" + (f" ({one(dest, 'ciamProviderRef')})"
                                                              if one(dest, "ciamProviderRef") else "")
            if dest is not None else "to Cloud Logging") + (f", kept {days} days there" if days else "")
    return Rendered(tuple(
        f"# {rdn_value(b)}: subnetwork {rdn_value(s)} logs its flows {goes}: set its log_config "
        "(aggregation_interval INTERVAL_5_SEC, flow_sampling 0.5, metadata INCLUDE_ALL_METADATA) where the "
        "subnetwork is defined" for s in found), (), ())


# ------------------------------------------------------------------ kept elsewhere
def kept_elsewhere(m, b, here=()):
    """A PSC endpoint for Google's APIs, or an egress firewall's FQDN rules in its keeper's network firewall policy
    for every instance of the network (the stack's tag values aren't theirs)."""
    if is_kind(m.d, b, "ciamProxy"):
        policy = (one(b, "ciamProviderRef") or "").rsplit("/", 1)[-1] or policy_ref(m)
        return Rendered((f"# {rdn_value(b)}: its rules apply to every instance of the network, in policy {policy}",
                         *egress_rules(m, b, targets=(), policy=policy)), (), ())
    blocks = private_endpoint(m, b)
    made = any(x.startswith('resource "google_compute_global_forwarding_rule"') for x in blocks)
    return Rendered((*blocks, *(_adopt(f"google_compute_global_forwarding_rule.{tf_name(rdn_value(b))}", b)
                                if made else ())), (), ())


RENDERERS = (("ciamEgress", egress), ("ciamRouteTable", route_table), ("ciamNetworkAcl", network_acl),
             ("ciamInterconnect", interconnect), ("ciamFlowLog", flow_log), ("ciamPrivateEndpoint", kept_elsewhere),
             ("ciamProxy", kept_elsewhere))


def render_plumbing(m, keeper):
    """Rendered of what a keeper keeps of environment m's plumbing (opsdir.domains.network.plumbing.Keeper): the
    network and subnetwork data sources and what bindings share first, inputs unique by name."""
    here = {b.dn for b in keeper.bindings}
    parts = tuple(next(fn for oc, fn in RENDERERS if is_kind(m.d, b, oc))(m, b, here) for b in keeper.bindings)
    return Rendered(tuple(x for p in parts for x in p.blocks),
                    tuple(dict.fromkeys(v for p in parts for v in p.variables)),
                    (*network_data(m), *dict.fromkeys(x for p in parts for x in p.shared)))
