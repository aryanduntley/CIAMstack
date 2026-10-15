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
What it leaves out or to a person is a render note (core.notes, flow 43) written as its comment, enumerated the way the
keepers' roots are walked (plumbing_notes). Pure.
"""
import ipaddress
import re
from typing import NamedTuple

from opsdir.core.directory import is_kind, one, rdn_value, values
from opsdir.core.environment import of_class, one_role
from opsdir.core.network import is_private
from opsdir.core.notes import RECORD, note_comment
from opsdir.domains.network.plumbing import (adopted, cross_cloud_peering_note, keeper_notes, link_kind_note,
                                             network_note, peer_cloud, peer_half_note, peer_network, route_target)
from opsdir.domains.network.routing import parse_route
from opsdir.domains.network.stack import subnets
from opsdir_adapter_gcp.firewall_policy import egress_rules, network_project, policy_ref
from opsdir_adapter_gcp.identities import project_of
from opsdir_adapter_gcp.names import NETWORK, label, name_parts, network_tag
from opsdir_adapter_gcp.network import endpoint_notes, peering_connection_id, private_endpoint
from opsdir_format_terraform.hcl import (Block, blocks_of, comment, distinct, from_entry, ref, tf_block, tf_import,
                                         tf_name)

# blocks: what the binding renders; variables: inputs only its keeper knows; shared: data sources and resources
# rendered once in the root, however many bindings use them
Rendered = NamedTuple("Rendered", [("blocks", tuple), ("variables", tuple), ("shared", tuple)])
COMPUTE = "https://www.googleapis.com/compute/v1/"
INTERNET = "default-internet-gateway"
# what a route of each kind is on Google Cloud when it isn't a next hop: (severity, text, how) of its note
NOT_HOPS = {"nat": ("note", "Cloud NAT isn't a next hop: egress to the internet takes the default internet gateway "
                            "route", ()),
            "peering": ("note", "a peering's routes are exchanged by the peering, not written as routes", ()),
            "transit": ("blocker", "Google Cloud has no transit gateway: routes come from a hub (Network Connectivity "
                                   "Center)", (f"Record a hub or peering link instead (ciamLinkKind), {RECORD}",)),
            "endpoint": ("note", "a Private Service Connect endpoint is an address in the network, not a next hop", ()),
            "egress-only": ("blocker", "Google Cloud has no egress-only gateway",
                            (f"Drop the route, or send the range's egress another way, {RECORD}",)),
            "none": ("blocker", "a blackhole route; Terraform doesn't create those",
                     (f"Drop the route and deny the range in firewall rules instead, {RECORD}",))}
# what a link of each other kind is on Google Cloud: (severity, text, how) of its note
LINKS = {"dedicated": ("action", "a Cloud Interconnect attachment (VLAN) on a dedicated or partner interconnect, "
                                 "ordered with Google or the partner: not rendered",
                       ("Order the interconnect (dedicated with Google, or through the partner) and create its VLAN "
                        "attachment",)),
         "hub": ("action", "a Network Connectivity Center spoke on the hub its keeper runs: not rendered",
                 ("Have the hub's keeper add this network as a spoke",)),
         "transit": ("blocker", "Google Cloud has no transit gateway: not rendered",
                     (f"Record a hub (Network Connectivity Center) or peering link (ciamLinkKind), {RECORD}",))}


def _subnet(m, s):
    ref_ = one(s, "ciamProviderRef")
    path = name_parts(ref_)
    return tf_block("data", ["google_compute_subnetwork", tf_name(rdn_value(s))], [
        ("name", path.get("subnetworks", ref_)), ("region", path.get("regions", one(m.cloud, "ciamRegion"))),
        *project_of(path)] if ref_ else [("#", "UNBOUND: the subnet has no provider ref")])


def network_data(m):
    """Data sources for environment m's network and subnetworks (by their provider refs; a Shared VPC host project
    read from them)."""
    net = one_role(m, "network")
    path = name_parts(one(net, "ciamProviderRef")) if net is not None else {}
    name = path.get("networks", one(net, "ciamProviderRef") if net is not None else None)
    return (tf_block("data", ["google_compute_network", "main"],
                     [("name", name), *project_of(path)] if name else
                     [("#", "UNBOUND: the network has no provider ref")]),
            *(_subnet(m, s) for s in of_class(m, "ciamSubnetBinding")))


def _var(name, description, sensitive=False):
    return tf_block("variable", [name], [("type", ref("string")), ("description", description),
                                         *((("sensitive", True),) if sensitive else ())])


def _adopt(address, b, id_=None):
    """An import block for a binding that exists (its provider ref, or the id given), else ()."""
    return (tf_import(address, id_ or one(b, "ciamProviderRef")),) if adopted(b) else ()


def _note(b, text):
    return Rendered((comment(f"{rdn_value(b)}: {text}"),), (), ())


def _noted(notes):
    """Rendered of render notes' comments."""
    return Rendered(tuple(comment(note_comment(n)) for n in notes), (), ())


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
    data = tuple(tf_block("data", ["google_compute_addresses", f"{n}_{i}"], [
        *((("project", project),) if project else ()), ("region", region), ("filter", f"address:{a}")])
        for i, a in enumerate(addresses))
    return (("nat_ips", [ref(f"data.google_compute_addresses.{n}_{i}.addresses[0].self_link")
                         for i in range(len(addresses))]),), data


def _private_nat(b):
    return bool(values(b, "ciamCidr")) and all(is_private(c) for c in values(b, "ciamCidr"))


def _kept_subnets_note(m, b):
    return network_note(m, b, "note", "the subnetworks an existing NAT serves aren't recorded: they stay as they are")


def egress_notes(m, b, here=()):
    """The render notes of NAT egress b as egress writes them: a private range (a blocker: Private NAT isn't
    rendered), an existing NAT's subnetworks left as they are (a plain note)."""
    if _private_nat(b):
        return (network_note(m, b, "blocker", "a private range is Private NAT, which translates between networks "
                             "through Network Connectivity Center: not rendered",
                             ("Set up Private NAT by hand through Network Connectivity Center, or record the public "
                              f"addresses it sends from (ciamCidr), {RECORD}",)),)
    return (_kept_subnets_note(m, b),) if adopted(b) else ()


def egress(m, b, here=()):
    """A Cloud Router and its Cloud NAT for the environment's subnetworks: MANUAL_ONLY with its static addresses, or
    AUTO_ONLY; an existing NAT ignores changes to its subnetworks (which the record doesn't hold: a note); a private
    range is Private NAT (its note, egress_notes)."""
    if _private_nat(b):
        return _noted(egress_notes(m, b))
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
        tf_block("resource", ["google_compute_router", n], [("name", router), *where, ("network", NETWORK)]),
        *(_adopt(f"google_compute_router.{n}", b, f"{project}/{region}/{router}") if project else ()),
        tf_block("resource", ["google_compute_router_nat", n], [
            ("name", nat), ("router", ref(f"google_compute_router.{n}.name")), *where,
            ("nat_ip_allocate_option", "MANUAL_ONLY" if static else "AUTO_ONLY"), *ips, *scope,
            *((("#", note_comment(_kept_subnets_note(m, b))),
               ("lifecycle", Block((("ignore_changes", [ref("source_subnetwork_ip_ranges_to_nat"),
                                                        ref("subnetwork")]),)))) if adopted(b) else ())]),
        *_adopt(f"google_compute_router_nat.{n}", b)), (), data)


# ------------------------------------------------------------------ route tables
def _target(m, route):
    b = route_target(m, route)
    return one(b, "ciamProviderRef") if b is not None else route.target


def _not_hop(m, route, here):
    """(severity, text, how) of the note of a route that isn't a next hop on Google Cloud (NOT_HOPS, a route over an
    HA VPN rendered here, a kind with no next hop), else None (rendered, or UNBOUND)."""
    b = route_target(m, route)
    if route.kind in NOT_HOPS:
        return NOT_HOPS[route.kind]
    if route.kind == "vpn" and b is not None and b.dn in here:
        return "note", "routes over an HA VPN are learned by BGP, not written as routes", ()
    if route.kind in ("internet", "vpn", "gateway-lb", "firewall", "appliance") or not _target(m, route):
        return None
    return "blocker", f"Google Cloud has no {route.kind} next hop", (f"Record a next hop Google Cloud has, {RECORD}",)


def _route_note(m, b, route, why):
    severity, text, how = why
    return network_note(m, b, severity, f"{route.destination} {route.kind}: {text}", how)


def _hop(m, route, here):
    """((next hop attribute, value) or None, variables, why not: an UNBOUND text) of a route on Google Cloud that is
    a next hop (_not_hop says what isn't)."""
    b = route_target(m, route)
    if route.kind == "internet":
        return ("next_hop_gateway", INTERNET), (), None
    if route.kind == "firewall" and b is not None:
        name = f"{tf_name(one(b, 'ciamBindingRole'))}_ilb"
        return ("next_hop_ilb", ref(f"var.{name}")), (_var(name, f"The internal passthrough load balancer "
                                                                f"(forwarding rule) in front of {rdn_value(b)}"),), None
    target = _target(m, route)
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


def _routes(b):
    return tuple(r for r in map(parse_route, values(b, "ciamRoute")) if r and r.kind != "local")


def _head_notes(m, b):
    """The notes of a route table as a whole: subnets it can't be associated with (routes are network-wide), existing
    routes to import or replace."""
    return (*((network_note(m, b, "note", "Google Cloud's routes apply to the whole network (or to tagged instances), "
                            f"not to subnets: {', '.join(values(b, 'ciamSubnetRole'))} aren't associated"),)
              if values(b, "ciamSubnetRole") else ()),
            *((network_note(m, b, "action", "existing routes keep their own names: import each "
                            "(projects/<project>/global/routes/<name>) or let these replace them",
                            ("Before applying, import each existing route (projects/<project>/global/routes/<name>) "
                             "or let these replace them",)),) if adopted(b) else ()))


def route_notes(m, b, here=()):
    """The render notes of route table b as route_table writes them: the table's (_head_notes), then each route's that
    isn't a next hop on Google Cloud (_not_hop); each once."""
    return tuple(dict.fromkeys((*_head_notes(m, b), *(_route_note(m, b, r, why) for r in _routes(b)
                                                      for why in (_not_hop(m, r, here),) if why is not None))))


def route_table(m, b, here=()):
    """A route per route of the table (Google Cloud's routes are network-wide), tagged for the roles a route is
    for; what isn't a next hop on Google Cloud its note's comment (route_notes)."""
    n = tf_name(rdn_value(b))
    head = tuple(comment(note_comment(x)) for x in _head_notes(m, b))
    out = []
    for i, r in enumerate(_routes(b)):
        why = _not_hop(m, r, here)
        if why is not None:
            out.append(Rendered((comment(note_comment(_route_note(m, b, r, why))),), (), ()))
            continue
        hop, variables, why = _hop(m, r, here)
        if hop is None:
            out.append(Rendered((comment(f"{rdn_value(b)} {r.destination} {r.kind}: {why}"),), (), ()))
            continue
        out.append(Rendered((tf_block("resource", ["google_compute_route", f"{n}_{i}"], [
            ("name", _name(m, rdn_value(b), str(i))), *network_project(m), ("network", NETWORK),
            ("dest_range", r.destination), ("priority", 1000), hop,
            *((("tags", [network_tag(m, role) for role in r.roles]),) if r.roles else ()),
            ("description", f"{r.destination} {r.kind} ({rdn_value(b)})")]),), variables, ()))
    return Rendered((*head, *(x for p in out for x in p.blocks)), tuple(v for p in out for v in p.variables), ())


def acl_notes(m, b, here=()):
    """The render note (a blocker) of network ACL b: Google Cloud has no stateless network ACLs."""
    return (network_note(m, b, "blocker", "Google Cloud has no stateless network ACLs (firewall rules and policies "
                         "filter traffic): not rendered", (f"Record these rules as firewall rules, {RECORD}",)),)


def network_acl(m, b, here=()):
    """Google Cloud has no network ACLs: its note's comment (acl_notes)."""
    return _noted(acl_notes(m, b))


# ------------------------------------------------------------------ interconnects
def _cross_cloud(m, b):
    cloud = peer_cloud(m.d, b)
    return cloud is not None and one(cloud, "ciamCloudProvider") != "gcp"


def _peer(m, b):
    net = peer_network(m.d, b)
    return one(net, "ciamProviderRef") if net is not None else None


def _half_note(m, b):
    return peer_half_note(m, b, f"the other network adds its half (a peering from {_peer(m, b)} back to this "
                                "network) in its project")


def _single_tunnel_note(m, b):
    return network_note(m, b, "note", "one peer address: a tunnel from the gateway's second interface to it too gives "
                        "the 99.99% availability HA VPN offers")


def _peering(m, b, n):
    if _cross_cloud(m, b):
        return _noted((cross_cloud_peering_note(m, b, "Google Cloud"),))
    peer = _peer(m, b)
    if peer is None:
        return _note(b, "UNBOUND: the other environment's network has no provider ref to peer with. Not rendered.")
    ours = name_parts(one(one_role(m, "network"), "ciamProviderRef") if one_role(m, "network") is not None else "")
    name = (one(b, "ciamProviderRef") or "").rsplit("/peerings/", 1)[-1] if "/peerings/" in (
        one(b, "ciamProviderRef") or "") else _name(m, rdn_value(b))
    importable = "projects" in ours and "networks" in ours
    return Rendered((
        *((comment(note_comment(_half_note(m, b))),) if one(b, "ciamPeerAccepted") != "TRUE" else ()),
        tf_block("resource", ["google_compute_network_peering", n], [
            ("name", name), ("network", NETWORK), ("peer_network", _self_link(peer))]),
        *(_adopt(f"google_compute_network_peering.{n}", b, f"{ours['projects']}/{ours['networks']}/{name}")
          if importable else ())), (), ())


def _vpn(m, b, n):
    gateways, local, peer_asn = values(b, "ciamPeerGateway")[:4], one(b, "ciamLocalAsn"), one(b, "ciamPeerAsn")
    if not gateways:
        return _note(b, "UNBOUND: a VPN needs the other end's gateway address (ciamPeerGateway). Not rendered.")
    if not (local and peer_asn):
        return _noted(interconnect_notes(m, b))
    path = name_parts(one(b, "ciamProviderRef") or "")
    where = (*network_project(m), ("region", _region(m, path)))
    name = _name(m, rdn_value(b))
    redundancy = {1: "SINGLE_IP_INTERNALLY_REDUNDANT", 2: "TWO_IPS_REDUNDANCY"}.get(len(gateways),
                                                                                      "FOUR_IPS_REDUNDANCY")
    advertised = tuple(("advertised_ip_ranges", Block((("range", c),))) for c in values(b, "ciamAdvertisedCidr"))
    secret = f"{n}_shared_secret"

    def tunnel(i):
        t = f"{n}_{i}"
        return (tf_block("resource", ["google_compute_vpn_tunnel", t], [
                    ("name", f"{name}-{i}"[:63]), *where,
                    ("vpn_gateway", ref(f"google_compute_ha_vpn_gateway.{n}.id")), ("vpn_gateway_interface", i % 2),
                    ("peer_external_gateway", ref(f"google_compute_external_vpn_gateway.{n}.id")),
                    ("peer_external_gateway_interface", i), ("shared_secret", ref(f"var.{secret}")),
                    ("router", ref(f"google_compute_router.{n}.id")), ("ike_version", 2),
                    ("labels", {"role": label(one(b, "ciamBindingRole")), "managed_by": "opsdir"})]),
                *(_adopt(f"google_compute_vpn_tunnel.{t}", b) if i == 0 and path else ()),
                tf_block("resource", ["google_compute_router_interface", t], [
                    ("name", f"{name}-{i}"[:63]), ("router", ref(f"google_compute_router.{n}.name")), *where,
                    ("ip_range", ref(f"var.{t}_bgp_range")),
                    ("vpn_tunnel", ref(f"google_compute_vpn_tunnel.{t}.name"))]),
                tf_block("resource", ["google_compute_router_peer", t], [
                    ("name", f"{name}-{i}"[:63]), ("router", ref(f"google_compute_router.{n}.name")), *where,
                    ("interface", ref(f"google_compute_router_interface.{t}.name")),
                    ("peer_ip_address", ref(f"var.{t}_bgp_peer_ip")), ("peer_asn", int(peer_asn))]))
    accepted = values(b, "ciamAcceptedCidr")
    return Rendered((
        *((comment(f"{rdn_value(b)}: accepts {', '.join(accepted)} from the peer, learned by BGP"),)
          if accepted else ()),
        *((comment(note_comment(_single_tunnel_note(m, b))),) if len(gateways) == 1 else ()),
        tf_block("resource", ["google_compute_ha_vpn_gateway", n], [("name", name), *where, ("network", NETWORK)]),
        tf_block("resource", ["google_compute_external_vpn_gateway", n], [
            ("name", f"{name}-peer"[:63]), *network_project(m), ("redundancy_type", redundancy),
            *(("interface", Block((("id", i), ("ip_address", g)))) for i, g in enumerate(gateways))]),
        tf_block("resource", ["google_compute_router", n], [
            ("name", f"{name}-router"[:63]), *where, ("network", NETWORK),
            ("bgp", Block((("asn", int(local)), *((("advertise_mode", "CUSTOM"), ("advertised_groups", ["ALL_SUBNETS"]),
                                                  *advertised) if advertised else ()))))]),
        *(x for i in range(len(gateways)) for x in tunnel(i))),
        (_var(secret, f"The pre-shared key of {rdn_value(b)}'s tunnels (agreed with the peer; never in the record)",
              sensitive=True),
         *(v for i in range(len(gateways)) for v in (
             _var(f"{n}_{i}_bgp_range", f"Tunnel {i}'s link-local BGP range (169.254.x.x/30) agreed with the peer"),
             _var(f"{n}_{i}_bgp_peer_ip", f"The peer's BGP address in tunnel {i}'s link-local range")))), ())


def interconnect_notes(m, b, here=()):
    """The render notes of interconnect b as interconnect writes them: a peering to another cloud (a blocker), the
    other network's half of a peering (peer_half_note), an HA VPN without both ASNs (a blocker) or to one peer address
    (a plain note), the kinds it doesn't render (LINKS), an unrecorded kind of link (a blocker); an UNBOUND link has
    none."""
    kind = one(b, "ciamLinkKind")
    if kind == "peering" and _cross_cloud(m, b):
        return (cross_cloud_peering_note(m, b, "Google Cloud"),)
    if kind == "peering":
        return (_half_note(m, b),) if _peer(m, b) is not None and one(b, "ciamPeerAccepted") != "TRUE" else ()
    if kind == "vpn" and not values(b, "ciamPeerGateway"):
        return ()
    if kind == "vpn" and not (one(b, "ciamLocalAsn") and one(b, "ciamPeerAsn")):
        return (network_note(m, b, "blocker", "HA VPN routes by BGP, and both ends' ASNs aren't recorded: not "
                             "rendered", (f"Record both ends' ASNs (ciamLocalAsn, ciamPeerAsn), {RECORD}",)),)
    if kind == "vpn":
        return (_single_tunnel_note(m, b),) if len(values(b, "ciamPeerGateway")) == 1 else ()
    if kind in LINKS:
        severity, text, how = LINKS[kind]
        return (network_note(m, b, severity, text, how),)
    return (link_kind_note(m, b),)


def interconnect(m, b, here=()):
    """An interconnect by its kind: peering (our half), HA VPN with BGP; dedicated attachments, hubs, transit and
    unrecorded kinds their notes' comments (interconnect_notes)."""
    n, kind = tf_name(rdn_value(b)), one(b, "ciamLinkKind")
    if kind == "peering":
        return _peering(m, b, n)
    if kind == "vpn":
        return _vpn(m, b, n)
    return _noted(interconnect_notes(m, b))


# ------------------------------------------------------------------ flow logs
def flow_log_notes(m, b, here=()):
    """The render notes of flow log b as flow_log writes them: no subnetwork found for its scope (a blocker), else
    its subnetworks' log_config, set where each is defined (an action)."""
    found = of_class(m, "ciamSubnetBinding") if one(b, "ciamFlowScope") == "network" else subnets(m, b)
    if one(b, "ciamFlowScope") not in ("network", "subnet") or not found:
        return (network_note(m, b, "blocker", f"Google Cloud's flow logs are subnetworks' ({one(b, 'ciamFlowScope')} "
                             "named, no subnet found): not rendered",
                             (f"Record it on the network or its subnets (ciamFlowScope, ciamSubnetRole), {RECORD}",)),)
    dest = one_role(m, one(b, "ciamLogDestinationRole") or "")
    days = one(b, "ciamRetentionDays")
    goes = (f"to Cloud Logging, routed to {rdn_value(dest)}" + (f" ({one(dest, 'ciamProviderRef')})"
                                                              if one(dest, "ciamProviderRef") else "")
            if dest is not None else "to Cloud Logging") + (f", kept {days} days there" if days else "")
    names = ", ".join(rdn_value(s) for s in found)
    which = f"subnetworks {names} log their" if len(found) > 1 else f"subnetwork {names} logs its"
    return (network_note(m, b, "action", f"{which} flows {goes}: the log_config isn't rendered here",
                         ("Set the log_config (aggregation_interval INTERVAL_5_SEC, flow_sampling 0.5, metadata "
                          "INCLUDE_ALL_METADATA) of each subnetwork where it is defined",)),)


def flow_log(m, b, here=()):
    """A subnetwork's log_config per subnet (the landing zone keeps the subnetworks), with where the logs go: its
    notes' comments (flow_log_notes)."""
    return _noted(flow_log_notes(m, b))


# ------------------------------------------------------------------ kept elsewhere
def _kept_policy(m, b):
    return (one(b, "ciamProviderRef") or "").rsplit("/", 1)[-1] or policy_ref(m)


def _instances_note(m, b):
    return network_note(m, b, "note", f"its rules apply to every instance of the network, in policy "
                        f"{_kept_policy(m, b)}")


def kept_notes(m, b, here=()):
    """The render notes of a private endpoint or egress firewall someone else keeps, as kept_elsewhere renders it:
    the firewall's rules applying to every instance of the network (a plain note), the endpoint's
    (network.endpoint_notes)."""
    return (_instances_note(m, b),) if is_kind(m.d, b, "ciamProxy") else endpoint_notes(m, b)


def kept_elsewhere(m, b, here=()):
    """A PSC endpoint for Google's APIs, private services access (its address and connection), or an egress
    firewall's FQDN rules in its keeper's network firewall policy for every instance of the network (the stack's tag
    values aren't theirs)."""
    if is_kind(m.d, b, "ciamProxy"):
        policy = _kept_policy(m, b)
        return Rendered((comment(note_comment(_instances_note(m, b))),
                         *egress_rules(m, b, targets=(), policy=policy)), (), ())
    blocks, n, connection = private_endpoint(m, b), tf_name(rdn_value(b)), peering_connection_id(m)
    made = bool(blocks_of(blocks, "resource", "google_compute_global_forwarding_rule"))
    peered = bool(blocks_of(blocks, "resource", "google_service_networking_connection"))
    return Rendered((*blocks, *(_adopt(f"google_compute_global_forwarding_rule.{n}", b) if made else ()),
                     *(_adopt(f"google_compute_global_address.{n}", b) if peered else ()),
                     *(_adopt(f"google_service_networking_connection.{n}", b, connection)
                       if peered and connection else ())), (), ())


NOTES = (("ciamEgress", egress_notes), ("ciamRouteTable", route_notes), ("ciamNetworkAcl", acl_notes),
         ("ciamInterconnect", interconnect_notes), ("ciamFlowLog", flow_log_notes),
         ("ciamPrivateEndpoint", kept_notes), ("ciamProxy", kept_notes))


def plumbing_notes(m):
    """The render notes of environment m's plumbing as its keepers' roots write them (core keeper_notes over
    NOTES)."""
    return keeper_notes(m, NOTES)


RENDERERS = (("ciamEgress", egress), ("ciamRouteTable", route_table), ("ciamNetworkAcl", network_acl),
             ("ciamInterconnect", interconnect), ("ciamFlowLog", flow_log), ("ciamPrivateEndpoint", kept_elsewhere),
             ("ciamProxy", kept_elsewhere))


def render_plumbing(m, keeper):
    """Rendered of what a keeper keeps of environment m's plumbing (opsdir.domains.network.plumbing.Keeper): the
    network and subnetwork data sources and what bindings share first, inputs unique by name; each binding's blocks
    stamped with its entry, what they share with the keeper's first (hcl.from_entry)."""
    here = {b.dn for b in keeper.bindings}
    parts = tuple((b, next(fn for oc, fn in RENDERERS if is_kind(m.d, b, oc))(m, b, here)) for b in keeper.bindings)
    return Rendered(tuple(x for b, p in parts for x in from_entry(b.dn, p.blocks)),
                    distinct(tuple(v for _, p in parts for v in p.variables)),
                    (*network_data(m), *from_entry(keeper.bindings[0].dn,
                                                   distinct(tuple(x for _, p in parts for x in p.shared)))))
