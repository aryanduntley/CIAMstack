"""Azure: the network plumbing an environment's landing zone, or another party, keeps (opsdir.domains.network.plumbing),
rendered into their root (terraform/landing-zone/[<party>/]network.tf). What already exists (a provider ref) is
adopted with an import block (its ARM ID, built from the resource group when the record holds only a name); what
doesn't is created.

  NAT egress        a NAT gateway (Standard) with its public addresses: each /32 a public IP resource, a wider range a
                    public IP prefix, both inputs (Azure looks public IPs up by name, not address), on the
                    environment's subnets. Azure NAT is public only: a private range is named, not rendered
  route tables      a route table with its routes (user-defined: next hop VirtualAppliance at the firewall's or
                    appliance's private address, VirtualNetworkGateway for VPN and transit, Internet, VnetLocal,
                    None; a destination may be a service tag) and its subnet associations. NAT, peering and endpoints
                    aren't next hops in Azure (subnets reach them without a route): named. No main table in Azure
  network ACLs      none in Azure (stateless ACLs are another provider's; the NSGs are the stack's rules): named
  interconnects     our half of a VNet peering (the other environment's VNet, Azure only), a site-to-site VPN (local
                    network gateway with the peer's address, ranges and BGP; the connection on the virtual network
                    gateway, an input, its shared key a sensitive input from the secret store), a virtual WAN hub
                    connection (the hub an input). Transit and ExpressRoute circuits are named, not rendered
  flow logs         virtual network flow logs (Network Watcher, an input) on the VNet or each subnet, to the storage
                    account the destination names (traffic analytics when it is a Log Analytics workspace, the
                    storage account then an input), retention as recorded. Never NSG flow logs (they retire)
  kept elsewhere    private endpoints and egress firewalls' rule collection groups someone else keeps
                    (opsdir_adapter_azure.network)
Tags Role (and opsdir's mark), read back by the importers. Pure.
"""
import ipaddress
from typing import NamedTuple

from opsdir.core.directory import is_kind, one, rdn_value, values
from opsdir.core.environment import of_class, one_role
from opsdir.core.network import is_private
from opsdir.domains.network.plumbing import adopted, peer_cloud, peer_network, route_target
from opsdir.domains.network.routing import parse_route
from opsdir.domains.network.stack import subnets
from opsdir_format_terraform.hcl import Block, block, import_block, ref, tf_name
from .arm_ids import arm_segment
from .identities import LOC, RG
from .network import application_rules, binding_tags, private_endpoint
from .account import tagged

VNET = "data.azurerm_virtual_network.main"
# blocks: what the binding renders; variables: inputs only its keeper knows; shared: data sources and resources
# rendered once in the root, however many bindings use them
Rendered = NamedTuple("Rendered", [("blocks", tuple), ("variables", tuple), ("shared", tuple)])
# the next hop each kind of route target is in Azure (VirtualAppliance needs its address)
NEXT_HOPS = {"internet": "Internet", "local": "VnetLocal", "none": "None", "vpn": "VirtualNetworkGateway",
             "transit": "VirtualNetworkGateway", "firewall": "VirtualAppliance", "appliance": "VirtualAppliance"}
GATEWAY = "virtual_network_gateway_id"
WATCHER = ("network_watcher_name", "network_watcher_resource_group")


def _subnet_data(s):
    """A subnet's data source by its provider ref (<virtual network>/<subnet>)."""
    pref = one(s, "ciamProviderRef")
    if not pref or "/" not in pref:
        return block("data", ["azurerm_subnet", tf_name(rdn_value(s))], [
            ("#", "UNBOUND: the binding has no provider ref (<virtual network>/<subnet>)")])
    vnet, sub = pref.split("/", 1)
    return block("data", ["azurerm_subnet", tf_name(rdn_value(s))], [
        ("name", sub), ("virtual_network_name", vnet), ("resource_group_name", RG)])


def network_data(m):
    """Data sources for environment m's resource group, virtual network and subnets (by their provider refs)."""
    net = one_role(m, "network")
    name = one(net, "ciamProviderRef") if net is not None else None
    group = (one(net, "ciamResourceGroup") if net is not None else None) or one(m.env, "ciamResourceGroup")
    return (block("data", ["azurerm_resource_group", "main"], [("name", group)] if group else
                  [("#", "UNBOUND: neither the network binding nor the environment names a resource group")]),
            block("data", ["azurerm_virtual_network", "main"], [("name", name), ("resource_group_name", RG)] if name
                  else [("#", "UNBOUND: the network binding has no provider ref")]),
            *(_subnet_data(s) for s in of_class(m, "ciamSubnetBinding")))


def _var(name, description, sensitive=False):
    return block("variable", [name], [("type", ref("string")), ("description", description),
                                      *((("sensitive", True),) if sensitive else ())])


def arm_id(b, kind=None):
    """The ARM ID of a binding's resource: its provider ref when that is one, else built from the resource group and
    the name the ref holds (Microsoft.Network/<kind>/<name>); None when it is a name and no kind is given (a child
    resource, whose ID a name doesn't give)."""
    pref = one(b, "ciamProviderRef") or ""
    return pref if pref.startswith("/subscriptions/") else \
        f"${{data.azurerm_resource_group.main.id}}/providers/Microsoft.Network/{kind}/{pref}" if pref and kind else None


def _adopt(address, b, kind=None):
    """An import block for a binding that exists (by its ARM ID), else ()."""
    found = arm_id(b, kind) if adopted(b) else None
    return (import_block(address, found),) if found else ()


def _pair(gateway, variable):
    """An association's import ID '<gateway ID>|<the input's ID>', as a template (the formatter would read a string
    that starts with ${ and ends with } as a bare expression)."""
    return ref(f'"{gateway}|${{var.{variable}}}"')


def _note(b, text):
    return Rendered((f"# {rdn_value(b)}: {text}",), (), ())


def _subnet(s):
    return ref(f"data.azurerm_subnet.{tf_name(rdn_value(s))}.id")


def _name(m, b, prefix):
    return f"{prefix}-ciam-{rdn_value(m.env)}-{rdn_value(b)}"


# ------------------------------------------------------------------ NAT egress
def egress(m, b, here=()):
    """A NAT gateway with its public IPs (/32) and public IP prefixes (wider ranges) as inputs (an existing gateway's
    associations imported: '<gateway ID>|<IP ID>'), a new one on the environment's subnets (an existing one's subnets
    aren't recorded, so stay as they are); a note for a private range."""
    n, cidrs = tf_name(rdn_value(b)), values(b, "ciamCidr")
    private = tuple(c for c in cidrs if is_private(c))
    if private and len(private) == len(cidrs):
        return _note(b, f"Azure NAT gateways are public only; {', '.join(private)} is private address space. "
                        "Not rendered.")
    public = tuple(c for c in cidrs if not is_private(c))
    single = tuple(c for c in public if ipaddress.ip_network(c, strict=False).num_addresses == 1)
    ranges = tuple(c for c in public if c not in single)
    found = of_class(m, "ciamSubnetBinding")
    zone = one(b, "ciamZone")
    nat = arm_id(b, "natGateways") if adopted(b) else None          # the existing gateway's ID, its associations'
    return Rendered((
        block("resource", ["azurerm_nat_gateway", n], [
            ("name", one(b, "ciamProviderRef") or _name(m, b, "ng")), ("location", LOC), ("resource_group_name", RG),
            ("sku_name", "Standard"), *((("zones", [zone]),) if zone else ()), ("tags", tagged(m, binding_tags(b)))]),
        *_adopt(f"azurerm_nat_gateway.{n}", b, "natGateways"),
        *(x for i, _ in enumerate(single) for x in (
            block("resource", ["azurerm_nat_gateway_public_ip_association", f"{n}_{i}"], [
                ("nat_gateway_id", ref(f"azurerm_nat_gateway.{n}.id")),
                ("public_ip_address_id", ref(f"var.{n}_ip_{i}"))]),
            *((import_block(f"azurerm_nat_gateway_public_ip_association.{n}_{i}", _pair(nat, f"{n}_ip_{i}")),)
              if nat else ()))),
        *(x for i, _ in enumerate(ranges) for x in (
            block("resource", ["azurerm_nat_gateway_public_ip_prefix_association", f"{n}_{i}"], [
                ("nat_gateway_id", ref(f"azurerm_nat_gateway.{n}.id")),
                ("public_ip_prefix_id", ref(f"var.{n}_prefix_{i}"))]),
            *((import_block(f"azurerm_nat_gateway_public_ip_prefix_association.{n}_{i}",
                            _pair(nat, f"{n}_prefix_{i}")),) if nat else ()))),
        # an existing gateway's subnets aren't recorded (ciamEgress names none): they stay as its keeper has them
        *((f"# {rdn_value(b)}: the subnets an existing NAT gateway serves aren't recorded; its subnet "
           "associations stay as they are",) if nat else
          (block("resource", ["azurerm_subnet_nat_gateway_association", f"{n}_{tf_name(rdn_value(s))}"], [
              ("subnet_id", _subnet(s)), ("nat_gateway_id", ref(f"azurerm_nat_gateway.{n}.id"))]) for s in found))),
        (*(_var(f"{n}_ip_{i}", f"The public IP resource (Standard, static) with address {c} NAT gateway "
                               f"{rdn_value(b)} sends from") for i, c in enumerate(single)),
         *(_var(f"{n}_prefix_{i}", f"The public IP prefix {c} NAT gateway {rdn_value(b)} sends from")
           for i, c in enumerate(ranges))),
        ())


# ------------------------------------------------------------------ route tables
def _address(m, route):
    """(next hop address or None, variables) of a route to a firewall or appliance: an address the route names, the
    target binding's proxy address when it is one, else an input."""
    b = route_target(m, route)
    host = (one(b, "ciamProxyAddress") or "").rsplit(":", 1)[0] if b is not None else route.target
    try:
        return str(ipaddress.ip_address(host)), ()
    except ValueError:
        name = f"{tf_name(one(b, 'ciamBindingRole') if b is not None else route.target or 'appliance')}_private_ip"
        what = rdn_value(b) if b is not None else route.target or "the appliance"
        return ref(f"var.{name}"), (_var(name, f"The private address of {what} routes send traffic to"),)


def _route(m, route):
    """Rendered whose blocks are body items of the table: ("route", Block) or a comment."""
    hop = NEXT_HOPS.get(route.kind)
    if hop is None:
        return Rendered((("#", f"{route.destination} {route.kind}: not a next hop in Azure (subnets reach it without "
                               "a route); not rendered"),), (), ())
    address, variables = _address(m, route) if hop == "VirtualAppliance" else (None, ())
    scoped = (("#", f"{route.destination} applies to {', '.join(route.roles)} only elsewhere; Azure routes apply to "
                    "the whole subnet"),) if route.roles else ()
    name = "to-" + "-".join(filter(None, route.destination.replace("/", ".").replace(":", ".").split(".")))
    return Rendered((*scoped, ("route", Block((
        ("name", name), ("address_prefix", route.destination), ("next_hop_type", hop),
        *((("next_hop_in_ip_address", address),) if address else ()))))), variables, ())


def route_table(m, b, here=()):
    """A route table with its routes and subnet associations."""
    n = tf_name(rdn_value(b))
    parts = tuple(_route(m, r) for r in map(parse_route, values(b, "ciamRoute")) if r)
    main = (f"# {rdn_value(b)}: Azure has no main route table (subnets without one use the system routes); "
            "associate it with each subnet instead",) if one(b, "ciamMainTable") == "TRUE" else ()
    pref = one(b, "ciamProviderRef")
    name = arm_segment(pref, "routeTables") if pref and pref.startswith("/") else pref
    return Rendered((
        *main,
        block("resource", ["azurerm_route_table", n], [
            ("name", name or _name(m, b, "rt")), ("location", LOC), ("resource_group_name", RG),
            *(x for p in parts for x in p.blocks), ("tags", tagged(m, binding_tags(b)))]),
        *_adopt(f"azurerm_route_table.{n}", b, "routeTables"),
        *(x for s in subnets(m, b) for x in (
            block("resource", ["azurerm_subnet_route_table_association", f"{n}_{tf_name(rdn_value(s))}"], [
                ("subnet_id", _subnet(s)), ("route_table_id", ref(f"azurerm_route_table.{n}.id"))]),
            *((import_block(f"azurerm_subnet_route_table_association.{n}_{tf_name(rdn_value(s))}", _subnet(s)),)
              if adopted(b) and one(s, "ciamProviderRef") else ())))),
        tuple(v for p in parts for v in p.variables), ())


def network_acl(m, b, here=()):
    """Azure has no stateless network ACLs: named."""
    return _note(b, "Azure has no stateless network ACLs (the stack's NSGs carry its firewall rules); record these "
                    "rules as firewall rules. Not rendered.")


# ------------------------------------------------------------------ interconnects
def _remote(n, b, pref, group):
    """(remote VNet ID, data, variables) of a peering: the other network's ARM ID, its data source by name and resource
    group, else an input."""
    if pref.startswith("/subscriptions/"):
        return pref, (), ()
    if group:
        return (ref(f"data.azurerm_virtual_network.{n}_peer.id"),
                (block("data", ["azurerm_virtual_network", f"{n}_peer"], [
                    ("name", pref), ("resource_group_name", group)]),), ())
    return (ref(f"var.{n}_remote_vnet_id"), (),
            (_var(f"{n}_remote_vnet_id", f"The virtual network {rdn_value(b)} peers with"),))


def _peering(m, b, n):
    cloud, net = peer_cloud(m.d, b), peer_network(m.d, b)
    if cloud is not None and one(cloud, "ciamCloudProvider") != "azure":
        return _note(b, f"peering joins two networks of one provider, and the other end is on "
                        f"{one(cloud, 'ciamCloudProvider')}: record it as a vpn link. Not rendered.")
    pref = one(net, "ciamProviderRef") if net is not None else None
    if pref is None:
        return _note(b, "UNBOUND: the other environment's network has no provider ref to peer with. Not rendered.")
    remote, data, variables = _remote(n, b, pref, one(net, "ciamResourceGroup"))
    return Rendered((
        *data,
        *((f"# {rdn_value(b)}: the other side adds its half of the peering (its virtual network to ours)",)
          if one(b, "ciamPeerAccepted") != "TRUE" else ()),
        block("resource", ["azurerm_virtual_network_peering", n], [
            ("name", _name(m, b, "peer")), ("resource_group_name", RG),
            ("virtual_network_name", ref(f"{VNET}.name")), ("remote_virtual_network_id", remote),
            ("allow_virtual_network_access", True)]),
        *_adopt(f"azurerm_virtual_network_peering.{n}", b)), variables, ())


def _vpn(m, b, n):
    gateway, peer_asn, local_asn = one(b, "ciamPeerGateway"), one(b, "ciamPeerAsn"), one(b, "ciamLocalAsn")
    if gateway is None:
        return _note(b, "UNBOUND: a VPN needs the other end's gateway address (ciamPeerGateway). Not rendered.")
    bgp = (("bgp_settings", Block((("asn", int(peer_asn)), ("bgp_peering_address", ref(f"var.{n}_bgp_peer_ip"))))),) \
        if peer_asn else ()
    return Rendered((
        *((f"# {rdn_value(b)}: our side's BGP ASN {local_asn} is set on the virtual network gateway",)
          if local_asn else ()),
        block("resource", ["azurerm_local_network_gateway", n], [
            ("name", _name(m, b, "lgw")), ("location", LOC), ("resource_group_name", RG),
            ("gateway_address", gateway),
            *((("address_space", values(b, "ciamAcceptedCidr")),) if values(b, "ciamAcceptedCidr") else ()),
            *bgp, ("tags", tagged(m, binding_tags(b)))]),
        block("resource", ["azurerm_virtual_network_gateway_connection", n], [
            ("name", _name(m, b, "cn")), ("location", LOC), ("resource_group_name", RG), ("type", "IPsec"),
            ("virtual_network_gateway_id", ref(f"var.{GATEWAY}")),
            ("local_network_gateway_id", ref(f"azurerm_local_network_gateway.{n}.id")),
            ("shared_key", ref(f"var.{n}_shared_key")), ("bgp_enabled", peer_asn is not None),
            ("tags", tagged(m, binding_tags(b)))]),
        *_adopt(f"azurerm_virtual_network_gateway_connection.{n}", b, "connections")),
        (_var(GATEWAY, "The virtual network gateway (VPN) the connections are made on"),
         _var(f"{n}_shared_key", f"The IPsec shared key of {rdn_value(b)}, from the secret store (never recorded)",
              sensitive=True),
         *((_var(f"{n}_bgp_peer_ip", f"The BGP peering address of {rdn_value(b)}'s other end"),) if bgp else ())),
        ())


def interconnect(m, b, here=()):
    """An interconnect by its kind: peering, VPN, hub connection; transit and dedicated circuits named."""
    n, kind = tf_name(rdn_value(b)), one(b, "ciamLinkKind")
    if kind == "peering":
        return _peering(m, b, n)
    if kind == "vpn":
        return _vpn(m, b, n)
    if kind == "hub":
        return Rendered((block("resource", ["azurerm_virtual_hub_connection", n], [
            ("name", _name(m, b, "hub")), ("virtual_hub_id", ref("var.virtual_hub_id")),
            ("remote_virtual_network_id", ref(f"{VNET}.id"))]),
            *_adopt(f"azurerm_virtual_hub_connection.{n}", b)),
            (_var("virtual_hub_id", "The virtual WAN hub the network connects to"),), ())
    if kind == "transit":
        return _note(b, "Azure's transit is a virtual WAN hub (record it as a hub link) or a hub network peered with "
                        "this one (a peering link). Not rendered.")
    if kind == "dedicated":
        return _note(b, "an ExpressRoute circuit is ordered from a connectivity provider; its connection is made on "
                        "the virtual network gateway. Named, not rendered.")
    return _note(b, f"{one(b, 'ciamInterconnectKind')}: what kind of link it is isn't recorded (ciamLinkKind). "
                    "Not rendered.")


# ------------------------------------------------------------------ flow logs
def _destination(m, b):
    """(storage account ID or None, traffic analytics Block items, data, variables) of a flow log's destination."""
    dest = one_role(m, one(b, "ciamLogDestinationRole") or "")
    pref = (one(dest, "ciamProviderRef") or "") if dest is not None else ""
    if "/microsoft.storage/storageaccounts/" in pref.lower():
        return pref, (), (), ()
    if "/microsoft.operationalinsights/workspaces/" in pref.lower():
        n = tf_name(rdn_value(dest))
        data = block("data", ["azurerm_log_analytics_workspace", n], [
            ("name", arm_segment(pref, "workspaces")), ("resource_group_name", arm_segment(pref, "resourceGroups"))])
        analytics = ("traffic_analytics", Block((
            ("enabled", True), ("workspace_id", ref(f"data.azurerm_log_analytics_workspace.{n}.workspace_id")),
            ("workspace_region", ref(f"data.azurerm_log_analytics_workspace.{n}.location")),
            ("workspace_resource_id", pref), ("interval_in_minutes", 10))))
        return ref("var.flow_logs_storage_account_id"), (analytics,), (data,), (
            _var("flow_logs_storage_account_id", "The storage account flow logs are written to (traffic analytics "
                                                 "reads them into the workspace)"),)
    return None, (), (), ()


def flow_log(m, b, here=()):
    """Virtual network flow logs on the VNet or each subnet, to the destination's storage account."""
    n, scope = tf_name(rdn_value(b)), one(b, "ciamFlowScope")
    if scope == "security-group":
        return _note(b, "NSG flow logs retire (no new ones since 2025-07-30, all on 2027-09-30): record a virtual "
                        "network flow log instead. Not rendered.")
    on = ({"network": ((n, _name(m, b, "fl"), ref(f"{VNET}.id")),),
           "subnet": tuple((f"{n}_{tf_name(rdn_value(s))}", f"{_name(m, b, 'fl')}-{rdn_value(s)}", _subnet(s))
                           for s in subnets(m, b))}.get(scope, ()))
    if not on:
        return _note(b, f"a flow log on {scope}s needs their ids, which aren't recorded. Not rendered.")
    storage, analytics, data, variables = _destination(m, b)
    if storage is None:
        return _note(b, "UNBOUND: its log destination has no binding naming a storage account or Log Analytics "
                        "workspace. Not rendered.")
    days = one(b, "ciamRetentionDays")
    return Rendered(
        tuple(x for name, title, target in on for x in (
            block("resource", ["azurerm_network_watcher_flow_log", name], [
                ("name", title),
                ("network_watcher_name", ref(f"var.{WATCHER[0]}")),
                ("resource_group_name", ref(f"var.{WATCHER[1]}")),
                ("target_resource_id", target), ("storage_account_id", storage), ("enabled", True), ("version", 2),
                ("retention_policy", Block((("enabled", bool(days)), ("days", int(days or 0))))), *analytics,
                ("tags", tagged(m, binding_tags(b)))]),
            *(_adopt(f"azurerm_network_watcher_flow_log.{name}", b) if len(on) == 1 else ()))),
        (_var(WATCHER[0], "The Network Watcher of the network's region"),
         _var(WATCHER[1], "The resource group of that Network Watcher"), *variables),
        data)


# ------------------------------------------------------------------ kept elsewhere
def kept_elsewhere(m, b, here=()):
    """A private endpoint or an egress firewall's rule collection group someone else keeps, as the stack would render
    it."""
    if is_kind(m.d, b, "ciamProxy"):
        return Rendered(application_rules(m, b), (), ())
    blocks = private_endpoint(m, b)
    single = sum(x.startswith('resource "azurerm_private_endpoint"') for x in blocks) == 1
    return Rendered((*blocks, *(_adopt(f"azurerm_private_endpoint.{tf_name(rdn_value(b))}", b, "privateEndpoints")
                                if single else ())), (), ())


RENDERERS = (("ciamEgress", egress), ("ciamRouteTable", route_table), ("ciamNetworkAcl", network_acl),
             ("ciamInterconnect", interconnect), ("ciamFlowLog", flow_log), ("ciamPrivateEndpoint", kept_elsewhere),
             ("ciamProxy", kept_elsewhere))


def render_plumbing(m, keeper):
    """Rendered of what a keeper keeps of environment m's plumbing (opsdir.domains.network.plumbing.Keeper): the
    resource group, VNet and subnet data sources and what bindings share first, inputs unique by name."""
    here = {b.dn for b in keeper.bindings}
    parts = tuple(next(fn for oc, fn in RENDERERS if is_kind(m.d, b, oc))(m, b, here) for b in keeper.bindings)
    return Rendered(tuple(x for p in parts for x in p.blocks),
                    tuple(dict.fromkeys(v for p in parts for v in p.variables)),
                    (*network_data(m), *dict.fromkeys(x for p in parts for x in p.shared)))
