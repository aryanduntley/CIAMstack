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
                    gateway, an input, through azapi: below), a virtual WAN hub connection (the hub an input).
                    Transit and ExpressRoute circuits are named, not rendered
  flow logs         virtual network flow logs (Network Watcher, an input) on the VNet or each subnet, to the storage
                    account the destination names (traffic analytics when it is a Log Analytics workspace, the
                    storage account then an input), retention as recorded. Never NSG flow logs (they retire)
  kept elsewhere    private endpoints and egress firewalls' rule collection groups someone else keeps
                    (opsdir_adapter_azure.network)
A VPN connection's shared key never enters Terraform state (U.5, task 586): azurerm's connection has no write-only
argument for it and reads it back (Get Shared Key) even when it isn't set, so the connection is rendered through
Microsoft's azapi provider when the cloud allows that add-on (ciamProviderAddOn azapi): a Microsoft.Network/connections
azapi_resource whose body holds everything but the key, and whose write-only sensitive_body holds the key read from Key
Vault (its vault and secret name inputs: the record has no reference for it) by an ephemeral azurerm_key_vault_secret.
Without the add-on it is an action for the network's keeper: create the connection by hand. An existing connection is
not adopted (an import would read its key into state and plan): a note. Bicep/ARM take the merged body, the key a
secure parameter filled from the vault.
Tags Role (and opsdir's mark), read back by the importers. What it leaves out or to a person is a render note
(core.notes, flow 43) written as its comment, enumerated the way the keepers' roots are walked (plumbing_notes). Pure.
"""
import ipaddress

from opsdir.core.directory import is_kind, one, rdn_value, values
from opsdir.core.environment import of_class, one_role
from opsdir.core.network import is_private
from opsdir.core.notes import RECORD, note_comment
from opsdir.domains.network.plumbing import (adopted, cross_cloud_peering_note, flow_scope_note, keeper_notes,
                                             link_kind_note, network_note, peer_cloud, peer_half_note, peer_network,
                                             route_target, subnet_wide_note)
from opsdir.domains.network.routing import parse_route
from opsdir.domains.network.stack import subnets
from opsdir_format_terraform.placing import Rendered, keeper_rendered
from opsdir_format_terraform.hcl import (Block, blocks_of, comment, ref, tf_block, tf_import,
                                         tf_name)
from .arm_ids import arm_segment
from .identities import GROUP, LOC, RG
from .network import application_rules, binding_tags, endpoint_notes, firewall_notes, private_endpoint
from .account import azapi_allowed, tagged

VNET = "data.azurerm_virtual_network.main"
# the next hop each kind of route target is in Azure (VirtualAppliance needs its address)
NEXT_HOPS = {"internet": "Internet", "local": "VnetLocal", "none": "None", "vpn": "VirtualNetworkGateway",
             "transit": "VirtualNetworkGateway", "firewall": "VirtualAppliance", "appliance": "VirtualAppliance"}
GATEWAY = "virtual_network_gateway_id"
WATCHER = ("network_watcher_name", "network_watcher_resource_group")
AZAPI = "azapi_resource"
# A VPN connection through azapi: the newest Microsoft.Network/connections API version azapi 2.13's schemas know
# (research 586; ARM's newest is 2026-01-01)
CONNECTION = "Microsoft.Network/connections@2025-07-01"


def _subnet_data(s):
    """A subnet's data source by its provider ref (<virtual network>/<subnet>)."""
    pref = one(s, "ciamProviderRef")
    if not pref or "/" not in pref:
        return tf_block("data", ["azurerm_subnet", tf_name(rdn_value(s))], [
            ("#", "UNBOUND: the binding has no provider ref (<virtual network>/<subnet>)")])
    vnet, sub = pref.split("/", 1)
    return tf_block("data", ["azurerm_subnet", tf_name(rdn_value(s))], [
        ("name", sub), ("virtual_network_name", vnet), ("resource_group_name", RG)])


def network_data(m):
    """Data sources for environment m's resource group, virtual network and subnets (by their provider refs)."""
    net = one_role(m, "network")
    name = one(net, "ciamProviderRef") if net is not None else None
    group = (one(net, "ciamResourceGroup") if net is not None else None) or one(m.env, "ciamResourceGroup")
    return (tf_block("data", ["azurerm_resource_group", "main"], [("name", group)] if group else
                     [("#", "UNBOUND: neither the network binding nor the environment names a resource group")]),
            tf_block("data", ["azurerm_virtual_network", "main"], [("name", name), ("resource_group_name", RG)] if name
                     else [("#", "UNBOUND: the network binding has no provider ref")]),
            *(_subnet_data(s) for s in of_class(m, "ciamSubnetBinding")))


def _var(name, description):
    return tf_block("variable", [name], [("type", ref("string")), ("description", description)])


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
    return (tf_import(address, found),) if found else ()


def _pair(gateway, variable):
    """An association's import ID '<gateway ID>|<the input's ID>', as a template (the formatter would read a string
    that starts with ${ and ends with } as a bare expression)."""
    return ref(f'"{gateway}|${{var.{variable}}}"')


def _note(b, text):
    return Rendered((comment(f"{rdn_value(b)}: {text}"),), (), ())


def _noted(notes):
    """Rendered of render notes' comments."""
    return Rendered(tuple(comment(note_comment(n)) for n in notes), (), ())


def _subnet(s):
    return ref(f"data.azurerm_subnet.{tf_name(rdn_value(s))}.id")


def _name(m, b, prefix):
    return f"{prefix}-ciam-{rdn_value(m.env)}-{rdn_value(b)}"


# ------------------------------------------------------------------ NAT egress
def _private_only(b):
    """The egress's ranges when every one is private address space, else ()."""
    cidrs = values(b, "ciamCidr")
    return cidrs if cidrs and all(is_private(c) for c in cidrs) else ()


def _kept_subnets_note(m, b):
    return network_note(m, b, "note", "the subnets an existing NAT gateway serves aren't recorded; its subnet "
                        "associations stay as they are")


def egress_notes(m, b, here=()):
    """The render notes of NAT egress b as egress writes them: a private range only (a blocker: Azure NAT gateways
    are public only), an existing gateway's subnets left as they are (a plain note)."""
    private = _private_only(b)
    if private:
        return (network_note(m, b, "blocker", f"Azure NAT gateways are public only; {', '.join(private)} is private "
                             "address space: not rendered",
                             ("Record the public addresses it sends from (ciamCidr), or send private egress through a "
                              f"firewall or appliance route, {RECORD}",)),)
    return (_kept_subnets_note(m, b),) if adopted(b) else ()


def egress(m, b, here=()):
    """A NAT gateway with its public IPs (/32) and public IP prefixes (wider ranges) as inputs (an existing gateway's
    associations imported: '<gateway ID>|<IP ID>'), a new one on the environment's subnets (an existing one's subnets
    aren't recorded, so stay as they are: a note); a private range's note (egress_notes)."""
    n, cidrs = tf_name(rdn_value(b)), values(b, "ciamCidr")
    if _private_only(b):
        return _noted(egress_notes(m, b))
    public = tuple(c for c in cidrs if not is_private(c))
    single = tuple(c for c in public if ipaddress.ip_network(c, strict=False).num_addresses == 1)
    ranges = tuple(c for c in public if c not in single)
    found = of_class(m, "ciamSubnetBinding")
    zone = one(b, "ciamZone")
    nat = arm_id(b, "natGateways") if adopted(b) else None          # the existing gateway's ID, its associations'
    return Rendered((
        tf_block("resource", ["azurerm_nat_gateway", n], [
            ("name", one(b, "ciamProviderRef") or _name(m, b, "ng")), ("location", LOC), ("resource_group_name", RG),
            ("sku_name", "Standard"), *((("zones", [zone]),) if zone else ()), ("tags", tagged(m, binding_tags(b)))]),
        *_adopt(f"azurerm_nat_gateway.{n}", b, "natGateways"),
        *(x for i, _ in enumerate(single) for x in (
            tf_block("resource", ["azurerm_nat_gateway_public_ip_association", f"{n}_{i}"], [
                ("nat_gateway_id", ref(f"azurerm_nat_gateway.{n}.id")),
                ("public_ip_address_id", ref(f"var.{n}_ip_{i}"))]),
            *((tf_import(f"azurerm_nat_gateway_public_ip_association.{n}_{i}", _pair(nat, f"{n}_ip_{i}")),)
              if nat else ()))),
        *(x for i, _ in enumerate(ranges) for x in (
            tf_block("resource", ["azurerm_nat_gateway_public_ip_prefix_association", f"{n}_{i}"], [
                ("nat_gateway_id", ref(f"azurerm_nat_gateway.{n}.id")),
                ("public_ip_prefix_id", ref(f"var.{n}_prefix_{i}"))]),
            *((tf_import(f"azurerm_nat_gateway_public_ip_prefix_association.{n}_{i}",
                         _pair(nat, f"{n}_prefix_{i}")),) if nat else ()))),
        # an existing gateway's subnets aren't recorded (ciamEgress names none): they stay as its keeper has them
        *((comment(note_comment(_kept_subnets_note(m, b))),) if nat else
          (tf_block("resource", ["azurerm_subnet_nat_gateway_association", f"{n}_{tf_name(rdn_value(s))}"], [
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


def _hopless_note(m, b, route):
    return network_note(m, b, "note", f"{route.destination} {route.kind}: not a next hop in Azure (subnets reach it "
                        "without a route): not rendered")


def _main_note(m, b):
    return network_note(m, b, "blocker", "Azure has no main route table (subnets without one use the system routes): "
                        "only the subnets it names are associated", ("Name each subnet it serves (ciamSubnetRole), "
                                                                     f"{RECORD}",))


def _routes(b):
    return tuple(r for r in map(parse_route, values(b, "ciamRoute")) if r)


def route_notes(m, b, here=()):
    """The render notes of route table b as route_table writes them: a main table (a blocker: Azure has none), routes
    whose kind isn't a next hop in Azure (plain notes), routes for some roles (subnet_wide_note); each once."""
    return tuple(dict.fromkeys((
        *((_main_note(m, b),) if one(b, "ciamMainTable") == "TRUE" else ()),
        *(n for r in _routes(b) for n in ((_hopless_note(m, b, r),) if NEXT_HOPS.get(r.kind) is None else
                                          (subnet_wide_note(m, b, r, "Azure"),) if r.roles else ())))))


def _route(m, b, route):
    """Rendered whose blocks are body items of table b: ("route", Block) or a comment."""
    hop = NEXT_HOPS.get(route.kind)
    if hop is None:
        return Rendered((("#", note_comment(_hopless_note(m, b, route))),), (), ())
    address, variables = _address(m, route) if hop == "VirtualAppliance" else (None, ())
    scoped = (("#", note_comment(subnet_wide_note(m, b, route, "Azure"))),) if route.roles else ()
    name = "to-" + "-".join(filter(None, route.destination.replace("/", ".").replace(":", ".").split(".")))
    return Rendered((*scoped, ("route", Block((
        ("name", name), ("address_prefix", route.destination), ("next_hop_type", hop),
        *((("next_hop_in_ip_address", address),) if address else ()))))), variables, ())


def route_table(m, b, here=()):
    """A route table with its routes and subnet associations."""
    n = tf_name(rdn_value(b))
    parts = tuple(_route(m, b, r) for r in _routes(b))
    main = (comment(note_comment(_main_note(m, b))),) if one(b, "ciamMainTable") == "TRUE" else ()
    pref = one(b, "ciamProviderRef")
    name = arm_segment(pref, "routeTables") if pref and pref.startswith("/") else pref
    return Rendered((
        *main,
        tf_block("resource", ["azurerm_route_table", n], [
            ("name", name or _name(m, b, "rt")), ("location", LOC), ("resource_group_name", RG),
            *(x for p in parts for x in p.blocks), ("tags", tagged(m, binding_tags(b)))]),
        *_adopt(f"azurerm_route_table.{n}", b, "routeTables"),
        *(x for s in subnets(m, b) for x in (
            tf_block("resource", ["azurerm_subnet_route_table_association", f"{n}_{tf_name(rdn_value(s))}"], [
                ("subnet_id", _subnet(s)), ("route_table_id", ref(f"azurerm_route_table.{n}.id"))]),
            *((tf_import(f"azurerm_subnet_route_table_association.{n}_{tf_name(rdn_value(s))}", _subnet(s)),)
              if adopted(b) and one(s, "ciamProviderRef") else ())))),
        tuple(v for p in parts for v in p.variables), ())


def acl_notes(m, b, here=()):
    """The render note (a blocker) of network ACL b: Azure has no stateless network ACLs."""
    return (network_note(m, b, "blocker", "Azure has no stateless network ACLs (the stack's NSGs carry its firewall "
                         "rules): not rendered", (f"Record these rules as firewall rules, {RECORD}",)),)


def network_acl(m, b, here=()):
    """Azure has no stateless network ACLs: its note's comment (acl_notes)."""
    return _noted(acl_notes(m, b))


# ------------------------------------------------------------------ interconnects
def _remote(n, b, pref, group):
    """(remote VNet ID, data, variables) of a peering: the other network's ARM ID, its data source by name and resource
    group, else an input."""
    if pref.startswith("/subscriptions/"):
        return pref, (), ()
    if group:
        return (ref(f"data.azurerm_virtual_network.{n}_peer.id"),
                (tf_block("data", ["azurerm_virtual_network", f"{n}_peer"], [
                    ("name", pref), ("resource_group_name", group)]),), ())
    return (ref(f"var.{n}_remote_vnet_id"), (),
            (_var(f"{n}_remote_vnet_id", f"The virtual network {rdn_value(b)} peers with"),))


def _cross_cloud(m, b):
    cloud = peer_cloud(m.d, b)
    return cloud is not None and one(cloud, "ciamCloudProvider") != "azure"


def _half_note(m, b):
    return peer_half_note(m, b, "the other side adds its half of the peering (its virtual network to ours)")


def _asn_note(m, b, asn):
    return network_note(m, b, "action", f"our side's BGP ASN {asn} is set on the virtual network gateway (an input, "
                        "not rendered here)", (f"Check that the virtual network gateway uses BGP ASN {asn} (whoever "
                                               "keeps the gateway)",))


def _peering(m, b, n):
    net = peer_network(m.d, b)
    if _cross_cloud(m, b):
        return _noted((cross_cloud_peering_note(m, b, "Azure"),))
    pref = one(net, "ciamProviderRef") if net is not None else None
    if pref is None:
        return _note(b, "UNBOUND: the other environment's network has no provider ref to peer with. Not rendered.")
    remote, data, variables = _remote(n, b, pref, one(net, "ciamResourceGroup"))
    return Rendered((
        *data,
        *((comment(note_comment(_half_note(m, b))),) if one(b, "ciamPeerAccepted") != "TRUE" else ()),
        tf_block("resource", ["azurerm_virtual_network_peering", n], [
            ("name", _name(m, b, "peer")), ("resource_group_name", RG),
            ("virtual_network_name", ref(f"{VNET}.name")), ("remote_virtual_network_id", remote),
            ("allow_virtual_network_access", True)]),
        *_adopt(f"azurerm_virtual_network_peering.{n}", b)), variables, ())


def _kept_connection_note(m, b):
    return network_note(m, b, "note", f"the existing connection {one(b, 'ciamProviderRef')} stays as its keeper has "
                        "it, its shared key where it is: adopting it would read the key into Terraform state and plan "
                        "(U.5: no secret in state): not imported")


def _hand_connection_note(m, b):
    bgp = "on" if one(b, "ciamPeerAsn") else "off"
    return network_note(m, b, "action", "its connection isn't rendered: azurerm keeps an IPsec connection's shared key "
                        "in Terraform state (it reads the key back even when not set; U.5: no secret in state), and "
                        "the cloud doesn't allow the azapi add-on, whose write-only body keeps it out",
                        (f"Create connection {_name(m, b, 'cn')} on the virtual network gateway (type IPsec, to local "
                         f"network gateway {_name(m, b, 'lgw')}, BGP {bgp}) in the environment's resource group, its "
                         "shared key the one Key Vault holds for it (pasted there, never written down elsewhere), by "
                         "hand (the portal, or az network vpn-connection create)",
                         f"Or allow the azapi add-on on {rdn_value(m.cloud)} (ciamProviderAddOn azapi), {RECORD}: the "
                         "connection is then rendered, its shared key write-only"))


def vpn_connection_note(m, b):
    """The render note of VPN link b's connection when it isn't rendered (U.5: azurerm keeps the shared key in state):
    an existing connection kept as it is (a plain note), a new one without the azapi add-on created by hand (an
    action); None when azapi renders it (or the link has no peer gateway)."""
    if one(b, "ciamPeerGateway") is None:
        return None
    return _kept_connection_note(m, b) if adopted(b) else None if azapi_allowed(m) else _hand_connection_note(m, b)


def _connection(m, b, n):
    """(blocks, variables) of VPN link b's connection through azapi: the Key Vault secret holding its shared key read
    ephemerally (its vault and name inputs) and a Microsoft.Network/connections resource whose write-only
    sensitive_body alone holds the key (in no Terraform state or plan, U.5; resent on every update: no
    sensitive_body_version); the note's comment instead when it isn't rendered (vpn_connection_note)."""
    found = vpn_connection_note(m, b)
    if found is not None:
        return (comment(note_comment(found)),), ()
    secret = ref(f"ephemeral.azurerm_key_vault_secret.{n}_shared_key.value")
    return (
        tf_block("ephemeral", ["azurerm_key_vault_secret", f"{n}_shared_key"], [
            ("name", ref(f"var.{n}_shared_key_secret")), ("key_vault_id", ref(f"var.{n}_shared_key_vault_id"))]),
        tf_block("resource", [AZAPI, n], [
            ("#", "the IPsec shared key is write-only (azapi's sensitive_body; a secure parameter in Bicep/ARM): in no "
                  "Terraform state (U.5)"),
            ("type", CONNECTION), ("name", _name(m, b, "cn")), ("parent_id", GROUP), ("location", LOC),
            ("body", {"properties": {
                "connectionType": "IPsec", "enableBgp": one(b, "ciamPeerAsn") is not None,
                "virtualNetworkGateway1": {"id": ref(f"var.{GATEWAY}"), "properties": {}},
                "localNetworkGateway2": {"id": ref(f"azurerm_local_network_gateway.{n}.id"), "properties": {}}}}),
            ("sensitive_body", {"properties": {"sharedKey": secret}}),
            ("tags", tagged(m, binding_tags(b)))])), (
        _var(GATEWAY, "The virtual network gateway (VPN) the connections are made on"),
        _var(f"{n}_shared_key_vault_id", f"The Key Vault (its resource ID) holding the IPsec shared key of "
                                         f"{rdn_value(b)} (read when applied, never in state)"),
        _var(f"{n}_shared_key_secret", f"The name of the Key Vault secret holding the IPsec shared key of "
                                       f"{rdn_value(b)}"))


def _vpn(m, b, n):
    gateway, peer_asn, local_asn = one(b, "ciamPeerGateway"), one(b, "ciamPeerAsn"), one(b, "ciamLocalAsn")
    if gateway is None:
        return _note(b, "UNBOUND: a VPN needs the other end's gateway address (ciamPeerGateway). Not rendered.")
    bgp = (("bgp_settings", Block((("asn", int(peer_asn)), ("bgp_peering_address", ref(f"var.{n}_bgp_peer_ip"))))),) \
        if peer_asn else ()
    blocks, variables = _connection(m, b, n)
    return Rendered((
        *((comment(note_comment(_asn_note(m, b, local_asn))),) if local_asn else ()),
        tf_block("resource", ["azurerm_local_network_gateway", n], [
            ("name", _name(m, b, "lgw")), ("location", LOC), ("resource_group_name", RG),
            ("gateway_address", gateway),
            *((("address_space", values(b, "ciamAcceptedCidr")),) if values(b, "ciamAcceptedCidr") else ()),
            *bgp, ("tags", tagged(m, binding_tags(b)))]),
        *blocks),
        (*variables, *((_var(f"{n}_bgp_peer_ip", f"The BGP peering address of {rdn_value(b)}'s other end"),) if bgp
                       else ())),
        ())


def plumbing_azapi(m):
    """Whether environment m's plumbing writes an azapi resource: a new VPN connection (_connection) with the add-on
    allowed."""
    return azapi_allowed(m) and any(
        one(b, "ciamLinkKind") == "vpn" and one(b, "ciamPeerGateway") and not adopted(b)
        for b in of_class(m, "ciamInterconnect"))


def interconnect_notes(m, b, here=()):
    """The render notes of interconnect b as interconnect writes them: a peering to another cloud (a blocker), the
    other side's half of a peering (peer_half_note), our side's BGP ASN set on the virtual network gateway (an action),
    a VPN connection left out (vpn_connection_note), a transit link (a blocker), an ExpressRoute circuit ordered by
    hand (an action), an unrecorded kind of link (a blocker); an UNBOUND link has none."""
    kind = one(b, "ciamLinkKind")
    if kind == "peering" and _cross_cloud(m, b):
        return (cross_cloud_peering_note(m, b, "Azure"),)
    if kind == "peering":
        net = peer_network(m.d, b)
        bound = net is not None and one(net, "ciamProviderRef") is not None
        return (_half_note(m, b),) if bound and one(b, "ciamPeerAccepted") != "TRUE" else ()
    if kind == "vpn":
        found = vpn_connection_note(m, b)
        return (*((_asn_note(m, b, one(b, "ciamLocalAsn")),) if one(b, "ciamPeerGateway") and one(b, "ciamLocalAsn")
                  else ()), *((found,) if found is not None else ()))
    if kind == "hub":
        return ()
    if kind == "transit":
        return (network_note(m, b, "blocker", "Azure's transit is a virtual WAN hub (a hub link) or a hub network "
                             "peered with this one (a peering link): not rendered",
                             (f"Record it as a hub or peering link (ciamLinkKind), {RECORD}",)),)
    if kind == "dedicated":
        return (network_note(m, b, "action", "an ExpressRoute circuit is ordered from a connectivity provider; its "
                             "connection is made on the virtual network gateway: not rendered",
                             ("Order the ExpressRoute circuit from a connectivity provider and connect it on the "
                              "virtual network gateway",)),)
    return (link_kind_note(m, b),)


def interconnect(m, b, here=()):
    """An interconnect by its kind: peering, VPN, hub connection; transit, dedicated circuits and unrecorded kinds
    their notes' comments (interconnect_notes)."""
    n, kind = tf_name(rdn_value(b)), one(b, "ciamLinkKind")
    if kind == "peering":
        return _peering(m, b, n)
    if kind == "vpn":
        return _vpn(m, b, n)
    if kind == "hub":
        return Rendered((tf_block("resource", ["azurerm_virtual_hub_connection", n], [
            ("name", _name(m, b, "hub")), ("virtual_hub_id", ref("var.virtual_hub_id")),
            ("remote_virtual_network_id", ref(f"{VNET}.id"))]),
            *_adopt(f"azurerm_virtual_hub_connection.{n}", b)),
            (_var("virtual_hub_id", "The virtual WAN hub the network connects to"),), ())
    return _noted(interconnect_notes(m, b))


# ------------------------------------------------------------------ flow logs
def _destination(m, b):
    """(storage account ID or None, traffic analytics Block items, data, variables) of a flow log's destination."""
    dest = one_role(m, one(b, "ciamLogDestinationRole") or "")
    pref = (one(dest, "ciamProviderRef") or "") if dest is not None else ""
    if "/microsoft.storage/storageaccounts/" in pref.lower():
        return pref, (), (), ()
    if "/microsoft.operationalinsights/workspaces/" in pref.lower():
        n = tf_name(rdn_value(dest))
        data = tf_block("data", ["azurerm_log_analytics_workspace", n], [
            ("name", arm_segment(pref, "workspaces")), ("resource_group_name", arm_segment(pref, "resourceGroups"))])
        analytics = ("traffic_analytics", Block((
            ("enabled", True), ("workspace_id", ref(f"data.azurerm_log_analytics_workspace.{n}.workspace_id")),
            ("workspace_region", ref(f"data.azurerm_log_analytics_workspace.{n}.location")),
            ("workspace_resource_id", pref), ("interval_in_minutes", 10))))
        return ref("var.flow_logs_storage_account_id"), (analytics,), (data,), (
            _var("flow_logs_storage_account_id", "The storage account flow logs are written to (traffic analytics "
                                                 "reads them into the workspace)"),)
    return None, (), (), ()


def _flows_on(m, b, n):
    """((resource name, flow log name, target id), ...) of what a flow log is on: the VNet or each subnet; () for
    another scope."""
    return ({"network": ((n, _name(m, b, "fl"), ref(f"{VNET}.id")),),
             "subnet": tuple((f"{n}_{tf_name(rdn_value(s))}", f"{_name(m, b, 'fl')}-{rdn_value(s)}", _subnet(s))
                             for s in subnets(m, b))}.get(one(b, "ciamFlowScope"), ()))


def flow_log_notes(m, b, here=()):
    """The render notes (blockers) of flow log b as flow_log writes them: NSG flow logs (they retire), a scope whose
    ids aren't recorded (flow_scope_note)."""
    if one(b, "ciamFlowScope") == "security-group":
        return (network_note(m, b, "blocker", "NSG flow logs retire (no new ones since 2025-07-30, all on 2027-09-30): "
                             "not rendered", ("Record a virtual network flow log instead (ciamFlowScope network or "
                                              f"subnet), {RECORD}",)),)
    return () if _flows_on(m, b, tf_name(rdn_value(b))) else (flow_scope_note(m, b),)


def flow_log(m, b, here=()):
    """Virtual network flow logs on the VNet or each subnet, to the destination's storage account; its notes'
    comments when it isn't rendered (flow_log_notes)."""
    n = tf_name(rdn_value(b))
    on = _flows_on(m, b, n)
    if one(b, "ciamFlowScope") == "security-group" or not on:
        return _noted(flow_log_notes(m, b))
    storage, analytics, data, variables = _destination(m, b)
    if storage is None:
        return _note(b, "UNBOUND: its log destination has no binding naming a storage account or Log Analytics "
                        "workspace. Not rendered.")
    days = one(b, "ciamRetentionDays")
    return Rendered(
        tuple(x for name, title, target in on for x in (
            tf_block("resource", ["azurerm_network_watcher_flow_log", name], [
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
    single = len(blocks_of(blocks, "resource", "azurerm_private_endpoint")) == 1
    return Rendered((*blocks, *(_adopt(f"azurerm_private_endpoint.{tf_name(rdn_value(b))}", b, "privateEndpoints")
                                if single else ())), (), ())


def kept_notes(m, b, here=()):
    """The render notes of a private endpoint or egress firewall someone else keeps, as kept_elsewhere renders it."""
    return firewall_notes(m, b) if is_kind(m.d, b, "ciamProxy") else endpoint_notes(m, b)


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
    resource group, VNet and subnet data sources and what bindings share first, inputs unique by name; each binding's
    blocks stamped with its entry, what they share with the keeper's first (hcl.from_entry)."""
    return keeper_rendered(m, keeper, RENDERERS, network_data(m))
