"""What Azure's networks carry beyond virtual networks, subnets and NSGs, read back in the network domain's terms
(hashicorp/azurerm attribute names; the CLI and ARM readers normalize to them). Pure.

  azurerm_route_table (+ azurerm_route,     -> route table: routes '<destination> <kind> [<target>]' (a prefix or a
    azurerm_subnet_route_table_association)    service tag; next hop VirtualAppliance: appliance at its address, or
                                               firewall when it is an Azure Firewall's private address (its policy is
                                               the target), VirtualNetworkGateway: vpn, VnetLocal: local, Internet,
                                               None), the subnets associated
  azurerm_private_endpoint                  -> private endpoint (interface): what its connection's subresource reaches
                                               (vault, blob, namespace, registry), its subnet, a static address, the
                                               private DNS zone group's zone (private DNS)
  azurerm_private_link_service              -> endpoint service: the load balancer whose frontend it exposes, its
                                               alias, the subscriptions it is visible to and approves automatically
                                               (none: each connection waits for acceptance), its NAT subnet
  azurerm_firewall_policy_rule_collection_  -> egress firewall (proxy kind firewall) under its Firewall policy: the
    group (+ azurerm_firewall_policy,          sites its application rules (HTTP on 80, HTTPS) and FQDN network rules
    azurerm_firewall)                          allow, with their ports (443 left implicit)
  azurerm_virtual_network_peering,          -> interconnect depth: peering, VPN (IPsec, VNet-to-VNet), dedicated
    azurerm_virtual_network_gateway_           (ExpressRoute) with the peer's gateway address, BGP numbers and the
    connection (+ local and virtual network    ranges it routes to, hub (a virtual WAN hub connection)
    gateways), azurerm_virtual_hub_connection
  azurerm_network_watcher_flow_log          -> flow log: what it records (a virtual network, subnet or interface; an
                                               NSG's flow logs, which retire on 2027-09-30, are named), its retention,
                                               the workspace traffic analytics sends it to
Peerings carry no tags in Azure: their roles come from the role map (roles.json); a peering's other side is the
environment whose network binding is its remote virtual network (core), else a tag PeerEnvironment.
"""
from opsdir.core.inventory import of_types, peer_environment, resource, tagged_role
from opsdir.domains.network.routing import Route, route_text
from .arm_ids import arm_segment, subnet_ref
from .network import SUBRESOURCES

SERVICE_KINDS = {"vault": "secrets", **{group: kind for kind, (group, _) in SUBRESOURCES.items() if group != "vault"}}
NEXT_HOPS = {"virtualnetworkgateway": "vpn", "vnetlocal": "local", "internet": "internet", "none": "none"}
LINK_TYPES = {"ipsec": ("vpn", "Site-to-site VPN"), "vnet2vnet": ("vpn", "VNet-to-VNet VPN"),
              "expressroute": ("dedicated", "ExpressRoute")}
WEB = {80: "Http", 443: "Https"}


def _low(x):
    return (x or "").lower()


def _first(xs):
    return (xs[0] if xs else {}) if isinstance(xs, list) else (xs or {})


def _tags(a):
    return a.get("tags") or {}


def firewall_addresses(found):
    """{an Azure Firewall's private address: its firewall policy's ID}."""
    return {c.get("private_ip_address"): fw.get("firewall_policy_id")
            for fw in of_types(found, "azurerm_firewall") for c in fw.get("ip_configuration") or ()
            if c.get("private_ip_address") and fw.get("firewall_policy_id")}


def _route(r, firewalls):
    hop, address = _low(r.get("next_hop_type")), r.get("next_hop_in_ip_address")
    kind, target = (("firewall", firewalls[address]) if address in firewalls else ("appliance", address)) \
        if hop == "virtualappliance" else (NEXT_HOPS.get(hop), None)
    return Route(r.get("address_prefix"), kind, target or "", ()) if kind and r.get("address_prefix") else None


def _route_tables(found):
    firewalls = firewall_addresses(found)
    separate = of_types(found, "azurerm_route")
    associations = of_types(found, "azurerm_subnet_route_table_association")

    def one_table(t):
        routes = (*(t.get("route") or ()),
                  *(r for r in separate if _low(r.get("route_table_name")) == _low(t.get("name"))))
        subnets = (*(t.get("subnets") or ()),
                   *(a.get("subnet_id") for a in associations if _low(a.get("route_table_id")) == _low(t.get("id"))))
        return resource("route-table", t.get("id"), {
            "ciamRoute": tuple(dict.fromkeys(route_text(x) for x in (_route(r, firewalls) for r in routes) if x))},
            links={"ciamSubnetRole": tuple(dict.fromkeys(s for s in map(subnet_ref, subnets) if s))},
            name=t.get("name"), role=tagged_role(_tags(t)), tags=_tags(t))
    return tuple(one_table(t) for t in of_types(found, "azurerm_route_table") if t.get("id"))


def _private_endpoints(found):
    def one_endpoint(e):
        connection = _first(e.get("private_service_connection"))
        group = _low(_first(connection.get("subresource_names") or []) or None)
        zones = [z for g in e.get("private_dns_zone_group") or () for z in g.get("private_dns_zone_ids") or ()]
        static = next((c.get("private_ip_address") for c in e.get("ip_configuration") or ()
                       if c.get("private_ip_address")), None)
        return resource("private-endpoint", e.get("id"), {
            "ciamPrivateService": SERVICE_KINDS.get(group, "other"), "ciamPrivateEndpointKind": "interface",
            "ciamFrontendIp": static, "ciamPrivateDns": "TRUE" if zones else "FALSE",
            "ciamDnsZoneRef": zones[0] if zones else None,
            "ciamDnsZone": arm_segment(zones[0], "privateDnsZones") if zones else None},
            links={"ciamSubnetRole": subnet_ref(e.get("subnet_id"))},
            name=e.get("name"), role=tagged_role(_tags(e)), tags=_tags(e))
    return tuple(one_endpoint(e) for e in of_types(found, "azurerm_private_endpoint") if e.get("id"))


def _link_services(found):
    def one_service(s):
        frontend = next(iter(s.get("load_balancer_frontend_ip_configuration_ids") or ()), "")
        approved = tuple(s.get("auto_approval_subscription_ids") or ())
        nat = (subnet_ref(c.get("subnet_id")) for c in s.get("nat_ip_configuration") or ())
        return resource("endpoint-service", s.get("id"), {
            "ciamServiceAlias": s.get("alias"), "ciamVisibleTo": tuple(s.get("visibility_subscription_ids") or ()),
            "ciamAllowedPrincipal": approved, "ciamAcceptanceRequired": "FALSE" if approved else "TRUE"},
            links={"ciamServiceRole": frontend.split("/frontendIPConfigurations/", 1)[0] if frontend else None,
                   "ciamSubnetRole": tuple(dict.fromkeys(r for r in nat if r))},
            name=s.get("name"), role=tagged_role(_tags(s)), tags=_tags(s))
    return tuple(one_service(s) for s in of_types(found, "azurerm_private_link_service") if s.get("id"))


def _site(host, port):
    return host if port == 443 else f"{host}:{port}"


def _allowed(group):
    """The sites a rule collection group lets out to: application rules' FQDNs per protocol port, network rules'
    FQDNs per destination port."""
    app = (_site(h, int(p.get("port") or (80 if _low(p.get("type")) == "http" else 443)))
           for c in group.get("application_rule_collection") or () if _low(c.get("action")) == "allow"
           for r in c.get("rule") or () for p in r.get("protocols") or () for h in r.get("destination_fqdns") or ())
    net = (_site(h, int(port))
           for c in group.get("network_rule_collection") or () if _low(c.get("action")) == "allow"
           for r in c.get("rule") or () for port in r.get("destination_ports") or () if str(port).isdigit()
           for h in r.get("destination_fqdns") or ())
    return (*app, *net)


def _proxies(found):
    groups = of_types(found, "azurerm_firewall_policy_rule_collection_group")
    policies = {_low(p.get("id")): p for p in of_types(found, "azurerm_firewall_policy")}
    firewalls = {_low(f.get("firewall_policy_id")): f for f in of_types(found, "azurerm_firewall")}
    refs = tuple(dict.fromkeys(g.get("firewall_policy_id") for g in groups if g.get("firewall_policy_id")))

    def one_proxy(ref):
        tags = next((_tags(x) for x in (policies.get(_low(ref)) or {}, firewalls.get(_low(ref)) or {})
                     if tagged_role(_tags(x))), {})
        sites = (s for g in groups if _low(g.get("firewall_policy_id")) == _low(ref) for s in _allowed(g))
        return resource("proxy", ref, {"ciamProxyKind": "firewall",
                                       "ciamAllowedDestination": tuple(dict.fromkeys(sites))},
                        name=arm_segment(ref, "firewallPolicies") or ref, role=tagged_role(tags), tags=tags)
    return tuple(one_proxy(ref) for ref in refs)


def _interconnects(found):
    locals_ = {_low(g.get("id")): g for g in of_types(found, "azurerm_local_network_gateway")}
    gateways = {_low(g.get("id")): g for g in of_types(found, "azurerm_virtual_network_gateway")}

    def link(a, kind, text, extra=None, network=None):
        return resource("interconnect", a.get("id"), {"ciamLinkKind": kind, "ciamInterconnectKind": text,
                                                      "ciamPeerEnvironment": peer_environment(_tags(a)),
                                                      **(extra or {})},
                        links={"ciamPeerEnvironment": network}, name=a.get("name"), role=tagged_role(_tags(a)), tags=_tags(a))

    def connection(c):
        kind, text = LINK_TYPES.get(_low(c.get("type")), ("vpn", "VPN"))
        peer = locals_.get(_low(c.get("local_network_gateway_id"))) or {}
        ours = gateways.get(_low(c.get("virtual_network_gateway_id"))) or {}
        return link(c, kind, text, {"ciamPeerGateway": peer.get("gateway_address"),
                                    "ciamPeerAsn": _first(peer.get("bgp_settings")).get("asn"),
                                    "ciamLocalAsn": _first(ours.get("bgp_settings")).get("asn"),
                                    "ciamAcceptedCidr": tuple(peer.get("address_space") or ())})
    return tuple(r for r in (
        *(link(p, "peering", "VNet peering",
               {"ciamPeerAccepted": None if not p.get("peering_state") else
                "TRUE" if _low(p.get("peering_state")) == "connected" else "FALSE"},
               arm_segment(p.get("remote_virtual_network_id"), "virtualNetworks"))     # the record names VNets
          for p in of_types(found, "azurerm_virtual_network_peering")),
        *(connection(c) for c in of_types(found, "azurerm_virtual_network_gateway_connection")),
        *(link(h, "hub", "Virtual WAN hub connection") for h in of_types(found, "azurerm_virtual_hub_connection")))
        if r.ref)


def _flow_scope(target):
    kind = _low(target).split("/providers/", 1)[-1]
    return "subnet" if "/subnets/" in kind else "network" if "virtualnetworks/" in kind else \
        "interface" if "networkinterfaces/" in kind else "security-group" if "networksecuritygroups/" in kind else None


def _flow_logs(found):
    """(flow logs, notices): an NSG's flow logs are named (they retire on 2027-09-30: VNet flow logs replace them)."""
    def one_log(f):
        target = f.get("target_resource_id") or f.get("network_security_group_id")
        retention = _first(f.get("retention_policy"))
        analytics = _first(f.get("traffic_analytics"))
        return resource("flow-log", f.get("id"), {
            "ciamFlowScope": _flow_scope(target),
            "ciamRetentionDays": retention.get("days") if retention.get("enabled") else None},
            links={"ciamSubnetRole": subnet_ref(target) if "/subnets/" in _low(target) else None,
                   "ciamLogDestinationRole": analytics.get("workspace_resource_id")},
            name=f.get("name"), role=tagged_role(_tags(f)), tags=_tags(f))
    logs = tuple(one_log(f) for f in of_types(found, "azurerm_network_watcher_flow_log") if f.get("id"))
    return logs, tuple(f"flow log {r.name}: an NSG flow log (they retire on 2027-09-30): move to a virtual network "
                       "flow log" for r in logs if r.attrs.get("ciamFlowScope") == ("security-group",))


def network_resources(found):
    """(resources, notices) of the network depth among (azurerm resource type, attributes) pairs."""
    logs, notices = _flow_logs(found)
    return ((*_route_tables(found), *_private_endpoints(found), *_link_services(found), *_proxies(found),
             *_interconnects(found), *logs), notices)
