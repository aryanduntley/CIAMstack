"""What the Azure CLI (and ARM templates, flattened to its shape) reports about an environment's network depth,
normalized to the hashicorp/azurerm attribute names the shared mapping reads (opsdir_adapter_azure.network_inventory).
Pure.

  az network route-table list                      Microsoft.Network/routeTables (+ routes, subnets)
  az network route-table route list                Microsoft.Network/routeTables/routes
  az network private-endpoint list                 Microsoft.Network/privateEndpoints (+ connection, static address)
  az network private-endpoint dns-zone-group list  Microsoft.Network/privateEndpoints/privateDnsZoneGroups
  az network private-link-service list             Microsoft.Network/privateLinkServices
  az network firewall list                         Microsoft.Network/azureFirewalls (its policy, private address)
  az network firewall policy list                  Microsoft.Network/firewallPolicies
  az network firewall policy rule-collection-group list
                                                   Microsoft.Network/firewallPolicies/ruleCollectionGroups
  az network vnet peering list                     Microsoft.Network/virtualNetworks/virtualNetworkPeerings (its state)
  az network vpn-connection list                   Microsoft.Network/connections
  az network local-gateway list                    Microsoft.Network/localNetworkGateways
  az network vnet-gateway list                     Microsoft.Network/virtualNetworkGateways
  az network vhub connection list                  Microsoft.Network/virtualHubs/hubVirtualNetworkConnections
  az network watcher flow-log list                 Microsoft.Network/networkWatchers/flowLogs
"""
from .arm_ids import arm_segment

TYPES = ("Microsoft.Network/routeTables", "Microsoft.Network/routeTables/routes", "Microsoft.Network/privateEndpoints",
         "Microsoft.Network/privateEndpoints/privateDnsZoneGroups", "Microsoft.Network/privateLinkServices",
         "Microsoft.Network/azureFirewalls", "Microsoft.Network/firewallPolicies",
         "Microsoft.Network/firewallPolicies/ruleCollectionGroups",
         "Microsoft.Network/virtualNetworks/virtualNetworkPeerings", "Microsoft.Network/connections",
         "Microsoft.Network/localNetworkGateways", "Microsoft.Network/virtualNetworkGateways",
         "Microsoft.Network/virtualHubs/hubVirtualNetworkConnections", "Microsoft.Network/networkWatchers/flowLogs")


def _low(x):
    return (x or "").lower()


def _of(items, kind):
    return [i for k, i in items if k == kind.lower()]


def _id(ref):
    return (ref or {}).get("id") if isinstance(ref, dict) else None


def _route(r):
    return {"name": r.get("name"), "address_prefix": r.get("addressPrefix"), "next_hop_type": r.get("nextHopType"),
            "next_hop_in_ip_address": r.get("nextHopIpAddress")}


def _routing(items):
    return [*(("azurerm_route_table", {"id": t.get("id"), "name": t.get("name"), "tags": t.get("tags") or {},
                                       "route": [_route(r) for r in t.get("routes") or ()],
                                       "subnets": [_id(s) for s in t.get("subnets") or () if _id(s)]})
              for t in _of(items, "Microsoft.Network/routeTables")),
            *(("azurerm_route", {**_route(r), "route_table_name": arm_segment(r.get("id"), "routeTables")})
              for r in _of(items, "Microsoft.Network/routeTables/routes"))]


def _endpoints(items):
    zone_groups = {_low((g.get("id") or "").split("/privateDnsZoneGroups/", 1)[0]): g
                   for g in _of(items, "Microsoft.Network/privateEndpoints/privateDnsZoneGroups")}

    def zones(e):
        group = zone_groups.get(_low(e.get("id"))) or {}
        return [{"private_dns_zone_ids": [c.get("privateDnsZoneId") for c in group.get("privateDnsZoneConfigs") or ()
                                          if c.get("privateDnsZoneId")]}] if group else []

    def connection(e):
        c = next(iter(e.get("privateLinkServiceConnections") or e.get("manualPrivateLinkServiceConnections") or ()), {})
        return [{"private_connection_resource_id": c.get("privateLinkServiceId"),
                 "subresource_names": c.get("groupIds") or []}] if c else []
    return [("azurerm_private_endpoint", {
        "id": e.get("id"), "name": e.get("name"), "subnet_id": _id(e.get("subnet")), "tags": e.get("tags") or {},
        "private_service_connection": connection(e), "private_dns_zone_group": zones(e),
        "ip_configuration": [{"private_ip_address": c.get("privateIPAddress") or c.get("privateIpAddress")}
                             for c in e.get("ipConfigurations") or ()]})
        for e in _of(items, "Microsoft.Network/privateEndpoints")]


def _link_services(items):
    return [("azurerm_private_link_service", {
        "id": s.get("id"), "name": s.get("name"), "alias": s.get("alias"), "tags": s.get("tags") or {},
        "load_balancer_frontend_ip_configuration_ids": [_id(f) for f in s.get("loadBalancerFrontendIpConfigurations")
                                                        or () if _id(f)],
        "nat_ip_configuration": [{"subnet_id": _id(c.get("subnet"))} for c in s.get("ipConfigurations") or ()],
        "visibility_subscription_ids": (s.get("visibility") or {}).get("subscriptions") or [],
        "auto_approval_subscription_ids": (s.get("autoApproval") or {}).get("subscriptions") or []})
        for s in _of(items, "Microsoft.Network/privateLinkServices")]


def _collections(group):
    """A rule collection group's allow collections as azurerm's application and network rule collections."""
    def protocols(r):
        return [{"type": p.get("protocolType"), "port": p.get("port")} for p in r.get("protocols") or ()]
    allow = [c for c in group.get("ruleCollections") or () if _low((c.get("action") or {}).get("type")) == "allow"]
    return {"application_rule_collection": [{"action": "Allow", "rule": [
                {"destination_fqdns": r.get("targetFqdns") or [], "protocols": protocols(r)}
                for r in c.get("rules") or () if _low(r.get("ruleType")) == "applicationrule"]} for c in allow],
            "network_rule_collection": [{"action": "Allow", "rule": [
                {"destination_fqdns": r.get("destinationFqdns") or [], "destination_ports": r.get("destinationPorts")
                 or []} for r in c.get("rules") or () if _low(r.get("ruleType")) == "networkrule"]} for c in allow]}


def _firewalls(items):
    return [*(("azurerm_firewall", {"id": f.get("id"), "name": f.get("name"), "tags": f.get("tags") or {},
                                    "firewall_policy_id": _id(f.get("firewallPolicy")),
                                    "ip_configuration": [{"private_ip_address": c.get("privateIPAddress")}
                                                         for c in f.get("ipConfigurations") or ()]})
              for f in _of(items, "Microsoft.Network/azureFirewalls")),
            *(("azurerm_firewall_policy", {"id": p.get("id"), "name": p.get("name"), "tags": p.get("tags") or {}})
              for p in _of(items, "Microsoft.Network/firewallPolicies")),
            *(("azurerm_firewall_policy_rule_collection_group", {
                "id": g.get("id"), "firewall_policy_id": (g.get("id") or "").split("/ruleCollectionGroups/", 1)[0],
                **_collections(g)}) for g in _of(items, "Microsoft.Network/firewallPolicies/ruleCollectionGroups"))]


def _links(items):
    return [*(("azurerm_virtual_network_peering", {
                "id": p.get("id"), "name": p.get("name"), "peering_state": p.get("peeringState"),
                "virtual_network_name": arm_segment(p.get("id"), "virtualNetworks"),
                "remote_virtual_network_id": _id(p.get("remoteVirtualNetwork"))})
              for p in _of(items, "Microsoft.Network/virtualNetworks/virtualNetworkPeerings")),
            *(("azurerm_virtual_network_gateway_connection", {
                "id": c.get("id"), "name": c.get("name"), "type": c.get("connectionType"), "tags": c.get("tags") or {},
                "local_network_gateway_id": _id(c.get("localNetworkGateway2")),
                "virtual_network_gateway_id": _id(c.get("virtualNetworkGateway1"))})
              for c in _of(items, "Microsoft.Network/connections")),
            *(("azurerm_local_network_gateway", {
                "id": g.get("id"), "gateway_address": g.get("gatewayIpAddress"),
                "address_space": (g.get("localNetworkAddressSpace") or {}).get("addressPrefixes") or [],
                "bgp_settings": [{"asn": (g.get("bgpSettings") or {}).get("asn")}] if g.get("bgpSettings") else []})
              for g in _of(items, "Microsoft.Network/localNetworkGateways")),
            *(("azurerm_virtual_network_gateway", {
                "id": g.get("id"),
                "bgp_settings": [{"asn": (g.get("bgpSettings") or {}).get("asn")}] if g.get("bgpSettings") else []})
              for g in _of(items, "Microsoft.Network/virtualNetworkGateways")),
            *(("azurerm_virtual_hub_connection", {"id": h.get("id"), "name": h.get("name"),
                                                  "remote_virtual_network_id": _id(h.get("remoteVirtualNetwork"))})
              for h in _of(items, "Microsoft.Network/virtualHubs/hubVirtualNetworkConnections"))]


def _flow_logs(items):
    def analytics(f):
        config = ((f.get("flowAnalyticsConfiguration") or {}).get("networkWatcherFlowAnalyticsConfiguration") or {})
        return [{"workspace_resource_id": config.get("workspaceResourceId")}] if config.get("enabled") else []
    return [("azurerm_network_watcher_flow_log", {
        "id": f.get("id"), "name": f.get("name"), "tags": f.get("tags") or {},
        "target_resource_id": f.get("targetResourceId"),
        "retention_policy": [{"enabled": (f.get("retentionPolicy") or {}).get("enabled"),
                              "days": (f.get("retentionPolicy") or {}).get("days")}],
        "traffic_analytics": analytics(f)})
        for f in _of(items, "Microsoft.Network/networkWatchers/flowLogs")]


def network_items(items):
    """(azurerm type, attributes) pairs of the network depth among (kind, item) pairs."""
    return [*_routing(items), *_endpoints(items), *_link_services(items), *_firewalls(items), *_links(items),
            *_flow_logs(items)]
