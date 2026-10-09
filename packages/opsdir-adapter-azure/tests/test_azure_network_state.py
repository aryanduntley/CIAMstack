"""The network depth read back from Azure: route tables (an Azure Firewall's address as the firewall, by its policy),
private endpoints (subresource, static address, DNS zone group), Private Link Services, Firewall policy rule collection
groups as the egress allowlist (ports kept), peering, VPN and hub depth, VNet flow logs (an NSG's named); from
Terraform state, the CLI and ARM alike."""
import json

from opsdir_adapter_azure.arm import arm_resources
from opsdir_adapter_azure.cli import cli_resources
from opsdir_adapter_azure.inventory import state_resources

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers"
NET = f"{SUB}/Microsoft.Network"
POLICY = f"{NET}/firewallPolicies/fwp-hub"
ZONE = f"{NET}/privateDnsZones/privatelink.vaultcore.azure.net"
LB = f"{NET}/loadBalancers/lb-ldaps"
WORKSPACE = f"{SUB}/Microsoft.OperationalInsights/workspaces/law-ops"


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


STATE = _state(
    ("azurerm_firewall", "hub", {"id": f"{NET}/azureFirewalls/fw-hub", "firewall_policy_id": POLICY,
                                 "ip_configuration": [{"private_ip_address": "10.0.0.4"}]}),
    ("azurerm_route_table", "pf", {"id": f"{NET}/routeTables/rt-pf", "name": "rt-pf", "tags": {"Role": "rt-pf"},
                                   "route": [{"name": "default", "address_prefix": "0.0.0.0/0",
                                              "next_hop_type": "VirtualAppliance",
                                              "next_hop_in_ip_address": "10.0.0.4"},
                                             {"name": "dc", "address_prefix": "10.9.0.0/16",
                                              "next_hop_type": "VirtualNetworkGateway"}]}),
    ("azurerm_route", "kv", {"route_table_name": "rt-pf", "address_prefix": "AzureKeyVault",
                             "next_hop_type": "Internet"}),
    ("azurerm_subnet_route_table_association", "pf", {
        "route_table_id": f"{NET}/routeTables/rt-pf",
        "subnet_id": f"{NET}/virtualNetworks/vnet-ciam-prod/subnets/snet-pf"}),
    ("azurerm_private_endpoint", "secrets", {
        "id": f"{NET}/privateEndpoints/pe-secrets", "name": "pe-ciam-prod-pe-secrets",
        "tags": {"Role": "private-secrets"},
        "subnet_id": f"{NET}/virtualNetworks/vnet-ciam-prod/subnets/snet-pf",
        "private_service_connection": [{"private_connection_resource_id": f"{SUB}/Microsoft.KeyVault/vaults/kv",
                                        "subresource_names": ["vault"]}],
        "ip_configuration": [{"private_ip_address": "10.60.2.50"}],
        "private_dns_zone_group": [{"private_dns_zone_ids": [ZONE]}]}),
    ("azurerm_private_link_service", "ldaps", {
        "id": f"{NET}/privateLinkServices/pls-ldaps", "name": "pls-ldaps",
        "alias": "pls-ldaps.abc.eastus.azure.privatelinkservice",
        "load_balancer_frontend_ip_configuration_ids": [f"{LB}/frontendIPConfigurations/frontend"],
        "nat_ip_configuration": [{"subnet_id": f"{NET}/virtualNetworks/vnet-ciam-prod/subnets/snet-ds"}],
        "visibility_subscription_ids": ["sub-partner"], "tags": {"Role": "ldaps-endpoint-service"}}),
    ("azurerm_firewall_policy", "hub", {"id": POLICY, "tags": {"Role": "egress-firewall"}}),
    ("azurerm_firewall_policy_rule_collection_group", "sites", {
        "firewall_policy_id": POLICY,
        "application_rule_collection": [{"action": "Allow", "rule": [
            {"destination_fqdns": ["ocsp.ca.test"], "protocols": [{"type": "Http", "port": 80}]},
            {"destination_fqdns": ["idp.partner.test", "*.okta.test"],
             "protocols": [{"type": "Https", "port": 443}]}]}],
        "network_rule_collection": [{"action": "Allow", "rule": [
            {"destination_fqdns": ["smtp.mail.test"], "destination_ports": ["587"]}]}]}),
    ("azurerm_virtual_network_peering", "hub", {
        "id": f"{NET}/virtualNetworks/vnet-ciam-prod/virtualNetworkPeerings/to-hub",
        "name": "to-hub",
        "remote_virtual_network_id": f"{SUB}/Microsoft.Network/virtualNetworks/vnet-hub"}),
    ("azurerm_local_network_gateway", "dc", {"id": f"{NET}/localNetworkGateways/lgw-dc",
                                             "gateway_address": "198.51.100.7",
                                             "address_space": ["10.9.0.0/16"], "bgp_settings": [{"asn": 65010}]}),
    ("azurerm_virtual_network_gateway", "vgw", {"id": f"{NET}/virtualNetworkGateways/vgw",
                                                "bgp_settings": [{"asn": 65515}]}),
    ("azurerm_virtual_network_gateway_connection", "dc", {
        "id": f"{NET}/connections/cn-dc", "name": "cn-dc", "type": "IPsec", "tags": {"PeerEnvironment": "dc/prod"},
        "local_network_gateway_id": f"{NET}/localNetworkGateways/lgw-dc",
        "virtual_network_gateway_id": f"{NET}/virtualNetworkGateways/vgw"}),
    ("azurerm_network_watcher_flow_log", "vnet", {
        "id": f"{NET}/networkWatchers/nw/flowLogs/fl-vnet", "name": "fl-vnet", "tags": {"Role": "flow-vnet"},
        "target_resource_id": f"{NET}/virtualNetworks/vnet-ciam-prod",
        "retention_policy": [{"enabled": True, "days": 90}],
        "traffic_analytics": [{"workspace_resource_id": WORKSPACE}]}),
    ("azurerm_network_watcher_flow_log", "nsg", {"id": f"{NET}/networkWatchers/nw/flowLogs/fl-nsg", "name": "fl-nsg",
                                                 "network_security_group_id": f"{NET}/networkSecurityGroups/nsg-ds"}))


def _by(resources):
    return {(r.kind, r.ref): r for r in resources}


def test_route_tables_and_the_firewall_as_next_hop():
    by = _by(state_resources(STATE)[0])
    rt = by[("route-table", f"{NET}/routeTables/rt-pf")]
    assert rt.attrs["ciamRoute"] == (f"0.0.0.0/0 firewall {POLICY}", "10.9.0.0/16 vpn", "AzureKeyVault internet")
    assert rt.links["ciamSubnetRole"] == ("vnet-ciam-prod/snet-pf",) and rt.role == "rt-pf"


def test_a_private_endpoint_with_its_zone_and_address():
    pe = _by(state_resources(STATE)[0])[("private-endpoint", f"{NET}/privateEndpoints/pe-secrets")]
    assert pe.attrs == {"ciamPrivateService": ("secrets",), "ciamPrivateEndpointKind": ("interface",),
                        "ciamFrontendIp": ("10.60.2.50",), "ciamPrivateDns": ("TRUE",), "ciamDnsZoneRef": (ZONE,),
                        "ciamDnsZone": ("privatelink.vaultcore.azure.net",)}
    assert pe.links["ciamSubnetRole"] == "vnet-ciam-prod/snet-pf"


def test_a_private_link_service_waits_for_acceptance_without_auto_approval():
    s = _by(state_resources(STATE)[0])[("endpoint-service", f"{NET}/privateLinkServices/pls-ldaps")]
    assert s.attrs["ciamAcceptanceRequired"] == ("TRUE",) and s.attrs["ciamVisibleTo"] == ("sub-partner",)
    assert "ciamAllowedPrincipal" not in s.attrs
    assert s.links == {"ciamServiceRole": LB, "ciamSubnetRole": ("vnet-ciam-prod/snet-ds",)}


def test_the_firewall_policys_sites_with_their_ports():
    p = _by(state_resources(STATE)[0])[("proxy", POLICY)]
    assert p.attrs["ciamAllowedDestination"] == ("ocsp.ca.test:80", "idp.partner.test", "*.okta.test",
                                                 "smtp.mail.test:587")
    assert p.role == "egress-firewall"


def test_links_and_flow_logs():
    resources, notices = state_resources(STATE)
    by = _by(resources)
    vpn = by[("interconnect", f"{NET}/connections/cn-dc")].attrs
    assert vpn["ciamLinkKind"] == ("vpn",) and vpn["ciamPeerGateway"] == ("198.51.100.7",)
    assert vpn["ciamPeerAsn"] == ("65010",) and vpn["ciamLocalAsn"] == ("65515",)
    assert vpn["ciamAcceptedCidr"] == ("10.9.0.0/16",)
    assert vpn["ciamPeerEnvironment"] == ("env=prod,cloud=dc,ou=environments,dc=ciam-ops",)
    peering = by[("interconnect", f"{NET}/virtualNetworks/vnet-ciam-prod/virtualNetworkPeerings/to-hub")]
    assert "ciamPeerAccepted" not in peering.attrs                         # state doesn't say
    assert peering.links["ciamPeerEnvironment"] == "vnet-hub"              # the record names virtual networks
    log = by[("flow-log", f"{NET}/networkWatchers/nw/flowLogs/fl-vnet")]
    assert log.attrs == {"ciamFlowScope": ("network",), "ciamRetentionDays": ("90",)}
    assert log.links["ciamLogDestinationRole"] == WORKSPACE
    assert "flow log fl-nsg: an NSG flow log (they retire on 2027-09-30): move to a virtual network flow log" in notices


CLI = [
    {"type": "Microsoft.Network/azureFirewalls", "id": f"{NET}/azureFirewalls/fw-hub", "firewallPolicy": {"id": POLICY},
     "ipConfigurations": [{"privateIPAddress": "10.0.0.4"}]},
    {"type": "Microsoft.Network/routeTables", "id": f"{NET}/routeTables/rt-pf", "name": "rt-pf",
     "routes": [{"name": "default", "addressPrefix": "0.0.0.0/0", "nextHopType": "VirtualAppliance",
                 "nextHopIpAddress": "10.0.0.4"}],
     "subnets": [{"id": f"{NET}/virtualNetworks/vnet-ciam-prod/subnets/snet-pf"}]},
    {"type": "Microsoft.Network/privateEndpoints", "id": f"{NET}/privateEndpoints/pe-secrets", "name": "pe",
     "subnet": {"id": f"{NET}/virtualNetworks/vnet-ciam-prod/subnets/snet-pf"},
     "privateLinkServiceConnections": [{"privateLinkServiceId": f"{SUB}/Microsoft.KeyVault/vaults/kv",
                                        "groupIds": ["vault"]}],
     "ipConfigurations": [{"privateIPAddress": "10.60.2.50"}]},
    {"type": "Microsoft.Network/privateEndpoints/privateDnsZoneGroups",
     "id": f"{NET}/privateEndpoints/pe-secrets/privateDnsZoneGroups/default",
     "privateDnsZoneConfigs": [{"privateDnsZoneId": ZONE}]},
    {"type": "Microsoft.Network/privateLinkServices", "id": f"{NET}/privateLinkServices/pls-ldaps", "name": "pls",
     "loadBalancerFrontendIpConfigurations": [{"id": f"{LB}/frontendIPConfigurations/frontend"}],
     "autoApproval": {"subscriptions": ["sub-partner"]}, "visibility": {"subscriptions": ["sub-partner"]}},
    {"type": "Microsoft.Network/firewallPolicies/ruleCollectionGroups", "id": f"{POLICY}/ruleCollectionGroups/sites",
     "ruleCollections": [{"action": {"type": "Allow"}, "rules": [
         {"ruleType": "ApplicationRule", "targetFqdns": ["idp.partner.test"],
          "protocols": [{"protocolType": "Https", "port": 443}]},
         {"ruleType": "NetworkRule", "destinationFqdns": ["smtp.mail.test"], "destinationPorts": ["587"]}]}]},
    {"type": "Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
     "id": f"{NET}/virtualNetworks/vnet-ciam-prod/virtualNetworkPeerings/to-hub", "name": "to-hub",
     "peeringState": "Initiated"},
    {"type": "Microsoft.Network/networkWatchers/flowLogs", "id": f"{NET}/networkWatchers/nw/flowLogs/fl-vnet",
     "name": "fl-vnet", "targetResourceId": f"{NET}/virtualNetworks/vnet-ciam-prod",
     "retentionPolicy": {"enabled": True, "days": 30}},
]


def test_the_cli_reads_the_same_depth():
    by = _by(cli_resources({"network.json": json.dumps(CLI)})[0])
    assert by[("route-table", f"{NET}/routeTables/rt-pf")].attrs["ciamRoute"] == (f"0.0.0.0/0 firewall {POLICY}",)
    pe = by[("private-endpoint", f"{NET}/privateEndpoints/pe-secrets")]
    assert pe.attrs["ciamDnsZoneRef"] == (ZONE,) and pe.attrs["ciamFrontendIp"] == ("10.60.2.50",)
    pls = by[("endpoint-service", f"{NET}/privateLinkServices/pls-ldaps")].attrs
    assert pls["ciamAllowedPrincipal"] == ("sub-partner",) and pls["ciamAcceptanceRequired"] == ("FALSE",)
    assert by[("proxy", POLICY)].attrs["ciamAllowedDestination"] == ("idp.partner.test", "smtp.mail.test:587")
    peering = by[("interconnect", f"{NET}/virtualNetworks/vnet-ciam-prod/virtualNetworkPeerings/to-hub")]
    assert peering.attrs["ciamPeerAccepted"] == ("FALSE",)
    assert by[("flow-log", f"{NET}/networkWatchers/nw/flowLogs/fl-vnet")].attrs["ciamRetentionDays"] == ("30",)


TEMPLATE = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {"type": "Microsoft.Network/routeTables", "apiVersion": "2023-09-01", "name": "rt-pf",
         "tags": {"Role": "rt-pf"},
         "properties": {"routes": [{"name": "dc", "properties": {"addressPrefix": "10.9.0.0/16",
                                                                 "nextHopType": "VirtualNetworkGateway"}}]}},
        {"type": "Microsoft.Network/privateEndpoints", "apiVersion": "2023-09-01", "name": "pe-secrets",
         "properties": {"subnet": {"id": "[resourceId('Microsoft.Network/virtualNetworks/subnets', "
                                         "'vnet-ciam-prod', 'snet-pf')]"},
                        "privateLinkServiceConnections": [{"name": "kv", "properties": {
                            "privateLinkServiceId": "[resourceId('Microsoft.KeyVault/vaults', 'kv')]",
                            "groupIds": ["vault"]}}]},
         "resources": [{"type": "privateDnsZoneGroups", "apiVersion": "2023-09-01", "name": "default",
                        "properties": {"privateDnsZoneConfigs": [{"name": "kv",
                                                                  "properties": {"privateDnsZoneId": ZONE}}]}}]}]}


def test_arm_deploys_the_same_depth():
    by = _by(arm_resources({"net/azuredeploy.json": json.dumps(TEMPLATE)})[0])
    rt = next(r for (k, _), r in by.items() if k == "route-table")
    assert rt.attrs["ciamRoute"] == ("10.9.0.0/16 vpn",) and rt.role == "rt-pf"
    pe = next(r for (k, _), r in by.items() if k == "private-endpoint")
    assert pe.attrs["ciamPrivateService"] == ("secrets",) and pe.attrs["ciamDnsZoneRef"] == (ZONE,)
    assert pe.links["ciamSubnetRole"] == "vnet-ciam-prod/snet-pf"
