"""The network plumbing an Azure environment's landing zone, or another party, keeps, rendered into their root: a NAT
gateway with its public IPs and prefixes on the subnets, route tables with user-defined routes and associations, VNet
peering, a site-to-site VPN, a virtual WAN hub connection, VNet flow logs, and what someone else keeps of the stack's
private endpoints and egress allowlists; import blocks for what exists; notes for what Azure has no resource for."""
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir_adapter_azure.landing import render_landing
from network_fixtures import ALPHA, BETA, entry, model
from support import REGISTRY, build_directory

LZ, NET = "terraform/landing-zone", "terraform/landing-zone/network.tf"
TEAM = "cn=network-security,ou=parties,dc=ciam-ops"
ARM = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network"
GAMMA = "env=prod,cloud=gamma,ou=environments,dc=ciam-ops"
AZURE_PEER = ("dn: cloud=gamma,ou=environments,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamCloud\ncloud: gamma\n"
              "ciamCloudProvider: azure\nciamRegion: eastus2\n",
              f"dn: {GAMMA}\nobjectClass: top\nobjectClass: ciamEnvironment\nenv: prod\n",
              f"dn: ou=bindings,{GAMMA}\nobjectClass: top\nobjectClass: organizationalUnit\nou: bindings\n",
              entry(GAMMA, "net", "ciamNetwork", ciamBindingRole="network", ciamCidr="10.9.0.0/16",
                    ciamProviderRef="vnet-gamma", ciamResourceGroup="rg-gamma"))


def _files(*records, tree=()):
    return render_landing(model(alpha=records, tree=tree)[1])


def _net(*records, tree=()):
    return _files(*records, tree=tree)[NET]


def _link(cn, kind, peer=BETA, **attrs):
    return entry(ALPHA, cn, "ciamInterconnect", ciamBindingRole=cn, ciamInterconnectKind=kind or "a link",
                 ciamPeerEnvironment=peer, ciamSourceCidr="10.9.0.0/16", **({"ciamLinkKind": kind} if kind else {}),
                 **attrs)


def test_no_plumbing_renders_no_landing_zone():
    assert render_landing(model()[1]) == {}


def test_an_existing_nat_gateway_adopted_with_its_public_ips_and_prefixes_its_subnets_left_as_they_are():
    out = _net(entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress", ciamProviderRef="ng-1",
                     ciamCidr=("203.0.113.10/32", "198.51.100.0/30")))
    nat = "${data.azurerm_resource_group.main.id}/providers/Microsoft.Network/natGateways/ng-1"
    assert 'resource "azurerm_nat_gateway" "egress"' in out and 'name                = "ng-1"' in out
    assert f'id = "{nat}"' in out
    assert "public_ip_address_id = var.egress_ip_0" in out and "public_ip_prefix_id = var.egress_prefix_0" in out
    assert f'to = azurerm_nat_gateway_public_ip_association.egress_0\n  id = "{nat}|${{var.egress_ip_0}}"' in out
    assert f'to = azurerm_nat_gateway_public_ip_prefix_association.egress_0\n  id = "{nat}|${{var.egress_prefix_0}}"' \
        in out
    assert "azurerm_subnet_nat_gateway_association" not in out
    assert "# egress: the subnets an existing NAT gateway serves aren't recorded" in out


def test_a_new_nat_gateway_on_the_environment_s_subnets():
    out = _net(entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress", ciamCidr="203.0.113.10/32"))
    assert 'resource "azurerm_subnet_nat_gateway_association" "egress_subnet_ds"' in out
    assert 'resource "azurerm_subnet_nat_gateway_association" "egress_subnet_web"' in out and "import" not in out
    providers = _files(entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress",
                             ciamCidr="203.0.113.10/32"))[f"{LZ}/providers.tf"]
    assert 'variable "egress_ip_0"' in providers and "with address 203.0.113.10/32" in providers


def test_a_private_nat_range_is_named():
    out = _net(entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress", ciamCidr="10.1.250.0/28"))
    assert "Azure NAT gateways are public only" in out and "azurerm_nat_gateway" not in out


def test_a_route_table_with_its_next_hops_and_associations():
    out = _net(entry(ALPHA, "fw", "ciamProxy", ciamBindingRole="fw", ciamProxyKind="firewall",
                     ciamProxyAddress="10.1.9.4:3128"),
               entry(ALPHA, "rt-ds", "ciamRouteTable", ciamBindingRole="rt-ds", ciamSubnetRole="subnet-ds",
                     ciamProviderRef=f"{ARM}/routeTables/rt-ds",
                     ciamRoute=("0.0.0.0/0 firewall fw", "10.9.0.0/16 vpn", "AzureCloud internet",
                                "10.8.0.0/16 nat egress", "10.7.0.0/16 appliance 10.1.9.5", "10.6.0.0/16 local",
                                "10.5.0.0/16 none for web")))
    assert 'name                = "rt-ds"' in out and f'id = "{ARM}/routeTables/rt-ds"' in out
    assert 'next_hop_type          = "VirtualAppliance"' in out and 'next_hop_in_ip_address = "10.1.9.4"' in out
    assert 'next_hop_in_ip_address = "10.1.9.5"' in out
    assert 'address_prefix = "AzureCloud"' in out and 'next_hop_type  = "Internet"' in out
    assert '"VirtualNetworkGateway"' in out and '"VnetLocal"' in out and 'next_hop_type  = "None"' in out
    assert "10.8.0.0/16 nat: not a next hop in Azure" in out and "applies to web only elsewhere" in out
    assert 'resource "azurerm_subnet_route_table_association" "rt_ds_subnet_ds"' in out
    assert "to = azurerm_subnet_route_table_association.rt_ds_subnet_ds" not in out    # the subnet has no ref


def test_a_firewall_without_an_address_is_an_input_and_the_main_table_is_named():
    files = _files(entry(ALPHA, "fw", "ciamProxy", ciamBindingRole="fw", ciamProxyKind="forward-proxy"),
                   entry(ALPHA, "rt", "ciamRouteTable", ciamBindingRole="rt", ciamRoute="0.0.0.0/0 firewall fw",
                         ciamMainTable="TRUE"))
    assert "next_hop_in_ip_address = var.fw_private_ip" in files[NET]
    assert "Azure has no main route table" in files[NET] and "import {" not in files[NET]
    assert 'variable "fw_private_ip"' in files[f"{LZ}/providers.tf"]


def test_network_acls_are_named():
    out = _net(entry(ALPHA, "acl", "ciamNetworkAcl", ciamBindingRole="acl",
                     ciamAclRule="100 allow in tcp 636 10.0.0.0/8"))
    assert "Azure has no stateless network ACLs" in out


def test_our_half_of_a_peering_with_an_azure_network():
    out = _net(_link("link", "peering", GAMMA, ciamProviderRef=f"{ARM}/virtualNetworks/v/virtualNetworkPeerings/p"),
               tree=AZURE_PEER)
    assert 'data "azurerm_virtual_network" "link_peer"' in out and 'name                = "vnet-gamma"' in out
    assert "remote_virtual_network_id    = data.azurerm_virtual_network.link_peer.id" in out
    assert "the other side adds its half of the peering" in out
    assert f'id = "{ARM}/virtualNetworks/v/virtualNetworkPeerings/p"' in out


def test_peering_across_providers_and_a_link_without_a_kind_are_named():
    out = _net(_link("link", "peering"), _link("other", None))
    assert "the other end is on fakecloud: record it as a vpn link" in out
    assert "a link: what kind of link it is isn't recorded" in out and "azurerm_virtual_network_peering" not in out


def test_a_site_to_site_vpn_with_bgp_and_its_shared_key_as_a_sensitive_input():
    files = _files(_link("vpn-dc", "vpn", ciamPeerGateway="198.51.100.1", ciamPeerAsn="65010", ciamLocalAsn="65515",
                         ciamAcceptedCidr="192.168.0.0/16", ciamProviderRef=f"{ARM}/connections/cn-1"))
    out, providers = files[NET], files[f"{LZ}/providers.tf"]
    assert 'gateway_address     = "198.51.100.1"' in out and 'address_space       = ["192.168.0.0/16"]' in out
    assert "asn                 = 65010" in out and "bgp_peering_address = var.vpn_dc_bgp_peer_ip" in out
    assert 'type                       = "IPsec"' in out and "bgp_enabled                = true" in out
    assert "shared_key                 = var.vpn_dc_shared_key" in out and f'id = "{ARM}/connections/cn-1"' in out
    assert "our side's BGP ASN 65515 is set on the virtual network gateway" in out
    assert 'variable "vpn_dc_shared_key"' in providers and "sensitive   = true" in providers
    assert 'variable "virtual_network_gateway_id"' in providers


def test_a_vpn_without_its_peer_gateway_is_unbound():
    assert "UNBOUND: a VPN needs the other end's gateway address" in _net(_link("vpn", "vpn"))


def test_a_hub_connection_and_named_transit_and_dedicated_links():
    out = _net(_link("hub", "hub"), _link("tgw", "transit"), _link("er", "dedicated"))
    assert 'resource "azurerm_virtual_hub_connection" "hub"' in out
    assert "virtual_hub_id            = var.virtual_hub_id" in out
    assert "Azure's transit is a virtual WAN hub" in out and "an ExpressRoute circuit is ordered" in out


def test_vnet_flow_logs_to_a_storage_account_and_through_traffic_analytics():
    storage = entry(ALPHA, "logs", "ciamLogDestination", ciamBindingRole="logs", ciamDestinationKind="storage",
                    ciamProviderRef="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st")
    out = _net(storage, entry(ALPHA, "fl", "ciamFlowLog", ciamBindingRole="fl", ciamFlowScope="network",
                              ciamLogDestinationRole="logs", ciamRetentionDays="90",
                              ciamProviderRef=f"{ARM}/networkWatchers/nw/flowLogs/fl"))
    assert "target_resource_id   = data.azurerm_virtual_network.main.id" in out and "version              = 2" in out
    assert 'storage_account_id   = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/' in out
    assert "days    = 90" in out and f'id = "{ARM}/networkWatchers/nw/flowLogs/fl"' in out
    workspace = entry(ALPHA, "law", "ciamLogDestination", ciamBindingRole="law", ciamDestinationKind="workspace",
                      ciamProviderRef="/subscriptions/s/resourceGroups/rg-l/providers/"
                                      "Microsoft.OperationalInsights/workspaces/law-1")
    files = _files(workspace, entry(ALPHA, "fl", "ciamFlowLog", ciamBindingRole="fl", ciamFlowScope="subnet",
                                    ciamSubnetRole=("subnet-ds", "subnet-web"), ciamLogDestinationRole="law"))
    out = files[NET]
    assert 'name                 = "fl-ciam-prod-fl-subnet-ds"' in out and "fl_subnet_web" in out
    assert "workspace_id          = data.azurerm_log_analytics_workspace.law.workspace_id" in out
    assert "storage_account_id   = var.flow_logs_storage_account_id" in out and "enabled = false" in out
    assert 'variable "network_watcher_name"' in files[f"{LZ}/providers.tf"]


def test_nsg_flow_logs_and_logs_without_a_destination_are_named():
    out = _net(entry(ALPHA, "nsg", "ciamFlowLog", ciamBindingRole="nsg", ciamFlowScope="security-group"),
               entry(ALPHA, "fl", "ciamFlowLog", ciamBindingRole="fl", ciamFlowScope="network",
                     ciamLogDestinationRole="nowhere"),
               entry(ALPHA, "nic", "ciamFlowLog", ciamBindingRole="nic", ciamFlowScope="interface"))
    assert "NSG flow logs retire" in out and "UNBOUND: its log destination" in out
    assert "a flow log on interfaces needs their ids" in out and "azurerm_network_watcher_flow_log" not in out


def test_what_another_party_keeps_goes_in_its_own_root():
    secret = entry(ALPHA, "secret", "ciamSecretRef", ciamBindingRole="admin-password",
                   ciamRefUri="azkv://kv-1/admin-password")
    files = _files(secret,
                   entry(ALPHA, "pe", "ciamPrivateEndpoint", ciamBindingRole="pe", ciamPrivateService="secrets",
                         ciamReachesRole="admin-password", ciamSubnetRole="subnet-ds", ciamManagedBy=TEAM,
                         ciamProviderRef=f"{ARM}/privateEndpoints/pe-1"),
                   entry(ALPHA, "fw", "ciamProxy", ciamBindingRole="fw", ciamProxyKind="firewall",
                         ciamAllowedDestination="metadata.example.test", ciamManagedBy=TEAM,
                         ciamProviderRef=f"{ARM}/firewallPolicies/fwp"))
    out = files[f"{LZ}/network-security/network.tf"]
    assert set(files) == {f"{LZ}/network-security/network.tf", f"{LZ}/network-security/providers.tf"}
    assert "Azure network kept by cn=network-security,ou=parties,dc=ciam-ops" in out
    assert 'resource "azurerm_private_endpoint" "pe"' in out and f'id = "{ARM}/privateEndpoints/pe-1"' in out
    assert 'resource "azurerm_firewall_policy_rule_collection_group" "fw_sites"' in out


def test_a_landing_zone_with_guardrails_and_plumbing_declares_its_data_sources_once():
    env = "env=prod,cloud=az,ou=environments,dc=ciam-ops"
    ldif = "\n".join((
        "dn: dc=ciam-ops\nobjectClass: top\nobjectClass: domain\ndc: ciam-ops\n",
        "dn: ou=environments,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: environments\n",
        "dn: cloud=az,ou=environments,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamCloud\ncloud: az\n"
        "ciamCloudProvider: azure\nciamRegion: eastus2\n",
        f"dn: {env}\nobjectClass: top\nobjectClass: ciamEnvironment\nenv: prod\n",
        f"dn: ou=bindings,{env}\nobjectClass: top\nobjectClass: organizationalUnit\nou: bindings\n",
        entry(env, "vnet", "ciamNetwork", ciamBindingRole="network", ciamCidr="10.60.0.0/16",
              ciamProviderRef="vnet-ciam-prod", ciamResourceGroup="rg-ciam-prod"),
        entry(env, "egress", "ciamEgress", ciamBindingRole="egress", ciamCidr="203.0.113.10/32")))
    m = env_model(build_directory(REGISTRY, tuple(parse(ldif))), "az/prod")
    files = render_landing(m, guardrails=lambda _: ("# a guardrail",))
    main = files[f"{LZ}/main.tf"]
    assert 'data "azurerm_resource_group" "main"' in main and "# a guardrail" in main
    assert 'data "azurerm_resource_group" "main"' not in files[NET]
    assert 'data "azurerm_virtual_network" "main"' in files[NET]
    assert 'name                = "vnet-ciam-prod"' in files[NET]
    providers = files[f"{LZ}/providers.tf"]
    assert 'variable "subscription_id"' in providers and 'variable "egress_ip_0"' in providers
