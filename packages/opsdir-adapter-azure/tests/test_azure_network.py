"""The network depth the stack keeps as Azure Terraform: private endpoints (one per resource reached, the subresource
of its service, a static address and the private DNS zone group as recorded), Private Link Services on a Standard load
balancer's frontend, an egress firewall's allowlist as Firewall policy application rules; comments otherwise."""
from opsdir_adapter_azure.network import render_network
from network_fixtures import ALPHA, entry, model

TERMINATE = ("dn: ou=edge-policies,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: edge-policies\n",
             entry("ou=edge-policies,dc=ciam-ops", "sso-edge", "ciamTrafficPolicy", ciamServiceRole="sso-service",
                   ciamTlsMode="terminate"))
ZONE = ("/subscriptions/s/resourceGroups/rg-hub-dns/providers/Microsoft.Network/privateDnsZones/"
        "privatelink.vaultcore.azure.net")
SECRETS = (entry(ALPHA, "secret-a", "ciamSecretRef", ciamBindingRole="admin-password", ciamRefUri="azkv://kv-a/admin"),
           entry(ALPHA, "secret-b", "ciamSecretRef", ciamBindingRole="ds-password", ciamRefUri="azkv://kv-a/ds"),
           entry(ALPHA, "key-c", "ciamKeyRef", ciamBindingRole="signing-key", ciamRefUri="azkv-key://kv-c/keys/sign"))


def _render(*records, tree=()):
    return "\n\n".join(render_network(model(alpha=records, tree=tree)[1]))


def test_nothing_recorded_renders_nothing():
    assert render_network(model()[1]) == ()


def test_one_private_endpoint_per_vault_reached_with_its_dns_zone_group():
    out = _render(*SECRETS, entry(ALPHA, "pe-vault", "ciamPrivateEndpoint", ciamBindingRole="pe-vault",
                                  ciamPrivateService="secrets", ciamReachesRole=("admin-password", "ds-password",
                                                                                 "signing-key"),
                                  ciamSubnetRole="subnet-ds", ciamPrivateDns="TRUE", ciamDnsZoneRef=ZONE))
    assert 'data "azurerm_key_vault" "pe_vault_0_kv_a"' not in out                  # data named by the endpoint
    assert 'data "azurerm_key_vault" "pe_vault_kv_a"' in out and 'data "azurerm_key_vault" "pe_vault_kv_c"' in out
    assert 'resource "azurerm_private_endpoint" "pe_vault_0"' in out and '"pe_vault_1"' in out
    assert "private_connection_resource_id = data.azurerm_key_vault.pe_vault_kv_a.id" in out
    assert 'subresource_names              = ["vault"]' in out
    assert "subnet_id           = data.azurerm_subnet.subnet_ds.id" in out
    assert f'private_dns_zone_ids = ["{ZONE}"]' in out


def test_a_static_address_a_storage_account_and_a_missing_zone():
    out = _render(entry(ALPHA, "backup", "ciamBackupTarget", ciamBindingRole="backup-target",
                        ciamStorageRef="azblob://stciam/ds-backups"),
                  entry(ALPHA, "pe-blob", "ciamPrivateEndpoint", ciamBindingRole="pe-blob",
                        ciamPrivateService="object-storage", ciamReachesRole="backup-target",
                        ciamSubnetRole="subnet-ds", ciamFrontendIp="10.1.1.50", ciamPrivateDns="TRUE"))
    assert 'data "azurerm_storage_account" "pe_blob_stciam"' in out and 'name                = "stciam"' in out
    assert 'resource "azurerm_private_endpoint" "pe_blob"' in out and 'subresource_names              = ["blob"]' in out
    assert 'private_ip_address = "10.1.1.50"' in out and 'member_name        = "default"' in out
    assert "# UNBOUND: private DNS asked, but no private DNS zone ref (zone privatelink.blob.core.windows.net)" in out


def test_what_azure_doesnt_reach_this_way_is_said():
    out = _render(entry(ALPHA, "pe-s3", "ciamPrivateEndpoint", ciamBindingRole="pe-s3",
                        ciamPrivateService="object-storage", ciamPrivateEndpointKind="gateway"),
                  entry(ALPHA, "pe-db", "ciamPrivateEndpoint", ciamBindingRole="pe-db", ciamPrivateService="database"),
                  entry(ALPHA, "pe-none", "ciamPrivateEndpoint", ciamBindingRole="pe-none",
                        ciamPrivateService="secrets", ciamReachesRole="nowhere"))
    assert "# Private endpoint 'pe-s3': Azure's private endpoints are interface endpoints (gateway" in out
    assert "# Private endpoint 'pe-db' to database: record the target's resource id" in out
    assert "# UNBOUND: private endpoint 'pe-none' reaches nothing this environment binds" in out
    assert "azurerm_private_endpoint" not in out


def test_a_resource_id_as_provider_ref_is_used_as_is():
    out = _render(entry(ALPHA, "bus", "ciamStreamBinding", ciamBindingRole="audit-events", ciamStreamKind="topic",
                        ciamProviderRef="/subscriptions/s/resourceGroups/rg/providers/Microsoft.ServiceBus/"
                                        "namespaces/sb-ciam"),
                  entry(ALPHA, "pe-bus", "ciamPrivateEndpoint", ciamBindingRole="pe-bus",
                        ciamPrivateService="messaging", ciamReachesRole="audit-events", ciamSubnetRole="subnet-ds"))
    assert ('private_connection_resource_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ServiceBus/'
            'namespaces/sb-ciam"') in out and 'subresource_names              = ["namespace"]' in out


def test_a_private_link_service_on_the_load_balancer_frontend():
    service = entry(ALPHA, "ldaps-link", "ciamEndpointService", ciamBindingRole="ldaps-link",
                    ciamServiceRole="sso-service", ciamAllowedPrincipal="11111111-2222-3333-4444-555555555555",
                    ciamVisibleTo="11111111-2222-3333-4444-555555555555", ciamSubnetRole="subnet-web")
    out = _render(service)
    assert 'resource "azurerm_private_link_service" "ldaps_link"' in out
    assert "load_balancer_frontend_ip_configuration_ids = [azurerm_lb.svc_sso.frontend_ip_configuration[0].id]" in out
    assert "subnet_id = data.azurerm_subnet.subnet_web.id" in out
    assert 'visibility_subscription_ids    = ["11111111-2222-3333-4444-555555555555"]' in out
    assert 'auto_approval_subscription_ids = ["11111111-2222-3333-4444-555555555555"]' in out
    manual = _render(entry(ALPHA, "ldaps-link", "ciamEndpointService", ciamBindingRole="ldaps-link",
                           ciamServiceRole="sso-service", ciamAllowedPrincipal="sub-1", ciamAcceptanceRequired="TRUE"))
    assert "auto_approval_subscription_ids" not in manual and "visibility_subscription_ids" not in manual
    assert "# UNBOUND: no NAT subnet recorded (ciamSubnetRole)" in manual
    gateway = _render(service, tree=TERMINATE)
    assert "runs on an Application Gateway" in gateway and "azurerm_private_link_service" not in gateway


def test_the_stacks_egress_firewall_gets_application_rules_per_port():
    out = _render(entry(ALPHA, "egress-fw", "ciamProxy", ciamBindingRole="egress-firewall", ciamProxyKind="firewall",
                        ciamProviderRef="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/"
                                        "firewallPolicies/fwp-ciam",
                        ciamAllowedDestination=("idp.partner.example", "*.okta.example", "ocsp.ca.example:80")))
    assert 'resource "azurerm_firewall_policy_rule_collection_group" "egress_fw_sites"' in out
    assert 'firewall_policy_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/' in out
    assert 'name = "sites-80"' in out and 'destination_fqdns = ["ocsp.ca.example"]' in out
    assert 'type = "Http"\n        port = 80' in out and 'type = "Https"\n        port = 443' in out
    assert 'destination_fqdns = ["idp.partner.example", "*.okta.example"]' in out
    assert 'source_addresses  = ["10.1.0.0/16"]' in out and 'action   = "Allow"' in out


def test_sites_on_other_ports_are_network_rules_by_fqdn():
    out = _render(entry(ALPHA, "egress-fw", "ciamProxy", ciamBindingRole="egress-firewall", ciamProxyKind="firewall",
                        ciamAllowedDestination=("smtp.example:587",)))
    assert "application_rule_collection" not in out and "network_rule_collection {" in out
    assert "# FQDNs in network rules need the firewall policy's DNS proxy" in out
    assert 'protocols         = ["TCP"]' in out and 'destination_ports = ["587"]' in out
    assert 'destination_fqdns = ["smtp.example"]' in out
