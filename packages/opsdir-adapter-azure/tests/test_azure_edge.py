"""A service whose policies terminate TLS at the edge as Azure Terraform: an Application Gateway v2 in the subnet bound
to subnet-edge, its listener's TLS policy and Key Vault certificate read by its own identity, backend settings with the
policy's probe, affinity, timeout and draining; a WAF policy with custom rules for addresses, countries and rate limits
aimed at the products' endpoints, the Default Rule Set and exclusions. Without the subnet, nothing but a comment."""
from opsdir.domains.edge.resolve import RateLimit, tls_level, tls_policy
from opsdir_adapter_azure.edge import TLS_POLICIES, ddos_note, gateway_service, rate, servers_backend, waf_policy
from edge_fixtures import environment, server, service, spec, subnet

EDGE = subnet("subnet-edge", "subnet-edge", "10.60.250.0/24")


def _gateway(s, ip="198.51.100.77", *bindings):
    svc = service(ip, ciamProviderRef="pip-ciam-sso-prod")
    return "\n".join(gateway_service(environment(svc, *bindings), svc, s,
                                     servers_backend((server("pf-1", "10.60.2.10"),))))


def test_tls_terms_map_to_predefined_policies_and_back():
    assert tls_policy(TLS_POLICIES, "1.2", "intermediate") == ("AppGwSslPolicy20220101", True)
    assert tls_policy(TLS_POLICIES, "1.3", "modern") == ("AppGwSslPolicy20220101S", False)     # no TLS 1.3-only
    assert tls_level(TLS_POLICIES, "AppGwSslPolicy20220101S") == ("1.3", "modern")


def test_a_gateway_in_the_edge_subnet_with_its_certificate_probe_and_waf():
    out = _gateway(spec(certificate="azkv-cert://kv-ciam-prod/sso-tls-2026"), "198.51.100.77", EDGE)
    assert 'data "azurerm_public_ip" "sso"' in out and "subnet_id = data.azurerm_subnet.subnet_edge.id" in out
    assert 'resource "azurerm_user_assigned_identity" "sso_gateway"' in out
    assert 'role_definition_name = "Key Vault Secrets User"' in out
    assert 'key_vault_secret_id = "${data.azurerm_key_vault.sso_tls.vault_uri}secrets/sso-tls-2026"' in out
    assert 'name = "WAF_v2"' in out and "firewall_policy_id = azurerm_web_application_firewall_policy.sso.id" in out
    assert 'policy_name = "AppGwSslPolicy20220101"' in out and 'ip_addresses = ["10.60.2.10"]' in out
    assert 'cookie_based_affinity = "Enabled"' in out and "drain_timeout_sec = 30" in out
    assert 'path                = "/pf/heartbeat.ping"' in out and "timeout             = 10" in out
    assert "depends_on = [azurerm_role_assignment.sso_gateway_certificate]" in out


def test_without_an_edge_subnet_or_certificate_it_says_what_is_unbound():
    assert _gateway(spec()).startswith("# UNBOUND: `sso.example.test` terminates TLS at an Application Gateway")
    out = _gateway(spec(categories=(), rate_limits=(), ip_rules=(), geo_rules=(), waf_mode=None), "10.60.250.10", EDGE)
    assert "# UNBOUND: no Key Vault certificate holds this service's certificate" in out
    assert 'name = "Standard_v2"' in out and "azurerm_web_application_firewall_policy" not in out
    assert 'private_ip_address            = "10.60.250.10"' in out and "azurerm_public_ip" not in out


def test_the_waf_policy_custom_rules_and_managed_rules():
    out = waf_policy(environment(), "sso", spec(rate_limits=(RateLimit("token", 100, 300, "ip", ("/as/token.oauth2",)),
                                                              RateLimit("login", 20, 30, "header:X-Key", ()))))
    assert 'operator     = "IPMatch"' in out and 'match_values = ["203.0.113.0/24"]' in out
    assert 'operator           = "GeoMatch"' in out
    assert 'rate_limit_duration  = "FiveMins"' in out and 'match_values = ["^/as/token\\\\.oauth2$"]' in out
    assert "# grouped by client address: Azure can't group by header:X-Key" in out and 'operator = "Any"' in out
    assert 'selector                = "SAMLResponse"' in out and 'type    = "Microsoft_DefaultRuleSet"' in out
    assert 'mode               = "Prevention"' in out
    assert rate(20, 30) == (40, "OneMin") and rate(100, 300) == (100, "FiveMins")


def test_categories_azure_lacks_are_named_and_ddos_is_asked_of_the_landing_zone():
    out = waf_policy(environment(), "sso", spec(categories=("bot-control", "account-takeover"), waf_mode="detect"))
    assert "# not offered by Application Gateway WAF: account-takeover" in out
    assert 'type    = "Microsoft_BotManagerRuleSet"' in out and 'mode               = "Detection"' in out
    assert ddos_note(spec()) == () and "landing zone" in ddos_note(spec(ddos="network-advanced"))[0]
