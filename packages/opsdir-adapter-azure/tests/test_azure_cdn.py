"""A CDN in front of a service as Azure Terraform: Front Door (Premium when it inspects) over the Application Gateway
or the load balancer by its public address, the service name a custom domain (Key Vault certificate or a managed one)
validated by a _dnsauth record, a route without caching, the protection policy as a Front Door firewall policy on the
domain; the gateway behind it keeps no WAF."""
import re

from opsdir_adapter_azure.edge import gateway_service, servers_backend
from opsdir_adapter_azure.frontdoor import endpoint, front_door
from edge_fixtures import environment, server, service, spec, subnet


def _fd(s, ip="198.51.100.77"):
    svc = service(ip, ciamDnsZone="example.test", ciamProviderRef="pip-ciam-sso-prod")
    return "\n".join(front_door(environment(svc), svc, s, "sso"))


def test_front_door_over_the_gateway_with_its_firewall_policy():
    out = _fd(spec(cdn=True, certificate="azkv-cert://kv-ciam-prod/sso-tls-2026"))
    assert 'sku_name            = "Premium_AzureFrontDoor"' in out
    assert "host_name                      = data.azurerm_public_ip.sso.ip_address" in out
    assert 'origin_host_header             = "sso.example.test"' in out and 'name                           = "application-gateway"' in out
    assert 'certificate_type        = "CustomerCertificate"' in out
    assert 'key_vault_certificate_id = "${data.azurerm_key_vault.sso_cdn_tls.vault_uri}certificates/sso-tls-2026"' in out
    assert re.search(r'forwarding_protocol\s+= "HttpsOnly"', out) and "cache {" not in out
    assert 'type                           = "RateLimitRule"' in out and 'match_values   = ["^/as/token\\\\.oauth2$"]' in out
    assert 'type    = "Microsoft_DefaultRuleSet"' in out and 'match_variable = "RequestBodyPostArgNames"' in out
    assert 'resource "azurerm_cdn_frontdoor_security_policy" "sso"' in out
    assert 'name                = "_dnsauth.sso"' in out and "custom_domain.sso.validation_token" in out
    assert endpoint("sso") == "${azurerm_cdn_frontdoor_endpoint.sso.host_name}"


def test_without_inspection_standard_front_door_over_the_load_balancer_with_a_managed_certificate():
    out = _fd(spec(cdn=True, mode="passthrough", layer7=False, waf_mode=None, categories=(), rate_limits=(),
                   ip_rules=(), geo_rules=()))
    assert 'sku_name            = "Standard_AzureFrontDoor"' in out and 'name                           = "load-balancer"' in out
    assert 'certificate_type    = "ManagedCertificate"' in out and "firewall_policy" not in out
    assert _fd(spec(cdn=True), "10.60.250.10").startswith("# `sso.example.test`: a CDN in front of a private address")


def test_the_gateway_behind_front_door_keeps_no_waf():
    svc = service(ciamProviderRef="pip-ciam-sso-prod")
    out = "\n".join(gateway_service(environment(svc, subnet("subnet-edge", "subnet-edge", "10.60.250.0/24")), svc,
                                    spec(cdn=True), servers_backend((server("pf-1", "10.60.2.10"),))))
    assert 'name = "Standard_v2"' in out and "web_application_firewall_policy" not in out
