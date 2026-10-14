"""A CDN in front of a service as Azure Terraform: Front Door (Premium when it inspects) over the Application Gateway
or the load balancer by its public address, the service name a custom domain (Key Vault certificate or a managed one)
validated by a _dnsauth record, a route without caching, the protection policy as a Front Door firewall policy on the
domain; the gateway behind it keeps no WAF."""
import re

from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_azure.edge import gateway_service, servers_backend
from opsdir_adapter_azure.frontdoor import endpoint, front_door
from edge_fixtures import environment, server, service, spec, subnet


def _fd(s, ip="198.51.100.77"):
    svc = service(ip, ciamDnsZone="example.test", ciamProviderRef="pip-ciam-sso-prod")
    return "\n".join(as_text(front_door(environment(svc), svc, s, "sso")))


def test_front_door_over_the_gateway_with_its_firewall_policy():
    out = _fd(spec(cdn=True, certificate="azkv-cert://kv-ciam-prod/sso-tls-2026"))
    assert 'sku_name            = "Premium_AzureFrontDoor"' in out
    assert "host_name                      = data.azurerm_public_ip.sso.ip_address" in out
    assert ('origin_host_header             = "sso.example.test"' in out
            and 'name                           = "application-gateway"' in out)
    assert 'certificate_type        = "CustomerCertificate"' in out
    assert ('key_vault_certificate_id = "${data.azurerm_key_vault.sso_cdn_tls.vault_uri}'
            'certificates/sso-tls-2026"') in out
    assert re.search(r'forwarding_protocol\s+= "HttpsOnly"', out) and "cache {" not in out
    assert ('type                           = "RateLimitRule"' in out
            and 'match_values   = ["^/as/token\\\\.oauth2$"]' in out)
    assert 'type    = "Microsoft_DefaultRuleSet"' in out and 'match_variable = "RequestBodyPostArgNames"' in out
    assert 'resource "azurerm_cdn_frontdoor_security_policy" "sso"' in out
    assert 'name                = "_dnsauth.sso"' in out and "custom_domain.sso.validation_token" in out
    assert endpoint("sso") == "${azurerm_cdn_frontdoor_endpoint.sso.host_name}"


def test_without_inspection_standard_front_door_over_the_load_balancer_with_a_managed_certificate():
    out = _fd(spec(cdn=True, mode="passthrough", layer7=False, waf_mode=None, categories=(), rate_limits=(),
                   ip_rules=(), geo_rules=()))
    assert ('sku_name            = "Standard_AzureFrontDoor"' in out
            and 'name                           = "load-balancer"' in out)
    assert 'certificate_type = "ManagedCertificate"' in out and "firewall_policy" not in out
    assert 'minimum_version  = "TLS12"' in out and "minimum_tls_version" not in out
    assert _fd(spec(cdn=True), "10.60.250.10") == "# NOTE: service name `sso` (sso.example.test): a CDN in front of " \
        "a private address needs Front Door Premium's Private Link origin: not rendered, so no CDN fronts it"


def test_the_gateway_behind_front_door_keeps_no_waf():
    svc = service(ciamProviderRef="pip-ciam-sso-prod")
    edge = environment(svc, subnet("subnet-edge", "subnet-edge", "10.60.250.0/24"))
    backend = servers_backend((server("pf-1", "10.60.2.10"),))
    out = "\n".join(as_text(gateway_service(edge, svc, spec(cdn=True), backend)))
    assert 'name = "Standard_v2"' in out and "web_application_firewall_policy" not in out


def test_the_edge_notes_are_the_comments_its_service_names_write():
    from opsdir.core.environment import of_class
    from opsdir.core.notes import note_comment
    from opsdir.domains.edge.resolve import inspection_notes
    from opsdir_format_terraform.hcl import as_text
    from opsdir_adapter_azure.frontdoor import frontdoor_notes
    from opsdir_adapter_azure.terraform import _service
    from edge_fixtures import note_lines, noted_edges
    _, m = noted_edges()
    out = "\n".join(x for svc in of_class(m, "ciamServiceName") for x in as_text(_service(m, svc, ())))
    notes = (*inspection_notes(m, ()), *frontdoor_notes(m, ()))
    assert set(note_lines(out)) == {note_comment(n) for n in notes}
    assert [(n.severity, n.subject) for n in notes] == [
        ("note", "service name `svc-l4` (l4.example.test)"),
        ("blocker", "service name `svc-cdn-in` (cdn-in.example.test)")]


def test_a_key_vault_certificate_needs_front_doors_grant_on_the_vault():
    from opsdir.core.notes import note_comment
    from opsdir_adapter_azure.frontdoor import vault_note
    out = _fd(spec(cdn=True, certificate="azkv-cert://kv-edge/sso"))
    assert f"# {note_comment(vault_note(environment(), 'kv-edge'))}" in out
    assert vault_note(environment(), "kv-edge").severity == "action"
