"""DNS as Azure Terraform: a service name's A record with its TTL, a failover pair and a weighted set as Traffic
Manager rendered by the environment holding the primary (every address an external endpoint) with a CNAME to it,
records by type in public and private zones, nothing in a zone someone else runs, outbound forwarders as forwarding
ruleset rules."""
from opsdir_adapter_azure.dns import forwarding_rules, record_name, records, service_record
from edge_fixtures import binding, dns_estate


def test_routing_between_environments_is_traffic_manager_from_the_primary():
    d, alpha, beta = dns_estate()
    out = "\n".join(service_record(d, alpha, binding(alpha, "svc-login"), "svc_login"))
    assert 'traffic_routing_method = "Priority"' in out and "ttl           = 60" in out
    assert 'target     = "198.51.100.10"' in out and 'target     = "198.51.100.20"' in out
    assert "priority   = 1" in out and "priority   = 2" in out
    assert 'resource "azurerm_dns_cname_record" "svc_login"' in out
    assert "record              = azurerm_traffic_manager_profile.svc_login.fqdn" in out
    weighted = "\n".join(service_record(d, alpha, binding(alpha, "svc-api"), "svc_api"))
    assert 'traffic_routing_method = "Weighted"' in weighted and "weight     = 3" in weighted
    assert service_record(d, beta, binding(beta, "svc-login"), "svc_login")[0].startswith("# `login.example.test`")


def test_records_by_type_and_zone_visibility():
    d, alpha, _ = dns_estate()
    out = "\n".join(records(d, alpha))
    assert 'resource "azurerm_dns_txt_record" "record_txt_verify"' in out and 'value = "token=abc"' in out
    assert 'resource "azurerm_dns_mx_record" "record_mx_mail"' in out and 'name                = "@"' in out
    assert "preference = 10" in out and 'exchange   = "mail2.example.test"' in out
    assert 'tag   = "issue"' in out and 'value = "letsencrypt.org"' in out
    assert 'resource "azurerm_private_dns_srv_record" "record_srv_ldap"' in out and "port     = 636" in out
    assert 'record              = "login.example.test"' in out                     # a CNAME's one record
    assert "# `_verify.partner.example` is in a zone dns-team runs" in out
    assert record_name("example.test", "example.test") == "@" and record_name("a.other.test", "example.test") is None


def test_outbound_forwarders_are_ruleset_rules():
    _, alpha, _ = dns_estate()
    out = "\n".join(forwarding_rules(alpha))
    assert out.count('resource "azurerm_private_dns_resolver_forwarding_rule"') == 2
    assert 'domain_name               = "ad.corp.example."' in out
    assert "dns_forwarding_ruleset_id = var.dns_forwarding_ruleset_id" in out
    assert out.count("target_dns_servers {") == 4 and "# Inbound forwarder `fwd-in`" in out
    _, _, beta = dns_estate()
    hosted = forwarding_rules(beta)                               # on its own DNS servers: no rule, a comment
    assert len(hosted) == 1 and "runs on DNS servers 10.2.0.4, 10.2.0.5 (virtual machines)" in hosted[0]
