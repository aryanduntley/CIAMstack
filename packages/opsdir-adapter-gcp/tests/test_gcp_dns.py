"""DNS as Google Cloud Terraform: a service name's record set with its TTL, a weighted set as weighted round robin
from the environment holding the first answer, a failover pair as a plain record with a comment, records in their
managed zones (TXT quoted), nothing in a zone someone else runs, outbound forwarders as private forwarding zones."""
from opsdir_adapter_gcp.dns import forwarding_zones, records, service_record
from edge_fixtures import binding, dns_estate


def test_weighted_round_robin_and_failover_from_the_first_answer():
    d, alpha, beta = dns_estate()
    out = "\n".join(service_record(d, alpha, binding(alpha, "svc-api"), "svc_api"))
    assert out.count("wrr {") == 2 and "weight  = 3" in out
    assert 'rrdatas = [google_compute_forwarding_rule.svc_api.ip_address]' in out and '"198.51.100.21"' in out
    failover = "\n".join(service_record(d, alpha, binding(alpha, "svc-login"), "svc_login"))
    assert "# failover-primary: configure Cloud DNS's primary-backup policy" in failover and "ttl          = 60" in failover
    assert service_record(d, beta, binding(beta, "svc-api"), "svc_api")[0].startswith("# `api.example.test`")


def test_records_in_managed_zones():
    d, alpha, _ = dns_estate()
    out = "\n".join(records(d, alpha))
    assert 'rrdatas      = ["\\"token=abc\\""]' in out and 'managed_zone = "Z1ALPHA"' in out
    assert 'name         = "example.test."' in out and '"10 mail1.example.test"' in out
    assert "# UNBOUND: no Cloud DNS zone bound for TXT `_verify.elsewhere.test`" in out


def test_outbound_forwarders_are_private_forwarding_zones():
    _, alpha, _ = dns_estate()
    out = "\n".join(forwarding_zones(alpha))
    assert out.count('resource "google_dns_managed_zone"') == 2 and 'dns_name    = "corp.example."' in out
    assert 'visibility  = "private"' in out and out.count("ipv4_address = ") == 4
    assert "network_url = data.google_compute_network.main.self_link" in out and "# Inbound forwarder `fwd-in`" in out
