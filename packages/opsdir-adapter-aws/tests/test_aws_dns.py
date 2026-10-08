"""DNS as AWS Terraform: a service name's alias record, a failover pair and a weighted set routed from the environment
holding the primary (the others' answers health-checked), records in their Route 53 zones, nothing in a zone someone
else runs, outbound forwarders as Resolver rules on the VPC."""
from opsdir_adapter_aws.dns import records, resolver_rules, service_record
from edge_fixtures import binding, dns_estate


def test_a_failover_pair_is_answered_from_the_primarys_zone():
    d, alpha, beta = dns_estate()
    out = "\n".join(service_record(d, alpha, binding(alpha, "svc-login"), "svc_login"))
    assert 'set_identifier = "alpha/prod"' in out and 'type = "PRIMARY"' in out and "alias {" in out
    assert "# an alias takes the load balancer's TTL; the recorded 60 s doesn't apply" in out
    assert 'resource "aws_route53_health_check" "svc_login_beta_prod"' in out and 'ip_address        = "198.51.100.20"' in out
    assert 'type = "SECONDARY"' in out and "health_check_id = aws_route53_health_check.svc_login_beta_prod.id" in out
    (note,) = service_record(d, beta, binding(beta, "svc-login"), "svc_login")
    assert note.startswith("# `login.example.test` routes between environments (failover-secondary)")


def test_a_weighted_set_and_a_name_in_someone_elses_zone():
    d, alpha, _ = dns_estate()
    out = "\n".join(service_record(d, alpha, binding(alpha, "svc-api"), "svc_api"))
    assert out.count("weighted_routing_policy {") == 2 and "weight = 3" in out and "weight = 1" in out
    (note,) = service_record(d, alpha, binding(alpha, "svc-portal"), "svc_portal")
    assert note == "# `portal.partner.example` is in a zone dns-team runs: not rendered here (the plan drafts the " \
                   "request to them)"


def test_records_in_their_zones_and_what_cant_be_placed():
    d, alpha, beta = dns_estate()
    out = "\n".join(records(d, alpha))
    assert 'resource "aws_route53_record" "record_txt_verify"' in out and "ttl     = 120" in out
    assert 'zone_id = "Z2CORP"' in out and 'records = ["0 5 636 ldap.corp.example.test"]' in out    # private zone
    assert 'records = ["10 mail1.example.test", "20 mail2.example.test"]' in out
    assert "# UNBOUND: no Route 53 zone bound for TXT `_verify.elsewhere.test`" in out
    assert "# `_verify.partner.example` is in a zone dns-team runs" in out
    assert records(d, beta) == ()


def test_outbound_forwarders_are_resolver_rules_on_the_vpc():
    _, alpha, beta = dns_estate()
    out = "\n".join(resolver_rules(alpha))
    assert out.count('resource "aws_route53_resolver_rule" ') == 2 and 'domain_name          = "corp.example"' in out
    assert "resolver_endpoint_id = var.resolver_endpoint_id" in out and out.count("target_ip {") == 4
    assert "vpc_id           = data.aws_vpc.main.id" in out
    assert "# Inbound forwarder `fwd-in` (example.internal)" in out
    hosted = resolver_rules(beta)                                 # on its own DNS servers: no rule, a comment
    assert len(hosted) == 1 and hosted[0].startswith("# Forwarder `fwd-legacy` runs on DNS servers 10.2.0.4, 10.2.0.5 "
                                                     "(EC2 instances)")
