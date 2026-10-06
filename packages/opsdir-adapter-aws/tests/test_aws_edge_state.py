"""The edge read back from AWS Terraform state: an ALB's TLS mode, policy, health check, stickiness, draining and idle
timeout as facts on its service name (in the policies' terms, so the planner compares them with the intent); its web
ACL, Shield protection and CloudFront distribution as edge services with roles from the service they front; Route 53
zones, records, a routed name's TTL and routing, the other environment's answer named; Resolver rules as forwarders;
the load balancer's own security group rules left out."""
import json

from opsdir.core.directory import make_directory, one, values
from opsdir.domains.edge.policies import intended_facts
from opsdir_adapter_aws.inventory import read_terraform_state, state_resources
from support import imported_directory

ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"
LB = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/ciam-prod-sso/0a1b"
TG = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/ciam-prod-sso-443/0c1d"
ACL = "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/ciam-prod-sso/1"
IPS = "arn:aws:wafv2:us-east-1:111122223333:regional/ipset/ciam-prod-sso-deny-ipv4/2"
CDN = "arn:aws:cloudfront::111122223333:distribution/E1"
ALB_DNS, CDN_DNS = "ciam-prod-sso-0a1b.us-east-1.elb.amazonaws.com", "d1.cloudfront.net"


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record():
    return imported_directory((), {}, (
        _row("cloud=main,ou=environments,dc=ciam-ops", ("ciamCloud",), cloud="main", ciamCloudProvider="aws",
             ciamRegion="us-east-1"),
        _row(ENV, ("ciamEnvironment",), env="prod"),
        _row(B, ("organizationalUnit",), ou="bindings"),
        _row(f"cn=sso,{B}", ("ciamServiceName",), cn="sso", ciamBindingRole="pf-sso-service",
             ciamFqdn="sso.example.test", ciamTargetRole="pf-engine", ciamPort="443")))


def _res(type_, name, attrs):
    return {"mode": "managed", "type": type_, "name": name,
            "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
            "instances": [{"schema_version": 1, "attributes": attrs, "sensitive_attributes": []}]}


def _rule(name, priority, statement, action="block", managed=False):
    acted = ("override_action", [{"none": [{}]} if action == "block" else {"count": [{}]}]) if managed else \
        ("action", [{action: [{}]}])
    return {"name": name, "priority": priority, acted[0]: acted[1], "statement": [statement]}


def _state():
    return json.dumps({"version": 4, "terraform_version": "1.9.5", "serial": 1, "lineage": "e", "outputs": {},
                       "resources": [
        _res("aws_instance", "pf_1", {"id": "i-0pf", "private_ip": "10.20.2.10", "subnet_id": "subnet-pf",
                                      "vpc_security_group_ids": ["sg-0pf"],
                                      "tags": {"Name": "pf-1", "Role": "pf-engine", "Hostname": "pf-1.internal"}}),
        _res("aws_security_group", "pf_engine", {"id": "sg-0pf", "name": "ciam-prod-pf-engine", "ingress": []}),
        _res("aws_security_group", "sso_alb", {"id": "sg-0alb", "name": "ciam-prod-sso-alb", "ingress": []}),
        _res("aws_vpc_security_group_ingress_rule", "sso_alb_clients", {
            "security_group_rule_id": "sgr-1", "security_group_id": "sg-0alb", "cidr_ipv4": "0.0.0.0/0",
            "from_port": 443, "to_port": 443, "ip_protocol": "tcp", "description": "clients (fw-sso-public)"}),
        _res("aws_vpc_security_group_ingress_rule", "servers_from_alb", {
            "security_group_rule_id": "sgr-2", "security_group_id": "sg-0pf", "referenced_security_group_id": "sg-0alb",
            "from_port": 443, "to_port": 443, "ip_protocol": "tcp", "description": "from the load balancer"}),
        _res("aws_lb", "sso", {"arn": LB, "name": "ciam-prod-sso", "internal": False, "dns_name": ALB_DNS,
                               "load_balancer_type": "application", "security_groups": ["sg-0alb"],
                               "idle_timeout": 120}),
        _res("aws_lb_listener", "sso_443", {"load_balancer_arn": LB, "port": 443, "protocol": "HTTPS",
                                            "ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
                                            "default_action": [{"type": "forward", "target_group_arn": TG}]}),
        _res("aws_lb_target_group", "sso_443", {
            "arn": TG, "port": 443, "protocol": "HTTPS", "deregistration_delay": "30",
            "health_check": [{"protocol": "HTTPS", "path": "/pf/heartbeat.ping", "matcher": "200"}],
            "stickiness": [{"type": "lb_cookie", "enabled": True, "cookie_duration": 3600}]}),
        _res("aws_lb_target_group_attachment", "sso_443_pf_1", {"target_group_arn": TG, "target_id": "i-0pf"}),
        _res("aws_wafv2_ip_set", "sso_deny", {"arn": IPS, "addresses": ["203.0.113.0/24"]}),
        _res("aws_wafv2_web_acl", "sso", {"arn": ACL, "name": "ciam-prod-sso", "rule": [
            _rule("deny-addresses-0", 0, {"ip_set_reference_statement": [{"arn": IPS}]}),
            _rule("geo-0", 1, {"geo_match_statement": [{"country_codes": ["KP"]}]}),
            _rule("rate-token", 2, {"rate_based_statement": [{"limit": 100, "evaluation_window_sec": 300,
                                                              "aggregate_key_type": "IP"}]}),
            _rule("legacy-throttle", 3, {"rate_based_statement": [{"limit": 2000, "aggregate_key_type": "IP"}]}),
            _rule("core-rules", 4, {"managed_rule_group_statement": [
                {"name": "AWSManagedRulesCommonRuleSet", "vendor_name": "AWS"}]}, managed=True),
            _rule("vendor", 5, {"managed_rule_group_statement": [
                {"name": "SomeVendorRules", "vendor_name": "Vendor"}]}, managed=True)]}),
        _res("aws_wafv2_web_acl_association", "sso", {"resource_arn": LB, "web_acl_arn": ACL}),
        _res("aws_shield_protection", "sso", {"id": "p-1", "name": "sso", "resource_arn": LB}),
        _res("aws_shield_application_layer_automatic_response", "sso", {"resource_arn": LB}),
        _res("aws_cloudfront_distribution", "sso", {
            "arn": CDN, "id": "E1", "domain_name": CDN_DNS, "comment": "CIAM sso",
            "origin": [{"domain_name": ALB_DNS, "origin_id": "load-balancer"}],
            "viewer_certificate": [{"minimum_protocol_version": "TLSv1.2_2021"}]}),
        _res("aws_route53_zone", "public", {"zone_id": "Z1", "name": "example.test", "vpc": []}),
        _res("aws_route53_zone", "corp", {"zone_id": "Z2", "name": "corp.example.test.",
                                          "vpc": [{"vpc_id": "vpc-1"}]}),
        _res("aws_route53_record", "sso", {"zone_id": "Z1", "name": "sso.example.test", "type": "A",
                                           "set_identifier": "main/prod",
                                           "failover_routing_policy": [{"type": "PRIMARY"}],
                                           "alias": [{"name": CDN_DNS, "zone_id": "Z2FDTNDATAQYW2"}]}),
        _res("aws_route53_record", "sso_standby", {"zone_id": "Z1", "name": "sso.example.test", "type": "A",
                                                   "ttl": 60, "records": ["198.51.100.90"],
                                                   "set_identifier": "standby/prod",
                                                   "failover_routing_policy": [{"type": "SECONDARY"}]}),
        _res("aws_route53_record", "verify", {"zone_id": "Z1", "name": "_verify.example.test", "type": "TXT",
                                              "ttl": 300, "records": ["token=abc"]}),
        _res("aws_route53_resolver_rule", "ad", {"id": "rslvr-rr-1", "name": "ad", "rule_type": "FORWARD",
                                                 "domain_name": "ad.corp.example.",
                                                 "target_ip": [{"ip": "10.9.0.2", "port": 53}]}),
        _res("aws_route53_resolver_rule", "system", {"id": "rslvr-rr-2", "rule_type": "SYSTEM",
                                                     "domain_name": "internal.example."})]})


def _imported():
    d = _record()
    imported = read_terraform_state({"main/prod/terraform.tfstate": _state()}, d, ())
    return {e.dn: e for _, es in imported.groups for e in es}, imported.notices


def test_the_alb_runs_what_its_policies_would_ask_as_facts_on_its_service_name():
    entries, _ = _imported()
    sso = entries[f"cn=sso,{B}"]
    assert set(values(sso, "ciamEdgeFact")) == {
        "tls-mode reencrypt", "tls-min 1.2", "tls-profile intermediate", "health https /pf/heartbeat.ping",
        "stickiness cookie 3600", "drain 30", "idle-timeout 120"}
    assert (one(sso, "ciamTtlSeconds"), one(sso, "ciamRoutingPolicy")) == ("60", "failover-primary")
    policy = imported_directory((), {}, (_row("cn=p,ou=edge-policies,dc=ciam-ops", ("ciamTrafficPolicy",), cn="p",
                                          ciamServiceRole="pf-sso-service", ciamTlsMode="reencrypt",
                                          ciamTlsMinVersion="1.2", ciamTlsProfile="intermediate",
                                          ciamHealthProtocol="https", ciamHealthPath="/pf/heartbeat.ping",
                                          ciamStickiness="cookie", ciamStickinessSeconds="3600",
                                          ciamDrainSeconds="30", ciamIdleTimeoutSeconds="120"),))
    (traffic,) = policy.entries.values()
    assert intended_facts(traffic, None) == set(values(sso, "ciamEdgeFact"))           # the round trip


def test_the_web_acl_shield_and_cloudfront_are_edge_services_of_the_service_they_front():
    entries, notices = _imported()
    kinds = {one(e, "ciamEdgeKind"): e for e in entries.values() if "ciamEdgeService" in e.classes}
    waf, ddos, cdn = kinds["waf"], kinds["ddos"], kinds["cdn"]
    assert (one(waf, "ciamBindingRole"), one(waf, "ciamServiceRole"), one(waf, "ciamEdgeKind")) == \
        ("waf-pf-sso-service", "pf-sso-service", "waf")
    assert set(values(waf, "ciamEdgeFact")) == {"waf-mode block", "ip-rule deny 203.0.113.0/24", "geo-rule deny KP",
                                                 "rate-limit token 100/300s per ip", "waf-category core-rules"}
    assert set(values(waf, "ciamEdgeSetting")) == {"rate-based rule legacy-throttle: 2000/300s per ip",
                                                    "managed rule group Vendor/SomeVendorRules"}
    assert (one(ddos, "ciamBindingRole"), values(ddos, "ciamEdgeFact")) == \
        ("ddos-pf-sso-service", ("ddos application-advanced",))
    assert (one(cdn, "ciamBindingRole"), values(cdn, "ciamEdgeFact"), values(cdn, "ciamEdgeSetting")) == \
        ("cdn-pf-sso-service", ("cdn on",), ("minimum_protocol_version TLSv1.2_2021",))


def test_zones_records_forwarders_and_the_other_environments_answer():
    entries, notices = _imported()
    zones = {one(e, "ciamDnsZone"): e for e in entries.values() if "ciamDnsZoneBinding" in e.classes}
    assert {z: (one(e, "ciamZoneVisibility"), one(e, "ciamBindingRole")) for z, e in zones.items()} == {
        "example.test": ("public", "zone-example.test"), "corp.example.test": ("private", "zone-corp.example.test")}
    (txt,) = [e for e in entries.values() if "ciamDnsRecord" in e.classes]
    assert (one(txt, "ciamRecordName"), one(txt, "ciamTtlSeconds"), one(txt, "ciamBindingRole"),
            one(txt, "ciamDnsZone")) == ("_verify.example.test", "300", "record-txt-_verify.example.test",
                                         "example.test")
    (fwd,) = [e for e in entries.values() if "ciamDnsForwarder" in e.classes]
    assert (values(fwd, "ciamForwardDomain"), values(fwd, "ciamForwardTarget"), one(fwd, "ciamBindingRole")) == \
        (("ad.corp.example",), ("10.9.0.2",), "forwarder-ad.corp.example")
    assert "Route 53 record A sso.example.test (standby/prod) answers for another environment of a routed name: not " \
           "recorded here" in notices


def test_the_load_balancers_own_security_group_rules_are_left_out():
    resources, notices = state_resources(_state())
    assert not [r for r in resources if r.kind == "firewall"]
    assert not [n for n in notices if "security group" in n]
