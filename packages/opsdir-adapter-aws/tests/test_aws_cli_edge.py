"""The edge read back from AWS CLI output: the same facts and edge services as from Terraform state (listeners'
protocols and TLS policies, target group and load balancer attributes, a web ACL with its resources and IP set, Shield,
CloudFront, hosted zones, record sets with TTLs and routing, resolver rules)."""
import json

from opsdir_adapter_aws.cli import cli_resources

LB = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/ciam-prod-sso/0a1b"
TG = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/ciam-prod-sso-443/0c1d"
ACL = "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/ciam-prod-sso/1"
IPS = "arn:aws:wafv2:us-east-1:111122223333:regional/ipset/deny/2"
ALB_DNS = "ciam-prod-sso-0a1b.us-east-1.elb.amazonaws.com"


def _outputs():
    docs = {
        "load-balancers.json": {"LoadBalancers": [{
            "LoadBalancerArn": LB, "LoadBalancerName": "ciam-prod-sso", "Scheme": "internet-facing",
            "DNSName": ALB_DNS, "Type": "application", "SecurityGroups": ["sg-0alb"], "AvailabilityZones": []}]},
        "lb-attributes/ciam-prod-sso.json": {"Attributes": [{"Key": "idle_timeout.timeout_seconds", "Value": "120"}]},
        "listeners.json": {"Listeners": [{"LoadBalancerArn": LB, "Port": 443, "Protocol": "HTTPS",
                                          "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
                                          "DefaultActions": [{"Type": "forward", "TargetGroupArn": TG}]}]},
        "target-groups.json": {"TargetGroups": [{"TargetGroupArn": TG, "TargetGroupName": "ciam-prod-sso-443",
                                                 "Port": 443, "Protocol": "HTTPS", "HealthCheckProtocol": "HTTPS",
                                                 "HealthCheckPath": "/pf/heartbeat.ping"}]},
        "tg-attributes/ciam-prod-sso-443.json": {"Attributes": [
            {"Key": "stickiness.enabled", "Value": "true"}, {"Key": "stickiness.type", "Value": "lb_cookie"},
            {"Key": "stickiness.lb_cookie.duration_seconds", "Value": "3600"},
            {"Key": "deregistration_delay.timeout_seconds", "Value": "30"}]},
        "web-acl-sso.json": {"WebACL": {"Name": "ciam-prod-sso", "ARN": ACL, "Rules": [
            {"Name": "deny-addresses-0", "Priority": 0, "Action": {"Block": {}},
             "Statement": {"IPSetReferenceStatement": {"ARN": IPS}}},
            {"Name": "rate-token", "Priority": 1, "Action": {"Count": {}},
             "Statement": {"RateBasedStatement": {"Limit": 100, "EvaluationWindowSec": 300,
                                                  "AggregateKeyType": "CUSTOM_KEYS",
                                                  "CustomKeys": [{"Header": {"Name": "X-Key"}}]}}},
            {"Name": "core-rules", "Priority": 2, "OverrideAction": {"None": {}},
             "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS",
                                                         "Name": "AWSManagedRulesCommonRuleSet"}}}]},
            "LockToken": "t"},
        "waf-resources/ciam-prod-sso.json": {"ResourceArns": [LB]},
        "ip-set-deny.json": {"IPSet": {"Name": "deny", "ARN": IPS, "Addresses": ["203.0.113.0/24"]}},
        "protections.json": {"Protections": [{"Id": "p-1", "Name": "sso", "ResourceArn": LB}]},
        "distributions.json": {"DistributionList": {"Items": [{
            "ARN": "arn:aws:cloudfront::1:distribution/E1", "Id": "E1", "DomainName": "d1.cloudfront.net",
            "Origins": {"Items": [{"Id": "lb", "DomainName": ALB_DNS}]},
            "ViewerCertificate": {"MinimumProtocolVersion": "TLSv1.2_2021"}}]}},
        "hosted-zones.json": {"HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.test.",
                                               "Config": {"PrivateZone": False}}]},
        "route53/Z1.json": {"ResourceRecordSets": [
            {"Name": "example.test.", "Type": "NS", "TTL": 172800, "ResourceRecords": [{"Value": "ns-1."}]},
            {"Name": "sso.example.test.", "Type": "A", "SetIdentifier": "main/prod", "Failover": "PRIMARY",
             "AliasTarget": {"DNSName": "d1.cloudfront.net.", "HostedZoneId": "Z2FDTNDATAQYW2"}},
            {"Name": "_verify.example.test.", "Type": "TXT", "TTL": 300,
             "ResourceRecords": [{"Value": '"token=abc"'}]}]},
        "resolver-rules.json": {"ResolverRules": [{"Id": "rslvr-rr-1", "Name": "ad", "RuleType": "FORWARD",
                                                   "DomainName": "ad.corp.example.",
                                                   "TargetIps": [{"Ip": "10.9.0.2", "Port": 53}]}]}}
    return {p: json.dumps(d) for p, d in docs.items()}


def test_the_cli_reads_the_edge_back_like_state():
    resources, _ = cli_resources(_outputs())
    (sso,) = [r for r in resources if r.kind == "service"]
    assert set(sso.attrs["ciamEdgeFact"]) == {"tls-mode reencrypt", "tls-min 1.2", "tls-profile intermediate",
                                              "health https /pf/heartbeat.ping", "stickiness cookie 3600", "drain 30",
                                              "idle-timeout 120"}
    assert (sso.attrs["ciamFqdn"], sso.attrs["ciamRoutingPolicy"], sso.attrs["ciamTtlSeconds"]) == \
        (("sso.example.test",), ("failover-primary",), ("60",))
    edge = {r.attrs["ciamEdgeKind"][0]: r for r in resources if r.kind == "edge"}
    assert set(edge["waf"].attrs["ciamEdgeFact"]) == {"waf-mode block", "ip-rule deny 203.0.113.0/24",
                                                      "rate-limit token 100/300s per header:X-Key",
                                                      "waf-category core-rules"}
    assert edge["waf"].links == {"ciamServiceRole": LB} and edge["ddos"].links == {"ciamServiceRole": LB}
    assert edge["cdn"].attrs["ciamEdgeFact"] == ("cdn on",)
    zones = [r for r in resources if r.kind == "zone"]
    assert [(z.attrs["ciamDnsZone"], z.attrs["ciamZoneVisibility"]) for z in zones] == [(("example.test",),
                                                                                          ("public",))]
    (txt,) = [r for r in resources if r.kind == "record"]                         # the zone's own NS isn't read
    assert (txt.attrs["ciamRecordValue"], txt.attrs["ciamTtlSeconds"]) == (("token=abc",), ("300",))
    (fwd,) = [r for r in resources if r.kind == "forwarder"]
    assert fwd.attrs["ciamForwardDomain"] == ("ad.corp.example",)
