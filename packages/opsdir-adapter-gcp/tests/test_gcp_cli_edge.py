"""The edge read back from gcloud output: a forwarding rule through a target HTTPS proxy, URL map and backend service
(SSL policy, health check, affinity, timeout, draining), a Cloud Armor policy with its rules, managed zones (one a
forwarding zone) and a record set's weighted routing: the same facts and edge services as from Terraform state."""
import json

from opsdir_adapter_gcp.cli import cli_resources

P = "https://www.googleapis.com/compute/v1/projects/p/regions/us-central1"


def _outputs():
    docs = {
        "compute.json": [
            {"kind": "compute#forwardingRule", "selfLink": f"{P}/forwardingRules/sso", "name": "sso",
             "region": f"{P}", "IPAddress": "198.51.100.90", "portRange": "443-443",
             "target": f"{P}/targetHttpsProxies/sso"},
            {"kind": "compute#targetHttpsProxy", "selfLink": f"{P}/targetHttpsProxies/sso", "region": f"{P}",
             "urlMap": f"{P}/urlMaps/sso", "sslPolicy": f"{P}/sslPolicies/sso"},
            {"kind": "compute#urlMap", "selfLink": f"{P}/urlMaps/sso", "region": f"{P}",
             "defaultService": f"{P}/backendServices/sso"},
            {"kind": "compute#sslPolicy", "selfLink": f"{P}/sslPolicies/sso", "region": f"{P}", "profile": "MODERN",
             "minTlsVersion": "TLS_1_2"},
            {"kind": "compute#healthCheck", "selfLink": f"{P}/healthChecks/sso", "region": f"{P}", "type": "HTTPS",
             "httpsHealthCheck": {"port": 443, "requestPath": "/pf/heartbeat.ping"}},
            {"kind": "compute#backendService", "selfLink": f"{P}/backendServices/sso", "name": "sso",
             "region": f"{P}", "protocol": "HTTPS", "sessionAffinity": "CLIENT_IP", "timeoutSec": 120,
             "connectionDraining": {"drainingTimeoutSec": 30}, "healthChecks": [f"{P}/healthChecks/sso"],
             "securityPolicy": f"{P}/securityPolicies/armor", "backends": []},
            {"kind": "compute#securityPolicy", "selfLink": f"{P}/securityPolicies/armor", "name": "armor",
             "region": f"{P}", "type": "CLOUD_ARMOR", "rules": [
                 {"priority": 1000, "action": "deny(403)",
                  "match": {"versionedExpr": "SRC_IPS_V1", "config": {"srcIpRanges": ["203.0.113.0/24"]}}},
                 {"priority": 1010, "action": "throttle", "description": "rate-login",
                  "match": {"expr": {"expression": "true"}},
                  "rateLimitOptions": {"enforceOnKey": "IP", "rateLimitThreshold": {"count": 50, "intervalSec": 60}}},
                 {"priority": 2147483647, "action": "allow",
                  "match": {"versionedExpr": "SRC_IPS_V1", "config": {"srcIpRanges": ["*"]}}}]}],
        "zones.json": [
            {"kind": "dns#managedZone", "id": "1", "name": "ciam-public", "dnsName": "example.test.",
             "visibility": "public"},
            {"kind": "dns#managedZone", "id": "2", "name": "fwd-ad", "dnsName": "ad.corp.example.",
             "visibility": "private", "forwardingConfig": {"targetNameServers": [{"ipv4Address": "10.9.0.2"}]}}],
        "ciam-public.json": [
            {"kind": "dns#resourceRecordSet", "name": "sso.example.test.", "type": "A", "ttl": 60,
             "routingPolicy": {"wrr": {"items": [{"weight": 3, "rrdatas": ["198.51.100.90"]},
                                                 {"weight": 1, "rrdatas": ["198.51.100.20"]}]}}}]}
    return {p: json.dumps(d) for p, d in docs.items()}


def test_gcloud_reads_the_edge_back_like_state():
    resources, notices = cli_resources(_outputs())
    (sso,) = [r for r in resources if r.kind == "service"]
    assert set(sso.attrs["ciamEdgeFact"]) == {"tls-mode reencrypt", "tls-min 1.2", "tls-profile intermediate",
                                              "health https /pf/heartbeat.ping", "stickiness source-ip",
                                              "idle-timeout 120", "drain 30"}
    assert (sso.attrs["ciamFqdn"], sso.attrs["ciamRoutingPolicy"], sso.attrs["ciamRoutingWeight"]) == \
        (("sso.example.test",), ("weighted",), ("3",))
    (armor,) = [r for r in resources if r.kind == "edge"]
    assert set(armor.attrs["ciamEdgeFact"]) == {"waf-mode block", "ip-rule deny 203.0.113.0/24",
                                                "rate-limit login 50/60s per ip"}
    assert armor.links == {"ciamServiceRole": sso.ref}
    assert [r.attrs["ciamDnsZone"] for r in resources if r.kind == "zone"] == [("example.test",)]
    (fwd,) = [r for r in resources if r.kind == "forwarder"]
    assert fwd.attrs["ciamForwardTarget"] == ("10.9.0.2",)
    assert any("198.51.100.20 answers for another environment" in n for n in notices)
