"""The edge read back from Google Cloud Terraform state: a regional Application Load Balancer's TLS mode, SSL policy,
health check, affinity, timeout and draining as facts on its service name, with the weighted routing of its record
set (the other environment's answer named); its Cloud Armor policy as an edge service; a global one with Cloud CDN and
Adaptive Protection; advanced network DDoS protection; DNS zones, records and forwarding zones; the proxy-only subnet's
and the health checks' firewall rules left out."""
import json

from opsdir.core.directory import make_directory, one, values
from opsdir_adapter_gcp.inventory import read_terraform_state, state_resources
from support import imported_directory

ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"
P = "projects/p/regions/us-central1"


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record():
    return imported_directory((), {}, (
        _row("cloud=main,ou=environments,dc=ciam-ops", ("ciamCloud",), cloud="main", ciamCloudProvider="gcp",
             ciamRegion="us-central1"),
        _row(ENV, ("ciamEnvironment",), env="prod"),
        _row(B, ("organizationalUnit",), ou="bindings"),
        _row(f"cn=sso,{B}", ("ciamServiceName",), cn="sso", ciamBindingRole="pf-sso-service",
             ciamFqdn="sso.example.test", ciamTargetRole="pf-engine", ciamPort="443"),
        _row(f"cn=app,{B}", ("ciamServiceName",), cn="app", ciamBindingRole="app-service",
             ciamFqdn="app.example.test", ciamTargetRole="pf-engine", ciamPort="443")))


def _res(type_, name, attrs):
    return {"mode": "managed", "type": type_, "name": name,
            "provider": 'provider["registry.terraform.io/hashicorp/google"]',
            "instances": [{"schema_version": 0, "attributes": attrs, "sensitive_attributes": []}]}


def _state():
    return json.dumps({"version": 4, "terraform_version": "1.9.5", "serial": 1, "lineage": "e", "outputs": {},
                       "resources": [
        _res("google_compute_instance", "pf_1", {"id": "projects/p/zones/a/instances/pf-1", "name": "pf-1",
                                                 "metadata": {"ciam-role": "pf-engine"}, "labels": {"role": "pf-engine"},
                                                 "network_interface": [{"network_ip": "10.70.2.10"}]}),
        _res("google_compute_instance_group", "g", {"id": "projects/p/zones/a/instanceGroups/g",
                                                    "instances": ["projects/p/zones/a/instances/pf-1"]}),
        _res("google_compute_subnetwork", "edge", {"id": f"{P}/subnetworks/proxy", "name": "proxy",
                                                   "purpose": "REGIONAL_MANAGED_PROXY", "ip_cidr_range": "10.70.250.0/23"}),
        _res("google_compute_firewall", "proxies", {"name": "ciam-prod-sso-proxies", "source_ranges": ["10.70.250.0/23"],
                                                    "allow": [{"protocol": "tcp", "ports": ["443"]}],
                                                    "target_tags": ["ciam-prod-pf-engine"]}),
        _res("google_compute_firewall", "checks", {"name": "ciam-prod-sso-health-checks",
                                                   "source_ranges": ["35.191.0.0/16", "130.211.0.0/22"],
                                                   "allow": [{"protocol": "tcp", "ports": ["443"]}],
                                                   "target_tags": ["ciam-prod-pf-engine"]}),
        _res("google_compute_region_health_check", "sso", {"id": f"{P}/healthChecks/sso", "https_health_check": [
            {"port": 443, "request_path": "/pf/heartbeat.ping"}]}),
        _res("google_compute_region_ssl_policy", "sso", {"id": f"{P}/sslPolicies/sso", "profile": "MODERN",
                                                         "min_tls_version": "TLS_1_2"}),
        _res("google_compute_region_security_policy", "sso", {"id": f"{P}/securityPolicies/ciam-prod-sso",
                                                              "name": "ciam-prod-sso", "type": "CLOUD_ARMOR"}),
        *(_res("google_compute_region_security_policy_rule", f"r{p}", {
            "security_policy": "ciam-prod-sso", "priority": p, **body}) for p, body in (
            (1000, {"action": "deny(403)", "match": [{"versioned_expr": "SRC_IPS_V1",
                                                       "config": [{"src_ip_ranges": ["203.0.113.0/24"]}]}]}),
            (1010, {"action": "deny(403)", "match": [{"expr": [{"expression": "!(origin.region_code == 'US')"}]}]}),
            (1020, {"action": "throttle", "description": "rate-token", "match": [{"expr": [{"expression": "true"}]}],
                    "rate_limit_options": [{"enforce_on_key": "IP", "rate_limit_threshold": [
                        {"count": 100, "interval_sec": 300}]}]}),
            (1030, {"action": "deny(403)", "match": [{"expr": [{"expression":
                                                                "evaluatePreconfiguredWaf('sqli-v33-stable')"}]}]}),
            (1040, {"action": "deny(403)", "match": [{"expr": [{"expression":
                                                                "evaluatePreconfiguredWaf('php-v33-stable')"}]}]}),
            (2147483647, {"action": "allow", "match": [{"versioned_expr": "SRC_IPS_V1",
                                                         "config": [{"src_ip_ranges": ["*"]}]}]}))),
        _res("google_compute_region_backend_service", "sso", {
            "id": f"{P}/backendServices/sso", "name": "sso", "protocol": "HTTPS", "session_affinity": "GENERATED_COOKIE",
            "affinity_cookie_ttl_sec": 3600, "timeout_sec": 120, "connection_draining_timeout_sec": 30,
            "health_checks": [f"{P}/healthChecks/sso"], "security_policy": f"{P}/securityPolicies/ciam-prod-sso",
            "backend": [{"group": "projects/p/zones/a/instanceGroups/g"}]}),
        _res("google_compute_region_url_map", "sso", {"id": f"{P}/urlMaps/sso",
                                                      "default_service": f"{P}/backendServices/sso"}),
        _res("google_compute_region_target_https_proxy", "sso", {"id": f"{P}/targetHttpsProxies/sso",
                                                                 "url_map": f"{P}/urlMaps/sso",
                                                                 "ssl_policy": f"{P}/sslPolicies/sso"}),
        _res("google_compute_forwarding_rule", "sso", {"id": f"{P}/forwardingRules/sso", "name": "sso",
                                                       "ip_address": "198.51.100.90", "port_range": "443-443",
                                                       "target": f"{P}/targetHttpsProxies/sso"}),
        _res("google_compute_security_policy", "app", {
            "id": "projects/p/global/securityPolicies/app", "name": "app", "type": "CLOUD_ARMOR",
            "adaptive_protection_config": [{"layer_7_ddos_defense_config": [{"enable": True}]}]}),
        _res("google_compute_backend_service", "app", {
            "id": "projects/p/global/backendServices/app", "name": "app", "protocol": "HTTPS", "enable_cdn": True,
            "cdn_policy": [{"cache_mode": "USE_ORIGIN_HEADERS"}],
            "security_policy": "projects/p/global/securityPolicies/app",
            "backend": [{"group": "projects/p/zones/a/instanceGroups/g"}]}),
        _res("google_compute_url_map", "app", {"id": "projects/p/global/urlMaps/app",
                                               "default_service": "projects/p/global/backendServices/app"}),
        _res("google_compute_target_https_proxy", "app", {"id": "projects/p/global/targetHttpsProxies/app",
                                                          "url_map": "projects/p/global/urlMaps/app"}),
        _res("google_compute_global_forwarding_rule", "app", {"id": "projects/p/global/forwardingRules/app",
                                                              "name": "app", "ip_address": "198.51.100.91",
                                                              "port_range": "443-443",
                                                              "target": "projects/p/global/targetHttpsProxies/app"}),
        _res("google_compute_region_security_policy", "network", {
            "id": f"{P}/securityPolicies/net", "name": "net", "type": "CLOUD_ARMOR_NETWORK",
            "ddos_protection_config": [{"ddos_protection": "ADVANCED"}], "labels": {"role": "ddos-network"}}),
        _res("google_dns_managed_zone", "public", {"id": "z1", "name": "ciam-public", "dns_name": "example.test.",
                                                   "visibility": "public"}),
        _res("google_dns_managed_zone", "corp", {"id": "z2", "name": "corp", "dns_name": "corp.example.test.",
                                                 "visibility": "private"}),
        _res("google_dns_managed_zone", "ad", {"id": "z3", "name": "fwd-ad", "dns_name": "ad.corp.example.",
                                               "visibility": "private", "forwarding_config": [
                                                   {"target_name_servers": [{"ipv4_address": "10.9.0.2"}]}]}),
        _res("google_dns_record_set", "sso", {"id": "rs-sso", "name": "sso.example.test.", "type": "A", "ttl": 60,
                                              "managed_zone": "ciam-public", "routing_policy": [{"wrr": [
                                                  {"weight": 3, "rrdatas": ["198.51.100.90"]},
                                                  {"weight": 1, "rrdatas": ["198.51.100.20"]}]}]}),
        _res("google_dns_record_set", "app", {"id": "rs-app", "name": "app.example.test.", "type": "A", "ttl": 300,
                                              "managed_zone": "ciam-public", "rrdatas": ["198.51.100.91"]}),
        _res("google_dns_record_set", "verify", {"id": "rs-v", "name": "_verify.example.test.", "type": "TXT",
                                                 "ttl": 300, "managed_zone": "ciam-public",
                                                 "rrdatas": ['"token=abc"']})]})


def _imported():
    imported = read_terraform_state({"main/prod/terraform.tfstate": _state()}, _record(), ())
    return {e.dn: e for _, es in imported.groups for e in es}, imported.notices


def test_regional_and_global_application_load_balancers_with_what_they_run():
    entries, notices = _imported()
    sso, app = entries[f"cn=sso,{B}"], entries[f"cn=app,{B}"]
    assert set(values(sso, "ciamEdgeFact")) == {
        "tls-mode reencrypt", "tls-min 1.2", "tls-profile intermediate", "health https /pf/heartbeat.ping",
        "stickiness cookie 3600", "idle-timeout 120", "drain 30"}
    assert (one(sso, "ciamTtlSeconds"), one(sso, "ciamRoutingPolicy"), one(sso, "ciamRoutingWeight")) == \
        ("60", "weighted", "3")
    assert values(app, "ciamEdgeFact") == ("tls-mode reencrypt",) and one(app, "ciamTtlSeconds") == "300"
    assert any("Cloud DNS answer 198.51.100.20 answers for another environment" in n for n in notices)


def test_cloud_armor_cloud_cdn_and_ddos_are_edge_services():
    entries, _ = _imported()
    edge = sorted((one(e, "ciamEdgeKind"), one(e, "ciamBindingRole"), values(e, "ciamEdgeFact"))
                  for e in entries.values() if "ciamEdgeService" in e.classes)
    assert edge == [
        ("cdn", "cdn-app-service", ("cdn on",)),
        ("ddos", "ddos-app-service", ("ddos application-advanced",)),
        ("ddos", "ddos-network", ("ddos network-advanced",)),
        ("waf", "waf-app-service", ("waf-mode block",)),
        ("waf", "waf-pf-sso-service", ("geo-rule allow US", "ip-rule deny 203.0.113.0/24",
                                       "rate-limit token 100/300s per ip", "waf-category core-rules",
                                       "waf-mode block"))]
    (armor,) = [e for e in entries.values() if one(e, "ciamBindingRole") == "waf-pf-sso-service"]
    assert values(armor, "ciamEdgeSetting") == ("preconfigured php-v33-stable",)


def test_zones_records_forwarding_zones_and_no_load_balancer_rules():
    entries, _ = _imported()
    zones = {one(e, "ciamDnsZone"): one(e, "ciamZoneVisibility") for e in entries.values()
             if "ciamDnsZoneBinding" in e.classes}
    assert zones == {"example.test": "public", "corp.example.test": "private"}
    (txt,) = [e for e in entries.values() if "ciamDnsRecord" in e.classes]
    assert (one(txt, "ciamRecordName"), values(txt, "ciamRecordValue")) == ("_verify.example.test", ("token=abc",))
    (fwd,) = [e for e in entries.values() if "ciamDnsForwarder" in e.classes]
    assert (values(fwd, "ciamForwardDomain"), values(fwd, "ciamForwardTarget")) == (("ad.corp.example",), ("10.9.0.2",))
    resources, _ = state_resources(_state())
    assert not [r for r in resources if r.kind == "firewall"]
