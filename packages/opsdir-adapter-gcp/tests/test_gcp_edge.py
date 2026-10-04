"""A service whose policies terminate TLS at the edge as Google Cloud Terraform: a regional Application Load Balancer
beside the proxy-only subnet bound to subnet-edge (SSL policy, Certificate Manager certificate, URL map, backend service
with the policy's health check, affinity, timeout and draining, firewall rules for the proxies and health checks); a
Cloud Armor policy with address, country and rate-limit rules aimed at the products' endpoints and preconfigured WAF
rules with their exclusions; advanced network DDoS protection for a passthrough service when asked."""
import re

from opsdir.domains.edge.resolve import Health, tls_level, tls_policy
from opsdir_adapter_gcp.edge import TLS_POLICIES, application_lb, armor, network_ddos, rate
from edge_fixtures import environment, service, spec, subnet

EDGE = subnet("subnet-edge", "subnet-edge", "10.70.250.0/23")


def _alb(s, ip="198.51.100.90", *bindings):
    svc = service(ip)
    return "\n".join(application_lb(environment(svc, *bindings), svc, s, ("sso_us_central1_a",), ((), ip), ()))


def test_tls_terms_are_ssl_policy_profiles_and_minimums():
    assert tls_policy(TLS_POLICIES, "1.2", "intermediate") == ("MODERN/TLS_1_2", True)
    assert tls_policy(TLS_POLICIES, "1.3", "modern") == ("RESTRICTED/TLS_1_3", True)
    assert tls_level(TLS_POLICIES, "COMPATIBLE/TLS_1_2") == ("1.2", "compatible")


def test_an_application_load_balancer_beside_the_proxy_only_subnet():
    out = _alb(spec(certificate="gcp-cert://projects/p/locations/us-central1/certificates/sso-tls-2026"),
               "198.51.100.90", EDGE)
    assert 'profile         = "MODERN"' in out and 'min_tls_version = "TLS_1_2"' in out
    assert 'certificate_manager_certificates = ["projects/p/locations/us-central1/certificates/sso-tls-2026"]' in out
    assert 'load_balancing_scheme           = "EXTERNAL_MANAGED"' in out and 'network_tier          = "STANDARD"' in out
    assert 'session_affinity                = "GENERATED_COOKIE"' in out and "timeout_sec                     = 120" in out
    assert 'source_ranges = ["10.70.250.0/23"]' in out and '"130.211.0.0/22"' in out
    assert 'request_path = "/pf/heartbeat.ping"' in out and "https_health_check {" in out
    assert "security_policy                 = google_compute_region_security_policy.sso.self_link" in out


def test_without_a_proxy_only_subnet_or_certificate_it_says_what_is_unbound():
    assert _alb(spec()).startswith("# UNBOUND: `sso.example.test` terminates TLS at an Application Load Balancer")
    out = _alb(spec(mode="terminate", health=Health("tcp", None, None, None, None)), "10.70.1.10", EDGE)
    assert "# UNBOUND: no Certificate Manager certificate holds this service's certificate here" in out
    assert 'load_balancing_scheme           = "INTERNAL_MANAGED"' in out and "network_tier" not in out
    assert "http_health_check {" in out and 'protocol                        = "HTTP"' in out


def test_cloud_armor_rules():
    out = "\n".join(armor(environment(), "sso", spec(categories=("core-rules", "bot-control"), waf_mode="detect")))
    assert out.startswith("# not rendered: bot-control needs reCAPTCHA keys")
    assert 'src_ip_ranges = ["203.0.113.0/24"]' in out and "origin.region_code == 'KP'" in out
    assert "request.path.matches('^/as/token\\\\.oauth2$')" in out and "interval_sec = 300" in out
    assert out.count("evaluatePreconfiguredWaf(") == 9 and out.count("exclusion {") == 9    # one per rule set
    assert len(re.findall(r"preview\s+= true", out)) == out.count('resource "google_compute_region_security_policy_rule"')
    assert rate(100, 300) == (100, 300) and rate(20, 45) == (27, 60)


def test_advanced_network_ddos_only_when_asked():
    assert network_ddos(environment(), "sso", spec()) == ()
    out = "\n".join(network_ddos(environment(), "sso", spec(ddos="network-advanced")))
    assert 'type   = "CLOUD_ARMOR_NETWORK"' in out and 'ddos_protection = "ADVANCED"' in out
    assert 'resource "google_compute_network_edge_security_service" "sso"' in out
