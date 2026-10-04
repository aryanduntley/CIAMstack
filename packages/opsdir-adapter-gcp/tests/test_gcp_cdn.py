"""A CDN in front of a service as Google Cloud Terraform: a global external Application Load Balancer (Cloud CDN is
its) with the CDN on its backend service following the origin's caching headers, a global Cloud Armor policy (Adaptive
Protection for application-advanced DDoS protection), a global forwarding rule on the reserved global address, no
proxy-only subnet needed; a private address can't have one."""
import re

from opsdir_adapter_gcp.dns import service_record
from opsdir_adapter_gcp.edge import application_lb
from edge_fixtures import binding, dns_estate, environment, service, spec


def _alb(s, ip="198.51.100.90", **attrs):
    svc = service(ip, **attrs)
    return "\n".join(application_lb(environment(svc), svc, s, ("sso_us_central1_a",), ((), ip), ()))


def test_a_global_load_balancer_with_cloud_cdn_and_global_cloud_armor():
    out = _alb(spec(cdn=True, ddos="application-advanced"), ciamProviderRef="ciam-sso-global")
    assert 'data "google_compute_global_address" "sso"' in out and not re.search(r"\bregion\s+= var.region", out)
    assert 'resource "google_compute_ssl_policy" "sso"' in out and 'resource "google_compute_backend_service" "sso"' in out
    assert "enable_cdn                      = true" in out and 'cache_mode = "USE_ORIGIN_HEADERS"' in out
    assert 'resource "google_compute_security_policy" "sso"' in out and "layer_7_ddos_defense_config {" in out
    assert 'resource "google_compute_security_policy_rule" "sso_1000"' in out
    assert 'resource "google_compute_global_forwarding_rule" "sso"' in out
    assert "ip_address            = data.google_compute_global_address.sso.address" in out
    assert "_proxies" not in out and "_health_checks" in out


def test_a_passthrough_service_behind_the_cdn_keeps_tls_to_its_servers_and_a_private_one_cant():
    out = _alb(spec(cdn=True, mode="passthrough", layer7=False))
    assert 'protocol                        = "HTTPS"' in out
    assert _alb(spec(cdn=True), "10.70.1.10").startswith("# `sso.example.test`: Cloud CDN serves external")


def test_the_record_points_at_the_global_forwarding_rule():
    d, alpha, _ = dns_estate()
    api = binding(alpha, "svc-api")
    (out,) = service_record(d, alpha, api._replace(attrs={**api.attrs, "ciamRoutingPolicy": ()}), "svc_api", True)
    assert "google_compute_global_forwarding_rule.svc_api.ip_address" in out
