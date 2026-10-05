"""What Cloud Asset Inventory and gcloud report about an environment's edge, normalized to the hashicorp/google attribute
names the shared mapping reads (opsdir_adapter_gcp.edge_inventory). Pure.

  compute.googleapis.com/UrlMap, RegionUrlMap,                  gcloud compute url-maps list
    TargetHttpsProxy, RegionTargetHttpsProxy                    gcloud compute target-https-proxies list
    SslPolicy, RegionSslPolicy                                  gcloud compute ssl-policies list
    HealthCheck, RegionHealthCheck                              gcloud compute health-checks list
    SecurityPolicy, RegionSecurityPolicy (with their rules)     gcloud compute security-policies list / describe
  dns.googleapis.com/ManagedZone                                gcloud dns managed-zones list
Global and regional resources are told apart by whether the item names a region.
"""
from types import MappingProxyType

from .names import resource_id

KINDS = MappingProxyType({
    **{f"compute.googleapis.com/{p}{t}": kind for t, kind in (
        ("UrlMap", "url-map"), ("TargetHttpsProxy", "https-proxy"), ("SslPolicy", "ssl-policy"),
        ("HealthCheck", "health-check"), ("SecurityPolicy", "security-policy")) for p in ("", "Region")},
    "compute#urlMap": "url-map", "compute#targetHttpsProxy": "https-proxy", "compute#sslPolicy": "ssl-policy",
    "compute#healthCheck": "health-check", "compute#securityPolicy": "security-policy",
    "dns.googleapis.com/ManagedZone": "managed-zone", "dns#managedZone": "managed-zone"})


def _self(d):
    return resource_id(d.get("selfLink") or d.get("name"))


def _scoped(d, name):
    """A resource type at the item's scope: regional when it names a region."""
    return f"google_compute_{'region_' if d.get('region') else ''}{name}"


def _rule(r):
    match, options = r.get("match") or {}, r.get("rateLimitOptions") or {}
    threshold = options.get("rateLimitThreshold") or {}
    return {"priority": r.get("priority"), "action": r.get("action"), "preview": r.get("preview"),
            "description": r.get("description"),
            "match": [{"versioned_expr": match.get("versionedExpr"),
                       "config": [{"src_ip_ranges": (match.get("config") or {}).get("srcIpRanges") or []}],
                       "expr": [{"expression": (match.get("expr") or {}).get("expression")}]}],
            "rate_limit_options": [{"enforce_on_key": options.get("enforceOnKey"),
                                    "enforce_on_key_name": options.get("enforceOnKeyName"),
                                    "rate_limit_threshold": [{"count": threshold.get("count"),
                                                              "interval_sec": threshold.get("intervalSec")}]}]
            if options else []}


def _health_check(d):
    kind = (d.get("type") or "TCP").lower()
    block = d.get(f"{kind}HealthCheck") or {}
    return (_scoped(d, "health_check"), {
        "id": _self(d), "name": d.get("name"), "check_interval_sec": d.get("checkIntervalSec"),
        f"{kind}_health_check": [{"port": block.get("port"), "request_path": block.get("requestPath")}]})


def _security_policy(d):
    adaptive = ((d.get("adaptiveProtectionConfig") or {}).get("layer7DdosDefenseConfig") or {}).get("enable")
    return (_scoped(d, "security_policy"), {
        "id": _self(d), "name": d.get("name"), "type": d.get("type"), "labels": d.get("labels") or {},
        "rule": [_rule(r) for r in d.get("rules") or ()],
        "adaptive_protection_config": [{"layer_7_ddos_defense_config": [{"enable": adaptive}]}] if adaptive else [],
        "ddos_protection_config": [{"ddos_protection": (d.get("ddosProtectionConfig") or {}).get("ddosProtection")}]
        if d.get("ddosProtectionConfig") else []})


def _managed_zone(d):
    targets = (d.get("forwardingConfig") or {}).get("targetNameServers") or ()
    return ("google_dns_managed_zone", {
        "id": d.get("id") or d.get("name"), "name": d.get("name"), "dns_name": d.get("dnsName"),
        "visibility": d.get("visibility"), "labels": d.get("labels") or {},
        "forwarding_config": [{"target_name_servers": [{"ipv4_address": t.get("ipv4Address")} for t in targets]}]
        if targets else []})


def edge_pairs(of):
    """(Terraform type, attributes) pairs of the edge items; of(kind) -> [(data, origin), ...]."""
    return [*((_scoped(d, "url_map"), {"id": _self(d), "default_service": resource_id(d.get("defaultService"))})
              for d, _ in of("url-map")),
            *((_scoped(d, "target_https_proxy"), {
                "id": _self(d), "url_map": resource_id(d.get("urlMap")), "ssl_policy": resource_id(d.get("sslPolicy")),
                "certificate_manager_certificates": d.get("certificateManagerCertificates") or []})
              for d, _ in of("https-proxy")),
            *((_scoped(d, "ssl_policy"), {"id": _self(d), "profile": d.get("profile"),
                                          "min_tls_version": d.get("minTlsVersion")}) for d, _ in of("ssl-policy")),
            *(_health_check(d) for d, _ in of("health-check")),
            *(_security_policy(d) for d, _ in of("security-policy")),
            *(_managed_zone(d) for d, _ in of("managed-zone"))]


def backend_attributes(d):
    """What a backend service's item says of its edge, in Terraform's names."""
    return {"protocol": d.get("protocol"), "session_affinity": d.get("sessionAffinity"),
            "affinity_cookie_ttl_sec": d.get("affinityCookieTtlSec"), "timeout_sec": d.get("timeoutSec"),
            "connection_draining_timeout_sec": (d.get("connectionDraining") or {}).get("drainingTimeoutSec"),
            "health_checks": [resource_id(h) for h in d.get("healthChecks") or ()],
            "security_policy": resource_id(d.get("securityPolicy")), "enable_cdn": d.get("enableCDN"),
            "cdn_policy": [{"cache_mode": (d.get("cdnPolicy") or {}).get("cacheMode")}] if d.get("cdnPolicy") else []}


def record_routing(d):
    """A record set's TTL and weighted round robin, in Terraform's names."""
    items = ((d.get("routingPolicy") or {}).get("wrr") or {}).get("items") or ()
    return {"ttl": d.get("ttl"),
            "routing_policy": [{"wrr": [{"weight": i.get("weight"), "rrdatas": i.get("rrdatas") or []}
                                        for i in items]}] if items else []}
