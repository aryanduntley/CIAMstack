"""What Google Cloud's edge runs, read back in the edge domain's terms (Terraform state attribute names; the inventory
reader normalizes to them). Pure.

  forwarding rule -> backend service      -> facts on its service name: tls-mode passthrough (a backend service the
                                             rule names), else terminate or reencrypt (through a target HTTPS proxy
                                             and URL map: the backend's protocol), the proxy's SSL policy through the
                                             TLS table, an HTTP(S) health check, session affinity, a timeout other
                                             than 30 s, draining
  backend service security policy +       -> edge service waf (Cloud Armor): waf-mode (detect when every rule is a
    its rules                                preview), waf-category (preconfigured rule sets the WAF table knows),
                                             rate-limit (rules described rate-<kind>), ip-rule (SRC_IPS_V1), geo-rule
                                             (origin.region_code expressions); Adaptive Protection is ddos
                                             application-advanced
  backend service enable_cdn              -> edge service cdn
  CLOUD_ARMOR_NETWORK policy with ADVANCED -> edge service ddos network-advanced
  google_dns_managed_zone                 -> DNS zone (public, private); one with a forwarding config is a forwarder
  google_dns_record_set                   -> a service name's TTL and weighted routing (its own address's weight; the
                                             others' named); other record sets as DNS records (TXT unquoted)
"""
import re

from opsdir.core.inventory import of_types, resource
from opsdir.domains.edge.imports import forwarder_role, record_role, zone_role
from opsdir.domains.edge.resolve import endpoint_kind_named, rate_limit_fact, tls_level
from opsdir_format_terraform.state import blocks, first_block
from .edge import TLS_POLICIES, WAF_RULES

CATEGORIES = {rule_set: category for category, sets in WAF_RULES.items() for rule_set in sets}
_REGION_CODE = re.compile(r"origin\.region_code == '([A-Z]{2})'")
_PRECONFIGURED = re.compile(r"evaluatePreconfiguredWaf\('([a-z0-9-]+)'")
BACKENDS = ("google_compute_region_backend_service", "google_compute_backend_service")
FORWARDING = ("google_compute_forwarding_rule", "google_compute_global_forwarding_rule")
PROXIES = ("google_compute_region_target_https_proxy", "google_compute_target_https_proxy")
URL_MAPS = ("google_compute_region_url_map", "google_compute_url_map")
SSL_POLICIES = ("google_compute_region_ssl_policy", "google_compute_ssl_policy")
HEALTH_CHECKS = ("google_compute_region_health_check", "google_compute_health_check")
SECURITY_POLICIES = ("google_compute_region_security_policy", "google_compute_security_policy")
SECURITY_RULES = ("google_compute_region_security_policy_rule", "google_compute_security_policy_rule")


def ref_key(v):
    """A resource's identity across the forms references take (an ID, a self link, a name path)."""
    return re.sub(r"^https://www\.googleapis\.com/compute/v1/", "", v or "").lower()


def _labels(a):
    return a.get("labels") or {}


def _role(a):
    """The role a resource's labels name (role, else bindingrole, as the inventory reads them)."""
    return _labels(a).get("role") or _labels(a).get("bindingrole")


def _by_id(found, *types):
    return {ref_key(x): a for a in of_types(found, *types) for x in (a.get("id"), a.get("self_link")) if x}


def backend_of(found, fr):
    """(the backend service a forwarding rule leads to, its target HTTPS proxy or None)."""
    backends, proxies, maps = _by_id(found, *BACKENDS), _by_id(found, *PROXIES), _by_id(found, *URL_MAPS)
    if fr.get("backend_service"):
        return backends.get(ref_key(fr.get("backend_service"))), None
    proxy = proxies.get(ref_key(fr.get("target")))
    url_map = maps.get(ref_key((proxy or {}).get("url_map")))
    return backends.get(ref_key((url_map or {}).get("default_service"))), proxy


def service_facts(found, fr):
    """(facts, settings) of what a forwarding rule leads to."""
    backend, proxy = backend_of(found, fr)
    backend = backend or {}
    if proxy is None:
        mode = "passthrough"
    else:
        mode = "reencrypt" if (backend.get("protocol") or "").upper() in ("HTTPS", "HTTP2") else "terminate"
    facts, settings = [f"tls-mode {mode}"], []
    policy = _by_id(found, *SSL_POLICIES).get(ref_key((proxy or {}).get("ssl_policy")))
    if policy:
        name = f"{policy.get('profile')}/{policy.get('min_tls_version')}"
        level = tls_level(TLS_POLICIES, name)
        facts, settings = (facts + [f"tls-min {level[0]}", f"tls-profile {level[1]}"], settings) if level \
            else (facts, settings + [f"ssl_policy {name}"])
    checks = _by_id(found, *HEALTH_CHECKS)
    for check in (checks.get(ref_key(h)) for h in backend.get("health_checks") or ()):
        for protocol in ("http", "https"):
            block = first_block((check or {}).get(f"{protocol}_health_check"))
            facts += [f"health {protocol} {block.get('request_path') or '/'}"] if block else []
    affinity = backend.get("session_affinity")
    facts += [f"stickiness cookie {backend.get('affinity_cookie_ttl_sec')}" if backend.get("affinity_cookie_ttl_sec")
              else "stickiness cookie"] if affinity == "GENERATED_COOKIE" else \
        ["stickiness source-ip"] if affinity == "CLIENT_IP" else []
    facts += [f"idle-timeout {backend.get('timeout_sec')}"] if proxy is not None and \
        backend.get("timeout_sec") not in (None, 30, "30") else []
    facts += [f"drain {backend.get('connection_draining_timeout_sec')}"] if \
        backend.get("connection_draining_timeout_sec") not in (None, 0, 300, "0", "300") else []
    return sorted(set(facts)), settings


def _rule_facts(rule):
    """(facts, settings) of one Cloud Armor rule."""
    match, action = first_block(rule.get("match")), rule.get("action") or ""
    expression = first_block(match.get("expr")).get("expression") or ""
    if (rule.get("priority") or 0) >= 2147483647:
        return [], []                                                   # the default rule
    if action in ("throttle", "rate_based_ban"):
        options = first_block(rule.get("rate_limit_options"))
        threshold = first_block(options.get("rate_limit_threshold"))
        key = "ip" if options.get("enforce_on_key") in (None, "", "IP") else \
            f"header:{options.get('enforce_on_key_name')}"
        kind = endpoint_kind_named(rule.get("description"))
        return ([rate_limit_fact(kind, threshold.get("count"), threshold.get("interval_sec"), key)], []) if kind \
            else ([], [f"rate limit rule {rule.get('priority')}: {threshold.get('count')}/"
                       f"{threshold.get('interval_sec')}s per {key}"])
    verdict = "allow" if action == "allow" else "deny"
    ranges = first_block(match.get("config")).get("src_ip_ranges") or ()
    if match.get("versioned_expr") == "SRC_IPS_V1" and ranges:
        return [f"ip-rule {verdict} {r}" for r in ranges], []
    codes = _REGION_CODE.findall(expression)
    if codes:
        return [f"geo-rule {'allow' if expression.startswith('!') else 'deny'} {' '.join(codes)}"], []
    rule_sets = _PRECONFIGURED.findall(expression)
    if rule_sets:
        known = [CATEGORIES[r] for r in rule_sets if r in CATEGORIES]
        return [f"waf-category {c}" for c in known], [f"preconfigured {r}" for r in rule_sets if r not in CATEGORIES]
    return [], [f"rule {rule.get('priority')}: {expression or action}"]


def edge_services(found, served):
    """Cloud Armor policies, Cloud CDN and advanced network DDoS protection in front of the services; served:
    {backend service identity: the service's forwarding rule ref}."""
    policies = _by_id(found, *SECURITY_POLICIES)
    rules = of_types(found, *SECURITY_RULES)
    used = {ref_key(b.get("security_policy")): served.get(key) for key, b in _by_id(found, *BACKENDS).items()
            if b.get("security_policy") and served.get(key)}

    def armor(key, policy):
        own = [r for r in rules if ref_key(r.get("security_policy")) in (key, ref_key(policy.get("name")))] + \
            list(blocks(policy.get("rule")))
        parts = [_rule_facts(r) for r in own]
        counted = [r for r in own if (r.get("priority") or 0) < 2147483647]
        mode = "detect" if counted and all(r.get("preview") for r in counted) else "block"
        return resource("edge", policy.get("id"), {
            "ciamEdgeKind": "waf", "ciamEdgeFact": sorted({f"waf-mode {mode}", *(f for fs, _ in parts for f in fs)}),
            "ciamEdgeSetting": sorted({s for _, ss in parts for s in ss})},
            links={"ciamServiceRole": used.get(key)}, name=policy.get("name"), role=_role(policy))
    armored = {k: p for k, p in policies.items()
               if p.get("type") in (None, "", "CLOUD_ARMOR") and k == ref_key(p.get("id"))}
    adaptive = {k: used.get(k) for k, p in armored.items()
                if first_block(first_block(p.get("adaptive_protection_config")).get("layer_7_ddos_defense_config"))
                .get("enable")}
    return (*(armor(k, p) for k, p in armored.items()),
            *(resource("edge", f"{k}#adaptive", {"ciamEdgeKind": "ddos", "ciamEdgeFact": "ddos application-advanced"},
                       links={"ciamServiceRole": service}, name=f"{policies[k].get('name')}-adaptive")
              for k, service in adaptive.items()),
            *(resource("edge", f"{ref_key(b.get('id'))}#cdn", {
                "ciamEdgeKind": "cdn", "ciamEdgeFact": "cdn on",
                "ciamEdgeSetting": f"cache_mode {first_block(b.get('cdn_policy')).get('cache_mode')}"},
                links={"ciamServiceRole": served.get(ref_key(b.get("id")))}, name=f"{b.get('name')}-cdn")
              for b in of_types(found, *BACKENDS) if b.get("enable_cdn")),
            *(resource("edge", p.get("id"), {"ciamEdgeKind": "ddos", "ciamEdgeFact": "ddos network-advanced"},
                       name=p.get("name"), role=_role(p))
              for p in of_types(found, *SECURITY_POLICIES) if p.get("type") == "CLOUD_ARMOR_NETWORK"
              and first_block(p.get("ddos_protection_config")).get("ddos_protection") == "ADVANCED"))


def _unquoted(record_type, v):
    return v.strip('"').replace('\\"', '"') if record_type == "TXT" else v


def service_dns(found, ip):
    """({TTL and routing of the record set answering for an address}, the record set or None, other answers)."""
    for r in of_types(found, "google_dns_record_set"):
        items = [first_block(p) for p in blocks(first_block(r.get("routing_policy")).get("wrr"))]
        if ip in (r.get("rrdatas") or ()):
            return {"ciamTtlSeconds": r.get("ttl")}, r, ()
        own = next((i for i in items if ip in (i.get("rrdatas") or ())), None)
        if own is not None:
            return ({"ciamTtlSeconds": r.get("ttl"), "ciamRoutingPolicy": "weighted",
                     "ciamRoutingWeight": int(float(own.get("weight") or 1))}, r,
                    tuple(a for i in items if i is not own for a in i.get("rrdatas") or ()))
    return {}, None, ()


def dns_resources(found, served):
    """(zones, records, forwarders): served are the record sets answering for service names (by identity)."""
    zones = {z.get("name"): (z.get("dns_name") or "").rstrip(".") for z in of_types(found, "google_dns_managed_zone")}
    forwarding = [z for z in of_types(found, "google_dns_managed_zone") if blocks(z.get("forwarding_config"))]
    return (tuple(resource("zone", z.get("id") or z.get("name"), {
                "ciamDnsZone": zones[z.get("name")], "ciamProviderRef": z.get("name"),
                "ciamZoneVisibility": "private" if z.get("visibility") == "private" else "public"},
                name=z.get("name"), role=_role(z) or zone_role(zones[z.get("name")]))
                  for z in of_types(found, "google_dns_managed_zone") if z.get("name") and z not in forwarding),
            tuple(resource("record", r.get("id") or f"{r.get('name')}/{r.get('type')}", {
                "ciamRecordName": (r.get("name") or "").rstrip("."), "ciamRecordType": r.get("type"),
                "ciamTtlSeconds": r.get("ttl"), "ciamDnsZone": zones.get(r.get("managed_zone")),
                "ciamRecordValue": [_unquoted(r.get("type"), v) for v in r.get("rrdatas") or ()]},
                name=f"{r.get('type')}-{(r.get('name') or '').rstrip('.')}".lower(),
                role=record_role((r.get("name") or "").rstrip("."), r.get("type")))
                  for r in of_types(found, "google_dns_record_set") if id(r) not in served and r.get("name")),
            tuple(resource("forwarder", z.get("id") or z.get("name"), {
                "ciamForwardDomain": zones[z.get("name")], "ciamForwardDirection": "outbound",
                "ciamForwardTarget": [t.get("ipv4_address") for t in blocks(
                    first_block(z.get("forwarding_config")).get("target_name_servers"))],
                "ciamProviderRef": z.get("name")}, name=z.get("name"),
                role=_role(z) or forwarder_role((zones[z.get("name")],)))
                  for z in forwarding))


def proxy_subnets(found):
    """The proxy-only subnets' ranges: rules admitting only them belong to load balancers."""
    return {s.get("ip_cidr_range") for s in of_types(found, "google_compute_subnetwork")
            if s.get("purpose") in ("REGIONAL_MANAGED_PROXY", "INTERNAL_HTTPS_LOAD_BALANCER")
            and s.get("ip_cidr_range")}
