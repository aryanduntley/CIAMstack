"""Google Cloud edge: what the edge domain's terms mean on Google Cloud, and the Terraform for a service whose policies
ask for more than a TCP passthrough. A service name whose TLS terminates at the edge is a regional Application Load
Balancer (external or internal managed, beside the proxy-only subnet the environment binds to role subnet-edge): a
forwarding rule to a target HTTPS proxy with the TLS policy (an SSL policy) and the Certificate Manager certificate the
environment holds, a URL map, a backend service over HTTP or HTTPS with the policy's health check, session affinity,
timeout and draining, and the firewall rules admitting the proxies and the health checks (policy rules under the
policy firewall model). Its protection policy is a Cloud Armor policy on the backend service: preconfigured WAF rules,
rate limits aimed at the products' endpoints, address and country rules, exclusions. Advanced network DDoS protection
is a network policy with an edge security service. Pure.

Known limits: a preconfigured rule's exclusions apply to every path; IP reputation needs Cloud Armor Enterprise's
threat intelligence; bot management needs reCAPTCHA keys; account takeover and account creation fraud have no
preconfigured rules; Adaptive Protection is for global backend services.
"""
from collections import namedtuple

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import by_role
from opsdir.core.network import is_private
from opsdir.domains.edge.resolve import inspected, path_regex, tls_policy
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .health_checks import probe_ranges
from .names import NETWORK, REGION, label, network_tag

EDGE_SUBNET = "subnet-edge"           # the proxy-only subnet (purpose REGIONAL_MANAGED_PROXY) the proxies run in
# (min version, profile, SSL policy "profile/min_tls_version", exact)
TLS_POLICIES = tuple((v, p, f"{profile}/TLS_{v.replace('.', '_')}", True)
                     for v in ("1.3", "1.2") for p, profile in (("modern", "RESTRICTED"), ("intermediate", "MODERN"),
                                                               ("compatible", "COMPATIBLE")))
# WAF category -> preconfigured WAF rule sets (one Cloud Armor rule each); () when Cloud Armor has none to render
WAF_RULES = {"core-rules": ("sqli-v33-stable", "xss-v33-stable", "lfi-v33-stable", "rfi-v33-stable", "rce-v33-stable",
                            "methodenforcement-v33-stable", "scannerdetection-v33-stable", "protocolattack-v33-stable",
                            "sessionfixation-v33-stable"),
             "known-bad-inputs": ("cve-canary", "java-v33-stable"),
             "ip-reputation": (), "bot-control": (), "account-takeover": (), "account-creation-fraud": ()}
_NOT_RENDERED = {"ip-reputation": "needs Cloud Armor Enterprise threat intelligence",
                 "bot-control": "needs reCAPTCHA keys (bot management)",
                 "account-takeover": "has no preconfigured rule", "account-creation-fraud": "has no preconfigured rule"}
INTERVALS = (10, 30, 60, 120, 180, 240, 300, 600, 900, 1200, 1800, 2700, 3600)   # rate limit intervals, seconds
_EXCLUDED = {"header": "request_header", "cookie": "request_cookie", "query": "request_query_param",
             "body": "request_query_param"}          # form fields in a POST body are inspected as query parameters


def rate(requests, seconds):
    """(count, interval) for a rate limit: the first interval Cloud Armor allows at or above the seconds, the
    requests scaled to it (rounded up)."""
    interval = next((i for i in INTERVALS if i >= seconds), INTERVALS[-1])
    return -(-requests * interval // seconds), interval


def _kind(world, name):
    """A resource type at a scope: global (world) or regional."""
    return f"google_compute_{'' if world else 'region_'}{name}"


def _where(world):
    return () if world else (("region", REGION),)


def _rule(n, policy, priority, action, match, spec, extra=(), world=False):
    return block("resource", [_kind(world, "security_policy_rule"), f"{n}_{priority}"], [
        *_where(world), ("security_policy", ref(f"{_kind(world, 'security_policy')}.{policy}.name")),
        ("priority", priority), ("action", action), ("match", match),
        *((("preview", True),) if spec.waf_mode == "detect" else ()), *extra])


def _expr(expression):
    return Block((("expr", Block((("expression", expression),))),))


def _exclusions(spec, category, rule_set):
    """The preconfigured_waf_config of one rule set's rule: the fields its category's exclusions name."""
    excluded = [x for x in spec.exclusions if x.category == category]
    if not excluded:
        return ()
    return (("#", "exclusions apply on every path, not only the endpoint kind named"),
            ("preconfigured_waf_config", Block(tuple(("exclusion", Block((
                ("target_rule_set", rule_set),
                (_EXCLUDED[x.part], Block((("operator", "EQUALS"), ("value", x.name))))))) for x in excluded))))


def armor(m, n, spec, world=False):
    """The Cloud Armor policy a protection policy asks for (the backend service names it) and its rules: regional, or
    global (world) for a global load balancer, where application-advanced DDoS protection turns on Adaptive
    Protection."""
    rules, priority = [], 1000
    for action, cidr in spec.ip_rules:
        rules.append(("allow" if action == "allow" else "deny(403)",
                      Block((("versioned_expr", "SRC_IPS_V1"), ("config", Block((("src_ip_ranges", [cidr]),))))), ()))
    for action, codes in spec.geo_rules:
        expression = " || ".join(f"origin.region_code == '{c}'" for c in codes)
        rules.append(("deny(403)", _expr(expression if action == "deny" else f"!({expression})"), ()))
    for r in spec.rate_limits:
        count, interval = rate(r.requests, r.seconds)
        paths = " || ".join(f"request.path.matches('{path_regex(p)}')" for p in r.paths) or "true"
        key = (("enforce_on_key", "IP"),) if r.key == "ip" else \
            (("enforce_on_key", "HTTP_HEADER"), ("enforce_on_key_name", r.key.split(":", 1)[1]))
        rules.append(("throttle", _expr(paths), (("description", f"rate-{r.kind}"), ("rate_limit_options", Block((
            ("conform_action", "allow"), ("exceed_action", "deny(429)"), *key,
            ("rate_limit_threshold", Block((("count", count), ("interval_sec", interval))))))),)))
    for c in spec.categories:
        for rule_set in WAF_RULES.get(c, ()):
            rules.append(("deny(403)", _expr(f"evaluatePreconfiguredWaf('{rule_set}')"),
                          _exclusions(spec, c, rule_set)))
    missing = [f"{c} {_NOT_RENDERED[c]}" for c in spec.categories if not WAF_RULES.get(c)]
    return (*(f"# not rendered: {x}" for x in missing),
            block("resource", [_kind(world, "security_policy"), n], [
                ("name", f"ciam-{rdn_value(m.env)}-{n}"), *_where(world), ("type", "CLOUD_ARMOR"),
                *((("adaptive_protection_config", Block((("layer_7_ddos_defense_config",
                                                          Block((("enable", True),))),))),)
                  if world and spec.ddos == "application-advanced" else ())]),
            *(_rule(n, n, priority + 10 * i, action, match, spec, extra, world)
              for i, (action, match, extra) in enumerate(rules)))


def network_ddos(m, n, spec):
    """Advanced network DDoS protection for a passthrough service's external address, when the policy asks for it."""
    if spec.ddos == "standard":
        return ()
    return (block("resource", ["google_compute_region_security_policy", f"{n}_network"], [
                ("#", "Cloud Armor Enterprise: advanced network DDoS protection"),
                ("name", f"ciam-{rdn_value(m.env)}-{n}-network"), ("region", REGION), ("type", "CLOUD_ARMOR_NETWORK"),
                ("ddos_protection_config", Block((("ddos_protection", "ADVANCED"),)))]),
            block("resource", ["google_compute_network_edge_security_service", n], [
                ("name", f"ciam-{rdn_value(m.env)}-{n}"), ("region", REGION),
                ("security_policy", ref(f"google_compute_region_security_policy.{n}_network.self_link"))]))


def _health_check(n, name, spec, port, world=False, host=None):
    h = spec.health
    protocol = h.protocol if h.protocol != "tcp" else ("http" if spec.mode == "terminate" else "https")
    return block("resource", [_kind(world, "health_check"), n], [
        ("name", name), *_where(world),
        *((("check_interval_sec", h.interval),) if h.interval else ()),
        *((("healthy_threshold", h.healthy),) if h.healthy else ()),
        *((("unhealthy_threshold", h.unhealthy),) if h.unhealthy else ()),
        (f"{protocol}_health_check", Block((("port", int(port)), *((("host", host),) if host else ()),
                                            ("request_path", h.path or "/"))))])


def _affinity(spec):
    if spec.stickiness == "cookie":
        return (("session_affinity", "GENERATED_COOKIE"),
                *((("affinity_cookie_ttl_sec", spec.stickiness_seconds),) if spec.stickiness_seconds else ()))
    return (("session_affinity", "CLIENT_IP"),) if spec.stickiness == "source-ip" else ()


# Where an Application Load Balancer sends a service name's traffic: backends, its backend service's ("backend",
# Block) entries; port_name, the named port it uses (None for endpoints that carry their port); port, the port the
# backends listen on (None: the service name's own); target, what the VPC firewall rules admitting the proxies and
# health checks apply to (("target_tags", [...]),), host the Host header its health checks send (None: none). The
# servers of the service's role, or a cluster's gateway.
Backend = namedtuple("Backend", ("backends", "port_name", "port", "target", "host"), defaults=(None,))


def servers_backend(m, svc, groups):
    """The Backend of a service name's servers: their instance groups (terraform names, named port "ciam"), reached
    by the role's network tag."""
    return Backend(tuple(("backend", Block((("group", ref(f"google_compute_instance_group.{g}.self_link")),
                                            ("balancing_mode", "UTILIZATION"), ("capacity_scaler", 1.0))))
                         for g in groups),
                   "ciam", None, (("target_tags", [network_tag(m, one(svc, "ciamTargetRole"))]),))


def _firewall(m, svc, n, name, port, proxies, backend, admit=None):
    """The rules admitting the proxies (the proxy-only subnet; none for a global load balancer, whose front ends
    connect from the health-check ranges) and the health checks to the backend: VPC firewall rules on its target, or
    the rules admit builds (a firewall policy's, by secure tag: firewall_policy.health_check_rule)."""
    if admit is not None:
        return (*((admit(m, svc, n, (proxies,), port, "proxies"),) if proxies else ()),
                admit(m, svc, n, probe_ranges("MANAGED"), port))
    return (*((block("resource", ["google_compute_firewall", f"{n}_proxies"], [
                ("name", f"{name}-proxies"), ("description", f"Load balancer proxies for {rdn_value(svc)}"),
                ("network", NETWORK), ("direction", "INGRESS"),
                ("allow", Block((("protocol", "tcp"), ("ports", [port])))),
                ("source_ranges", [proxies]), *backend.target]),) if proxies else ()),
            block("resource", ["google_compute_firewall", f"{n}_health_checks"], [
                ("name", f"{name}-health-checks"), ("description", f"Google Cloud health checks for {rdn_value(svc)}"),
                ("network", NETWORK), ("direction", "INGRESS"),
                ("allow", Block((("protocol", "tcp"), ("ports", [port])))),
                ("source_ranges", list(probe_ranges("MANAGED"))), *backend.target]))


def _global_address(svc, n, ip):
    """(data sources, address) of a global load balancer: the reserved global address the service's provider ref
    names, else its frontend address."""
    if not one(svc, "ciamProviderRef"):
        return (), ip
    return ((block("data", ["google_compute_global_address", n], [("name", one(svc, "ciamProviderRef"))]),),
            ref(f"data.google_compute_global_address.{n}.address"))


def application_lb(m, svc, spec, backend, frontend, placement, admit=None):
    """An Application Load Balancer for a service name whose TLS terminates at the edge, and the Cloud Armor policy its
    protection policy asks for: regional, beside the proxy-only subnet; global when a CDN fronts it (Cloud CDN is the
    global load balancer's), with the CDN on its backend service. backend: where it sends traffic (its servers' instance
    groups, or a cluster's gateway); frontend: (data sources, address) of a regional one; placement: the regional
    forwarding rule's subnetwork when internal; admit: what builds the rules admitting the proxies and probes when they
    aren't VPC firewall rules (m, svc, n, ranges, port[, kind] -> rule)."""
    n, name = tf_name(rdn_value(svc)), f"ciam-{rdn_value(m.env)}-{rdn_value(svc)}"
    ip, port = one(svc, "ciamFrontendIp"), values(svc, "ciamPort")[0]
    internal = bool(ip) and is_private(ip)
    world = spec.cdn
    if world and internal:
        return (f"# `{one(svc, 'ciamFqdn')}`: Cloud CDN serves external load balancers only; its frontend address "
                "is private",)
    scheme = "INTERNAL_MANAGED" if internal else "EXTERNAL_MANAGED"
    edge = by_role(m, EDGE_SUBNET)
    if not edge and not world:
        return (f"# UNBOUND: `{one(svc, 'ciamFqdn')}` terminates TLS at an Application Load Balancer, which needs a "
                f"proxy-only subnet: bind role {EDGE_SUBNET} in this environment",)
    profile, version = tls_policy(TLS_POLICIES, spec.tls_min, spec.tls_profile)[0].split("/")
    cert = spec.certificate.split("://", 1)[1] if (spec.certificate or "").startswith("gcp-cert://") else None
    data, address = _global_address(svc, n, ip) if world else frontend
    waf = inspected(spec)
    kind = (lambda what: _kind(world, what))
    forwarding = (block("resource", ["google_compute_global_forwarding_rule", n], [
                      ("name", name), ("load_balancing_scheme", scheme), ("ip_protocol", "TCP"),
                      ("port_range", str(port)), ("ip_address", address),
                      ("target", ref(f"google_compute_target_https_proxy.{n}.id")),
                      ("labels", {"service": label(one(svc, "ciamFqdn")), "managed_by": "opsdir"})])
                  if world else
                  block("resource", ["google_compute_forwarding_rule", n], [
                      ("name", name), ("region", REGION), ("load_balancing_scheme", scheme), ("ip_protocol", "TCP"),
                      ("port_range", str(port)), ("ip_address", address), ("network", NETWORK),
                      *((("network_tier", "STANDARD"),) if not internal else ()), *placement,
                      ("target", ref(f"google_compute_region_target_https_proxy.{n}.id")),
                      ("labels", {"service": label(one(svc, "ciamFqdn")), "managed_by": "opsdir"})]))
    return (*data,
            block("resource", [kind("ssl_policy"), n], [
                ("name", name), *_where(world), ("profile", profile), ("min_tls_version", version)]),
            _health_check(n, name, spec, backend.port or port, world, backend.host),
            *_firewall(m, svc, n, name, backend.port or port, None if world else one(edge[0], "ciamCidr"), backend,
                       admit),
            *(armor(m, n, spec, world) if waf else ()),
            block("resource", [kind("backend_service"), n], [
                ("name", name), *_where(world), ("load_balancing_scheme", scheme),
                ("protocol", "HTTP" if spec.mode == "terminate" else "HTTPS"),
                *((("port_name", backend.port_name),) if backend.port_name else ()),
                ("health_checks", [ref(f"{kind('health_check')}.{n}.id")]),
                *_affinity(spec),
                *((("timeout_sec", spec.idle_timeout),) if spec.idle_timeout else ()),
                *((("connection_draining_timeout_sec", spec.drain),) if spec.drain is not None else ()),
                *((("enable_cdn", True),
                   ("#", "the origin's Cache-Control decides: sign-in pages and tokens send no-store"),
                   ("cdn_policy", Block((("cache_mode", "USE_ORIGIN_HEADERS"),)))) if world else ()),
                *((("security_policy", ref(f"{kind('security_policy')}.{n}.self_link")),) if waf else ()),
                *backend.backends]),
            block("resource", [kind("url_map"), n], [
                ("name", name), *_where(world), ("default_service", ref(f"{kind('backend_service')}.{n}.id"))]),
            block("resource", [kind("target_https_proxy"), n], [
                ("name", name), *_where(world), ("url_map", ref(f"{kind('url_map')}.{n}.id")),
                *((("certificate_manager_certificates", [cert]),) if cert else
                  (("#", "UNBOUND: no Certificate Manager certificate holds this service's certificate here"),)),
                ("ssl_policy", ref(f"{kind('ssl_policy')}.{n}.id"))]),
            forwarding)
