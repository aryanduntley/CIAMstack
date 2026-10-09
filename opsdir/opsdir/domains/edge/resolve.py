"""A service name's edge as a renderer needs it: its traffic and protection policies with the defaults filled in, the
paths of the endpoints its products serve (declared by the product adapters, moved by the policies), its rate limits
and exclusions aimed at those paths, and the certificate its listener presents in the environment. What the three cloud
renderers agree on, so each only maps it to its own resources. Pure.

A service whose role no policy names has no edge spec: its cloud renders it as before (a layer 4 load balancer). Paths
are written as globs ('*' for one or more path segments) and given to clouds as regular expressions.
"""
import re
from collections import namedtuple

from ...core.directory import one, values
from ...core.environment import of_class
from .naming import ENDPOINT_KINDS, LAYER7
from .policies import endpoint_paths, policy_for

Health = namedtuple("Health", ("protocol", "path", "interval", "healthy", "unhealthy"))
RateLimit = namedtuple("RateLimit", ("kind", "requests", "seconds", "key", "paths"))   # key: ip | header:<Name>
Exclusion = namedtuple("Exclusion", ("category", "kind", "part", "name", "paths"))     # part: body|query|header|cookie
EdgeSpec = namedtuple("EdgeSpec", (
    "role", "mode", "layer7", "tls_min", "tls_profile", "backend_validation", "health", "stickiness",
    "stickiness_seconds", "idle_timeout", "drain", "waf_mode", "categories", "rate_limits", "ip_rules", "geo_rules",
    "exclusions", "ddos", "cdn", "endpoints", "certificate", "traffic", "protection"))

_RATE = re.compile(r"^(\S+) (\d+)/(\d+)s per (\S+)$")
_EXCLUSION = re.compile(r"^(\S+) on (\S+) (body|query|header|cookie):(\S+)$")


def path_regex(glob):
    """A path glob ('/am/json/realms/*/authenticate') as an anchored regular expression; '*' is one or more path
    segments."""
    return "^" + re.escape(glob).replace(r"\*", "[^?#]+") + "$"


def declared_endpoints(endpoints, server_role, *policies):
    """{endpoint kind: (paths, ...)} for the servers of a role: the declared Endpoints, each kind replaced where the
    policies place it elsewhere."""
    declared = {}
    for e in (e for e in endpoints if e.server_role == server_role):
        declared.setdefault(e.kind, ())
        declared[e.kind] += (e.path,)
    return {**declared, **endpoint_paths(*policies)}


def certificate_ref(m, svc):
    """The reference (ciamRefUri) of the certificate store entry holding the certificate a service name presents in
    environment m, or None."""
    cert = one(svc, "ciamTlsCertificate")
    held = (r for r in of_class(m, "ciamCertificateRef") if cert and one(r, "ciamHoldsCertificate") == cert)
    return next((one(r, "ciamRefUri") for r in held), None)


def _one(e, attr, default=None):
    """An attribute of a policy that may be missing (None), or the default."""
    return (one(e, attr) if e is not None else None) or default


def _many(e, attr):
    return values(e, attr) if e is not None else ()


def _int(e, attr):
    v = _one(e, attr)
    return int(v) if v is not None else None


def _health(t, mode, paths):
    """The health check: the policy's, else the product's declared health endpoint over the protocol the edge speaks
    to the servers, else a TCP connect."""
    declared = (paths.get("health") or (None,))[0]
    protocol = _one(t, "ciamHealthProtocol") or \
        ({"reencrypt": "https", "terminate": "http"}.get(mode) if declared else None) or "tcp"
    path = (_one(t, "ciamHealthPath") or declared or "/") if protocol != "tcp" else None
    return Health(protocol, path, _int(t, "ciamHealthIntervalSeconds"), _int(t, "ciamHealthyThreshold"),
                  _int(t, "ciamUnhealthyThreshold"))


def service_edge(m, svc, endpoints):
    """The EdgeSpec of a service name in environment m (endpoints: the installed adapters' Endpoints), or None when no
    policy names its role."""
    d, role = m.d, one(svc, "ciamBindingRole")
    t, p = policy_for(d, "ciamTrafficPolicy", role), policy_for(d, "ciamProtectionPolicy", role)
    return None if t is None and p is None else _edge(m, svc, endpoints, t, p, _one(t, "ciamTlsMode", "passthrough"))


def front_edge(m, svc, endpoints):
    """The EdgeSpec of the cloud front before a cluster's in-cluster gateway (edge.gateways): the service name's
    policies, terminating TLS when they pass it through or there are none (the gateway routes HTTP by host and path, so
    the front is layer 7 whatever the policy; the planner names a passthrough policy that can't be kept)."""
    d, role = m.d, one(svc, "ciamBindingRole")
    t, p = policy_for(d, "ciamTrafficPolicy", role), policy_for(d, "ciamProtectionPolicy", role)
    mode = _one(t, "ciamTlsMode", "terminate")
    return _edge(m, svc, endpoints, t, p, mode if mode in LAYER7 else "terminate")


def _edge(m, svc, endpoints, t, p, mode):
    role = one(svc, "ciamBindingRole")
    paths = declared_endpoints(endpoints, one(svc, "ciamTargetRole"), t, p)
    rates = tuple(RateLimit(k, int(n), int(s), key, paths.get(k, ()))
                  for k, n, s, key in (_RATE.match(v).groups() for v in _many(p, "ciamRateLimit")))
    exclusions = tuple(Exclusion(c, k, part, name, paths.get(k, ()))
                       for c, k, part, name in (_EXCLUSION.match(v).groups() for v in _many(p, "ciamWafExclusion")))
    return EdgeSpec(
        role=role, mode=mode, layer7=mode in LAYER7, tls_min=_one(t, "ciamTlsMinVersion", "1.2"),
        tls_profile=_one(t, "ciamTlsProfile", "intermediate"),
        backend_validation=_one(t, "ciamBackendValidation", "none"), health=_health(t, mode, paths),
        stickiness=_one(t, "ciamStickiness", "none"), stickiness_seconds=_int(t, "ciamStickinessSeconds"),
        idle_timeout=_int(t, "ciamIdleTimeoutSeconds"), drain=_int(t, "ciamDrainSeconds"),
        waf_mode=_one(p, "ciamWafMode"), categories=tuple(_many(p, "ciamWafCategory")), rate_limits=rates,
        ip_rules=tuple(tuple(v.split(" ", 1)) for v in _many(p, "ciamIpRule")),
        geo_rules=tuple((a, tuple(cs.split())) for a, cs in (v.split(" ", 1) for v in _many(p, "ciamGeoRule"))),
        exclusions=exclusions, ddos=_one(p, "ciamDdosTier", "standard"), cdn=_one(p, "ciamCdn") == "TRUE",
        endpoints=paths, certificate=certificate_ref(m, svc), traffic=t, protection=p)


def inspected(spec):
    """Whether a spec asks for anything only a layer 7 hop can do (a firewall, rate limits, address or country
    rules)."""
    return bool(spec.waf_mode or spec.categories or spec.rate_limits or spec.ip_rules or spec.geo_rules)


# A cloud's TLS policies: ((min version, profile, policy name, exact), ...), the policy its renderer uses for each pair
# of the intent's terms and whether it means exactly that; read back, a policy name means the pair of its first row.
def tls_policy(table, version, profile):
    """(policy name, exact) a cloud renders for a TLS minimum version and profile."""
    return next((name, exact) for v, p, name, exact in table if (v, p) == (version, profile))


def tls_level(table, name):
    """(min version, profile) a cloud's TLS policy name stands for, or None when the table doesn't know it."""
    return next(((v, p) for v, p, n, _ in table if n == name), None)


def rate_limit_fact(kind, requests, seconds, key):
    """A rate limit read back as an edge fact ('rate-limit token 100/300s per ip')."""
    return f"rate-limit {kind} {requests}/{seconds}s per {key}"


def endpoint_kind_named(rule_name):
    """The endpoint kind a rate-limit rule the renderers wrote is named for ('rate-token', 'ratepasswordreset'), or
    None for a rule someone else named."""
    plain = re.sub(r"[^a-z]", "", (rule_name or "").lower())
    return next((k for k in ENDPOINT_KINDS if plain == "rate" + k.replace("-", "")), None)
