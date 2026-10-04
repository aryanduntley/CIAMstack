"""Traffic and protection policies: how traffic reaches the servers behind each service name and what protects it, the
same in every environment. A policy names the binding roles of the service names it applies to. Read here as the
facts an environment should run ('<key> <value>', the terms the cloud importers read an edge back in), so intent and
what runs compare without knowing any cloud. The report and the intent's own consistency check. Pure.

Inspecting requests (web application firewall rules, rate limits, address and country rules) needs a layer 7 hop: a
load balancer that terminates TLS, or a CDN in front. A policy that asks for them on a service whose TLS passes
through, with no CDN, can't be rendered as stated.
"""
from ...core.directory import children, one, rdn_value, values
from ...core.findings import findings, responsible
from .naming import EDGE_POLICIES, LAYER7

POLICY_HEADERS = ("service role", "traffic policy", "tls", "backend validation", "health", "stickiness",
                  "protection policy", "waf", "rate limits", "ddos", "cdn")
_KIND = {"ciamTrafficPolicy": "traffic", "ciamProtectionPolicy": "protection"}
_LAYER7_ONLY = ("ciamWafMode", "ciamWafCategory", "ciamRateLimit", "ciamIpRule", "ciamGeoRule", "ciamWafExclusion")


def policies(d, oc):
    """Every policy of a class (ciamTrafficPolicy, ciamProtectionPolicy), by name."""
    return sorted(children(d, EDGE_POLICIES, oc), key=rdn_value)


def policy_for(d, oc, role):
    """The first policy of a class (by name) that applies to the service names of a binding role, or None."""
    return next((p for p in policies(d, oc) if role in values(p, "ciamServiceRole")), None)


def service_roles(d):
    """Every binding role some policy applies to, sorted."""
    return sorted({r for oc in _KIND for p in policies(d, oc)
                   for r in values(p, "ciamServiceRole")})


def endpoint_paths(*entries):
    """{endpoint kind: (paths, ...)} the entries (policies) place elsewhere than their products declare."""
    found = {}
    for e in (e for e in entries if e is not None):
        for kind, path in (v.split(" ", 1) for v in values(e, "ciamEndpointPath")):
            found.setdefault(kind, ())
            found[kind] += (path,)
    return found


def _health(t):
    proto = one(t, "ciamHealthProtocol")
    return " ".join(x for x in (proto, one(t, "ciamHealthPath") if proto != "tcp" else None) if x) if proto else None


def _stickiness(t):
    kind = one(t, "ciamStickiness")
    return " ".join(x for x in (kind, one(t, "ciamStickinessSeconds") if kind != "none" else None) if x) \
        if kind else None


def intended_facts(traffic, protection):
    """The facts ('<key> <value>') a service's traffic and protection policies (either may be None) ask the edge to
    run, as a frozenset."""
    t, p = traffic, protection
    single = (("tls-mode", t, "ciamTlsMode"), ("tls-min", t, "ciamTlsMinVersion"), ("tls-profile", t, "ciamTlsProfile"),
              ("backend-validation", t, "ciamBackendValidation"), ("idle-timeout", t, "ciamIdleTimeoutSeconds"),
              ("drain", t, "ciamDrainSeconds"), ("waf-mode", p, "ciamWafMode"), ("ddos", p, "ciamDdosTier"))
    many = (("waf-category", "ciamWafCategory"), ("rate-limit", "ciamRateLimit"), ("ip-rule", "ciamIpRule"),
            ("geo-rule", "ciamGeoRule"))
    derived = (("health", _health(t) if t is not None else None),
               ("stickiness", _stickiness(t) if t is not None else None),
               ("cdn", "on" if p is not None and one(p, "ciamCdn") == "TRUE" else None))
    return frozenset((*(f"{key} {one(e, attr)}" for key, e, attr in single if e is not None and one(e, attr)),
                      *(f"{key} {v}" for key, attr in many if p is not None for v in values(p, attr)),
                      *(f"{key} {v}" for key, v in derived if v)))


def inspects(traffic, protection):
    """Whether the edge of a service can inspect requests: its load balancer terminates TLS, or a CDN fronts it."""
    return (traffic is not None and one(traffic, "ciamTlsMode") in LAYER7) or \
        (protection is not None and one(protection, "ciamCdn") == "TRUE")


def policy_rows(d, dn=None):
    """One row per service role a policy applies to: its traffic and protection policies in brief."""
    def row(role):
        t, p = policy_for(d, "ciamTrafficPolicy", role), policy_for(d, "ciamProtectionPolicy", role)
        get = (lambda e, attr: (one(e, attr) or "") if e is not None else "")
        tls = " ".join(x for x in (get(t, "ciamTlsMode"), get(t, "ciamTlsMinVersion") and
                                   f"≥{get(t, 'ciamTlsMinVersion')}", get(t, "ciamTlsProfile")) if x)
        waf = " ".join(x for x in (get(p, "ciamWafMode"),
                                   ", ".join(values(p, "ciamWafCategory")) if p is not None else "") if x)
        return (role, rdn_value(t) if t is not None else "", tls, get(t, "ciamBackendValidation"),
                (_health(t) or "") if t is not None else "", (_stickiness(t) or "") if t is not None else "",
                rdn_value(p) if p is not None else "", waf,
                "; ".join(values(p, "ciamRateLimit")) if p is not None else "", get(p, "ciamDdosTier"),
                "on" if get(p, "ciamCdn") == "TRUE" else "")
    return [row(r) for r in service_roles(d)]


def check_policies(ctx):
    """Policies that can't be rendered as stated: request inspection where nothing inspects requests, and service
    roles two policies of one kind claim. Intent, so the same in both environments: actions."""
    d = ctx.d
    claimed = {}
    for oc in _KIND:
        for p in policies(d, oc):
            for role in values(p, "ciamServiceRole"):
                claimed.setdefault((oc, role), []).append(rdn_value(p))
    blind = [(role, p) for role in service_roles(d)
             for p in (policy_for(d, "ciamProtectionPolicy", role),)
             if p is not None and any(values(p, a) for a in _LAYER7_ONLY)
             and not inspects(policy_for(d, "ciamTrafficPolicy", role), p)]
    return findings(actions=[
        *(("Edge", f"Protection policy `{rdn_value(p)}` asks for request inspection (firewall rules, rate limits, "
           f"address or country rules) on `{role}`, whose TLS passes through to the servers and which no CDN fronts: "
           "terminate TLS at its load balancer (a traffic policy with tls mode terminate or reencrypt), or put a CDN "
           "in front.", responsible(d, p), None) for role, p in blind),
        *(("Edge", f"Service role `{role}` has several {_KIND[oc]} policies ({', '.join(names)}); `{names[0]}` "
           "applies: keep one.", responsible(d, *(p for p in policies(d, oc) if rdn_value(p) in names)), None)
          for (oc, role), names in sorted(claimed.items()) if len(names) > 1)])

