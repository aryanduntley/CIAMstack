"""What each environment's edge runs, against what the policies ask. The cloud importers read a service's load balancer
(on its service name binding) and the firewalls, CDNs and DDoS protection in front of it (edge service bindings) back as
facts in the policies' terms ('<key> <value>'). The report and the planner's check. Pure.

The target is rendered from the intent, so whatever the source runs that the intent doesn't state is lost in the move:
a stronger TLS minimum, a firewall rule category, a rate limit, DDoS protection. Each is an action: state it in a
policy, or accept dropping it. A source weaker than the intent is fixed by the move; a default the intent doesn't state
(TLS passed through, standard DDoS protection, a TCP health check, no stickiness) is lost by nobody. A target read back
that doesn't run what the intent asks is an action too. An environment nothing was read back from has nothing to
compare.
"""
from ...core.directory import one, rdn_value, subtree, values
from ...core.environment import environment_of, of_class
from ...core.findings import findings, merge_findings, responsible
from ...core.naming import branch, env_label
from .naming import BACKEND_VALIDATION, DDOS_TIERS, TLS_VERSIONS
from .policies import intended_facts, policy_for

EDGE_SERVICE_HEADERS = ("environment", "binding", "kind", "service roles", "runs", "provider ref")
# Facts with an order, weakest first: a value above the intent's is stronger than the intent
RANKED = {"tls-min": TLS_VERSIONS, "tls-profile": ("compatible", "intermediate", "modern"),
          "backend-validation": BACKEND_VALIDATION, "ddos": DDOS_TIERS}
MANY = ("waf-category", "rate-limit", "ip-rule", "geo-rule")     # keys with several values; the rest have one
# What an edge runs when nobody chose otherwise: run without the intent stating it, nothing is lost in a move
DEFAULTS = {"tls-mode": "passthrough", "ddos": "standard", "stickiness": "none", "health": "tcp"}


def fact(text):
    """(key, value) of a fact."""
    key, value = text.split(" ", 1)
    return key, value


def runs_for(m, role):
    """The edge bindings of environment m in front of a service role: its service names, then the edge services
    naming the role."""
    return (*(b for b in of_class(m, "ciamServiceName") if one(b, "ciamBindingRole") == role),
            *(e for e in of_class(m, "ciamEdgeService") if role in values(e, "ciamServiceRole")))


def observed_facts(m, role):
    """What environment m's edge runs in front of a service role, as a frozenset of facts."""
    return frozenset(f for b in runs_for(m, role) for f in values(b, "ciamEdgeFact"))


def observed_roles(m):
    """The service roles environment m records any edge fact for."""
    return {one(b, "ciamBindingRole") for b in of_class(m, "ciamServiceName") if values(b, "ciamEdgeFact")} | \
        {r for e in of_class(m, "ciamEdgeService") if values(e, "ciamEdgeFact") for r in values(e, "ciamServiceRole")}


def _rank(key, value):
    order = RANKED[key]
    return order.index(value) if value in order else -1


def unstated(intended, observed):
    """((fact, intended value or None), ...): what runs that the intent doesn't ask. A key the intent gives one value
    (TLS mode, health check, DDoS tier, ...) is the intent's to change, except a ranked one it lowers; a key with
    several values (firewall categories, rate limits, address and country rules) loses each value it doesn't list."""
    asked = {key: value for key, value in (fact(f) for f in intended) if key not in MANY}
    return tuple(sorted(
        (f, asked.get(key)) for f in observed - intended for key, value in (fact(f),)
        if key in MANY or (key not in asked and DEFAULTS.get(key) != value)
        or (key in asked and key in RANKED and _rank(key, value) > _rank(key, asked[key]))))


def missing(intended, observed):
    """The intended facts an environment read back doesn't run, sorted. A ranked fact it runs stronger counts as
    run."""
    ran = dict(fact(f) for f in observed if fact(f)[0] in RANKED)
    return tuple(sorted(f for f in intended - observed for key, value in (fact(f),)
                        if key not in RANKED or key not in ran or _rank(key, ran[key]) < _rank(key, value)))


def edge_service_rows(d, dn=None):
    """One row per edge binding that records what it runs (load balancers on service names, firewalls, CDNs, DDoS
    protection, gateways, proxies) in every environment."""
    found = [e for oc in ("ciamServiceName", "ciamEdgeService") for e in subtree(d, branch("environments"), oc)
             if oc == "ciamEdgeService" or values(e, "ciamEdgeFact") or values(e, "ciamEdgeSetting")]
    return [(env_label(environment_of(e)), rdn_value(e),
             one(e, "ciamEdgeKind") or "load-balancer",
             ", ".join(values(e, "ciamServiceRole") or values(e, "ciamBindingRole")),
             "; ".join((*values(e, "ciamEdgeFact"), *values(e, "ciamEdgeSetting"))), one(e, "ciamProviderRef") or "")
            for e in sorted(found, key=lambda e: (env_label(environment_of(e)), rdn_value(e)))]


def _role(ctx, role):
    d = ctx.d
    t, p = policy_for(d, "ciamTrafficPolicy", role), policy_for(d, "ciamProtectionPolicy", role)
    intended, src, dst = intended_facts(t, p), observed_facts(ctx.src, role), observed_facts(ctx.dst, role)
    owner = responsible(d, p, t, *runs_for(ctx.src, role), ctx.src.env)
    lost = unstated(intended, src) if src else ()
    absent = missing(intended, dst) if dst else ()
    return findings(
        actions=[*(("Edge", f"{ctx.src.label} runs `{f}` in front of `{role}`, which "
                    + ("no policy states" if asked is None else f"is stronger than the intent's `{fact(f)[0]} {asked}`")
                    + f": {ctx.dst.label} is rendered from the intent and wouldn't. State it in a policy, or accept "
                    "dropping it.", owner, ctx.cutover) for f, asked in lost),
                 *(("Edge", f"{ctx.dst.label} doesn't run `{f}` in front of `{role}`, which the intent asks: render "
                    "and apply its edge again, or find what changed it.", responsible(d, p, t, ctx.dst.env),
                    ctx.cutover) for f in absent)],
        ok=[f"Edge kept: what {ctx.src.label} runs in front of `{role}` is stated in its policies."]
        if src and not lost and (t is not None or p is not None) else [])


def check_running(ctx):
    """What the source's edge runs that the intent doesn't state (the target wouldn't), and what the target's doesn't
    run that the intent asks, are actions."""
    roles = sorted(observed_roles(ctx.src) | observed_roles(ctx.dst))
    return merge_findings([_role(ctx, r) for r in roles])
