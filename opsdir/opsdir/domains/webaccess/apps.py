"""Protected web applications as the record holds them: lookups every reader shares (the planner, the product
renders, the report). Pure.

An environment sees an application through its overrides (core.environment.as_seen: a plan's and a render's models
already do): its enforcing role there is the one ciamEnforcedByRole has in the environment's snapshot."""
from ...core.directory import children, follow, follow_all, get, one, rdn_value, subtree, values, within
from ...core.findings import responsible
from .naming import ACCESS_RULES, PROTECTED_APPS

PROTECTED_APP_HEADERS = ("application", "base path", "enforced by", "published as", "backend", "sign-on",
                         "signs in as", "resources", "rules", "projected from", "owner")


def protected_apps(d):
    """Every protected application, in DN order."""
    return children(d, PROTECTED_APPS, "ciamProtectedApp")


def access_rules(d):
    """Every access rule, in DN order."""
    return children(d, ACCESS_RULES, "ciamAccessRule")


def _specificity(r):
    """Most specific first: a longer pattern before a shorter one, then a prefix before a wildcard before a regex."""
    longest = max((len(p) for p in values(r, "ciamPathPattern")), default=0)
    return -longest, ("prefix", "wildcard", "regex").index(one(r, "ciamMatchKind", "prefix")), rdn_value(r)


def path_resources(d, app):
    """An application's path resources in evaluation order: those with a ciamOrder first (lowest first), then the
    rest most specific first."""
    found = children(d, app.dn, "ciamPathResource")
    ordered = sorted((r for r in found if one(r, "ciamOrder")), key=lambda r: (int(one(r, "ciamOrder")), r.dn))
    return (*ordered, *sorted((r for r in found if not one(r, "ciamOrder")), key=_specificity))


def rules_of(d, e):
    """The access rules an application or resource applies (those the record holds), in the order it names them."""
    return tuple(r for r in follow_all(d, e, "ciamRuleRef") if r is not None)


def included(d, rule, seen=()):
    """A rule and every rule it includes, depth first, each once (a loop stops where it closes)."""
    if rule.norm in seen:
        return ()
    inner = tuple(r for r in follow_all(d, rule, "ciamIncludesRule") if r is not None)
    return (rule, *(x for r in inner for x in included(d, r, (*seen, rule.norm))))


def every_rule(d, app):
    """Every access rule an application uses, its resources' and the rules those include, each once, in order."""
    named = (*rules_of(d, app), *(r for res in path_resources(d, app) for r in rules_of(d, res)))
    return tuple({x.norm: x for r in named for x in included(d, r)}.values())


def enforcer(m, app):
    """The server role enforcing an application in environment m (as m sees it, its overrides applied)."""
    seen = get(m.d, app.dn)
    return one(seen if seen is not None else app, "ciamEnforcedByRole")


def enforced_by(m, roles):
    """The applications environment m has enforced by one of roles, as m sees them."""
    return tuple(a for a in protected_apps(m.d) if one(a, "ciamEnforcedByRole") in roles)


def projected_from(d, e):
    """The product entry a neutral entry was projected from (None: an operator's, or the product entry is gone)."""
    return follow(d, e, "ciamProjectedFrom")


def projected_within(e, base):
    """Whether a neutral entry was projected from a product entry at or below base (a product's own branch)."""
    source = one(e, "ciamProjectedFrom")
    return bool(source) and within(source, base)


def projection_of(d, source):
    """The neutral entries projected from a product entry (its DN), in DN order."""
    return tuple(e for e in (*protected_apps(d), *subtree(d, PROTECTED_APPS, "ciamPathResource"), *access_rules(d))
                 if (one(e, "ciamProjectedFrom") or "").lower() == source.lower())


def _label(d, dn):
    e = get(d, dn) if dn else None
    return rdn_value(e) if e is not None else (dn or "")


def protected_app_rows(d, dn=None):
    """One row per protected application: its base path, enforcing role, service names, backend, sign-on and the
    integration it signs in as, its resource and rule counts, the product entry it was read from, its owners."""
    return [(rdn_value(a), one(a, "ciamBasePath"), one(a, "ciamEnforcedByRole"),
             ", ".join(values(a, "ciamPublishedAs")),
             one(a, "ciamBackendRole", "") + (f":{one(a, 'ciamBackendPort')}" if one(a, "ciamBackendPort") else ""),
             one(a, "ciamSignOn", ""), _label(d, one(a, "ciamSignInAs")), str(len(path_resources(d, a))),
             ", ".join(rdn_value(r) for r in every_rule(d, a)), one(a, "ciamProjectedFrom", ""),
             responsible(d, a)) for a in protected_apps(d)]
