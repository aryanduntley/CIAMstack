"""PingAccess projected onto the neutral protected-application layer (opsdir.domains.webaccess), and what PingAccess
can express of it. Pure.

  paApplication   -> ciamProtectedApp (named as the application): its context root the base path, enforced by
                     pa-engine; published as its virtual hosts' service roles; its site's backend role, port and TLS;
                     sign-on through its web session's integration (oidc; an API application: token), served by the
                     identity service whose issuer the session trusts; the session's idle and maximum timeouts; the
                     header contracts of its identity mappings; the rules of its policy
  paResource      -> ciamPathResource below it: its path patterns (wildcard or regex; older path prefixes: prefix),
                     methods (* as none), anonymous or unprotected, the rules of its policy
  paRule          -> ciamAccessRule (named as the rule): a web session attribute rule tests an attribute, an OAuth
                     scope rule a scope, a network range rule a network; negated, it denies; a rule set includes its
                     members, all or any; any other rule is custom (rebuilt by hand in another product)
Every vendor form is api.py's (unverified). The ownership rule is webaccess.projection's."""
from opsdir.core.directory import children, follow, get, one, rdn_value, values
from opsdir.core.jsondata import held_json
from opsdir.domains.webaccess.express import Capabilities, pattern_as
from opsdir.domains.webaccess.naming import HTTP_METHODS, app_dn, resource_dn, rule_dn
from opsdir.domains.webaccess.projection import neutral_entry, projected, served_by_issuer
from .api import (ANONYMOUS, ANY_METHOD, API_APPLICATION, APP_REFERENCES, APPLICATION_TYPE, CASE_SENSITIVE, CLASS_NAME,
                  METHODS,
                  NEGATE, PATH_PATTERNS, PATH_PREFIXES, PATTERN_TYPES, POLICY, POLICY_KINDS, RULE_CONFIG, RULE_WHO,
                  SESSION_MINUTES, SUCCESS, SUCCESS_CRITERIA, UNPROTECTED, collection)
from .naming import ENGINE, KINDS, PINGACCESS, entry_dn, referenced

# What PingAccess renders of the neutral layer (takeover.py): wildcard and regex paths (a prefix as a wildcard); every
# access mode; attribute, scope and network tests of IPv4 ranges (network range rules); OAuth sign-on through an
# identity service, or a token; denials as negated rules; idle and maximum session limits per web session
CAPABILITIES = Capabilities("PingAccess", ("wildcard", "regex"), (("prefix", "wildcard"),),
                            ("standard", "anonymous", "unprotected"),
                            ("authenticated", "attribute", "scope", "network"), ("oidc", "token", "none"), True,
                            ("idle", "max"), False)


def _named(view, ref):
    """The entry a ${pingaccess-id:<collection>/<name>} reference names in the record, or None."""
    found = referenced(ref)
    c = collection(found[0]) if found else None
    return get(view, entry_dn(c.kind, found[1], c.path)) if c is not None and c.kind != "resource" else None


def _refs(value):
    """The references a setting holds: one, a list of them, or a {Web, API} map of them."""
    if isinstance(value, dict):
        return tuple(r for v in value.values() for r in _refs(v))
    if isinstance(value, list):
        return tuple(r for v in value for r in _refs(v))
    return (value,) if isinstance(value, str) else ()


def _policy_rules(view, config, kinds):
    """The neutral rule DNs of a policy's rules and rule sets, in its order."""
    policy = config.get(POLICY) if isinstance(config.get(POLICY), dict) else {}
    named = (_named(view, item.get("id")) for k in kinds for item in policy.get(k) or () if isinstance(item, dict))
    return tuple(dict.fromkeys(rule_dn(rdn_value(e)) for e in named if e is not None))


def _kinds(config):
    return (API_APPLICATION,) if config.get(APPLICATION_TYPE) == API_APPLICATION else POLICY_KINDS


def _session(view, config):
    session = next((e for e in map(lambda r: _named(view, r), _refs(config.get(APP_REFERENCES["web-session"])))
                    if e is not None), None)
    held = held_json(session, "paConfig") if session is not None else {}
    minutes = {attr: (str(int(held[f]) * 60),) for f, attr in SESSION_MINUTES if isinstance(held.get(f), int)}
    return session, {"ciamIdleTimeout": (), "ciamMaxSessionTime": (), **minutes}


def _app(view, a):
    config = held_json(a, "paConfig")
    site = _named(view, config.get(APP_REFERENCES["site"]))
    hosts = tuple(e for e in map(lambda r: _named(view, r), _refs(config.get(APP_REFERENCES["virtual-hosts"])))
                  if e is not None)
    mappings = tuple(e for e in map(lambda r: _named(view, r), _refs(config.get(APP_REFERENCES["identity-mappings"])))
                     if e is not None)
    session, limits = _session(view, config)
    api = config.get(APPLICATION_TYPE) == API_APPLICATION
    integration = follow(view, session, "paIntegration") if session is not None else None
    secure = held_json(site, "paConfig").get("secure") if site is not None else None
    return neutral_entry(app_dn(rdn_value(a)), "ciamProtectedApp", {
        "cn": (rdn_value(a),), "ciamBasePath": (one(a, "paContextRoot") or "/",), "ciamEnforcedByRole": (ENGINE,),
        "ciamPublishedAs": tuple(dict.fromkeys(one(h, "paServiceRole") for h in hosts if one(h, "paServiceRole"))),
        "ciamBackendRole": (one(site, "paBackendRole") if site is not None else None,),
        "ciamBackendPort": (one(site, "paPort") if site is not None else None,),
        "ciamBackendTls": ({True: "TRUE", False: "FALSE"}.get(secure),),
        "ciamSignOn": ("token" if api else "oidc" if session is not None else "none",),
        "ciamSignInAs": (integration.dn if integration is not None else None,),
        "ciamServedBy": (served_by_issuer(view, one(session, "paIssuer")) if session is not None else None,),
        **limits,
        "ciamSetsHeader": tuple(dict.fromkeys(h for m in mappings for h in values(m, "paHeaderContract"))),
        "ciamRuleRef": _policy_rules(view, config, _kinds(config)),
        "ciamCaseSensitive": ({True: "TRUE", False: "FALSE"}.get(config.get(CASE_SENSITIVE)),),
        "ciamProjectedFrom": (a.dn,)})


def _patterns(config):
    """(match kind, patterns) of a resource: one kind when they share it, else every pattern as a regex."""
    found = tuple((PATTERN_TYPES.get(p.get("type"), "wildcard"), p.get("pattern"))
                  for p in config.get(PATH_PATTERNS) or () if isinstance(p, dict) and p.get("pattern"))
    if not found:
        return "prefix", tuple(p for p in config.get(PATH_PREFIXES) or () if isinstance(p, str)) or ("/",)
    kinds = {k for k, _ in found}
    if len(kinds) == 1:
        return kinds.pop(), tuple(p for _, p in found)
    return "regex", tuple(pattern_as(k, p, "regex") for k, p in found)


def _resource(view, app, kinds, r):
    config = held_json(r, "paConfig")
    kind, patterns = _patterns(config)
    methods = tuple(m.upper() for m in config.get(METHODS) or () if isinstance(m, str))
    mode = "unprotected" if config.get(UNPROTECTED) is True else "anonymous" if config.get(ANONYMOUS) is True \
        else "standard"
    return neutral_entry(resource_dn(app.dn, rdn_value(r)), "ciamPathResource", {
        "cn": (rdn_value(r),), "ciamPathPattern": patterns, "ciamMatchKind": (kind,),
        "ciamHttpMethod": () if ANY_METHOD in methods else tuple(m for m in methods if m in HTTP_METHODS),
        "ciamAccessMode": (mode,), "ciamRuleRef": _policy_rules(view, config, kinds), "ciamProjectedFrom": (r.dn,)})


def _who(rule, config):
    """(who values, effect) of a single rule: what it tests, and deny when negated; ((), custom) when untestable."""
    form = RULE_WHO.get(config.get(CLASS_NAME))
    inner = config.get(RULE_CONFIG) if isinstance(config.get(RULE_CONFIG), dict) else {}
    vals = tuple(inner.get(f) for f in form[1]) if form else ()
    if not form or not all(isinstance(v, str) and v for v in vals):
        return (), "custom"
    return (f"{form[0]} {'='.join(vals)}",), "deny" if inner.get(NEGATE) is True else "allow"


def _rule(view, rule):
    config = held_json(rule, "paConfig")
    base = {"cn": (rdn_value(rule),), "ciamProjectedFrom": (rule.dn,)}
    if one(rule, "paRuleKind") == "rule-set":
        members = tuple(e for e in map(lambda r: _named(view, r), _refs(config.get(POLICY))) if e is not None)
        return neutral_entry(rule_dn(rdn_value(rule)), "ciamAccessRule", {
            **base, "ciamEffect": ("allow",), "ciamWho": (),
            "ciamRuleMatch": (SUCCESS_CRITERIA.get(config.get(SUCCESS), "all"),),
            "ciamIncludesRule": tuple(dict.fromkeys(rule_dn(rdn_value(m)) for m in members))})
    whos, effect = _who(rule, config)
    return neutral_entry(rule_dn(rdn_value(rule)), "ciamAccessRule",
                         {**base, "ciamEffect": (effect,), "ciamWho": whos, "ciamRuleMatch": (),
                          "ciamIncludesRule": ()})


def projection(view, label):
    """Projected of the record's PingAccess applications, resources and rules (view: the record as the import leaves
    it)."""
    apps = children(view, KINDS["application"][0], "paApplication")
    rules = (*children(view, KINDS["rule"][0], "paRule"), *children(view, KINDS["rule-set"][0], "paRule"))
    return projected(view, tuple((n, tuple(_resource(view, n, _kinds(held_json(a, "paConfig")), r)
                                           for r in children(view, a.dn, "paResource")))
                                 for a in apps for n in (_app(view, a),)),
                     tuple(_rule(view, r) for r in rules), (PINGACCESS,), label)
