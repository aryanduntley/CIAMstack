"""PingGateway's routes projected onto the neutral protected-application layer (opsdir.domains.webaccess), and what
PingGateway can express of it. Pure.

  pinggwRoute -> ciamProtectedApp (named as the route): enforced by ig; the base path a test of request.uri.path in
                 its condition names (a literal prefix, else '/' and a notice: the condition is the route's); published
                 as the service name its condition's host test names; its backend role and scheme; sign-on through
                 the integration its client filter signs in as (oidc, else none), served by the identity service of
                 the issuer it trusts; its session manager's timeout as the idle limit; the header contracts naming
                 the headers its HeaderFilters set; its ConditionEnforcementFilters as access rules <route>-<n> (a claim
                 test an attribute test, not() a denial; any other condition custom)
  its paths   -> ciamPathResource below it: each AllowOnlyFilter rule (its paths regular expressions below the base
                 path, its methods); the paths a ConditionalFilter keeps the sign-in from are anonymous; without an
                 AllowOnlyFilter, one resource 'all' (every path)
Every vendor form is routes.py's (unverified where it says). The ownership rule is webaccess.projection's."""
import re

from opsdir.core.directory import children, one, rdn_value
from opsdir.core.environment import published_role
from opsdir.core.jsondata import held_json
from opsdir.domains.webaccess.express import Capabilities
from opsdir.domains.webaccess.naming import HTTP_METHODS, app_dn, resource_dn, rule_dn
from opsdir.domains.webaccess.projection import header_contracts, neutral_entry, projected, served_by_issuer
from .naming import PINGGATEWAY, ROUTES, SERVER_ROLES
from .routes import (ALLOW_ONLY, CLAIM_TEST, CLIENT_FILTERS, CONDITIONAL, DURATION, DURATION_SECONDS, ENFORCE,
                     HEADERS, HOST_TEST, PATH_TEST, SESSION_TIMEOUTS, filters, objects)

ENFORCER = SERVER_ROLES[0]
# What PingGateway renders of the neutral layer (takeover.py): regular-expression paths (a prefix or a wildcard
# translated into one); every access mode (the sign-in skipped for anonymous and unprotected paths); a signed-in user
# and claim tests; OpenID Connect sign-on; denials (not()); one session timeout (the idle limit)
CAPABILITIES = Capabilities("PingGateway", ("regex",), (("prefix", "regex"), ("wildcard", "regex")),
                            ("standard", "anonymous", "unprotected"), ("authenticated", "attribute"), ("oidc", "none"),
                            True, ("idle",), False)
_LITERAL = re.compile(r"^\^?(/[A-Za-z0-9._~/-]*?)(?:/?\(\?:/\|\$\)|/?\$|/)?$")


def _unescaped(text):
    return re.sub(r"\\(.)", r"\1", text)


def base_path(condition):
    """The base path a route's condition tests request.uri.path for (a literal prefix), or None."""
    found = re.search(PATH_TEST, condition or "")
    literal = _LITERAL.match(found.group(1)) if found else None
    return (literal.group(1).rstrip("/") or "/") if literal else None


def _hosts(d, condition):
    found = re.search(HOST_TEST, condition or "")
    host = _unescaped(found.group(1).strip("^$")) if found else None
    role = published_role(d, host) if host else None
    return (role,) if role else ()


def _seconds(route):
    """The route's session timeout in seconds, or None."""
    session = route.get("session") if isinstance(route.get("session"), dict) else {}
    field = dict(SESSION_TIMEOUTS).get(session.get("type"))
    found = re.match(DURATION, str((session.get("config") or {}).get(field) or "")) if field else None
    return str(int(found.group(1)) * DURATION_SECONDS[found.group(2)]) if found else None


def _relative(base, path):
    """A path regular expression below base: its leading ^<base> dropped ('^' kept)."""
    prefix = "^" + base.rstrip("/")
    return "^" + path[len(prefix):] if base != "/" and path.startswith(prefix + "/") else path


def _resources(app, base, config):
    """The route's path resources (entries)."""
    rules = tuple(r for f in filters(config, ALLOW_ONLY) for r in (f.get("config") or {}).get("rules") or ()
                  if isinstance(r, dict))
    skipped = tuple(re.search(PATH_TEST, (f.get("config") or {}).get("condition") or "").group(1)
                    for f in filters(config, CONDITIONAL)
                    if re.search(PATH_TEST, (f.get("config") or {}).get("condition") or "")
                    and any(o.get("type") in CLIENT_FILTERS for o in objects((f.get("config") or {}).get("delegate"))))

    def entry(name, paths, methods, mode):
        return neutral_entry(resource_dn(app.dn, name), "ciamPathResource", {
            "cn": (name,), "ciamPathPattern": tuple(_relative(base, p) for p in paths) or ("/",),
            "ciamMatchKind": ("regex" if paths else "prefix",),
            "ciamHttpMethod": tuple(m.upper() for m in methods if m.upper() in HTTP_METHODS),
            "ciamAccessMode": (mode,), "ciamProjectedFrom": (app_source(app),)})
    allowed = tuple(entry(r.get("name") or f"rule-{i}", tuple((r.get("destination") or {}).get("paths") or ()),
                          tuple((r.get("destination") or {}).get("methods") or ()), "standard")
                    for i, r in enumerate(rules, 1))
    open_ = tuple(entry(f"anonymous-{i}", (p,), (), "anonymous") for i, p in enumerate(skipped, 1))
    return (*(allowed or (entry("all", (), (), "standard"),)), *open_)


def app_source(app):
    return one(app, "ciamProjectedFrom")


def _claim_rule(name, condition, source):
    """An access rule of a ConditionEnforcementFilter: an attribute test, deny under not(); else custom."""
    found = re.match(CLAIM_TEST, (condition or "").strip())
    attrs = {"cn": (name,), "ciamRuleMatch": (), "ciamIncludesRule": (), "ciamProjectedFrom": (source,)}
    if not found:
        return neutral_entry(rule_dn(name), "ciamAccessRule", {**attrs, "ciamEffect": ("custom",), "ciamWho": ()})
    claim = found.group(2) or found.group(3)
    return neutral_entry(rule_dn(name), "ciamAccessRule", {
        **attrs, "ciamEffect": ("deny" if found.group(1) else "allow",),
        "ciamWho": (f"attribute {claim}={found.group(4)}",)})


def _projected(d, route):
    """(application, resources, rules, notices) of one route."""
    name, config, condition = rdn_value(route), held_json(route, "pinggwConfig"), one(route, "pinggwCondition")
    base = base_path(condition)
    rules = tuple(_claim_rule(f"{name}-{i}", (f.get("config") or {}).get("condition"), route.dn)
                  for i, f in enumerate(filters(config, ENFORCE), 1))
    headers = tuple(h for f in filters(config, HEADERS) if (f.get("config") or {}).get("messageType") == "REQUEST"
                    for k in ("add", "replace") for h in ((f.get("config") or {}).get(k) or {}))
    signs_in = bool(one(route, "pinggwIntegration")) or any(o.get("type") in CLIENT_FILTERS for o in objects(config))
    app = neutral_entry(app_dn(name), "ciamProtectedApp", {
        "cn": (name,), "ciamBasePath": (base or "/",), "ciamEnforcedByRole": (ENFORCER,),
        "ciamPublishedAs": _hosts(d, condition), "ciamBackendRole": (one(route, "pinggwBackendRole"),),
        "ciamBackendTls": ({"https": "TRUE", "http": "FALSE"}.get(one(route, "pinggwBackendScheme", "https"))
                           if one(route, "pinggwBackendRole") else None,),
        "ciamSignOn": ("oidc" if signs_in else "none",), "ciamSignInAs": (one(route, "pinggwIntegration"),),
        "ciamServedBy": (served_by_issuer(d, one(route, "pinggwIssuer")),), "ciamIdleTimeout": (_seconds(config),),
        "ciamMaxSessionTime": (), "ciamSetsHeader": header_contracts(d, headers),
        "ciamRuleRef": tuple(r.dn for r in rules), "ciamProjectedFrom": (route.dn,)})
    notices = ((f"route {name}: its condition names no literal base path, so its protected application is recorded "
                "at '/' (the condition is the route's)",) if condition and base is None else ())
    return app, _resources(app, base or "/", config), rules, notices


def projection(d):
    """Projected of the record's routes (d: the record as the import leaves it)."""
    parts = tuple(_projected(d, r) for r in children(d, ROUTES, "pinggwRoute"))
    found = projected(d, tuple((a, res) for a, res, _, _ in parts), tuple(r for _, _, rs, _ in parts for r in rs),
                      (PINGGATEWAY,), "PingGateway")
    return found._replace(notices=(*found.notices, *(n for *_, ns in parts for n in ns)))
