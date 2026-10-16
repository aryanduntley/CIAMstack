"""PingGateway taking over protected applications another product (or an operator) recorded: the neutral applications
an environment has its gateways (ig) enforce (opsdir.domains.webaccess; its own override, else the shared value) that
no route projects, rendered as one route each, and what PingGateway can't express of them as render notes. Pure.

  pinggateway/routes/<application>.json
    condition   the hosts of the service names it is published as, and its base path (^<base>(?:/|$))
    baseURI     its backend role's binding (scheme from ciamBackendTls), UNBOUND:<role> where none is bound
    session     JwtSessionManager, its idle limit as the session timeout (PingGateway has one)
    handler     a Chain of:
                  the sign-in: AuthorizationCodeOAuth2ClientFilter for its integration's client id and the issuer of
                    the identity service serving it, inside a ConditionalFilter skipping the anonymous and unprotected
                    paths; the client's secret from the gateway's secrets provider (a render note names the reference)
                  AllowOnlyFilter: each path resource as a rule (its paths as regular expressions, its methods)
                  ConditionEnforcementFilter: each access rule PingGateway can test (a signed-in user: the sign-in
                    itself; a claim: contexts.oauth2Info.userInfo; a denial: not()), a resource's inside a
                    ConditionalFilter on its paths
                  HeaderFilter (REQUEST, replace: the client's own copy goes): each header contract it sets, from the
                    claim or attribute the contract says
                then ReverseProxyHandler
A route projected from an application another role enforces in the environment is not rendered there (render.py).
The filters follow PingGateway's 2026 reference, unverified against a running gateway (routes.py says where the
reference disagrees with itself)."""
import re

from opsdir.core.directory import follow, follow_all, one, rdn_value, values
from opsdir.core.environment import as_seen, bound, env_model, one_role, secret_placeholder
from opsdir.core.notes import note
from opsdir.domains.webaccess.apps import enforced_by, path_resources, projected_within, protected_apps, rules_of
from opsdir.domains.webaccess.express import expressible_rule, losses, pattern_as
from opsdir.domains.webaccess.naming import who
from .naming import PINGGATEWAY
from .neutral import CAPABILITIES, ENFORCER
from .routes import ALLOW_ONLY, CONDITIONAL, ENFORCE, HEADERS, USERINFO, WELL_KNOWN

AREA = "PingGateway"
CLIENT_FILTER = "AuthorizationCodeOAuth2ClientFilter"
SECRETS = "SystemAndEnvSecretStore-1"        # the secrets provider the registration reads its client secret from
DEFAULT_PORTS = {"https": "443", "http": "80"}


def taken_over(m):
    """The neutral applications environment m has its gateways enforce that no route projects."""
    return tuple(a for a in enforced_by(m, (ENFORCER,)) if not projected_within(a, PINGGATEWAY))


def handed_over(d):
    """The DNs (lower-cased) of the routes whose neutral application another role enforces, as snapshot d sees it."""
    return frozenset((one(a, "ciamProjectedFrom") or "").lower() for a in protected_apps(d)
                     if projected_within(a, PINGGATEWAY) and one(a, "ciamEnforcedByRole") != ENFORCER)


def _quoted(text):
    return text.replace("\\", "\\\\").replace("'", "\\'")


def _full(app, r, pattern):
    """A resource's pattern as a regular expression over the whole request path."""
    base, kind = (one(app, "ciamBasePath") or "/").rstrip("/"), one(r, "ciamMatchKind", "prefix")
    if kind != "regex":
        return pattern_as(kind, base + pattern, "regex")
    return "^" + re.escape(base) + pattern[1:] if pattern.startswith("^") else "^" + re.escape(base) + ".*" + pattern


def _paths(app, r):
    return [_full(app, r, p) for p in values(r, "ciamPathPattern")]


def _host_pattern(host):
    """A host name as a regular expression matching only itself (its dots escaped; an UNBOUND:<role> kept readable)."""
    return host.replace(".", r"\.")


def _condition(m, app):
    hosts = [bound(m, role, "ciamFqdn") for role in values(app, "ciamPublishedAs")]
    base = (one(app, "ciamBasePath") or "/").rstrip("/")
    tests = (*((" or ".join(f"find(request.uri.host, '^{_quoted(_host_pattern(h))}$')" for h in hosts),)
               if hosts else ()),
             *((f"find(request.uri.path, '^{_quoted(re.escape(base))}(?:/|$)')",) if base else ()))
    return "${" + " and ".join(f"({t})" if " or " in t else t for t in tests) + "}" if tests else None


def _backend(m, app):
    role = one(app, "ciamBackendRole")
    b = one_role(m, role) if role else None
    if b is None or not one(b, "ciamFqdn"):
        return f"UNBOUND:{role or rdn_value(app) + '-backend'}"
    scheme = "http" if one(app, "ciamBackendTls") == "FALSE" else "https"
    port = one(app, "ciamBackendPort") or next((p for p in values(b, "ciamPort") if p != DEFAULT_PORTS[scheme]), None)
    return f"{scheme}://{one(b, 'ciamFqdn')}" + (f":{port}" if port and port != DEFAULT_PORTS[scheme] else "")


def _claim_test(value):
    kind, rest = who(value)
    claim, _, wanted = rest.partition("=")
    return f"contains({USERINFO}['{_quoted(claim)}'], '{_quoted(wanted)}')" if kind == "attribute" else "true"


def _rule_test(d, rule):
    """A rule's test as an expression (None when PingGateway can't express it)."""
    if not expressible_rule(rule, CAPABILITIES):
        return None
    parts = (*(_claim_test(w) for w in values(rule, "ciamWho")),
             *(t for r in follow_all(d, rule, "ciamIncludesRule") if r is not None for t in (_rule_test(d, r),) if t))
    joined = _joined(parts, "and" if one(rule, "ciamRuleMatch") == "all" else "or") or "true"
    return f"not ({joined})" if one(rule, "ciamEffect") == "deny" else joined


def _joined(parts, op):
    """Expressions joined by and/or, each in parentheses only when there are several."""
    return parts[0] if len(parts) == 1 else f" {op} ".join(f"({p})" for p in parts)


def _enforce(d, rules, paths=None):
    tests = tuple(t for t in (_rule_test(d, r) for r in rules) if t and t != "true")
    if not tests:
        return []
    inner = {"type": ENFORCE, "config": {"condition": "${" + _joined(tests, "and") + "}"}}
    return [inner] if paths is None else [{"type": CONDITIONAL, "config": {
        "condition": "${" + " or ".join(f"find(request.uri.path, '{_quoted(p)}')" for p in paths) + "}",
        "delegate": inner}}]


def _sign_in(m, app):
    integration = follow(m.d, app, "ciamSignInAs")
    service = follow(m.d, app, "ciamServedBy")
    if integration is None:
        return []
    issuer = one(service, "ciamOidcIssuer") if service is not None else None
    client = {"name": f"{rdn_value(app)}-sign-in", "type": CLIENT_FILTER, "config": {
        "clientEndpoint": f"{(one(app, 'ciamBasePath') or '/').rstrip('/')}/openid", "requireHttps": True,
        "registrations": [{"name": rdn_value(app), "type": "ClientRegistration", "config": {
            "clientId": one(integration, "ciamClientId"),
            "issuer": {"type": "Issuer", "config": {"wellKnownEndpoint": (issuer or "UNBOUND:issuer") + WELL_KNOWN}},
            "scopes": list(values(integration, "ciamScope") or ("openid", "profile")),
            "secretsProvider": SECRETS}}]}}
    public = tuple(p for r in path_resources(m.d, app) if one(r, "ciamAccessMode") in ("anonymous", "unprotected")
                   for p in _paths(app, r))
    if not public:
        return [client]
    return [{"type": CONDITIONAL, "config": {
        "condition": "${not (" + " or ".join(f"find(request.uri.path, '{_quoted(p)}')" for p in public) + ")}",
        "delegate": client}}]


def _allow_only(app, d):
    found = [{"name": rdn_value(r), "destination": {"paths": _paths(app, r),
                                                    **({"methods": list(values(r, "ciamHttpMethod"))}
                                                       if values(r, "ciamHttpMethod") else {})}}
             for r in path_resources(d, app)]
    return [{"type": ALLOW_ONLY, "config": {"rules": found}}] if found else []


def _headers(d, app):
    contracts = tuple(c for c in follow_all(d, app, "ciamSetsHeader") if c is not None)
    named = {one(c, "ciamHeaderName"): f"${{{USERINFO}['{_quoted(rest.split()[0])}']}}" for c in contracts
             for kind, _, rest in ((one(c, "ciamHeaderValue") or "").partition(" "),)
             if kind in ("attribute", "claim") and rest.split()}
    return [{"type": HEADERS, "config": {"messageType": "REQUEST", "replace": {h: [v] for h, v in named.items()}}}] \
        if named else []


def route(m, app):
    """The route of one taken-over application in environment m."""
    d = m.d
    idle = one(app, "ciamIdleTimeout")
    filters = [*_sign_in(m, app), *_allow_only(app, d), *_enforce(d, rules_of(d, app)),
               *(f for r in path_resources(d, app) for f in _enforce(d, rules_of(d, r), _paths(app, r))),
               *_headers(d, app)]
    condition = _condition(m, app)
    return {"name": rdn_value(app), **({"condition": condition} if condition else {}), "baseURI": _backend(m, app),
            **({"session": {"type": "JwtSessionManager", "config": {"sessionTimeout": f"{idle} seconds"}}}
               if idle else {}),
            "handler": {"type": "Chain", "config": {"filters": filters, "handler": "ReverseProxyHandler"}}}


def takeover_notes(m, services=None):
    """Render notes for each taken-over application: what PingGateway can't express of it, and where its client's
    secret comes from."""
    return (*(note(AREA, {"info": "note"}.get(x.severity, x.severity), f"protected application `{rdn_value(a)}`",
                   x.text, (f"Decide how PingGateway protects `{rdn_value(a)}` without it, and record that, or keep "
                            "it with its current product.",), a.dn)
              for a in taken_over(m) for x in losses(m.d, a, CAPABILITIES)),
            *(note(AREA, "action", f"pinggateway/routes/{rdn_value(a)}.json",
                   f"the sign-in's client secret is read from the gateway's secrets provider ({SECRETS}): put "
                   + (f"{secret_placeholder(m, one(a, 'ciamCredentialRole'))}" if one(a, "ciamCredentialRole")
                      else "the client's secret (no credential role records it)")
                   + f" there for registration `{rdn_value(a)}`; the filters follow PingGateway's 2026 reference "
                     "and are unverified against a running gateway",
                   ("Check the route against the gateway's version (a test gateway, or its admin endpoints) before "
                    "deploying it.",), a.dn)
              for a in taken_over(m) if follow(m.d, a, "ciamSignInAs") is not None))


def own_routes(files, d, environment):
    """The rendered gateway files without the routes made for taken-over applications (Adapter.reads_back's prepare):
    those are the neutral layer's render, and reading them back would make them the gateway's own routes, which is
    what a cutover does, not a round trip. d: the record as the environment sees it."""
    m = as_seen(env_model(d, environment)) if environment else None
    taken = {f"routes/{rdn_value(a)}.json" for a in taken_over(m)} if m is not None else set()
    return {path: text for path, text in files.items() if path not in taken}


def takeover_routes(m):
    """{pinggateway/routes/<application>.json: route} for every application environment m has its gateways take
    over."""
    return {f"pinggateway/routes/{rdn_value(a)}.json": route(m, a) for a in taken_over(m)}
