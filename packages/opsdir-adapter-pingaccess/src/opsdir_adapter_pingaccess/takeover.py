"""PingAccess taking over protected applications another product (or an operator) recorded: the neutral applications
an environment has PingAccess's engines enforce (opsdir.domains.webaccess; its own override, else the shared value)
that no paApplication projects, rendered as the Admin API requests that create them, and what PingAccess can't
express of them as render notes. Pure.

For each such application <app>, the objects it needs, named after it:
  rules / rule sets        each access rule it uses that PingAccess can test (neutral.CAPABILITIES): one test a rule
                           (negated for a denial), several a rule set of rules <rule>-1, -2, ... (all or any); a rule
                           set of rules for one including others; 'authenticated' is the web session itself
  site <app>-backend       targets from its backend role's bindings (<ciamFqdn>:<its port, else the binding's>)
  virtual hosts            <role>:443 for each service name it is published as (one the record's PingAccess already
                           has is reused)
  identity mapping         <app>-headers: each header contract it sets, from the attribute or claim the contract says
  web session              <app>-session: its integration's client id and the way it authenticates, the client secret
                           from its credential role (ciamCredentialRole), its idle and maximum timeouts
  application, resources   its base path, the objects above, its rules; each path resource's patterns, methods,
                           access and rules
A PingAccess application whose neutral application an environment has another role enforce is not rendered there
(render.py). What PingAccess leaves out is a render note for the application's owners: an action, or a note when it is
only translated (a prefix written as a wildcard).
"""
from opsdir.core.directory import follow, follow_all, get, one, rdn_value, values
from opsdir.core.environment import UNBOUND, bound, role_bindings, secret_placeholder
from opsdir.core.jsondata import WITHHELD
from opsdir.core.notes import note
from opsdir.domains.webaccess.apps import enforced_by, every_rule, included, path_resources, projected_within, \
    protected_apps, rules_of
from opsdir.domains.webaccess.express import expressible_rule, expressible_who, losses, pattern_as
from opsdir.domains.webaccess.naming import who
from .api import (ANONYMOUS, ANY_METHOD, AUTH_METHODS, CLASS_NAME, HEADER_MAPPING, NEGATE, PATH_PATTERNS, PKCE,
                  RULE_CONFIG, RULE_WHO, SUCCESS, SUCCESS_CRITERIA, UNPROTECTED)
from .naming import ENGINE, PINGACCESS, entry_dn, reference, resources_path
from .neutral import CAPABILITIES

AREA = "PingAccess"
PORT = 443                                          # the port a taken-over application's virtual hosts answer on
_WHO_CLASS = {kind: (cls, fields) for cls, (kind, fields) in RULE_WHO.items()}
_PATTERN_TYPE = {"wildcard": "WILDCARD", "regex": "REGEX"}
_ANY = {v: k for k, v in SUCCESS_CRITERIA.items()}


def taken_over(m):
    """The neutral applications environment m has PingAccess's engines enforce that no paApplication projects."""
    return tuple(a for a in enforced_by(m, (ENGINE,)) if not projected_within(a, PINGACCESS))


def handed_over(d):
    """The DNs (lower-cased) of the PingAccess applications whose neutral application another role enforces, as the
    snapshot d sees it (an environment's: its overrides applied)."""
    return frozenset((one(a, "ciamProjectedFrom") or "").lower() for a in protected_apps(d)
                     if projected_within(a, PINGACCESS) and one(a, "ciamEnforcedByRole") != ENGINE)


def _request(path, name, body):
    return {"method": "PUT", "path": f"/{path}/{reference(path, name)}", "createWith": f"POST /{path}", "body": body}


# ------------------------------------------------------------------ rules
def _tests(rule):
    """The tests a rule renders as: its ciamWho values PingAccess can test, 'authenticated' left to the session."""
    return tuple(w for w in values(rule, "ciamWho")
                 if who(w)[0] != "authenticated" and expressible_who(w, CAPABILITIES))


def _test_body(name, value, deny):
    kind, rest = who(value)
    cls, fields = _WHO_CLASS[kind]
    parts = rest.split("=", 1) if len(fields) == 2 else (rest,)
    return {"name": name, CLASS_NAME: cls, RULE_CONFIG: {**dict(zip(fields, parts)), NEGATE: deny}}


def _rule_requests(d, rule):
    """(rule requests, rule set requests) of one access rule; nothing for one PingAccess can't express or that only
    asks for a signed-in user."""
    name, deny = rdn_value(rule), one(rule, "ciamEffect") == "deny"
    members = tuple(r for r in follow_all(d, rule, "ciamIncludesRule") if r is not None and _rendered(d, r))
    if not expressible_rule(rule, CAPABILITIES) or not (_tests(rule) or members):
        return (), ()
    tests = _tests(rule)
    if len(tests) == 1 and not members:
        return (_request("rules", name, _test_body(name, tests[0], deny)),), ()
    singles = tuple(_request("rules", f"{name}-{i}", _test_body(f"{name}-{i}", w, deny))
                    for i, w in enumerate(tests, 1))
    ids = (*(reference("rules", f"{name}-{i}") for i in range(1, len(tests) + 1)),
           *(reference(_kind_path(d, r), rdn_value(r)) for r in members))
    kind = "Ruleset" if members and not tests else "Rule"
    return singles, (_request("rulesets", name, {"name": name, "elementType": kind, "policy": list(ids),
                                                 SUCCESS: _ANY[one(rule, "ciamRuleMatch") or "any"]}),)


def _rendered(d, rule):
    return bool(_rule_requests(d, rule)[0] or _rule_requests(d, rule)[1])


def _kind_path(d, rule):
    """The collection a rendered rule is in: rulesets when it renders as a rule set."""
    return "rulesets" if _rule_requests(d, rule)[1] else "rules"


def _policy(d, entries):
    return [{"type": "Ruleset" if _kind_path(d, r) == "rulesets" else "Rule", "id": reference(_kind_path(d, r),
                                                                                            rdn_value(r))}
            for r in entries if _rendered(d, r)]


# ------------------------------------------------------------------ the application's objects
def _targets(m, app):
    role, port = one(app, "ciamBackendRole"), one(app, "ciamBackendPort")
    found = [f"{one(b, 'ciamFqdn')}:{port or one(b, 'ciamPort')}" for b in role_bindings(m, role)
             if one(b, "ciamFqdn") and (port or one(b, "ciamPort"))] if role else []
    return found or [f"{UNBOUND}{role or rdn_value(app) + '-backend'}" + (f":{port}" if port else "")]


def _host_name(role):
    return f"{role}:{PORT}"


def _attribute(contract):
    """The attribute or claim a header contract's value comes from ('attribute uid', 'claim sub'), else None."""
    kind, _, rest = (one(contract, "ciamHeaderValue") or "").partition(" ")
    return rest.split()[0] if kind in ("attribute", "claim") and rest.split() else None


def _session(m, app):
    integration = follow(m.d, app, "ciamSignInAs")
    if integration is None:
        return None
    methods = values(integration, "ciamTokenAuthMethod")
    kind = next((k for k, allowed in AUTH_METHODS.items() if set(allowed) & set(methods)), "SECRET")
    role = one(app, "ciamCredentialRole")
    secret = secret_placeholder(m, role) if role else WITHHELD
    limits = {f: int(int(one(app, attr)) / 60) for f, attr in (("idleTimeoutInMinutes", "ciamIdleTimeout"),
                                                               ("sessionTimeoutInMinutes", "ciamMaxSessionTime"))
              if one(app, attr)}
    return {"name": f"{rdn_value(app)}-session", "audience": rdn_value(app),
            "clientCredentials": {"clientId": one(integration, "ciamClientId"), "credentialsType": kind,
                                  **({"clientSecret": {"value": secret}} if kind == "SECRET" else {})},
            "oidcLoginType": "Code", **({PKCE: "SHA256"} if one(integration, "ciamPkceRequired") == "TRUE" else {}),
            "scopes": list(values(integration, "ciamScope") or ("openid", "profile")), **limits}


def _resource(d, app, r):
    kind = one(r, "ciamMatchKind", "prefix")
    as_kind = kind if kind in CAPABILITIES.match_kinds else dict(CAPABILITIES.translated).get(kind, "regex")
    mode = one(r, "ciamAccessMode", "standard")
    return {"name": rdn_value(r),
            PATH_PATTERNS: [{"type": _PATTERN_TYPE[as_kind], "pattern": pattern_as(kind, p, as_kind)}
                            for p in values(r, "ciamPathPattern")],
            "methods": list(values(r, "ciamHttpMethod")) or [ANY_METHOD],
            **({ANONYMOUS: True} if mode == "anonymous" else {}), **({UNPROTECTED: True} if mode == "unprotected"
                                                                       else {}),
            "policy": {"Web": _policy(d, rules_of(d, r)), "API": []}}


def _app_requests(m, app):
    """{collection: [requests]} for one taken-over application."""
    d, name = m.d, rdn_value(app)
    hosts = tuple(_host_name(r) for r in values(app, "ciamPublishedAs"))
    contracts = tuple(c for c in follow_all(d, app, "ciamSetsHeader") if c is not None and _attribute(c))
    session = _session(m, app)
    rules = tuple(x for r in every_rule(d, app) for x in included(d, r))
    built = tuple(_rule_requests(d, r) for r in {r.norm: r for r in rules}.values())
    app_body = {"name": name, "contextRoot": one(app, "ciamBasePath"), "applicationType": "Web",
                "destination": "Site", "siteId": reference("sites", f"{name}-backend"),
                "virtualHostIds": [reference("virtualhosts", h) for h in hosts],
                **({"webSessionId": reference("webSessions", f"{name}-session")} if session else {}),
                "identityMappingIds": ({"Web": reference("identityMappings", f"{name}-headers")} if contracts else {}),
                "policy": {"Web": _policy(d, rules_of(d, app)), "API": []},
                **({"caseSensitivePath": one(app, "ciamCaseSensitive") == "TRUE"}
                   if one(app, "ciamCaseSensitive") else {})}
    return {
        "rules": [q for rs, _ in built for q in rs], "rulesets": [q for _, ss in built for q in ss],
        "sites": [_request("sites", f"{name}-backend", {"name": f"{name}-backend", "targets": _targets(m, app),
                                                        "secure": one(app, "ciamBackendTls") != "FALSE"})],
        "virtualhosts": [_request("virtualhosts", h, {"host": bound(m, r, "ciamFqdn"), "port": PORT})
                         for r, h in zip(values(app, "ciamPublishedAs"), hosts)
                         if get(d, entry_dn("virtual-host", h)) is None],
        "identityMappings": [_request("identityMappings", f"{name}-headers", {
            "name": f"{name}-headers", CLASS_NAME: HEADER_MAPPING, "configuration": {"attributeHeaderMappings": [
                {"attributeName": _attribute(c), "headerName": one(c, "ciamHeaderName")} for c in contracts]}})]
        if contracts else [],
        "webSessions": [_request("webSessions", f"{name}-session", session)] if session else [],
        "applications": [_request("applications", name, app_body)],
        "applications/{application}/resources": [
            {**_request(resources_path(name), rdn_value(r), _resource(d, app, r))} for r in path_resources(d, app)]}


def requests(m, path):
    """The requests of collection path for every application environment m has PingAccess take over, each object
    once (a rule two applications use)."""
    made = [q for app in taken_over(m) for q in _app_requests(m, app).get(path, ())]
    return list({q["path"]: q for q in made}.values())


# ------------------------------------------------------------------ what it leaves to a person
def takeover_notes(m):
    """Render notes for each taken-over application: what PingAccess can't express of it, and a secret its session
    can't take from a credential role."""
    return (
        *(note(AREA, {"info": "note"}.get(x.severity, x.severity), f"protected application `{rdn_value(a)}`",
               x.text, (f"Decide how PingAccess protects `{rdn_value(a)}` without it, and record that (the "
                        "application's resources and rules), or keep it with its current product.",), a.dn)
          for a in taken_over(m) for x in losses(m.d, a, CAPABILITIES)),
        *(note(AREA, "blocker", f"protected application `{rdn_value(a)}`", "its web session's client secret has no "
               "credential role: the request carries ${withheld}",
               ("Set ciamCredentialRole to the secret role holding the client secret, bind it in the environment, "
                "and re-render.",), a.dn)
          for a in taken_over(m) if follow(m.d, a, "ciamSignInAs") is not None and not one(a, "ciamCredentialRole")
          and (_session(m, a) or {}).get("clientCredentials", {}).get("credentialsType") == "SECRET"))
