"""SiteMinder's realms projected onto the neutral protected-application layer (opsdir.domains.webaccess), so a plan
can move what SiteMinder protects to a product the target runs. Pure.

  smRealm   -> ciamProtectedApp <domain>-<realm>: its resource filter the base path, enforced by its agent's role (a web
               agent, or an Access Gateway); no backend (a web agent runs in the application's own web server); sign-on
               from its authentication scheme's type (xps.SCHEME_SIGN_ONS); its idle and maximum session timeouts; the
               header contracts of the responses the policies granting its rules return. The service names clients
               reach it at aren't in the export: the record adds them (ciamPublishedAs).
  smRule    -> ciamPathResource below it: its resource as a path below the realm's ('*' a wildcard, '?' making it a
               regex; a regex as written, a leading copy of the realm's filter dropped), the HTTP methods among its
               actions, unprotected when its realm doesn't protect everything (xps.PROTECT_ALL false), and the access
               rules of the enabled policies granting it. A disabled rule isn't projected.
  smPolicy  -> ciamAccessRule <domain>-<policy>, allowing its user selections (a group, user, filter, or every user
               of a directory: authenticated); <domain>-<policy>-deny for the deny rules it grants. A selection of
               another kind makes the rule custom. A disabled policy isn't projected.
Every vendor name is xps.py's (unverified). The ownership rule is webaccess.projection's."""
import re

from opsdir.core.directory import children, follow, get, one, rdn_value, subtree, values
from opsdir.core.jsondata import held_json
from opsdir.domains.webaccess.express import pattern_as
from opsdir.domains.webaccess.naming import HTTP_METHODS, app_dn, resource_dn, rule_dn
from opsdir.domains.webaccess.projection import neutral_entry, projected
from .checks import realm_role
from .naming import DOMAINS, SITEMINDER
from .xps import PROTECT_ALL, SCHEME_SIGN_ONS, SUBJECT_KINDS, is_true

_SUBJECT = re.compile(r"^(.*?) (" + "|".join(SUBJECT_KINDS) + r")(?: (.*))?$")


def domain_of(d, e):
    """The policy domain a realm, a rule or a policy is in (the entry below ou=realms or ou=policies of it)."""
    return get(d, re.split(r",ou=(?:realms|policies),", e.dn, maxsplit=1, flags=re.IGNORECASE)[1])


def granting(d, realm):
    """The enabled policies of a realm's domain granting one of its enabled rules."""
    rules = {r.norm for r in children(d, realm.dn, "smRule")}
    return tuple(p for p in subtree(d, domain_of(d, realm).dn, "smPolicy") if one(p, "smEnabled") != "FALSE"
                 and any(get(d, r) is not None and get(d, r).norm in rules for r in values(p, "smRule")))


def _name(d, e):
    return f"{rdn_value(domain_of(d, e))}-{rdn_value(e)}"


def _sign_on(scheme):
    kind = (one(scheme, "smSchemeType") or "").lower() if scheme is not None else ""
    return next((v for k, v in SCHEME_SIGN_ONS if k in kind), None) if kind else None


def _app(d, realm):
    scheme = follow(d, realm, "smAuthScheme")
    headers = tuple(dict.fromkeys(r for p in granting(d, realm) for r in values(p, "smResponse")
                                  if get(d, r) is not None and "ciamHeaderContract" in get(d, r).classes))
    base = one(realm, "smResourceFilter") or "/"
    return neutral_entry(app_dn(_name(d, realm)), "ciamProtectedApp", {
        "cn": (_name(d, realm),), "ciamBasePath": (base if base.startswith("/") else "/" + base,),
        "ciamEnforcedByRole": (realm_role(d, realm),), "ciamSignOn": (_sign_on(scheme),),
        "ciamIdleTimeout": (one(realm, "smIdleTimeout"),), "ciamMaxSessionTime": (one(realm, "smMaxTimeout"),),
        "ciamSetsHeader": headers, "ciamProjectedFrom": (realm.dn,)})


def _pattern(realm, rule):
    """(match kind, pattern) of a rule's resource, relative to its realm's filter."""
    resource, base = one(rule, "smResourceFilter") or "*", (one(realm, "smResourceFilter") or "/").rstrip("/")
    if one(rule, "smRegex") == "TRUE":
        return "regex", "^" + resource[len(base) + 1:] if resource.startswith("^" + base + "/") else resource
    path = resource if resource.startswith("/") else "/" + resource
    if "?" in path:
        return "regex", "^" + ".".join(pattern_as("wildcard", p, "regex")[1:-1] for p in path.split("?")) + "$"
    return ("wildcard" if "*" in path else "prefix"), path


def _effect_rule(d, policy, rule):
    """The neutral access rule DN a policy grants a rule through: its allowing rule, or its denying one."""
    return rule_dn(_name(d, policy) + ("-deny" if one(rule, "smAllow") == "FALSE" else ""))


def _resource(d, app, realm, rule):
    kind, pattern = _pattern(realm, rule)
    unprotected = not is_true(next(iter(held_json(realm, "smConfig").get(PROTECT_ALL) or ("true",)), "true"))
    return neutral_entry(resource_dn(app.dn, rdn_value(rule)), "ciamPathResource", {
        "cn": (rdn_value(rule),), "ciamPathPattern": (pattern,), "ciamMatchKind": (kind,),
        "ciamHttpMethod": tuple(dict.fromkeys(a.upper() for a in values(rule, "smAction")
                                              if a.upper() in HTTP_METHODS)),
        "ciamAccessMode": ("unprotected" if unprotected else "standard",),
        "ciamRuleRef": tuple(dict.fromkeys(_effect_rule(d, p, rule) for p in granting(d, realm)
                                           if any(get(d, r) is not None and get(d, r).norm == rule.norm
                                                  for r in values(p, "smRule")))),
        "ciamProjectedFrom": (rule.dn,)})


def _who(subject):
    """A neutral ciamWho of a user selection ("<directory> <kind> <value>"), or None."""
    found = _SUBJECT.match(subject or "")
    if not found:
        return None
    kind = SUBJECT_KINDS[found.group(2)]
    return kind if kind == "authenticated" else (f"{kind} {found.group(3)}" if found.group(3) else None)


def _rules(d, policy):
    """The access rules a policy becomes: one per effect of the rules it grants."""
    whos = tuple(_who(s) for s in values(policy, "smSubject"))
    granted = tuple(r for r in (get(d, x) for x in values(policy, "smRule")) if r is not None)
    effects = tuple(dict.fromkeys("deny" if one(r, "smAllow") == "FALSE" else "allow" for r in granted))
    custom = None in whos
    return tuple(neutral_entry(rule_dn(_name(d, policy) + ("-deny" if e == "deny" else "")), "ciamAccessRule", {
        "cn": (_name(d, policy) + ("-deny" if e == "deny" else ""),), "ciamEffect": ("custom" if custom else e,),
        "ciamWho": () if custom else tuple(dict.fromkeys(whos)), "ciamRuleMatch": ("any",),
        "ciamIncludesRule": (), "ciamProjectedFrom": (policy.dn,)}) for e in effects)


def _actions(d, realm):
    """Notices for a realm's rules matching actions that aren't HTTP methods (events): not projected."""
    return tuple(f"realm {_name(d, realm)}: rule {rdn_value(r)} matches {', '.join(other)}, which aren't HTTP methods: "
                 "not projected (rebuild what they do in the target)"
                 for r in children(d, realm.dn, "smRule")
                 for other in (tuple(a for a in values(r, "smAction") if a.upper() not in HTTP_METHODS),) if other)


def projection(d):
    """Projected of the record's SiteMinder realms, rules and policies (d: the record as the import leaves it)."""
    realms = subtree(d, DOMAINS, "smRealm")
    apps = tuple((app, tuple(_resource(d, app, realm, r) for r in children(d, realm.dn, "smRule")
                             if one(r, "smEnabled") != "FALSE"))
                 for realm in realms for app in (_app(d, realm),))
    rules = tuple(r for p in subtree(d, DOMAINS, "smPolicy") if one(p, "smEnabled") != "FALSE" for r in _rules(d, p))
    found = projected(d, apps, rules, (SITEMINDER,), "SiteMinder")
    return found._replace(notices=(*found.notices, *(n for realm in realms for n in _actions(d, realm))))
