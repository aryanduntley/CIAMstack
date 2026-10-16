"""PingAccess planner check: whether what PingAccess protects can work in the target. Pure.

Blockers: a web session signing users in as a client no integration in the record is, with an OpenID provider that is
no identity service's issuer, authenticating to the token endpoint in a way its integration isn't registered for, or
sending no PKCE challenge where its integration requires one; withheld secrets no credential role supplies, or whose
role the target doesn't bind; an object naming one the record doesn't hold (PingAccess refuses it); a virtual host's
service name role or a site's application role the target doesn't bind; a target that runs no engine.
Actions: an implicit-flow login (POST, x_post); a site sending requests to fixed hosts from every environment (fix:
record them as an external system's role); a header an identity mapping sets that no header contract names (fix:
record it, so the edge's header check guards it). The environment-bound objects to create in the target reach the
plan as the render's note (render.render_notes).
Fix: a protected application the source enforces and nothing in the target would (the web access domain's blocker)
can be taken over by PingAccess when the target runs its engines (protect:pa/<application>); what PingAccess can't
express of it reaches the plan as the render's notes (takeover.py).
"""
from opsdir.core.changeset import new_entry
from opsdir.core.directory import children, follow, get, one, rdn_value, referrers, values
from opsdir.core.environment import bound_nowhere, one_role
from opsdir.core.findings import Fix, findings, merge_findings, responsible
from opsdir.core.jsondata import held_json
from opsdir.domains.compute.workloads import runs_here
from opsdir.domains.edge.naming import HEADER_CONTRACTS
from opsdir.domains.federation.services import identity_services
from opsdir.domains.infrastructure.external import external_hosts_fix
from opsdir.domains.webaccess.apps import enforcer, protected_apps
from opsdir.domains.webaccess.checks import protect_fix
from .api import (ATTRIBUTE_FIELD, AUTH_METHODS, CLIENT_ID, CREDENTIALS_TYPE, HEADER_FIELDS, IMPLICIT_LOGINS,
                  LOGIN_TYPE, NO_PKCE, PKCE, TARGETS)
from .naming import ENGINE, KINDS
from .refs import leaves
from .render import environment_bound, missing_references, rendered

AREA = "PingAccess"
IMPORTER = "pingaccess/admin-api"


def _at(value, path):
    found = leaves(value, path)
    return found[0] if found else None


def _owner(ctx, *entries):
    return responsible(ctx.d, *entries, ctx.dst.env)


def _apps_using(d, e):
    """The applications whose settings name an entry."""
    return tuple(sorted({a.dn: a for _, a in referrers(d, e.dn, "paUses") if "paApplication" in a.classes}.values(),
                        key=rdn_value))


def session_problems(d, s):
    """Why a web session can't sign users in anywhere, in words."""
    config = held_json(s, "paConfig")
    integration = follow(d, s, "paIntegration")
    client = one(integration, "ciamClientId") if integration is not None else _at(config, CLIENT_ID)
    issuers = {one(x, "ciamOidcIssuer") for x in identity_services(d) if one(x, "ciamOidcIssuer")}
    kind = _at(config, CREDENTIALS_TYPE)
    allowed = AUTH_METHODS.get(kind, ())
    registered = values(integration, "ciamTokenAuthMethod") if integration is not None else ()
    pkce = integration is not None and one(integration, "ciamPkceRequired") == "TRUE" and config.get(PKCE) in NO_PKCE
    return (*((f"it signs users in as client `{client}`, which no integration in the record is",)
              if integration is None else ()),
            *((f"it trusts {one(s, 'paIssuer')}, which is no identity service's issuer in the record",)
              if one(s, "paIssuer") and one(s, "paIssuer") not in issuers else ()),
            *((f"it authenticates to the token endpoint as {' or '.join(allowed)} ({kind}), but integration "
               f"`{rdn_value(integration)}` is registered for {', '.join(registered)}: the token request fails",)
              if allowed and registered and not set(allowed) & set(registered) else ()),
            *((f"integration `{rdn_value(integration)}` requires PKCE and the session sends no challenge "
               f"({PKCE} {config.get(PKCE) or 'unset'})",) if pkce else ()))


def _session(ctx, s):
    name, why = rdn_value(s), session_problems(ctx.d, s)
    owner = _owner(ctx, s, *_apps_using(ctx.d, s))
    login = held_json(s, "paConfig").get(LOGIN_TYPE)
    return findings(
        blockers=[(AREA, f"Web session `{name}` can't sign users in: {'; '.join(why)}.", owner)] if why else [],
        actions=[(AREA, f"Web session `{name}` signs users in with the implicit flow ({LOGIN_TYPE} {login}): move it "
                  "to the authorization code flow (Code), which the record's OpenID Connect registrations render.",
                  owner, ctx.cutover)] if login in IMPLICIT_LOGINS else [])


def _secrets(ctx, c, e):
    role = one(e, "paCredentialRole")
    owner = _owner(ctx, e)
    if not values(e, "paWithheld"):
        return findings()
    if not role:
        return findings(blockers=[(AREA, f"`{c.path} {rdn_value(e)}` holds secrets no credential role supplies "
                                   "(paCredentialRole): its request carries ${withheld}.", owner)])
    return findings(blockers=[(AREA, f"`{c.path} {rdn_value(e)}` takes its secrets from role `{role}`, which "
                               f"{ctx.dst.label} doesn't bind.", owner)] if bound_nowhere((role,), ctx.dst) else [])


def _references(ctx, c, e):
    missing = missing_references(ctx.d, e)
    return findings(blockers=[(AREA, f"`{c.path} {rdn_value(e)}` names {', '.join(missing)}, which the record doesn't "
                               "hold: PingAccess refuses it until it is recorded.", _owner(ctx, e))] if missing else [])


def _virtual_host(ctx, v):
    role = one(v, "paServiceRole")
    apps = ", ".join(f"`{rdn_value(a)}`" for a in _apps_using(ctx.d, v)) or "no application"
    return findings(blockers=[(AREA, f"Virtual host `{rdn_value(v)}` answers as role `{role}`, which "
                               f"{ctx.dst.label} doesn't bind: {apps} can't be reached there.",
                               _owner(ctx, v, *_apps_using(ctx.d, v)))]) if bound_nowhere((role,), ctx.dst) \
        else findings()


def _site(ctx, s):
    name, role = rdn_value(s), one(s, "paBackendRole")
    owner = _owner(ctx, s, *_apps_using(ctx.d, s))
    if role:
        return findings(blockers=[(AREA, f"Site `{name}` sends requests to role `{role}`, which {ctx.dst.label} "
                                   "doesn't bind.", owner)]) if bound_nowhere((role,), ctx.dst) else findings()
    targets = tuple(t for t in held_json(s, "paConfig").get(TARGETS) or () if isinstance(t, str))
    if not targets:
        return findings()
    fix = external_hosts_fix(ctx.src, targets, f"PingAccess site `{name}`", f"external-host:pa-site/{name}",
                             IMPORTER)
    return findings(actions=[(AREA, f"Site `{name}` sends requests to {', '.join(f'`{t}`' for t in targets)} from "
                              f"every environment (no service name role): confirm {ctx.dst.label} can reach them, "
                              "or record the application's role.", owner, ctx.cutover)],
                    fixes=[fix] if fix else [])


def _backend_roles(ctx, m):
    """The server roles behind the applications an identity mapping's headers reach (their sites' service names)."""
    roles = (one(s, "paBackendRole") for a in _apps_using(ctx.d, m) for dn in values(a, "paUses")
             for s in (get(ctx.d, dn),) if s is not None and "paSite" in s.classes)
    return tuple(dict.fromkeys(one(b, "ciamTargetRole") for r in roles if r
                               for b in (one_role(ctx.src, r),) if b is not None and one(b, "ciamTargetRole")))


def header_fix(ctx, m, header):
    """The Fix recording a header contract for a header an identity mapping sets: header-based sign-on, set by the
    engines, trusted by the servers behind the applications using it."""
    config = held_json(m, "paConfig")
    attribute = next((x.get(ATTRIBUTE_FIELD) for x in leaves(config, ("configuration", "attributeHeaderMappings", "*"))
                      if isinstance(x, dict) and x.get("headerName") == header), None)
    slug = f"pa-{rdn_value(m)}-{header}".lower()
    owners = values(m, "ciamOwner") or tuple(o for a in _apps_using(ctx.d, m) for o in values(a, "ciamOwner"))
    attrs = {"cn": (slug,), "ciamHeaderName": (header,), "ciamHeaderKind": ("identity",), "ciamSetByRole": (ENGINE,),
             **({"ciamTrustedByRole": _backend_roles(ctx, m)} if _backend_roles(ctx, m) else {}),
             **({"ciamHeaderValue": (f"attribute {attribute}",)} if attribute else {}),
             **({"ciamOwner": tuple(dict.fromkeys(owners))} if owners else {})}
    container = () if get(ctx.d, HEADER_CONTRACTS) is not None else (
        new_entry(HEADER_CONTRACTS, ("top", "organizationalUnit"), {"ou": ("header-contracts",)}),)
    return Fix(f"header-contract:pa/{rdn_value(m)}/{header}", "Edge",
               f"Record header contract `{slug}` for `{header}`, which PingAccess's identity mapping "
               f"`{rdn_value(m)}` sets", (*container, new_entry(f"cn={slug},{HEADER_CONTRACTS}",
                                                                ("top", "ciamObject", "ciamHeaderContract"), attrs)),
               (), ("Set ciamStripsInbound only once PingAccess is confirmed to remove the header from incoming "
                    "requests: until then the edge's check names it as spoofable.",))


def _mapping(ctx, m):
    config = held_json(m, "paConfig")
    headers = tuple(dict.fromkeys(h for p in HEADER_FIELDS for h in leaves(config, p) if isinstance(h, str)))
    named = {(one(get(ctx.d, c), "ciamHeaderName") or "").lower() for c in values(m, "paHeaderContract")
             if get(ctx.d, c) is not None}
    missing = tuple(h for h in headers if h.lower() not in named)
    return findings(actions=[(AREA, f"Identity mapping `{rdn_value(m)}` sets header `{h}`, which no header contract "
                              "names: record who sets and trusts it, so the edge's checks guard it.",
                              _owner(ctx, m, *_apps_using(ctx.d, m)), ctx.cutover) for h in missing],
                    fixes=[header_fix(ctx, m, h) for h in missing])


def _unprotected(ctx):
    """The protected applications the source enforces and the target's enforcing role doesn't run there."""
    return tuple(a for a in protected_apps(ctx.src.d) for src, dst in ((enforcer(ctx.src, a), enforcer(ctx.dst, a)),)
                 if src and runs_here(ctx.src, src) and not (dst and runs_here(ctx.dst, dst)))


def _protect(ctx):
    """The fixes having PingAccess's engines protect, in the target, what nothing there would."""
    return findings(fixes=[protect_fix(ctx.dst, a, ENGINE, "PingAccess", "pa") for a in _unprotected(ctx)]) \
        if runs_here(ctx.dst, ENGINE) else findings()


def check_pingaccess(ctx):
    """What PingAccess protects, and whether it can work in the target; the fixes having it protect what nothing in
    the target would."""
    d = ctx.d
    objects = rendered(d)
    if not objects and not environment_bound(d):
        return _protect(ctx)
    sessions = children(d, KINDS["web-session"][0], "paWebSession")
    engines = findings(blockers=[(AREA, f"{ctx.dst.label} runs no PingAccess engine (`{ENGINE}`): the "
                                  f"{len(children(d, KINDS['application'][0], 'paApplication'))} applications it "
                                  "protects would go unprotected.", _owner(ctx))]) \
        if not runs_here(ctx.dst, ENGINE) else findings()
    found = merge_findings([engines, _protect(ctx),
                            *(_session(ctx, s) for s in sessions),
                            *(_secrets(ctx, c, e) for c, e in objects),
                            *(_references(ctx, c, e) for c, e in objects),
                            *(_virtual_host(ctx, v) for v in children(d, KINDS["virtual-host"][0], "paVirtualHost")
                              if one(v, "paServiceRole")),
                            *(_site(ctx, s) for s in children(d, KINDS["site"][0], "paSite")),
                            *(_mapping(ctx, m) for m in children(d, KINDS["identity-mapping"][0],
                                                                 "paIdentityMapping"))])
    counted = "The web session signs" if len(sessions) == 1 else f"All {len(sessions)} web sessions sign"
    return found if found.blockers or not sessions else found._replace(
        ok=(*found.ok, f"{counted} users in with clients and OpenID providers the record has."))
