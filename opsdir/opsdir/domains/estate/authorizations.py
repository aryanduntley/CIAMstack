"""Cloud authorizations, system boundaries and control responsibilities: the authorization of each cloud offering the
estate relies on (ciamCloudAuthorization under ou=authorizations, named by its FedRAMP package id: its levels and
status, the services inside its boundary as the provider's package overview lists them, where and when that list was
taken, its customer responsibility matrix and what a customer must configure), the authorization each environment relies
on and the levels it requires (its own, and its reporting obligations': DFARS 252.204-7012 asks for FedRAMP Moderate or
equivalent), the operator's own system boundaries (ciamSystemBoundary: the SSP and the environments inside it), and who
meets each control under an authorization (ciamControlResponsibility). The planner's check, the boundary check the
cloud adapters run with the services an environment uses, the import of a package overview, and the reports. Pure.

Where the target's data is classified restricted or a level is required, a target relying on no authorization, on one
below the level or not in good standing (certified, validated, or equivalent with evidence), or using a service outside
its boundary blocks the move, as does a control the target's authorization leaves to the customer that the source's
covered (inherited or shared) and nothing meets: no implementation, exception or POA&M item. An in-scope list older than
90 days, a configuration the authorization requires that the target hasn't recorded, and a target outside the system
boundary the source is inside give actions."""
from collections import namedtuple
import datetime as dt

from ...core.contract import Imported
from ...core.directory import (date_of, get, is_a, is_kind, make_entry, merged_attrs, norm_dn, one, ou_entry,
                               rdn_value, subtree, values)
from ...core.environment import env_model
from ...core.findings import findings, responsible
from ...core.naming import SUFFIX, branch
from .incidents import obligations_of
from .naming import AUTHORIZATION_LEVELS, AUTHORIZATIONS, RESTRICTED, SCOPE_STALE_DAYS, STANDING

AREA = "Authorization"
AUTHORIZATION, BOUNDARY, RESPONSIBILITY = "ciamCloudAuthorization", "ciamSystemBoundary", "ciamControlResponsibility"
COVERED = ("inherited", "shared")
AUTHORIZATION_HEADERS = ("package", "offering", "provider", "levels", "status", "certification", "certified",
                         "in-scope services", "scope as of", "environments")
RESPONSIBILITY_HEADERS = ("authorization", "controls", "responsibility", "customer action", "met by")
# A provider's package overview, as its importer reads it: the package id, offering, provider, certification type,
# deployment model, the level it states (None: the overview states none), the services it certifies, and when it was
# last updated (GeneralizedTime or None).
CpoRow = namedtuple("CpoRow", ("package_id", "offering", "provider", "certification_type", "deployment_model", "level",
                               "services", "as_of"))
OWNED = ("cn", "ciamPackageId", "ciamOfferingName", "ciamProviderName", "ciamCertificationType", "ciamDeploymentModel",
         "ciamInScopeService", "ciamScopeAsOf", "ciamSourceUrl", "ciamRetrievedAt")


def authorization_dn(package_id):
    """DN of the authorization of a package id."""
    return f"cn={package_id},{AUTHORIZATIONS}"


def authorization_import(d, row, source=None, retrieved=None):
    """Imported: the authorization a package overview describes, what the record adds to it kept."""
    dn, held = authorization_dn(row.package_id), get(d, authorization_dn(row.package_id))
    owned = {"cn": (row.package_id,), "ciamPackageId": (row.package_id,), "ciamOfferingName": (row.offering,),
             "ciamProviderName": (row.provider,), "ciamCertificationType": (row.certification_type,),
             "ciamDeploymentModel": (row.deployment_model,), "ciamInScopeService": tuple(row.services),
             "ciamScopeAsOf": (row.as_of,), "ciamSourceUrl": (source,), "ciamRetrievedAt": (retrieved,),
             **({"ciamAuthorizationLevel": (row.level,)} if row.level else {})}
    names = (*(n for n in OWNED if not (n == "ciamSourceUrl" and source is None)
               and not (n == "ciamRetrievedAt" and retrieved is None)),
             *(("ciamAuthorizationLevel",) if row.level else ()))
    before = set(values(held, "ciamInScopeService")) if held is not None else set()
    added, removed = sorted(set(row.services) - before), sorted(before - set(row.services))
    return Imported(
        containers=(ou_entry(AUTHORIZATIONS),),
        groups=((dn, (make_entry(dn, ("top", AUTHORIZATION), merged_attrs(held, owned, names)),)),),
        notices=(f"{row.package_id} ({row.offering}): {len(row.services)} service(s) in scope",
                 *((f"{row.package_id}: added {', '.join(added)}",) if held is not None and added else ()),
                 *((f"{row.package_id}: no longer in scope: {', '.join(removed)}",) if removed else ()),
                 *((f"{row.package_id}: the overview states no level: record it (ciamAuthorizationLevel)",)
                   if not row.level and not (held is not None and values(held, "ciamAuthorizationLevel")) else ())))


def authorization_of(m):
    """The cloud authorization environment m relies on, or None."""
    ref = one(m.env, "ciamAuthorizationRef")
    e = get(m.d, ref) if ref else None
    return e if e is not None and is_a(e, AUTHORIZATION) else None


def required_levels(m):
    """The authorization levels environment m requires: its own and its reporting obligations'."""
    return tuple(dict.fromkeys((*values(m.env, "ciamRequiredAuthorization"),
                                *(v for o in obligations_of(m) for v in values(o, "ciamRequiredAuthorization")))))


def level_met(granted, required):
    """Whether granted levels meet a required one: the same program at the same or a higher level."""
    return any(required in levels and lv in levels and levels.index(lv) >= levels.index(required)
               for _, levels in AUTHORIZATION_LEVELS for lv in granted)


def held_to(m):
    """Whether environment m must rely on an authorization: a level is required or its data is restricted."""
    return bool(required_levels(m)) or one(m.env, "ciamDataClassification") == RESTRICTED


def _standing(ctx, auth, owner):
    """Blockers for the target's authorization below its levels or not in good standing."""
    cn, status = rdn_value(auth), one(auth, "ciamAuthorizationStatus")
    granted = values(auth, "ciamAuthorizationLevel")
    return [*((AREA, f"{ctx.dst.label} requires {req} and relies on `{cn}`, which grants "
                     f"{', '.join(granted) or 'no recorded level'}: rely on an authorization at that level.", owner)
              for req in required_levels(ctx.dst) if not level_met(granted, req)),
            *(((AREA, f"Authorization `{cn}` ({ctx.dst.label} relies on it) is "
                      f"{status or 'of no recorded status'}: only certified, validated or equivalent (with evidence) "
                      "authorizations count.", owner),) if status not in STANDING else ()),
            *(((AREA, f"Authorization `{cn}` is recorded as equivalent to FedRAMP Moderate with no evidence "
                      "(ciamEvidenceRef: the body of evidence DoD's equivalency policy asks for).", owner),)
              if status == "equivalent" and not values(auth, "ciamEvidenceRef") else ())]


def _boundary_dns(d, env_dn):
    return [b for b in subtree(d, SUFFIX, BOUNDARY)
            if any(norm_dn(r) == norm_dn(env_dn) for r in values(b, "ciamAffectedEnvironment"))]


def _responsibilities(d, auth):
    return [r for r in subtree(d, SUFFIX, RESPONSIBILITY) if auth is not None
            and norm_dn(one(r, "ciamAuthorizationRef") or "") == norm_dn(auth.dn)]


def _met(d, r):
    """How a customer-responsible control is met (implementation, exception, POA&M item), or None."""
    exc, item = (get(d, one(r, a)) if one(r, a) else None for a in ("ciamExceptionRef", "ciamPoamRef"))
    return ("implementation" if one(r, "ciamImplementation") else f"exception {rdn_value(exc)}" if exc is not None
            else f"POA&M {rdn_value(item)}" if item is not None else None)


def _crm_delta(ctx, src_auth, dst_auth, owner):
    """Blockers for controls the target's authorization leaves to the customer that the source's covered and nothing
    meets."""
    covered = {c for r in _responsibilities(ctx.d, src_auth) if one(r, "ciamResponsibility") in COVERED
               for c in values(r, "ciamControlRef")}
    return [(AREA, f"{', '.join(values(r, 'ciamControlRef'))} is the customer's under `{rdn_value(dst_auth)}` and was "
                   f"covered by `{rdn_value(src_auth)}`: "
                   f"{one(r, 'ciamCustomerAction') or 'the customer must meet it'}. Record how it is met "
                   "(ciamImplementation), or an exception or POA&M item.", owner)
            for r in _responsibilities(ctx.d, dst_auth) if one(r, "ciamResponsibility") == "customer"
            and set(values(r, "ciamControlRef")) & covered and _met(ctx.d, r) is None]


def check_authorization(ctx):
    """The target's cloud authorization against what it must meet (see the module). Nothing when neither environment
    names one and the target needs none."""
    src_auth, dst_auth, held = authorization_of(ctx.src), authorization_of(ctx.dst), held_to(ctx.dst)
    ref = one(ctx.dst.env, "ciamAuthorizationRef")
    if not (held or ref or src_auth is not None):
        return findings()
    owner = responsible(ctx.d, ctx.dst.env)
    missing = [] if dst_auth is not None else [(AREA, (
        f"{ctx.dst.label} names `{ref}` as its cloud authorization, which isn't one" if ref else
        f"{ctx.dst.label} relies on no cloud authorization") + (
        f" and requires {', '.join(required_levels(ctx.dst))}" if required_levels(ctx.dst) else
        f" while its data is classified {RESTRICTED}") + ": record the authorization of the offering it runs on "
        "(ciamAuthorizationRef).", owner)] if held or ref else []
    standing = _standing(ctx, dst_auth, owner) if dst_auth is not None and held else []
    as_of = date_of(dst_auth, "ciamScopeAsOf") if dst_auth is not None else None
    stale = [(AREA, f"Authorization `{rdn_value(dst_auth)}`'s in-scope service list is "
                    + (f"as of {as_of}, more than {SCOPE_STALE_DAYS} days ago" if as_of else "undated")
                    + ": import the provider's current package overview.", owner, ctx.cutover)] \
        if dst_auth is not None and values(dst_auth, "ciamInScopeService") and (
            as_of is None or (ctx.as_of - as_of).days > SCOPE_STALE_DAYS) else []
    unmet = sorted(set(values(dst_auth, "ciamRequiresConfiguration")) - set(values(ctx.dst.env, "ciamConfigurationMet"))) \
        if dst_auth is not None else []
    config = [(AREA, f"Authorization `{rdn_value(dst_auth)}` requires {c} for a customer's use to be inside its "
                     f"boundary and {ctx.dst.label} doesn't record it (ciamConfigurationMet).", owner, ctx.cutover)
              for c in unmet]
    outside = [(AREA, f"{ctx.src.label} is inside system boundary "
                      f"{', '.join(f'`{rdn_value(b)}`' for b in _boundary_dns(ctx.d, ctx.src.dn))} and {ctx.dst.label} "
                      "in none: update the system security plan to cover the target.", owner, ctx.cutover)] \
        if _boundary_dns(ctx.d, ctx.src.dn) and not _boundary_dns(ctx.d, ctx.dst.dn) else []
    crm = _crm_delta(ctx, src_auth, dst_auth, owner) if src_auth is not None and dst_auth is not None else []
    blockers, actions = [*missing, *standing, *crm], [*stale, *config, *outside]
    return findings(blockers=blockers, actions=actions,
                    ok=() if blockers or actions or dst_auth is None else
                    (f"{ctx.dst.label} relies on `{rdn_value(dst_auth)}` "
                     f"({', '.join(values(dst_auth, 'ciamAuthorizationLevel'))}).",))


def services_used(m, names, server=None):
    """((service name as the provider's package lists it, what uses it), ...) of environment m, one per service: its
    servers' (server: the name, or None) and each binding's by names {object class: a name, or a function (binding) ->
    a name or None} (the first class of names a binding is of)."""
    def name_of(b):
        found = next(((oc, n) for oc, n in names.items() if is_kind(m.d, b, oc)), None)
        n = found[1](b) if found and callable(found[1]) else found[1] if found else None
        return n
    pairs = [*(((server, f"server {rdn_value(s)}") for s in m.servers) if server else ()),
             *((n, one(b, "ciamBindingRole")) for b in m.bindings for n in (name_of(b),) if n)]
    names_ = list(dict.fromkeys(n for n, _ in pairs))
    users = {n: list(dict.fromkeys(w for x, w in pairs if x == n)) for n in names_}
    return tuple((n, ", ".join(users[n][:3]) + (f" and {len(users[n]) - 3} more" if len(users[n]) > 3 else ""))
                 for n in names_)


def in_scope(name, scope):
    """Whether a service name is in an in-scope list: listed as is, or with a qualifier a package adds in brackets or
    parentheses (Amazon CloudFront [excludes ...])."""
    return name in scope or any(s.startswith(f"{name} [") or s.startswith(f"{name} (") for s in scope)


def boundary_findings(ctx, used, covered=None):
    """The services the target uses ((name as its provider's package lists it, what uses it), ...) that its
    authorization's in-scope list lacks: blockers where the target must rely on an authorization, else actions. A
    service its provider documents as covered by a listed one (covered: {name: (listed service, the provider's
    basis)}) is in place when that one is listed."""
    auth = authorization_of(ctx.dst)
    scope = set(values(auth, "ciamInScopeService")) if auth is not None else set()
    if auth is None or not scope:
        return findings()
    unlisted = list(dict.fromkeys((name, what) for name, what in used if not in_scope(name, scope)))
    by = {name: (covered or {})[name] for name, _ in unlisted
          if name in (covered or {}) and in_scope(covered[name][0], scope)}
    outside = [(name, what) for name, what in unlisted if name not in by]
    ok = [f"{ctx.dst.label} uses {name} ({what}), which `{rdn_value(auth)}` covers as part of {by[name][0]}: "
          f"{by[name][1]}." for name, what in unlisted if name in by]
    texts = [f"{ctx.dst.label} uses {name} ({what}), which `{rdn_value(auth)}` doesn't list in its boundary (as of "
             f"{date_of(auth, 'ciamScopeAsOf') or 'its import'}): check the provider's boundary documents (its SSP), "
             "use a service in scope, or record an exception." for name, what in outside]
    owner = responsible(ctx.d, ctx.dst.env)
    return findings(blockers=[(AREA, t, owner) for t in texts] if held_to(ctx.dst) else [],
                    actions=[] if held_to(ctx.dst) else [(AREA, t, owner, ctx.cutover) for t in texts], ok=ok)


# ------------------------------------------------------------------ reports
def _environments(d, auth):
    return [env_model(d, e.dn).label for e in subtree(d, branch("environments"), "ciamEnvironment")
            if norm_dn(one(e, "ciamAuthorizationRef") or "") == norm_dn(auth.dn)]


def authorization_rows(d, dn=None, as_of=None):
    """One row per authorization: package, offering, provider, levels, status, certification, certified, how many
    services are in scope, the scope's date (stale when older than 90 days as of the day), the environments relying."""
    day = as_of or dt.date.today()
    return [(one(a, "ciamPackageId"), one(a, "ciamOfferingName", ""), one(a, "ciamProviderName", ""),
             ", ".join(values(a, "ciamAuthorizationLevel")), one(a, "ciamAuthorizationStatus", ""),
             one(a, "ciamCertificationType", ""), str(date_of(a, "ciamCertifiedAt") or ""),
             str(len(values(a, "ciamInScopeService"))),
             (f"{date_of(a, 'ciamScopeAsOf')}" + (" (stale)" if (day - date_of(a, "ciamScopeAsOf")).days >
                                                    SCOPE_STALE_DAYS else "")) if date_of(a, "ciamScopeAsOf") else "",
             ", ".join(_environments(d, a))) for a in subtree(d, SUFFIX, AUTHORIZATION)]


def responsibility_rows(d, dn=None):
    """One row per control responsibility: its authorization, controls, who meets it, what the customer must do, and
    how the operator meets it."""
    return [(rdn_value(get(d, one(r, "ciamAuthorizationRef"))) if get(d, one(r, "ciamAuthorizationRef")) is not None
             else one(r, "ciamAuthorizationRef"), ", ".join(values(r, "ciamControlRef")), one(r, "ciamResponsibility"),
             one(r, "ciamCustomerAction", ""), _met(d, r) or ("" if one(r, "ciamResponsibility") != "customer"
                                                               else "nothing recorded"))
            for r in subtree(d, SUFFIX, RESPONSIBILITY)]
