"""PKI planner checks: certificates that expire around cutover, and where the target keeps every key and secret."""
import datetime as dt

from ...core.directory import children, follow, get, gtime_date, one, rdn_value, referrers, values
from ...core.findings import findings, merge_findings, owner_label, responsible
from ...core.naming import env_label
from .credentials import binding_for, credentials, environment_of, material_bindings
from .naming import CERTIFICATES

# attributes through which an entry depends on a certificate (integrations; service names presenting it; host
# baselines whose truststore adds it)
CERTIFICATE_USE = ("ciamUsesCertificate", "ciamTlsCertificate", "ciamTrustsCertificate")


def _certificate_action(d, as_of, c):
    exp = gtime_date(one(c, "ciamNotAfter"))
    partner = follow(d, c, "ciamPartnerContact")
    rb = follow(d, c, "ciamRotationRunbook")
    used = list(dict.fromkeys(rdn_value(u) for attr in CERTIFICATE_USE for _, u in referrers(d, c, attr)))
    text = (f"Certificate `{rdn_value(c)}` expires {exp} ({(exp - as_of).days} days), before cutover + 30 days. "
            f"Used by: {', '.join(used) or 'nothing recorded'}."
            + (f" Coordinate with partner {rdn_value(partner)}." if partner else "")
            + (f" Runbook {rdn_value(rb)}." if rb else ""))
    return ("Certificate", text, owner_label(d, c), exp - dt.timedelta(days=30))


def check_certificates(ctx):
    """Certificates that expire before cutover (or the as-of date) + 30 days."""
    horizon = (ctx.cutover or ctx.as_of) + dt.timedelta(days=30)
    return findings(actions=[_certificate_action(ctx.d, ctx.as_of, c)
                             for c in children(ctx.d, CERTIFICATES, "ciamCertificate")
                             if gtime_date(one(c, "ciamNotAfter")) <= horizon])


# ------------------------------------------------------------------ key placement
PROTECTED_OUTSIDE_SOFTWARE = ("hsm", "managed-hsm", "external")


def _hsm(ctx, cred, t):
    """A credential that must stay in an HSM, kept in software by the target."""
    if one(cred, "ciamHsmRequired") != "TRUE" or one(t, "ciamProtectionLevel", "software") != "software":
        return findings()
    return findings(blockers=[("Key", f"`{one(cred, 'ciamBindingRole')}` must be kept in an HSM, but {ctx.dst.label} "
                               f"keeps it in software ({one(t, 'ciamRefUri')}).", responsible(ctx.d, t, ctx.dst.env))])


def _carry_over(ctx, cred, s, t):
    """The same material must reach the target: recorded as carried over, copied before cutover, or blocked when it
    can't leave the source's store."""
    role, reason = one(cred, "ciamBindingRole"), one(cred, "ciamContinuityReason")
    why = f" ({reason})" if reason else ""
    source = get(ctx.d, one(t, "ciamMaterialFrom")) if one(t, "ciamMaterialFrom") else None
    if source is not None and one(source, "ciamBindingRole") != role:
        return findings(blockers=[("Key", f"`{role}` in {ctx.dst.label} records its material as carried over from "
                                   f"`{source.dn}`, which holds `{one(source, 'ciamBindingRole')}`: the target would "
                                   "hold the wrong material. Correct ciamMaterialFrom.",
                                   responsible(ctx.d, t, ctx.dst.env))])
    if source is not None:
        return findings(ok=[f"Key `{role}` carried over from {env_label(environment_of(source))} to "
                            f"{ctx.dst.label}{why}."])
    locked = (one(cred, "ciamExportable") == "FALSE" or
              (one(s, "ciamProtectionLevel") in PROTECTED_OUTSIDE_SOFTWARE and one(cred, "ciamExportable") != "TRUE"))
    if locked:
        return findings(blockers=[("Key", f"`{role}` must be carried over to {ctx.dst.label}{why}, but its material "
                                   f"can't leave {ctx.src.label}'s store ({one(s, 'ciamRefUri')}). Plan a way to keep "
                                   f"the same key (a store both environments reach) or a coordinated re-key.",
                                   responsible(ctx.d, cred, ctx.dst.env))])
    return findings(actions=[("Key", f"Copy `{role}` from {one(s, 'ciamRefUri')} to {one(t, 'ciamRefUri')} before "
                              f"cutover{why}, and record it on the target binding (ciamMaterialFrom).",
                              responsible(ctx.d, t, ctx.dst.env), ctx.cutover)])


def _regions(n):
    return f"{n} region{'' if n == 1 else 's'}"


def _weakened(ctx, cred, s, t):
    """What the source's store does for the material that the target's doesn't: automatic rotation, replicas."""
    role = one(cred, "ciamBindingRole")
    lost = (*(("automatic rotation",) if one(s, "ciamAutoRotate") == "TRUE" and one(t, "ciamAutoRotate") != "TRUE"
              else ()),
            *((f"replicas ({_regions(len(values(s, 'ciamReplicaRegion')))} in {ctx.src.label}, "
               f"{len(values(t, 'ciamReplicaRegion'))} in {ctx.dst.label})",)
              if len(values(t, "ciamReplicaRegion")) < len(values(s, "ciamReplicaRegion")) else ()))
    return findings(actions=[("Key", f"`{role}` loses {' and '.join(lost)} in {ctx.dst.label} "
                              f"({one(t, 'ciamRefUri')}): configure the store to match, or record why not.",
                              responsible(ctx.d, t, ctx.dst.env), None)] if lost else [])


def _credential(ctx, cred):
    s, t = binding_for(ctx.src, cred), binding_for(ctx.dst, cred)
    if s is None or t is None:     # nothing to move, or a missing role (the cross-domain role check reports it)
        return findings()
    return merge_findings([_hsm(ctx, cred, t),
                           _carry_over(ctx, cred, s, t) if one(cred, "ciamContinuity") == "carry-over" else findings(),
                           _weakened(ctx, cred, s, t)])


def _undescribed(ctx, described):
    """Key material the source holds under a role no credential describes: what the target needs is unknown."""
    return findings(actions=[("Key", f"`{one(b, 'ciamBindingRole')}` holds key material in {ctx.src.label} "
                              f"({one(b, 'ciamRefUri')}) but no credential describes it, so whether {ctx.dst.label} "
                              "needs the same material or its own is unknown. Describe it under ou=credentials.",
                              responsible(ctx.d, b, ctx.src.env), None)
                             for b in material_bindings(ctx.src) if one(b, "ciamBindingRole") not in described])


def check_credentials(ctx):
    """Where the target keeps every key and secret the source holds: HSM-only material in software is a blocker;
    carry-over material is copied before cutover (a blocker when it can't leave its store, or when it is recorded as
    carried over from material of another role); a target store that drops the source's automatic rotation or
    replicas is an action; material no credential describes is an action (its continuity is unknown)."""
    creds = credentials(ctx.d)
    return merge_findings([*(_credential(ctx, c) for c in creds),
                           _undescribed(ctx, {one(c, "ciamBindingRole") for c in creds})])
