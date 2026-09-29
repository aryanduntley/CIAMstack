"""Infrastructure planner checks: product versions, and external allowlists (other parties' firewalls that hold
our addresses)."""
import datetime as dt

from ...core.directory import children, follow, is_a, one, rdn_value, values
from ...core.environment import one_role
from ...core.findings import findings, merge_findings, responsible
from ...core.network import covers
from ...core.overlays import override_differences
from .naming import EXTERNAL_ALLOWLISTS


def _versions(m):
    return {one(s, "ciamProductVersion") for s in m.servers if one(s, "ciamProductVersion")}


def _unrecorded(ctx):
    """Servers with no product version: whether the move upgrades them can't be told."""
    missing = [f"{m.label} {rdn_value(s)}" for m in (ctx.src, ctx.dst) for s in m.servers
               if not one(s, "ciamProductVersion")]
    return findings(actions=[("Versions", f"No product version recorded for {', '.join(missing)}: whether the move "
                              "is a re-host or an upgrade can't be told for them.", responsible(ctx.d, ctx.dst.env),
                              None)] if missing else [])


def check_versions(ctx):
    """Same product versions in both environments is a re-host; a difference is an upgrade to test separately;
    servers with no version recorded are named."""
    sv, dv = _versions(ctx.src), _versions(ctx.dst)
    if not (ctx.src.servers or ctx.dst.servers):
        compared = findings(ok=["No servers recorded in either environment: no product versions to compare."])
    elif sv == dv:
        compared = findings(ok=[f"Same product versions in both environments "
                                f"({', '.join(sorted(sv)) or 'none recorded'}): a re-host, not an upgrade."])
    else:
        compared = findings(actions=[("Versions", f"Versions differ ({sorted(sv)} → {sorted(dv)}). Test "
                                      "compatibility separately from the move.", responsible(ctx.d, ctx.dst.env),
                                      None)])
    return merge_findings([compared, _unrecorded(ctx)])


def binding_address(b):
    """The address of one of OUR bindings as external parties would allowlist it (a service name's frontend IP, else
    the binding's range), or None when the binding records none."""
    if is_a(b, "ciamServiceName"):
        ip = one(b, "ciamFrontendIp")
        return f"{ip}/32" if ip else None
    return one(b, "ciamCidr")


def _allowlist(ctx, xa):
    role = one(xa, "ciamRefersToRole")
    b = one_role(ctx.dst, role)
    new = binding_address(b) if b is not None else None
    mgr = follow(ctx.d, xa, "ciamManagedBy")
    lead = int(one(xa, "ciamLeadTimeDays", "0"))
    if b is None:
        return findings(blockers=[("Allowlist", f"`{rdn_value(xa)}` refers to role `{role}`, which {ctx.dst.label} "
                                   "doesn't bind.", rdn_value(mgr))])
    if new is None:
        return findings(blockers=[("Allowlist", f"`{rdn_value(xa)}` refers to role `{role}`: {ctx.dst.label} binds "
                                   f"it (`{rdn_value(b)}`) but records no address for it (ciamFrontendIp or "
                                   f"ciamCidr), so what {rdn_value(mgr)} must allow is unknown.",
                                   responsible(ctx.d, b, ctx.dst.env))])
    if covers(values(xa, "ciamRecordedCidr"), new):
        return findings(ok=[f"External allowlist `{rdn_value(xa)}` ({rdn_value(mgr)}) already covers "
                            f"{ctx.dst.label}'s `{role}` ({new})."])
    by = (ctx.cutover - dt.timedelta(days=lead + 14)) if ctx.cutover else None
    late = " (**already late**)" if by is not None and by < ctx.as_of else ""
    text = (f"`{rdn_value(xa)}`: {rdn_value(mgr)} must add `{new}` ({role} in {ctx.dst.label}) to "
            f"\"{one(xa, 'ciamExternalSystem')}\". Lead time {lead} days → request by **{by}**{late}.")
    return findings(actions=[("Allowlist", text, rdn_value(mgr), by)], requests=[(mgr, xa, new, role, by)])


def check_allowlists(ctx):
    """External allowlists: other people's firewalls that contain our addresses."""
    return merge_findings([_allowlist(ctx, xa)
                           for xa in children(ctx.d, EXTERNAL_ALLOWLISTS, "ciamExternalAllowlist")])


def _shown(vals):
    return ", ".join(f"`{v}`" for v in vals) or "no value"


def _override_action(ctx, dn, attr, sv, dv, s, t):
    why = one(t, "description") if t is not None else None
    return ("Overrides", f"`{attr}` of `{dn}`: {ctx.src.label} runs {_shown(sv)}"
            f"{' (its override)' if s is not None else ' (the shared value)'}, {ctx.dst.label} runs {_shown(dv)}"
            f"{' (its override' + (': ' + why if why else '') + ')' if t is not None else ' (the shared value)'}. "
            "Confirm the target should behave differently, or align the overrides.",
            responsible(ctx.d, t, s, ctx.dst.env), None)


def check_overrides(ctx):
    """Where the two environments' overrides make them run different values of shared intent: one action each."""
    diffs = override_differences(ctx.d, ctx.src.overrides, ctx.dst.overrides)
    if not diffs:
        both = (ctx.src.overrides or ctx.dst.overrides)
        return findings(ok=[f"{ctx.src.label} and {ctx.dst.label} run the same values of shared intent "
                            f"({len(ctx.dst.overrides)} override(s) in {ctx.dst.label})."] if both else [])
    return findings(actions=[_override_action(ctx, *row) for row in diffs])
