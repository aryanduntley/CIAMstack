"""Infrastructure planner checks: product versions, and external allowlists (other parties' firewalls that hold
our addresses)."""
import datetime as dt

from ...core.changeset import delete_entry, new_entry, set_values
from ...core.directory import children, follow, get, is_a, one, rdn_value, values
from ...core.environment import one_role
from ...core.findings import Fix, Option, findings, merge_findings, responsible
from ...core.network import covers
from ...core.overlays import override_differences
from ..compute.workloads import product_versions, workload_binding, workloads
from .naming import EXTERNAL_ALLOWLISTS


def _versions(m):
    return set(product_versions(m))


def _unrecorded(ctx):
    """Servers and workload bindings with no product version: whether the move upgrades them can't be told."""
    missing = [*(f"{m.label} {rdn_value(s)}" for m in (ctx.src, ctx.dst) for s in m.servers
                 if not one(s, "ciamProductVersion")),
               *(f"{m.label} workload {rdn_value(w)}" for m in (ctx.src, ctx.dst) for w in workloads(m.d)
                 for b in (workload_binding(m, w),) if b is not None and not one(b, "ciamProductVersion"))]
    return findings(actions=[("Versions", f"No product version recorded for {', '.join(missing)}: whether the move "
                              "is a re-host or an upgrade can't be told for them.", responsible(ctx.d, ctx.dst.env),
                              None)] if missing else [])


def check_versions(ctx):
    """Same product versions in both environments (their servers' and workload bindings') is a re-host; a difference
    is an upgrade to test separately; servers and workload bindings with no version recorded are named."""
    sv, dv = _versions(ctx.src), _versions(ctx.dst)
    if not (ctx.src.servers or ctx.dst.servers or sv or dv):
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


SERVER_INPUTS = (("ciamImageRef", "image"), ("ciamInstanceSize", "size"))   # what a server's render can't do without


def check_server_inputs(ctx):
    """Blockers for the target's servers that record no image or size: their render writes UNBOUND values, so
    applying it fails."""
    m = ctx.dst
    return findings(blockers=[
        ("Servers", f"Server `{rdn_value(s)}` in {m.label} records no {' or '.join(missing)} "
         f"({', '.join(a for a, w in SERVER_INPUTS if w in missing)}): its render writes UNBOUND values there, so "
         "applying it fails. Record them.", responsible(ctx.d, s, m.env))
        for s in m.servers for missing in ([w for a, w in SERVER_INPUTS if not one(s, a)],) if missing])


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


def _owns(m, entry):
    """Whether an override is environment m's own (not inherited from the environment it overlays)."""
    return entry is not None and entry.dn.lower().endswith("," + m.dn.lower())


def override_fix(ctx, dn, attr, sv, dv, s, t):
    """The Fix aligning one attribute the overrides make differ: run what the source runs (the target's own override
    deleted, set to the source's values, or created, never an inherited one changed), or, when both override it, run
    the shared value; a person chooses, since the difference may be meant."""
    own, home = _owns(ctx.dst, t), f"ou=overrides,{ctx.dst.dn}"
    created = (*((new_entry(home, ("top", "organizationalUnit"), {"ou": ("overrides",)}),)
                 if get(ctx.d, home) is None else ()),
               new_entry(f"cn={rdn_value(s or t)},{home}", ("top", "ciamOverride"), {
                   "cn": (rdn_value(s or t),), "ciamOverrides": (dn,), "ciamOverrideAttribute": (attr,),
                   "ciamOverrideValue": tuple(sv), "description": (f"as {ctx.src.label} runs it",)}))
    like_source = ((delete_entry(t),) if own and s is None else
                   (set_values(t, "ciamOverrideValue", sv),) if own else created)
    options = (Option("source", f"run {_shown(sv)}, as {ctx.src.label} does", like_source, ()),
               *((Option("shared", "run the shared value (the target's override deleted)", (delete_entry(t),),
                         (f"{ctx.src.label} still runs its own override, so they keep differing.",)),)
                 if own and s is not None else ()))
    return Fix(f"override:{dn.split(',', 1)[0].split('=', 1)[1]}:{attr}", "Overrides",
               f"Align `{attr}` of `{dn}` in {ctx.dst.label}", (), (f"Render {ctx.dst.label} again.",),
               ("The difference may be meant (an override's description says why): aligning erases it.",), options)


def check_overrides(ctx):
    """Where the two environments' overrides make them run different values of shared intent: one action each, with
    the fix aligning it (a choice)."""
    diffs = override_differences(ctx.d, ctx.src.overrides, ctx.dst.overrides)
    if not diffs:
        both = (ctx.src.overrides or ctx.dst.overrides)
        return findings(ok=[f"{ctx.src.label} and {ctx.dst.label} run the same values of shared intent "
                            f"({len(ctx.dst.overrides)} override(s) in {ctx.dst.label})."] if both else [])
    return findings(actions=[_override_action(ctx, *row) for row in diffs],
                    fixes=[override_fix(ctx, *row) for row in diffs])
