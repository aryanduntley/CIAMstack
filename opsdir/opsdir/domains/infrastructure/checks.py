"""Infrastructure planner checks: product versions, and external allowlists (other parties' firewalls that hold
our addresses)."""
import datetime as dt

from ...core.directory import children, follow, is_a, one, rdn_value, values
from ...core.environment import one_role
from ...core.findings import findings, merge_findings, responsible
from ...core.network import covers
from .naming import EXTERNAL_ALLOWLISTS


def check_versions(ctx):
    """Same product versions in both environments is a re-host; a difference is an upgrade to test separately."""
    sv = {one(s, "ciamProductVersion") for s in ctx.src.servers}
    dv = {one(s, "ciamProductVersion") for s in ctx.dst.servers}
    if sv == dv:
        return findings(ok=[f"Same product versions in both environments ({', '.join(sorted(sv))}): "
                            "a re-host, not an upgrade."])
    return findings(actions=[("Versions", f"Versions differ ({sorted(sv)} → {sorted(dv)}). Test compatibility "
                              "separately from the move.", responsible(ctx.d, ctx.dst.env), None)])


def _role_address(m, role):
    """The address of one of OUR roles in an environment, as external parties would allowlist it."""
    b = one_role(m, role)
    if not b:
        return None
    if is_a(b, "ciamServiceName"):
        return one(b, "ciamFrontendIp") + "/32"
    return one(b, "ciamCidr")


def _allowlist(ctx, xa):
    role = one(xa, "ciamRefersToRole")
    new = _role_address(ctx.dst, role)
    mgr = follow(ctx.d, xa, "ciamManagedBy")
    lead = int(one(xa, "ciamLeadTimeDays", "0"))
    if new is None:
        return findings(blockers=[("Allowlist", f"`{rdn_value(xa)}` refers to role `{role}`, which {ctx.dst.label} "
                                   "doesn't bind.", rdn_value(mgr))])
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
