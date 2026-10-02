"""Log routes: the report and the planner's check. Pure.

A log route is intent: which logs of which server roles go where, and for how long they must be kept (an
obligation: audit logs outlive a move and the source's decommissioning). Where they go is a binding role
(ciamLogDestinationRole) each environment gives a log group, a workspace or a SIEM index, with the retention it is
provisioned with (ciamRetentionDays; 0 is indefinitely, as CloudWatch's never-expire). The target's destination
must keep them at least as long as the route requires.
"""
from ...core.directory import children, one, rdn_value, values
from ...core.environment import bound_nowhere, one_role
from ...core.findings import findings, merge_findings, responsible
from .naming import LOG_ROUTES

LOG_HEADERS = ("log route", "logs", "from", "kept by", "keep (days)", "legal hold")


def log_routes(d):
    return children(d, LOG_ROUTES, "ciamLogRoute")


def log_rows(d, dn=None):
    """One row per log route."""
    return [(rdn_value(r), ", ".join(values(r, "ciamLogKind")), ", ".join(values(r, "ciamPublishedBy")),
             one(r, "ciamLogDestinationRole"), one(r, "ciamRetentionDays") or "",
             "yes" if one(r, "ciamLegalHold") == "TRUE" else "")
            for r in log_routes(d)]


INDEFINITE = 0                                   # ciamRetentionDays of a destination that never expires logs


def _days(b):
    v = one(b, "ciamRetentionDays") if b is not None else None
    return int(v) if v is not None else None


def _short(days, need):
    return days is not None and days != INDEFINITE and days < need


def _route(ctx, r):
    name, owner, role = rdn_value(r), responsible(ctx.d, r, ctx.dst.env), one(r, "ciamLogDestinationRole")
    need = int(one(r, "ciamRetentionDays")) if one(r, "ciamRetentionDays") else None
    src, dst = (one_role(m, role) for m in (ctx.src, ctx.dst))
    have, had = _days(dst), _days(src)
    return findings(
        blockers=[*(("Logs", f"Log route `{name}` sends logs to role `{r}`, which neither {ctx.src.label} nor "
                     f"{ctx.dst.label} binds: they are kept nowhere. Record each environment's destination.", owner)
                    for r in bound_nowhere((role,), ctx.src, ctx.dst)),
                  *((("Logs", f"Log route `{name}` must keep logs {need} days; {ctx.dst.label}'s `{role}` keeps them "
                      f"{have}. Raise its retention before cutover.", owner),)
                    if need and _short(have, need) else ())],
        actions=[*((("Logs", f"Log route `{name}` must keep logs {need} days; {ctx.dst.label}'s `{role}` records no "
                     "retention. Record what it is provisioned with.", owner, None),)
                   if need and dst is not None and have is None else ()),
                 *((("Logs", f"Log route `{name}` must keep logs {need} days; {ctx.src.label}'s `{role}` keeps them "
                     f"{had} already: the obligation isn't met today.", owner, None),)
                   if need and _short(had, need) else ()),
                 *((("Logs", f"Log route `{name}` is under legal hold: {ctx.src.label}'s `{role}` must outlive the "
                     "source's decommissioning. Keep it, or move what it holds, before deleting the source.", owner,
                     None),) if one(r, "ciamLegalHold") == "TRUE" and src is not None else ())])


def check_logs(ctx):
    """Log routes kept nowhere, or kept for fewer days in the target than they must be, are blockers; a target that
    records no retention, a source already short of the obligation, and logs under legal hold the source must keep
    are actions."""
    routes = log_routes(ctx.d)
    if not routes:
        return findings()
    parts = merge_findings([_route(ctx, r) for r in routes])
    if parts.blockers or parts.actions:
        return parts
    return parts._replace(ok=(*parts.ok, f"Log routes ({len(routes)}) are kept long enough in {ctx.dst.label}."))
