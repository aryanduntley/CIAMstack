"""Log routes: the report and the planner's check. Pure.

A log route is intent: which logs of which server roles go where, and for how long they must be kept (an
obligation: audit logs outlive a move and the source's decommissioning). Where they go is a binding role
(ciamLogDestinationRole) each environment gives a log group, a workspace or a SIEM index, with the retention it is
provisioned with (ciamRetentionDays; 0 is indefinitely, as CloudWatch's never-expire). The target's destination
must keep them at least as long as the route requires.
"""
from ...core.directory import children, one, rdn_value, values
from ...core.environment import bound_nowhere, one_role
from ...core.changeset import set_values
from ...core.findings import Fix, each_checked, findings, responsible
from .naming import LOG_ROUTES
from .retention import INDEFINITE, retention_days

LOG_HEADERS = ("log route", "logs", "from", "kept by", "keep (days)", "legal hold")


def log_routes(d):
    return children(d, LOG_ROUTES, "ciamLogRoute")


def log_rows(d, dn=None):
    """One row per log route."""
    return [(rdn_value(r), ", ".join(values(r, "ciamLogKind")), ", ".join(values(r, "ciamPublishedBy")),
             one(r, "ciamLogDestinationRole"), one(r, "ciamRetentionDays") or "",
             "yes" if one(r, "ciamLegalHold") == "TRUE" else "")
            for r in log_routes(d)]


def _short(days, need):
    return days is not None and days != INDEFINITE and days < need


def _route(ctx, r):
    name, owner, role = rdn_value(r), responsible(ctx.d, r, ctx.dst.env), one(r, "ciamLogDestinationRole")
    need = int(one(r, "ciamRetentionDays")) if one(r, "ciamRetentionDays") else None
    src, dst = (one_role(m, role) for m in (ctx.src, ctx.dst))
    have, had = retention_days(dst), retention_days(src)
    return findings(
        blockers=[*(("Logs", f"Log route `{name}` sends logs to role `{r}`, which neither {ctx.src.label} nor "
                     f"{ctx.dst.label} binds: they are kept nowhere. Record each environment's destination.", owner)
                    for r in bound_nowhere((role,), ctx.src, ctx.dst)),
                  *((("Logs", f"Log route `{name}` must keep logs {need} days; {ctx.dst.label}'s `{role}` keeps them "
                      f"{have}. Raise its retention before cutover.", owner),)
                    if need and _short(have, need) else ())],
        fixes=[Fix(f"log-retention:{name}", "Logs", f"Keep {ctx.dst.label}'s `{role}` logs {need} days, as log route "
                   f"`{name}` requires", (set_values(dst, "ciamRetentionDays", (str(need),)),),
                   (f"Raise the retention of {ctx.dst.label}'s `{role}` where it is provisioned (its rendered "
                    "configuration, or by hand where nothing renders it).",),
                   ("A cloud import that reads the destination back before its retention is raised takes the value "
                    "back.",))] if need and _short(have, need) and dst is not None else [],
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
    return each_checked(routes, lambda r: _route(ctx, r),
                        f"Log routes ({len(routes)}) are kept long enough in {ctx.dst.label}.")
