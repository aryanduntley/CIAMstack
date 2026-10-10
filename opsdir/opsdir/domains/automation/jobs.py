"""Jobs: the jobs report and the planner's check. Pure.

A job runs on servers of a role (cron, timers, scheduled tasks: ciamTargetRole) or is realized in each environment by
a binding (functions, pipelines: ciamJobRole), and uses binding roles (ciamUsesRole). The check asks of the target
what the source has: servers of the job's role, a realization, the roles it uses. A role the source binds and the
target doesn't is the core binding check's; what nobody records is this check's. Hidden automation breaks silently
after a move, so a job nobody owns is an action. A job may apply only in some environments or providers'
(ciamInEnvironment, ciamOnProvider: core environment.applies_in): the check asks the target only for the jobs that
apply in the source, and names those that don't apply in the target (they won't run there).
"""
from ...core.directory import children, follow, get, one, rdn_value, values
from ...core.environment import applies_in, bound_nowhere, servers_with_role
from ...core.findings import findings, merge_findings, responsible
from ..compute.hosts import scope_text
from ..compute.workloads import kubernetes_roles
from .naming import JOBS, ON_SERVERS, REALIZED

JOBS_HEADERS = ("job", "kind", "schedule", "runs on", "applies in", "owner", "code", "uses", "found on")


def jobs(d):
    return children(d, JOBS, "ciamJob")


def runs_on(j):
    """Where a job runs, in words: the server role, the binding role that realizes it, the runners a pipeline asks
    its CI system for, or ''."""
    return (f"servers: {one(j, 'ciamTargetRole')}" if one(j, "ciamTargetRole")
            else f"binding: {one(j, 'ciamJobRole')}" if one(j, "ciamJobRole")
            else f"runners: {one(j, 'ciamRuntime')}" if one(j, "ciamJobKind") == "pipeline" and one(j, "ciamRuntime")
            else "")


def job_rows(d, dn=None):
    """One row per job: kind, schedules and triggers, where it runs, owner, code bundle, what it uses, where found."""
    def owners(j):
        return ", ".join(rdn_value(get(d, o)) for o in values(j, "ciamOwner") if get(d, o))
    return [(rdn_value(j), one(j, "ciamJobKind"), "; ".join((*values(j, "ciamSchedule"), *values(j, "ciamTrigger"))),
             runs_on(j), scope_text(d, j), owners(j),
             rdn_value(follow(d, j, "ciamCodeBundle")) if one(j, "ciamCodeBundle") else "",
             ", ".join((*values(j, "ciamUsesRole"), *(f"secret {s}" for s in values(j, "ciamSecretName")))),
             ", ".join(rdn_value(get(d, s)) for s in values(j, "ciamFoundOn") if get(d, s)))
            for j in jobs(d)]


def _job(ctx, j):
    name, kind, owner = rdn_value(j), one(j, "ciamJobKind"), responsible(ctx.d, j, ctx.dst.env)
    role, realized_by = one(j, "ciamTargetRole"), one(j, "ciamJobRole")
    nobody = bound_nowhere(values(j, "ciamUsesRole"), ctx.src, ctx.dst)
    moved = role and servers_with_role(ctx.src, role) and not servers_with_role(ctx.dst, role)
    pods = moved and role in kubernetes_roles(ctx.dst)
    blockers = (*((("Job", f"Job `{name}` runs on servers of role `{role}`, which {ctx.dst.label} "
                    + (f"runs on Kubernetes instead: run it there (a CronJob; record the role that realizes it, "
                       f"ciamJobRole) or somewhere else that reaches what it needs." if pods else "has none of."),
                    owner),) if moved else ()),
                *(("Job", f"Job `{name}` uses role `{r}`, which neither {ctx.src.label} nor {ctx.dst.label} binds.",
                   owner) for r in nobody),
                *((("Job", f"Job `{name}` is realized by role `{realized_by}`, which neither {ctx.src.label} nor "
                    f"{ctx.dst.label} binds: record where it runs.", owner),)
                  if bound_nowhere((realized_by,), ctx.src, ctx.dst) else ()))
    actions = (*((("Job", f"Job `{name}` has no owner: automation nobody owns breaks silently after a move. Name "
                   "who owns it.", owner, None),) if not values(j, "ciamOwner") else ()),
               *((("Job", f"Job `{name}` ({kind}) records neither the server role it runs on nor the role that "
                   "realizes it: record where it runs.", owner, None),)
                 if not role and not realized_by and kind in (*ON_SERVERS, *REALIZED) else ()))
    return findings(blockers=blockers, actions=actions)


def check_jobs(ctx):
    """Jobs the target can't run (no servers of their role, roles nobody binds) are blockers; jobs without an owner
    or a place to run are actions."""
    held = tuple(j for j in jobs(ctx.d) if applies_in(j, ctx.src))
    if not held:
        return findings()
    stays = [j for j in held if not applies_in(j, ctx.dst)]
    parts = merge_findings([*(_job(ctx, j) for j in held if j not in stays),
                            findings(actions=[("Job", f"Job `{rdn_value(j)}` applies in {scope_text(ctx.d, j)}, not "
                                               f"in {ctx.dst.label}: it won't run there. Scope it to "
                                               f"{ctx.dst.label} too if it should (ciamInEnvironment, "
                                               "ciamOnProvider).", responsible(ctx.d, j, ctx.dst.env), None)
                                              for j in stays])])
    if parts.blockers or parts.actions:
        return parts
    return parts._replace(ok=(*parts.ok, f"The {len(held)} job(s) have owners and run in {ctx.dst.label} on what "
                                         "they run on in the source."))
