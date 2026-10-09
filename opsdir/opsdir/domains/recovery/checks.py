"""The disaster-recovery planner check. Every recovery objective holds in both environments of a move for each role it
names that they run: the best recovery point within its RPO (an action, in the target with a fix copying as often as
the RPO allows where a snapshot policy or backup plan copies the role to another region; a copy kept in the
environment's own region doesn't count, a disaster taking the region takes it too), the recovery time shown within its
RTO, and a drill's data loss within the RPO. Standbys follow the move: an environment standing by for the source, or
joining its replication deployment, is re-pointed at the target at cutover (a fix) or retired, and a target nothing
stands by for is said; a standby in its primary's region, or one without a failover runbook, is an action. A name
failing over from the source must fail over from the target after cutover. Pure."""
from ...core.changeset import set_values
from ...core.directory import date_of, norm_dn, one, rdn_value, values
from ...core.findings import Fix, findings, merge_findings, responsible
from ...core.naming import env_label
from ..data.backups import holds_role, protected_roles
from ..data.protection import schedule_of, words
from ..data.restores import tests_of
from ..edge.records import answers
from .evidence import drills_from, recovery_point, recovery_time, regional_points
from .intent import joining, minutes, objectives, primary_of, region_of, runbooks, standbys_of

AREA = "Disaster recovery"
LINKS = ("ciamStandbyOf", "ciamJoinsDeploymentOf")      # what ties an environment to the one it recovers or copies


def _is(m, other):
    return norm_dn(m.dn) == norm_dn(other.dn)


def _interval_fixes(ctx, role, rpo, name):
    """Fixes making each target snapshot policy or backup plan copying a role to another region copy as often as an RPO
    of an hour or more allows."""
    hours = rpo // 60
    return tuple(Fix(f"recovery:{name}:{one(p, 'ciamBindingRole')}:{words(p).every_attr}", AREA,
                     f"{words(p).title_verb} `{role}` every {'hour' if hours == 1 else f'{hours} hours'} in "
                     f"{ctx.dst.label}",
                     (set_values(p, words(p).every_attr, (str(hours),)),), (),
                     ("The cloud's service may not copy that often: check the shortest interval it allows.",))
                 for p in protected_roles(ctx.dst).get(role, ())
                 if hours and schedule_of(p).every > hours
                 and any(r != region_of(ctx.d, ctx.dst.dn) for r in schedule_of(p).copies)) if rpo >= 60 else ()


def _rpo(ctx, o, m, role):
    rpo, name = minutes(o, "ciamRpoMinutes"), rdn_value(o)
    point = recovery_point(ctx.d, m, role)
    if rpo is None or (point is not None and point.minutes <= rpo):
        return findings()
    local = regional_points(ctx.d, m, role)
    now = (f"its best recovery point is {point.how} ({point.minutes} minutes)" if point else
           f"nothing copies it out of its region ({'; '.join(e.how for e in local)} stays there): a disaster taking "
           "the region loses all of it" if local else "nothing copies it: a disaster loses all of it")
    return findings(actions=[(AREA, f"Recovery objective `{name}` allows `{role}` to lose {rpo} minutes of changes; "
                                    f"in {m.label} {now}.", responsible(ctx.d, o, m.env), ctx.cutover)],
                    fixes=_interval_fixes(ctx, role, rpo, name) if _is(m, ctx.dst) else ())


def _rto(ctx, o, m, role):
    rto, name = minutes(o, "ciamRtoMinutes"), rdn_value(o)
    took = recovery_time(ctx.d, m, role)
    untested = not any(one(t, "ciamTestResult") == "passed" for t in tests_of(ctx.d, m.dn, role))
    if rto is None or (took is not None and took.minutes <= rto) or \
            (took is None and role in protected_roles(m) and untested):      # the restore-test check asks for one
        return findings()
    now = (f"its {took.how} took {took.minutes} minutes" if took else
           "no restore test or failover drill records how long recovering it takes")
    return findings(actions=[(AREA, f"Recovery objective `{name}` wants `{role}` back within {rto} minutes; in "
                                    f"{m.label} {now}.", responsible(ctx.d, o, m.env), ctx.cutover)])


def _loss(ctx, o, m, role):
    rpo, name = minutes(o, "ciamRpoMinutes"), rdn_value(o)
    drill = next((e for e in drills_from(ctx.d, m.dn, role) if one(e, "ciamDrillResult") == "passed"), None)
    lost = minutes(drill, "ciamDataLossMinutes")
    if rpo is None or lost is None or lost <= rpo:
        return findings()
    return findings(actions=[(AREA, f"The failover drill from {m.label} on {date_of(drill, 'ciamDrilledOn')} lost "
                                    f"{lost} minutes of `{role}`'s changes; recovery objective `{name}` allows {rpo}.",
                              responsible(ctx.d, o, m.env), ctx.cutover)])


def _objective(ctx, o):
    roles = [r for r in values(o, "ciamRecoversRole") if holds_role(ctx.src, r)]
    held = [(m, r) for r in roles for m in (ctx.src, ctx.dst) if _is(m, ctx.src) or holds_role(ctx.dst, r)]
    unrecovered = [] if not roles or runbooks(ctx.d, o) else [findings(actions=[(
        AREA, f"Recovery objective `{rdn_value(o)}` names no runbook that recovers "
              f"{', '.join(f'`{r}`' for r in roles)} "
              "(ciamRunbookRef).", responsible(ctx.d, o, ctx.src.env), ctx.cutover)])]
    return merge_findings([*(f(ctx, o, m, r) for m, r in held for f in (_rpo, _rto, _loss)), *unrecovered])


def repoint_fix(ctx, env):
    """The Fix re-pointing an environment that stands by for the source, or joins its replication deployment, at the
    target."""
    label = env_label(env.dn)
    records = tuple(set_values(env, a, (ctx.dst.dn,)) for a in LINKS
                    if norm_dn(one(env, a) or "") == norm_dn(ctx.src.dn))
    return Fix(f"recovery:repoint:{label}", AREA, f"Re-point {label} at {ctx.dst.label}", records,
               (f"At cutover, re-point {label}'s replication at {ctx.dst.label} (its replicas re-initialise from "
                f"{ctx.dst.label}'s deployment) and update its failover runbook.",),
               (f"Applied before cutover, the record says {label} follows {ctx.dst.label} while {ctx.src.label} still "
                "serves.",))


def _where(d, e):
    mode, region = one(e, "ciamStandbyMode"), region_of(d, e.dn)
    return ", ".join(x for x in (mode, region) if x)


def _moved(ctx, e, ours):
    """An environment standing by for the source or joining its deployment: what happens to it at cutover."""
    d, label, src, dst = ctx.d, env_label(e.dn), ctx.src.label, ctx.dst.label
    primary = primary_of(d, e)
    if primary is not None and norm_dn(primary.dn) == norm_dn(ctx.src.dn):
        text = (f"{label} stands by for {src} ({_where(d, e)}); nothing stands by for {dst}: after cutover a disaster "
                f"there has nowhere to fail over to. Re-point {label} at {dst}, or build a standby for it."
                if not ours else
                f"{label} stands by for {src}: at cutover re-point it at {dst} or retire it ({dst} has "
                f"{', '.join(env_label(s.dn) for s in ours)}).")
    else:
        text = (f"{label}'s replicas join {src}'s replication deployment: at cutover re-point them at {dst}, or they "
                "replicate from a deployment being retired.")
    return findings(actions=[(AREA, text, responsible(d, e), ctx.cutover)], fixes=[repoint_fix(ctx, e)])


def _standby(ctx, e):
    """A standby (of either environment) in its primary's region, or without a failover runbook."""
    d, label = ctx.d, env_label(e.dn)
    primary = primary_of(d, e)
    here, there = region_of(d, e.dn), region_of(d, primary.dn) if primary is not None else None
    found = []
    if here and here == there:
        found.append((AREA, f"{label} stands by for {env_label(primary.dn)} in the same region ({here}): a disaster "
                            "in that region takes both.", responsible(d, e), ctx.cutover))
    if not runbooks(d, e):
        found.append((AREA, f"No runbook says how to fail over to {label}"
                            f"{f' from {env_label(primary.dn)}' if primary is not None else ''} (ciamRunbookRef on "
                            "its environment).", responsible(d, e), ctx.cutover))
    return findings(actions=found)


def _standbys(ctx):
    d, ours = ctx.d, standbys_of(ctx.d, ctx.dst.dn)
    theirs = standbys_of(d, ctx.src.dn)
    moving = {e.norm: e for e in (*theirs, *joining(d, ctx.src.dn)) if e.norm != norm_dn(ctx.dst.dn)}
    every = {e.norm: e for e in (*theirs, *ours)}
    return merge_findings([*(_moved(ctx, e, ours) for e in moving.values()),
                           *(_standby(ctx, e) for e in every.values())])


def _dns(ctx):
    """Names failing over from the source (its answer the primary): the target's answer must be after cutover."""
    names = sorted({(one(b, "ciamFqdn") or one(b, "ciamRecordName") or "").lower() for b in ctx.src.bindings
                    if one(b, "ciamRoutingPolicy") == "failover-primary"})
    return findings(actions=[
        (AREA, f"`{n}` fails over from {ctx.src.label} (the primary) to "
               f"{', '.join(a.label for a in answers(ctx.d, n) if a.label != ctx.src.label) or 'nothing'}: at cutover "
               f"make {ctx.dst.label}'s answer the primary (ciamRoutingPolicy failover-primary) and retire "
               f"{ctx.src.label}'s.", responsible(ctx.d, ctx.dst.env), ctx.cutover) for n in names])


def check_recovery(ctx):
    """Recovery objectives in both environments, standbys at cutover, failover routing from the source."""
    goals = [o for o in objectives(ctx.d) if any(holds_role(ctx.src, r) for r in values(o, "ciamRecoversRole"))]
    parts = merge_findings([*(_objective(ctx, o) for o in goals), _standbys(ctx), _dns(ctx)])
    if goals and not (parts.blockers or parts.actions):
        return parts._replace(ok=(*parts.ok, f"{len(goals)} recovery objective(s) met in {ctx.src.label} and "
                                             f"{ctx.dst.label}."))
    return parts
