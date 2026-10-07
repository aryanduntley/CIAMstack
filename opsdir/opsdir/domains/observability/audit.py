"""Control-plane audit trails: the record of who did what to the cloud an environment runs in (CloudTrail, the Activity
Log's diagnostic setting, Cloud Audit Logs' sinks), as bindings of each environment: what a trail records (one account
or the whole organization; control-plane activity, data reads, data writes; every region or one), whether its records
can be proven unaltered, where they go (a log destination's or an object store's role, kept for its retention) and who
keeps it when the platform team doesn't (an organization trail the landing zone keeps: ciamManagedBy). The report, the
planner's check, and what the cloud adapters render and read from. Pure."""
from collections import namedtuple

from ...core.directory import get, one, rdn_value, subtree, values
from ...core.environment import env_model, of_class, one_role
from ...core.findings import findings, responsible
from ...core.naming import branch
from .naming import AUDIT_EVENTS, AUDIT_ROLE

AREA = "Audit"
TRAIL = "ciamAuditTrail"
INDEFINITE = 0                     # ciamRetentionDays of a destination that never expires records
AUDIT_HEADERS = ("environment", "audit trail", "scope", "records", "all regions", "integrity", "kept in",
                 "keep (days)", "kept by")
# What an environment's trails cover together: events recorded, whether any records every region, whether any proves
# its records unaltered, and the longest any destination keeps them (INDEFINITE: forever; None: not recorded).
Coverage = namedtuple("Coverage", ("events", "all_regions", "integrity", "days"))


def audit_trails(m):
    """Environment m's control-plane audit trails."""
    return of_class(m, TRAIL)


def audit_role(resource, roles):
    """The binding role of an audit trail a cloud reports without one (ImportKind role)."""
    return AUDIT_ROLE


def trail_keeper(m, trail):
    """The party that keeps an audit trail when the platform team doesn't (ciamManagedBy), or None."""
    ref = one(trail, "ciamManagedBy")
    return get(m.d, ref) if ref else None


def trail_destination(m, trail):
    """The binding of environment m that keeps an audit trail's records (its ciamLogDestinationRole), or None."""
    role = one(trail, "ciamLogDestinationRole")
    return one_role(m, role) if role else None


def _days(b):
    v = one(b, "ciamRetentionDays") if b is not None else None
    return int(v) if v is not None else None


def _longest(days):
    known = [d for d in days if d is not None]
    return INDEFINITE if INDEFINITE in known else max(known) if known else None


def coverage(m, trails):
    """The Coverage of environment m's trails taken together."""
    return Coverage(tuple(e for e in AUDIT_EVENTS if any(e in values(t, "ciamAuditEvents") for t in trails)),
                    any(one(t, "ciamAllRegions") == "TRUE" for t in trails),
                    any(one(t, "ciamIntegrityValidation") == "TRUE" for t in trails),
                    _longest([_days(trail_destination(m, t)) for t in trails]))


def _shorter(have, need):
    return have is not None and need is not None and have != INDEFINITE and (need == INDEFINITE or have < need)


def _weaker(ctx, src, dst, owner):
    """Actions for what the target's trails record less of than the source's."""
    s, t = coverage(ctx.src, src), coverage(ctx.dst, dst)
    lost = [e for e in s.events if e not in t.events]
    kept = "forever" if s.days == INDEFINITE else f"{s.days} days"
    return [(AREA, text, owner, ctx.cutover) for text in (
        *((f"{ctx.src.label}'s audit trails record {', '.join(lost)} activity and {ctx.dst.label}'s don't: record "
           "it in the target's trail, or decide it isn't needed there.",) if lost else ()),
        *((f"{ctx.src.label}'s audit trail records every region and {ctx.dst.label}'s records one: activity in the "
           "target's other regions would go unrecorded.",) if s.all_regions and not t.all_regions else ()),
        *((f"{ctx.src.label}'s audit records can be proven unaltered (integrity validation) and "
           f"{ctx.dst.label}'s can't: turn it on for the target's trail.",) if s.integrity and not t.integrity else ()),
        *((f"{ctx.src.label} keeps its audit records {kept} and {ctx.dst.label} {t.days} days: keep the target's at "
           "least as long.",) if _shorter(t.days, s.days) else ()))]


def _unkept(ctx, dst):
    """Blockers for the target's trails whose records go to a role it doesn't bind."""
    return [(AREA, f"Audit trail `{rdn_value(t)}` in {ctx.dst.label} sends its records to role "
                   f"`{one(t, 'ciamLogDestinationRole')}`, which {ctx.dst.label} doesn't bind: they are kept nowhere. "
                   "Record where they go.", responsible(ctx.d, t, ctx.dst.env))
            for t in dst if one(t, "ciamLogDestinationRole") and trail_destination(ctx.dst, t) is None]


def check_audit(ctx):
    """A target without a control-plane audit trail while the source keeps one, and a target trail whose records are
    kept nowhere, are blockers; a target trail recording less than the source's (activity, regions, integrity, how
    long) is an action. Nothing when neither environment records a trail."""
    src, dst = audit_trails(ctx.src), audit_trails(ctx.dst)
    if not src and not dst:
        return findings()
    owner = responsible(ctx.d, ctx.dst.env)
    if not dst:
        return findings(blockers=[(AREA, f"{ctx.src.label} keeps a control-plane audit trail "
                                         f"({', '.join(rdn_value(t) for t in src)}) and {ctx.dst.label} records none: "
                                         "who changes the target's cloud would go unrecorded. Record the target's "
                                         "trail (its own, or the organization trail the landing zone keeps).", owner)])
    blockers, actions = _unkept(ctx, dst), _weaker(ctx, src, dst, owner) if src else []
    return findings(blockers=blockers, actions=actions,
                    ok=() if blockers or actions else
                    (f"Control-plane audit trail recorded in {ctx.dst.label} ({len(dst)}).",))


def _yes(trail, attr):
    v = one(trail, attr)
    return "yes" if v == "TRUE" else "no" if v == "FALSE" else ""


def audit_rows(d, dn=None):
    """One row per audit trail of every environment: scope, what it records, all regions, integrity, where its records
    go and for how long, and who keeps it (the platform team unless ciamManagedBy names someone)."""
    models = [env_model(d, e.dn) for e in subtree(d, branch("environments"), "ciamEnvironment")]
    return [(m.label, rdn_value(t), one(t, "ciamAuditScope"), ", ".join(values(t, "ciamAuditEvents")),
             _yes(t, "ciamAllRegions"), _yes(t, "ciamIntegrityValidation"), one(t, "ciamLogDestinationRole", ""),
             "" if days is None else "forever" if days == INDEFINITE else str(days),
             rdn_value(keeper) if keeper is not None else "platform")
            for m in models for t in audit_trails(m)
            for days, keeper in ((_days(trail_destination(m, t)), trail_keeper(m, t)),)]
