"""Control-plane audit trails: the record of who did what to the cloud an environment runs in (CloudTrail, the Activity
Log's diagnostic setting, Cloud Audit Logs' sinks), as bindings of each environment: what a trail records (one account
or the whole organization; control-plane activity, data reads, data writes; every region or one), how well its records
are protected from alteration (integrity: the cloud's own cryptographic validation, or a locked immutable object store
keeping them, over an unlocked one, over neither), where they go (a log destination's or an object store's role, kept
for its retention) and who keeps it when the platform team doesn't (an organization trail the landing zone keeps:
ciamManagedBy). The report, the planner's check, and what the cloud adapters render and read from. Pure.

Integrity is graded, not a flag, because the clouds differ: CloudTrail signs digests of its log files (validation
detects alteration and deletion), while the Activity Log and Cloud Audit Logs have no digest and are protected by
where they are exported: a locked (compliance) immutability policy, which no one can lift, prevents both and meets the
same objective (NIST SP 800-53 AU-9, protection of audit information); an unlocked (governance) one a privileged user
can lift is weaker. A log destination (a Log Analytics workspace, a log bucket) never counts: its data can be
purged."""
from collections import namedtuple

from ...core.directory import get, one, rdn_value, subtree, values
from ...core.environment import env_model, of_class, one_role
from ...core.findings import findings, responsible
from ...core.naming import branch
from ..data.kept import lock_rank
from ..data.naming import IMMUTABILITY
from .naming import AUDIT_EVENTS, AUDIT_ROLE

AREA = "Audit"
TRAIL = "ciamAuditTrail"
INDEFINITE = 0                     # ciamRetentionDays of a destination that never expires records
AUDIT_HEADERS = ("environment", "audit trail", "scope", "records", "all regions", "integrity", "kept in",
                 "keep (days)", "kept by")
# Integrity grades: neither; an unlocked (governance) immutable store; cryptographic validation or a locked
# (compliance) immutable store.
UNPROTECTED, UNLOCKED, PROTECTED = 0, 1, 2
_LOCKED = IMMUTABILITY.index("compliance")
# What an environment's trails cover together: events recorded, whether any records every region, the best integrity
# grade any has, and the longest any destination keeps them (INDEFINITE: forever; None: not recorded).
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


def store_protection(m, trail):
    """How well the object store keeping an audit trail's records protects them: PROTECTED when it is locked
    (ciamStorageImmutability compliance), UNLOCKED when its immutability can be lifted (governance), else UNPROTECTED
    (no store, no immutability, or a log destination)."""
    dest = trail_destination(m, trail)
    rank = lock_rank(dest) if dest is not None else 0
    return PROTECTED if rank >= _LOCKED else UNLOCKED if rank > 0 else UNPROTECTED


def integrity(m, trail):
    """How well an audit trail's records are protected from alteration: PROTECTED when its integrity validation is on,
    else what its store gives (store_protection)."""
    return PROTECTED if one(trail, "ciamIntegrityValidation") == "TRUE" else store_protection(m, trail)


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
                    max((integrity(m, t) for t in trails), default=UNPROTECTED),
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
        *((_less_protected(ctx, t.integrity, s.integrity),) if t.integrity < s.integrity else ()),
        *((f"{ctx.src.label} keeps its audit records {kept} and {ctx.dst.label} {t.days} days: keep the target's at "
           "least as long.",) if _shorter(t.days, s.days) else ()))]


_PROTECTION = {PROTECTED: "cryptographic validation or a locked immutable store",
               UNLOCKED: "an immutable store whose policy a privileged user can lift"}


def _less_protected(ctx, have, need):
    """The action for a target whose audit records are less protected from alteration than the source's."""
    if have == UNLOCKED:
        return (f"{ctx.src.label}'s audit records are protected from alteration ({_PROTECTION[need]}) and "
                f"{ctx.dst.label}'s only by {_PROTECTION[UNLOCKED]}: lock the target's immutability policy "
                "(compliance), or turn on the cloud's cryptographic validation where it has one.")
    return (f"{ctx.src.label}'s audit records are protected from alteration ({_PROTECTION[need]}) and "
            f"{ctx.dst.label}'s aren't: turn on the cloud's cryptographic validation where it has one (CloudTrail log "
            "file validation), or keep the target's exported records in a locked immutable (WORM) object store.")


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


def _integrity(m, trail):
    """The report's integrity: validated, locked or unlocked immutable store, no, or '' (not recorded)."""
    if one(trail, "ciamIntegrityValidation") == "TRUE":
        return "validated"
    grade = integrity(m, trail)
    return "locked immutable store" if grade == PROTECTED else "unlocked immutable store" if grade == UNLOCKED \
        else _yes(trail, "ciamIntegrityValidation")


def audit_rows(d, dn=None):
    """One row per audit trail of every environment: scope, what it records, all regions, integrity (validated, locked
    or unlocked immutable store, no), where its records go and for how long, and who keeps it (the platform team
    unless ciamManagedBy names someone)."""
    models = [env_model(d, e.dn) for e in subtree(d, branch("environments"), "ciamEnvironment")]
    return [(m.label, rdn_value(t), one(t, "ciamAuditScope"), ", ".join(values(t, "ciamAuditEvents")),
             _yes(t, "ciamAllRegions"), _integrity(m, t), one(t, "ciamLogDestinationRole", ""),
             "" if days is None else "forever" if days == INDEFINITE else str(days),
             rdn_value(keeper) if keeper is not None else "platform")
            for m in models for t in audit_trails(m)
            for days, keeper in ((_days(trail_destination(m, t)), trail_keeper(m, t)),)]
