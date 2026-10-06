"""What copies a disk, a database or a server's data for recovery, whichever mechanism realizes it in an environment: a
snapshot policy (the cloud's own disk snapshot schedule) or a backup plan (a backup service writing to a vault). One
reader of what both say (how often, from when, how long each copy is kept, the regions it is copied to) and the
comparison a move keeps by it: as often, as long, and copied to another region where the source copies. A role is
realized by either in each environment, so a source's snapshot policy may be a target's backup plan. Pure."""
from collections import namedtuple

from ...core.changeset import set_values
from ...core.directory import one, values
from ...core.findings import Fix, Input, findings, merge_findings

POLICY, PLAN = "ciamSnapshotPolicy", "ciamBackupPlan"
DEFAULT_EVERY = 24                       # hours between copies when a policy or plan names none

# How one mechanism is described and where it keeps its schedule.
Words = namedtuple("Words", ("label", "verb", "title_verb", "one", "many", "key", "every_attr", "at_attr"))
WORDS = {POLICY: Words("Snapshot policy", "snapshots", "Snapshot", "snapshot", "snapshots", "snapshot-policy",
                       "ciamSnapshotEveryHours", "ciamSnapshotAt"),
         PLAN: Words("Backup plan", "backs up", "Back up", "recovery point", "recovery points", "backup-plan",
                     "ciamBackupEveryHours", "ciamBackupAt")}

# What a snapshot policy or backup plan says: hours between copies, the daily start (HH:MM UTC or None), days each
# copy is kept (or None) and the regions copies go to.
Schedule = namedtuple("Schedule", ("every", "at", "retention", "copies"))


def words(e):
    """How a snapshot policy or backup plan is described (by its class)."""
    return WORDS[PLAN if PLAN in e.classes else POLICY]


def schedule_of(e):
    """The Schedule a snapshot policy or backup plan states."""
    w, keep = words(e), one(e, "ciamRetentionDays")
    return Schedule(int(one(e, w.every_attr) or DEFAULT_EVERY), one(e, w.at_attr), int(keep) if keep else None,
                    tuple(values(e, "ciamCopyRegion")))


def compare_protection(ctx, sp, tp, owner, area, manual):
    """What the target's snapshot policy or backup plan (tp) loses of the source's (sp): it copies less often, keeps
    copies less long, or copies to no other region where the source does; an action with a fix each (manual: the
    steps applying it)."""
    s, t, ss, ts = words(sp), words(tp), schedule_of(sp), schedule_of(tp)
    role, src_role = one(tp, "ciamBindingRole"), one(sp, "ciamBindingRole")
    parts = []
    if ts.every > ss.every:
        parts.append(findings(
            actions=[(area, f"{t.label} `{role}` {t.verb} every {ts.every} hours in {ctx.dst.label}; `{src_role}` "
                      f"does every {ss.every} in {ctx.src.label}: a restore loses more.", owner, ctx.cutover)],
            fixes=[Fix(f"{t.key}:{role}:{t.every_attr}", area, f"{t.title_verb} every {ss.every} hours in "
                       f"{ctx.dst.label}", (set_values(tp, t.every_attr, (str(ss.every),)),), tuple(manual), ())]))
    if ss.retention and ts.retention and ts.retention < ss.retention:
        parts.append(findings(
            actions=[(area, f"{t.label} `{role}` keeps {t.many} {ts.retention} days in {ctx.dst.label}; "
                      f"`{src_role}` keeps them {ss.retention} in {ctx.src.label}: restores reach back less far.",
                      owner, ctx.cutover)],
            fixes=[Fix(f"{t.key}:{role}:ciamRetentionDays", area, f"Keep {t.many} {ss.retention} days in "
                       f"{ctx.dst.label}", (set_values(tp, "ciamRetentionDays", (str(ss.retention),)),),
                       tuple(manual), ())]))
    if ss.copies and not ts.copies:
        region = Input("ciamCopyRegion", f"the region {ctx.dst.label}'s {t.many} are copied to", (), ss.copies)
        parts.append(findings(
            actions=[(area, f"{s.label} `{src_role}` copies each {s.one} to {', '.join(ss.copies)} in "
                      f"{ctx.src.label}; `{role}` copies none in {ctx.dst.label}: losing its region loses the "
                      f"{t.many} too.", owner, ctx.cutover)],
            fixes=[Fix(f"{t.key}:{role}:ciamCopyRegion", area, f"Copy `{role}`'s {t.many} to another region in "
                       f"{ctx.dst.label}", (set_values(tp, "ciamCopyRegion", (region,)),), tuple(manual),
                       ("A copy to another region needs the disk key there (a multi-region key, or one per "
                        "region)." if t is WORDS[POLICY] else "A copy to another region needs a vault there, and "
                        "the key it encrypts with (a multi-region key, or one per region).",))]))
    return merge_findings(parts)
