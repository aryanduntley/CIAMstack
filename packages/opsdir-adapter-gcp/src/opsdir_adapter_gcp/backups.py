"""Google Cloud: backup vaults and backup plans (opsdir.domains.data.backups), rendered as Backup and DR and read back.
Pure.

  each backup vault the stack keeps: a google_backup_dr_backup_vault ciam-<env>-<name> in the copy region of the
  plans writing to it (a vault in another region is how Backup and DR copies a disk's backups there), else the
  environment's region; its lock as backup_minimum_enforced_retention_duration (its lock days; a day when nothing is
  locked, the least Backup and DR takes); labelled name and role. A compliance lock's effective time (after which
  the minimum can't be lowered) is a comment: it is a date the operator sets
  each backup plan the stack keeps: a google_backup_dr_backup_plan for disks (compute.googleapis.com/Disk) in the
  environment's region (a plan lives where the disks it backs up are) with one backup rule (backup_rule: its
  retention, which must be at least its vault's minimum, else the plan is a comment; a standard schedule HOURLY
  every ciamBackupEveryHours (6 to 23) or DAILY, in UTC,
  its window from ciamBackupAt for ciamBackupWindowHours), and a google_backup_dr_backup_plan_association per disk of
  the volumes it protects (its protected roles that are volumes, and the volumes naming it). Several copy regions:
  the first is the vault's, the rest a comment; a protected role that isn't a volume a comment
  One someone else keeps is a comment naming them; an adopted one an import block.

Read back from (google type, attributes) pairs, Terraform state as it is or Cloud Asset Inventory and gcloud
normalized to it (backup_attributes): Backup and DR vaults named by their label name (else their id), the minimum
enforced retention as their lock (governance, compliance once its effective time passed) and lock days, restoring in
another region when a plan in another location writes to it; plans named by their id: schedule, window, retention,
the vault's location as their copy region when it differs, their vault; the roles (label role) of the disks their
associations name; a new plan's role is its id (plans carry no labels in Terraform); the associations link the
disks' volumes to the plan (disk_plans). Vaults, plans and associations being deleted, deleted or inactive (their
state) are named, not read.
"""
import re

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import of_class, servers_with_role
from opsdir.core.inventory import of_types, resource
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.governance.keepers import is_rendered
from opsdir.domains.data.backups import VAULT, plan_vault
from opsdir.domains.data.protection import PLAN, schedule_of
from opsdir.domains.data.volumes import VOLUME, volume_policy
from opsdir.domains.network.plumbing import adopted
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_import, tf_name
from opsdir_format_terraform.state import blocks, first_block
from .names import REGION, label, name_parts, resource_id, state_labels

DAY = 86400
# what Backup and DR's items are: (kind, Cloud Asset Inventory asset type), (kind, the collection in their names)
BACKUP_ASSETS = (("backup-vault", "BackupVault"), ("backup-plan", "BackupPlan"),
                 ("backup-plan-association", "BackupPlanAssociation"))
BACKUP_COLLECTIONS = (("backup-vault", "backupVaults"), ("backup-plan", "backupPlans"),
                      ("backup-plan-association", "backupPlanAssociations"))
DISKS = "compute.googleapis.com/Disk"
HOURLY = range(6, 24)              # the hours an HOURLY schedule takes: six at least (Google's console guide)
GONE = ("DELETING", "DELETED", "INACTIVE")    # states of an item that isn't there to back anything up any more
WINDOW = 6                         # backup window hours when the record names none


def _seconds(text):
    m = re.match(r"^(\d+)s$", text or "")
    return int(m.group(1)) if m else None


def backup_rule(p):
    """The Block of plan p's backup rule, or None when its interval isn't hourly (6 to 23 hours) or daily."""
    s = schedule_of(p)
    if s.every != 24 and s.every not in HOURLY:
        return None
    start = int((s.at or "00:00")[:2])
    window = int(one(p, "ciamBackupWindowHours") or WINDOW)
    return Block((("rule_id", "ciam"), ("backup_retention_days", s.retention or 1),
                  ("standard_schedule", Block((
                      ("recurrence_type", "DAILY" if s.every == 24 else "HOURLY"),
                      *((("hourly_frequency", s.every),) if s.every != 24 else ()), ("time_zone", "UTC"),
                      ("backup_window", Block((("start_hour_of_day", start),
                                               ("end_hour_of_day", min(start + window, 24))))))))))


def rule_schedule(schedule):
    """(every hours, HH:MM, window hours) of a standard schedule (Terraform's or the API's names)."""
    kind = schedule.get("recurrence_type") or schedule.get("recurrenceType")
    window = first_block(schedule.get("backup_window")) or schedule.get("backupWindow") or {}
    start = window.get("start_hour_of_day", window.get("startHourOfDay"))
    end = window.get("end_hour_of_day", window.get("endHourOfDay"))
    every = 24 if kind == "DAILY" else (schedule.get("hourly_frequency") or schedule.get("hourlyFrequency")) \
        if kind == "HOURLY" else None
    return ((int(every) if every else None), (f"{int(start):02d}:00" if start is not None else None),
            (int(end) - int(start) if start is not None and end is not None else None))


def _labels(b):
    return {"name": label(rdn_value(b)), "role": label(one(b, "ciamBindingRole")), "managed_by": "opsdir"}


def _location(m, v):
    """Where vault v is: the copy region of the plans writing to it (the first), else the environment's region."""
    copies = [r for p in of_class(m, PLAN) if one(p, "ciamBackupVaultRole") == one(v, "ciamBindingRole")
              for r in values(p, "ciamCopyRegion")[:1]]
    return copies[0] if copies else REGION


def vault_notes(m, v):
    """The render notes (actions) of a backup vault: a compliance lock takes effect at a date someone sets (its
    effective_time); cross-region restore needs the region named in its plans' copy regions (else it stays in the
    environment's region)."""
    subject = f"Vault '{rdn_value(v)}'"
    return (*((note("Backups", "action", subject, "a compliance lock is the vault's effective_time (after it, the "
                    "minimum can't be lowered): set the date when it takes effect",
                    ("Set the vault's effective_time to the date its lock takes effect, by hand, once its retention is "
                     "confirmed",), v.dn),) if (one(v, "ciamStorageImmutability") or "none") == "compliance" else ()),
            *((note("Backups", "action", f"{subject} restores in another region through its location", "name the "
                    "region in its plans' ciamCopyRegion",
                    (f"Record the region it restores in as its plans' ciamCopyRegion, {RECORD}",), v.dn),)
              if one(v, "ciamCrossRegionRestore") == "TRUE" and _location(m, v) == REGION else ()))


def plan_note(m, p):
    """The render note of a backup plan Backup and DR can't take as recorded (a blocker: not rendered), or None: its
    vault isn't one this render writes, an interval it doesn't offer, or a retention below its vault's lock
    (refused)."""
    s, v, subject = schedule_of(p), plan_vault(m, p), f"Backup plan '{rdn_value(p)}'"
    if v is None or not is_rendered(m, v):
        return note("Backups", "blocker", subject, f"its vault (role {one(p, 'ciamBackupVaultRole')}) isn't one this "
                    "environment's render writes: not rendered",
                    (f"Bind {one(p, 'ciamBackupVaultRole')} to a backup vault this environment keeps, {RECORD}",), p.dn)
    if backup_rule(p) is None:
        return note("Backups", "blocker", subject, f"Backup and DR backs up every 6 to 23 hours or daily, not every "
                    f"{s.every} hours: not rendered", (f"Record an interval Backup and DR takes, {RECORD}",), p.dn)
    minimum = int(one(v, "ciamStorageLockDays") or 1) if (one(v, "ciamStorageImmutability") or "none") != "none" else 1
    if (s.retention or 1) < minimum:
        return note("Backups", "blocker", subject, f"keeps backups {s.retention} days, less than its vault enforces "
                    f"({minimum}), which Backup and DR refuses: not rendered",
                    (f"Record a retention of at least {minimum} days, or a shorter vault lock, {RECORD}",), p.dn)
    return None


def copies_note(p):
    """The render note of a rendered backup plan's copy regions past its vault's location (a blocker: the rest
    aren't rendered), or None."""
    s = schedule_of(p)
    if len(s.copies) <= 1:
        return None
    return note("Backups", "blocker", f"Backup plan '{rdn_value(p)}'", f"copies go to its vault's location, "
                f"{s.copies[0]}; {', '.join(s.copies[1:])} not rendered",
                (f"Record one copy region per plan, a plan per region with a vault there, {RECORD}",), p.dn)


def backup_notes(m):
    """The render notes of environment m's backup vaults and plans (render_backups writes their comments)."""
    return (*(n for v in of_class(m, VAULT) for n in vault_notes(m, v)),
            *(n for p in of_class(m, PLAN) for n in ((plan_note(m, p),) if plan_note(m, p) else (copies_note(p),))
              if n is not None))


def _vault(m, v):
    n, mode = tf_name(rdn_value(v)), one(v, "ciamStorageImmutability") or "none"
    days = int(one(v, "ciamStorageLockDays") or 1) if mode != "none" else 1
    return (*((comment(f"Vault '{rdn_value(v)}': nothing locked; Backup and DR enforces at least a day"),)
              if mode == "none" else ()),
            *(comment(note_comment(x)) for x in vault_notes(m, v)),
            tf_block("resource", ["google_backup_dr_backup_vault", n], [
                ("location", _location(m, v)), ("backup_vault_id", label(f"ciam-{rdn_value(m.env)}-{rdn_value(v)}")),
                ("backup_minimum_enforced_retention_duration", f"{days * DAY}s"), ("labels", _labels(v))]),
            *((tf_import(f"google_backup_dr_backup_vault.{n}", resource_id(one(v, "ciamProviderRef"))),)
              if adopted(v) else ()))


def _volumes(m, p):
    protects = set(values(p, "ciamProtectsRole"))
    return tuple(v for v in of_class(m, VOLUME) if one(v, "ciamVolumeKind") == "data"
                 and (one(v, "ciamBindingRole") in protects or getattr(volume_policy(m, v), "dn", None) == p.dn))


def _plan(m, p):
    n, v, rule = tf_name(rdn_value(p)), plan_vault(m, p), backup_rule(p)
    missing, copies = plan_note(m, p), copies_note(p)
    if missing is not None:
        return (comment(note_comment(missing)),)
    volumes = _volumes(m, p)
    others = [r for r in values(p, "ciamProtectsRole") if r not in {one(x, "ciamBindingRole") for x in volumes}]
    plan = f"google_backup_dr_backup_plan.{n}"
    return (*((comment(note_comment(copies)),) if copies is not None else ()),
            *(comment(f"Backup plan '{rdn_value(p)}' protects {r}, which isn't a volume: not rendered here")
              for r in others),
            tf_block("resource", ["google_backup_dr_backup_plan", n], [
                ("location", REGION), ("backup_plan_id", label(rdn_value(p))), ("resource_type", DISKS),
                ("backup_vault", ref(f"google_backup_dr_backup_vault.{tf_name(rdn_value(v))}.id")),
                ("backup_rules", rule)]),
            *(tf_block("resource", ["google_backup_dr_backup_plan_association", f"{n}_{dn}"], [
                ("location", REGION), ("backup_plan_association_id", label(f"{rdn_value(srv)}-{rdn_value(vol)}")),
                ("resource", ref(f"google_compute_disk.{dn}.id")), ("resource_type", DISKS),
                ("backup_plan", ref(f"{plan}.name"))])
              for vol in volumes if is_rendered(m, vol) for srv in servers_with_role(m, one(vol, "ciamTargetRole"))
              for dn in (tf_name(f"{rdn_value(srv)}_{rdn_value(vol)}"),)),
            *((tf_import(plan, resource_id(one(p, "ciamProviderRef"))),) if adopted(p) else ()))


def render_backups(m):
    """HCL for environment m's backup vaults and plans (whoever keeps them), each stamped with its entry (the render
    places it by its keeper; a plan reads a vault or disks another root writes through inputs)."""
    vaults, plans = of_class(m, VAULT), of_class(m, PLAN)
    return (*(x for v in vaults for x in from_entry(v.dn, _vault(m, v))),
            *(x for p in plans for x in from_entry(p.dn, _plan(m, p))))


# ------------------------------------------------------------------ read back
def _last(ref_):
    return (ref_ or "").rsplit("/", 1)[-1]


def backup_attributes(kind, d):
    """(google type, attributes) of a Backup and DR item as Cloud Asset Inventory or gcloud prints it."""
    rid = resource_id(d.get("name"))
    if kind == "backup-vault":
        return "google_backup_dr_backup_vault", {
            "id": rid, "name": rid, "location": name_parts(rid).get("locations"), "labels": d.get("labels") or {},
            "state": d.get("state"),
            "backup_minimum_enforced_retention_duration": d.get("backupMinimumEnforcedRetentionDuration"),
            "effective_time": d.get("effectiveTime")}
    if kind == "backup-plan":
        return "google_backup_dr_backup_plan", {
            "id": rid, "name": rid, "location": name_parts(rid).get("locations"),
            "resource_type": d.get("resourceType"),
            "backup_vault": resource_id(d.get("backupVault")), "state": d.get("state"),
            "backup_rules": [{"rule_id": r.get("ruleId"), "backup_retention_days": r.get("backupRetentionDays"),
                              "standard_schedule": [r.get("standardSchedule") or {}]}
                             for r in d.get("backupRules") or ()]}
    return "google_backup_dr_backup_plan_association", {
        "id": rid, "name": rid, "location": name_parts(rid).get("locations"),
        "resource": resource_id(d.get("resource")),
        "resource_type": d.get("resourceType"), "backup_plan": resource_id(d.get("backupPlan")),
        "state": d.get("state")}


def _live(a):
    """Whether a Backup and DR item is there to back something up (not being deleted, deleted or inactive)."""
    return (a.get("state") or "ACTIVE") not in GONE


def _gone(pairs, kind, what):
    return [f"{what} {_last(resource_id(a.get('id') or a.get('name')))}: {a.get('state')}; not read"
            for a in of_types(pairs, kind) if not _live(a)]


def disk_plans(pairs):
    """{disk name: the id of the backup plan an association puts it in}."""
    plans = {_last(a.get("id") or a.get("name")): resource_id(a.get("id") or a.get("name"))
             for a in of_types(pairs, "google_backup_dr_backup_plan")}
    return {_last(a.get("resource")): plans.get(_last(a.get("backup_plan")), resource_id(a.get("backup_plan")))
            for a in of_types(pairs, "google_backup_dr_backup_plan_association")
            if (a.get("resource_type") or DISKS) == DISKS and a.get("resource") and _live(a)}   # a type may be left out


def backup_resources(pairs):
    """(backup vault and plan resources, notices) of (google type, attributes) pairs."""
    disks = {d.get("name") or _last(d.get("id")): d.get("labels") or {} for d in of_types(pairs, "google_compute_disk")}
    plans = [a for a in of_types(pairs, "google_backup_dr_backup_plan") if (a.get("id") or a.get("name")) and _live(a)]
    associated = disk_plans(pairs)
    vault_of = {_last(a.get("backup_vault")): a.get("location") for a in plans}
    vaults = []
    for a in of_types(pairs, "google_backup_dr_backup_vault"):
        if not _live(a):
            continue
        vid = resource_id(a.get("id") or a.get("name"))
        days = (_seconds(a.get("backup_minimum_enforced_retention_duration")) or 0) // DAY
        elsewhere = [loc for v, loc in vault_of.items() if v == _last(vid) and loc and loc != a.get("location")]
        vaults.append(resource("backup-vault", vid, {
            "ciamStorageImmutability": ("compliance" if a.get("effective_time") else "governance")
            if days > 1 else "none",
            "ciamStorageLockDays": days if days > 1 else None,
            "ciamCrossRegionRestore": "TRUE" if elsewhere else "FALSE"},
            name=(a.get("labels") or {}).get("name") or _last(vid), role=(a.get("labels") or {}).get("role"),
            tags=state_labels(a)))
    locations = {_last(resource_id(a.get("id") or a.get("name"))): a.get("location")
                 for a in of_types(pairs, "google_backup_dr_backup_vault")}
    found = []
    notices = [*_gone(pairs, "google_backup_dr_backup_vault", "backup vault"),
               *_gone(pairs, "google_backup_dr_backup_plan", "backup plan"),
               *_gone(pairs, "google_backup_dr_backup_plan_association", "backup plan association")]
    for a in plans:
        pid = resource_id(a.get("id") or a.get("name"))
        rules = blocks(a.get("backup_rules"))
        if len(rules) > 1:
            notices.append(f"backup plan {_last(pid)}: {len(rules)} backup rules; the first is read")
        rule = rules[0] if rules else {}
        every, at, window = rule_schedule(first_block(rule.get("standard_schedule")))
        backed = [disks.get(d, {}) for d, plan in associated.items() if _last(plan) == _last(pid)]
        there = locations.get(_last(a.get("backup_vault")))
        found.append(resource("backup-plan", pid, {
            "ciamBackupEveryHours": every, "ciamBackupAt": at,
            "ciamBackupWindowHours": window if window != WINDOW else None,      # the default isn't recorded
            "ciamRetentionDays": rule.get("backup_retention_days"),
            "ciamCopyRegion": there if there and there != a.get("location") else None,
            "ciamProtectsRole": sorted({t.get("role") for t in backed if t.get("role")})},
            links={"ciamBackupVaultRole": resource_id(a.get("backup_vault"))}, name=_last(pid),
            role=_last(pid)))           # Terraform gives plans no labels: a new one's role is its id
    return (*vaults, *found), tuple(notices)
