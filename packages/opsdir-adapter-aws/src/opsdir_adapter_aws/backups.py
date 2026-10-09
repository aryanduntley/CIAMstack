"""AWS: backup vaults and backup plans (opsdir.domains.data.backups), rendered as AWS Backup Terraform and read back.
Pure.

  each backup vault the stack keeps: an aws_backup_vault ciam-<env>-<name> encrypted with its key role's KMS key
  (AWS Backup's own key when it names none, said), tagged Name and Role; its lock an
  aws_backup_vault_lock_configuration (min_retention_days its lock days; compliance with changeable_for_days 3, the
  grace AWS gives before a compliance lock can't be changed or removed; governance without one). Restoring in another
  region is the copies' job on AWS (a plan's copy rule to a vault there): a vault saying it restores elsewhere is a
  comment
  each backup plan the stack keeps: an aws_backup_plan ciam-<env>-<name> with one rule into its vault (backup_cron:
  every ciamBackupEveryHours from ciamBackupAt; start_window from ciamBackupWindowHours; delete_after its retention;
  a copy_action per ciamCopyRegion to the vault there, whose ARN is an input, kept as long), tagged Name and Role; and
  an aws_backup_selection choosing every resource tagged Role = a role it protects (volumes, databases and instances
  are tagged so), AWS Backup's IAM role an input
  One someone else keeps is a comment naming them; an adopted one an import block.

Read back from (Terraform type, attributes) pairs, Terraform state as it is or the CLI normalized to it
(cli_backup.py): aws_backup_vault as backup vaults named by their tag Name (else their name), the lock configuration
of each as its lock (compliance when it has a grace, governance otherwise), its key as its key role; aws_backup_plan
as backup plans (its first rule: schedule, start window, retention, the regions its copies go to, its vault) with the
roles its selections' Role tags choose. A plan with several rules, a selection choosing resources by ARN only: named.
"""
import re

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import UNBOUND, of_class, secret
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.data.backups import VAULT, plan_vault
from opsdir.domains.data.protection import PLAN, schedule_of
from opsdir.domains.network.plumbing import adopted
from opsdir.domains.network.stack import kept_by, owned
from opsdir_format_terraform.hcl import Block, block, import_block, ref, tf_name
from opsdir_format_terraform.state import blocks, first_block
from .tags import state_tags as _cloud_tags

BACKUP_ROLE = "backup_iam_role_arn"
COMPLIANCE_GRACE = 3            # days AWS requires before a compliance lock can't be changed (the minimum)
# what backup_cron writes (and the like: either of day-of-month and day-of-week may be the '?'): every few hours or
# daily from a start, or every few days
_HOURLY = re.compile(r"^cron\((\d{1,2}) (\d{1,2})(?:/(\d{1,2}))? [?*] \* [?*] \*\)$")
_DAYS = re.compile(r"^cron\((\d{1,2}) (\d{1,2}) \*/(\d+) \* \? \*\)$")


def backup_cron(every, at):
    """AWS Backup's schedule expression for every hours from at (HH:MM UTC): daily, every few hours from the start, or
    every few days; None when it can't say it (hours that aren't a whole number of days beyond 24)."""
    hour, minute = (int(x) for x in (at or "00:00").split(":"))
    if every == 24:
        return f"cron({minute} {hour} ? * * *)"
    if every < 24:
        return f"cron({minute} {hour}/{every} ? * * *)"
    return f"cron({minute} {hour} */{every // 24} * ? *)" if every % 24 == 0 else None


def cron_schedule(expression):
    """(every hours, HH:MM) of an AWS Backup cron expression like backup_cron's; (None, None) for another."""
    hourly, days = _HOURLY.match(expression or ""), _DAYS.match(expression or "")
    if hourly:
        minute, hour, step = int(hourly.group(1)), int(hourly.group(2)), hourly.group(3)
        return (int(step) if step else 24), f"{hour:02d}:{minute:02d}"
    if days:
        return int(days.group(3)) * 24, f"{int(days.group(2)):02d}:{int(days.group(1)):02d}"
    return None, None


def _tags(b):
    return {"Name": rdn_value(b), "Role": one(b, "ciamBindingRole"), "ManagedBy": "opsdir"}


def _name(m, b):
    return f"ciam-{rdn_value(m.env)}-{rdn_value(b)}"


def _vault(m, v):
    n, key_role = tf_name(rdn_value(v)), one(v, "ciamEncryptedByRole")
    uri = secret(m, key_role) if key_role else None
    mode, days = one(v, "ciamStorageImmutability") or "none", one(v, "ciamStorageLockDays")
    return (*((f"# Vault '{rdn_value(v)}': AWS Backup's own key encrypts it (it names no key role)",) if not key_role
              else (f"# Vault '{rdn_value(v)}': {UNBOUND}{key_role}: no key binding for role {key_role} in this "
                    "environment",) if uri is None else ()),
            *((f"# Vault '{rdn_value(v)}' restores in another region through the plans' copies to a vault there",)
              if one(v, "ciamCrossRegionRestore") == "TRUE" else ()),
            block("resource", ["aws_backup_vault", n], [
                ("name", _name(m, v)), *((("kms_key_arn", uri.split("://", 1)[1]),) if uri else ()),
                ("tags", _tags(v))]),
            *((block("resource", ["aws_backup_vault_lock_configuration", n], [
                ("backup_vault_name", ref(f"aws_backup_vault.{n}.name")),
                *((("min_retention_days", int(days)),) if days else ()),
                *((("changeable_for_days", COMPLIANCE_GRACE),) if mode == "compliance" else ())]),)
              if mode in ("governance", "compliance") else ()),
            *((import_block(f"aws_backup_vault.{n}", one(v, "ciamProviderRef").rsplit(":", 1)[1]),)
              if adopted(v) else ()))


def _copy(p, region):
    var = f"{tf_name(rdn_value(p))}_{tf_name(region)}_vault_arn"
    return ref(f"var.{var}"), block("variable", [var], [
        ("type", ref("string")), ("description", f"The backup vault in {region} the copies of {rdn_value(p)} go to")])


def _plan(m, p):
    n, s = tf_name(rdn_value(p)), schedule_of(p)
    cron, v = backup_cron(s.every, s.at), plan_vault(m, p)
    if cron is None:
        return (f"# Backup plan '{rdn_value(p)}': AWS Backup schedules by cron; every {s.every} hours isn't a whole "
                "number of days: not rendered",)
    target = (ref(f"aws_backup_vault.{tf_name(rdn_value(v))}.name") if v is not None and owned(v) else
              one(v, "ciamProviderRef").rsplit(":", 1)[1] if v is not None and one(v, "ciamProviderRef") else None)
    if target is None:
        return (f"# Backup plan '{rdn_value(p)}': {UNBOUND}{one(p, 'ciamBackupVaultRole')}: no backup vault "
                f"binding for role {one(p, 'ciamBackupVaultRole')} in this environment: not rendered",)
    copies = [(region, *_copy(p, region)) for region in s.copies]
    keep = Block((("delete_after", s.retention),)) if s.retention else None
    window = one(p, "ciamBackupWindowHours")
    return (*(var for _, _, var in copies),
            block("resource", ["aws_backup_plan", n], [
                ("name", _name(m, p)),
                ("rule", Block((
                    ("rule_name", tf_name(rdn_value(p))), ("target_vault_name", target), ("schedule", cron),
                    *((("start_window", int(window) * 60),) if window else ()),
                    *((("lifecycle", keep),) if keep else ()),
                    *(("copy_action", Block((("destination_vault_arn", arn),
                                             *((("lifecycle", keep),) if keep else ()))))
                      for _, arn, _ in copies)))),
                ("tags", _tags(p))]),
            block("resource", ["aws_backup_selection", n], [
                ("name", _name(m, p)), ("iam_role_arn", ref(f"var.{BACKUP_ROLE}")),
                ("plan_id", ref(f"aws_backup_plan.{n}.id")),
                *(("selection_tag", Block((("type", "STRINGEQUALS"), ("key", "Role"), ("value", role))))
                  for role in values(p, "ciamProtectsRole"))]),
            *((import_block(f"aws_backup_plan.{n}", one(p, "ciamProviderRef").rsplit(":", 1)[1]),)
              if adopted(p) else ()))


def render_backups(m):
    """HCL for environment m's backup vaults and plans: comments naming who keeps the others, then those the stack
    keeps (AWS Backup's IAM role an input)."""
    vaults, plans = of_class(m, VAULT), of_class(m, PLAN)
    kept = [b for b in (*vaults, *plans) if not owned(b)]
    return (*(f"# Backup {'vault' if b in vaults else 'plan'} '{rdn_value(b)}' (role {one(b, 'ciamBindingRole')}) is "
              f"kept by {kept_by(m, b)}: not rendered here" for b in kept),
            *((block("variable", [BACKUP_ROLE], [
                ("type", ref("string")),
                ("description", "The IAM role AWS Backup backs up and restores with (AWSBackupDefaultServiceRole)")]),)
              if any(owned(p) for p in plans) else ()),
            *(x for v in vaults if owned(v) for x in _vault(m, v)),
            *(x for p in plans if owned(p) for x in _plan(m, p)))


# ------------------------------------------------------------------ read back
def _locks(pairs):
    """{vault name: (mode, min retention days)} of the vaults' lock configurations."""
    return {a.get("backup_vault_name"): ("compliance" if a.get("changeable_for_days") is not None else "governance",
                                         a.get("min_retention_days"))
            for a in of_types(pairs, "aws_backup_vault_lock_configuration") if a.get("backup_vault_name")}


def backup_resources(pairs):
    """(backup vault and plan resources, notices) of (Terraform type, attributes) pairs."""
    locks, notices = _locks(pairs), []
    vaults = [a for a in of_types(pairs, "aws_backup_vault") if a.get("arn")]
    arn_of = {a.get("name"): a.get("arn") for a in vaults}
    found = [resource("backup-vault", a["arn"], {
                 "ciamStorageImmutability": locks.get(a.get("name"), ("none",))[0],
                 "ciamStorageLockDays": locks.get(a.get("name"), (None, None))[1]},
                 links={"ciamEncryptedByRole": a.get("kms_key_arn")},
                 name=_cloud_tags(a).get("Name") or a.get("name"), role=tagged_role(_cloud_tags(a)),
                 tags=_cloud_tags(a))
             for a in vaults]
    for a in of_types(pairs, "aws_backup_plan"):
        name, rules = _cloud_tags(a).get("Name") or a.get("name"), blocks(a.get("rule"))
        if not a.get("arn") or not rules:
            continue
        if len(rules) > 1:
            notices.append(f"backup plan {name}: {len(rules)} rules; the first is read")
        rule = rules[0]
        every, at = cron_schedule(rule.get("schedule"))
        if every is None:
            notices.append(f"backup plan {name}: schedule {rule.get('schedule')} isn't one this adapter reads; its "
                           "frequency not read")
        selections = [s for s in of_types(pairs, "aws_backup_selection") if s.get("plan_id") == a.get("id")]
        notices += [f"backup plan {name}: selection {s.get('name')} chooses resources by ARN, not by tag Role: "
                    "what it protects not read"
                    for s in selections if s.get("resources") and not blocks(s.get("selection_tag"))]
        window = rule.get("start_window")
        found.append(resource("backup-plan", a["arn"], {
            "ciamBackupEveryHours": every, "ciamBackupAt": at,
            "ciamBackupWindowHours": int(window) // 60 if window and int(window) % 60 == 0 else None,
            "ciamRetentionDays": first_block(rule.get("lifecycle")).get("delete_after"),
            "ciamCopyRegion": [c.get("destination_vault_arn", "").split(":")[3] for c in blocks(rule.get("copy_action"))
                               if c.get("destination_vault_arn", "").count(":") >= 3],
            "ciamProtectsRole": [t.get("value") for s in selections for t in blocks(s.get("selection_tag"))
                                 if t.get("key") == "Role"]},
            links={"ciamBackupVaultRole": arn_of.get(rule.get("target_vault_name"))},
            name=name, role=tagged_role(_cloud_tags(a)), tags=_cloud_tags(a)))
    return tuple(found), tuple(notices)
