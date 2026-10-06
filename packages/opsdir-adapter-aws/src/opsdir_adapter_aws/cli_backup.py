"""The AWS Backup outputs of the AWS CLI, normalized to the attribute names of the matching Terraform resources
(opsdir_adapter_aws.backups reads both). Pure.

  backup list-backup-vaults             BackupVaultList   -> aws_backup_vault, and its lock (Locked, MinRetentionDays;
                                                             a LockDate means compliance mode) as
                                                             aws_backup_vault_lock_configuration
  backup get-backup-plan                BackupPlan        -> aws_backup_plan (its rules, schedule, window, lifecycle,
                                                             copy actions)
  backup get-backup-selection           BackupSelection   -> aws_backup_selection (its tag conditions, resources)
  backup list-tags                      Tags              -> a vault's or plan's tags; the output doesn't name the
                                                             resource: save it as backup-tags/<vault or plan name>.json
"""
from .cli_outputs import documents, items, stem

KEYS = ("BackupVaultList", "BackupPlan", "BackupSelection")
TAGS = "backup-tags"            # the folder a vault's or plan's tags are saved under, by its name


def is_backup_tags(path):
    """Whether a file is a vault's or plan's tags (saved under backup-tags/)."""
    return path.startswith(f"{TAGS}/") or f"/{TAGS}/" in path


def _tags(outs):
    """{vault or plan name: tags} of the list-tags outputs saved under backup-tags/."""
    return {stem(p): doc.get("Tags") or {} for p, k, doc in outs if k == "Tags" and is_backup_tags(p)}


def _keep(lifecycle):
    return [{"delete_after": (lifecycle or {}).get("DeleteAfterDays")}] if lifecycle else []


def backup_pairs(outs):
    """The (Terraform type, attributes) pairs of the backup vaults (with their locks), plans and selections."""
    tags = _tags(outs)
    vaults = items(outs, "BackupVaultList")
    plans = [doc for _, doc in documents(outs, "BackupPlan")]
    selections = [doc for _, doc in documents(outs, "BackupSelection")]
    return [*(("aws_backup_vault", {"name": v.get("BackupVaultName"), "arn": v.get("BackupVaultArn"),
                                    "kms_key_arn": v.get("EncryptionKeyArn"),
                                    "tags": tags.get(v.get("BackupVaultName"), {})}) for v in vaults),
            *(("aws_backup_vault_lock_configuration", {
                "backup_vault_name": v.get("BackupVaultName"), "min_retention_days": v.get("MinRetentionDays"),
                "changeable_for_days": 0 if v.get("LockDate") else None})
              for v in vaults if v.get("Locked")),
            *(("aws_backup_plan", {
                "id": doc.get("BackupPlanId"), "arn": doc.get("BackupPlanArn"),
                "name": (doc.get("BackupPlan") or {}).get("BackupPlanName"),
                "tags": tags.get((doc.get("BackupPlan") or {}).get("BackupPlanName"), {}),
                "rule": [{"rule_name": r.get("RuleName"), "target_vault_name": r.get("TargetBackupVaultName"),
                          "schedule": r.get("ScheduleExpression"), "start_window": r.get("StartWindowMinutes"),
                          "lifecycle": _keep(r.get("Lifecycle")),
                          "copy_action": [{"destination_vault_arn": c.get("DestinationBackupVaultArn"),
                                           "lifecycle": _keep(c.get("Lifecycle"))}
                                          for c in r.get("CopyActions") or ()]}
                         for r in (doc.get("BackupPlan") or {}).get("Rules") or ()]})
              for doc in plans),
            *(("aws_backup_selection", {
                "id": doc.get("SelectionId"), "plan_id": doc.get("BackupPlanId"),
                "name": (doc.get("BackupSelection") or {}).get("SelectionName"),
                "iam_role_arn": (doc.get("BackupSelection") or {}).get("IamRoleArn"),
                "resources": (doc.get("BackupSelection") or {}).get("Resources") or [],
                "selection_tag": [{"type": t.get("ConditionType"), "key": t.get("ConditionKey"),
                                   "value": t.get("ConditionValue")}
                                  for t in (doc.get("BackupSelection") or {}).get("ListOfTags") or ()]})
              for doc in selections)]
