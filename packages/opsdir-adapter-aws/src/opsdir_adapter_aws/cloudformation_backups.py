"""Volumes and what protects them, as CloudFormation stacks declare them, normalized to the Terraform attribute names
the shared mapping reads (opsdir_adapter_aws.volumes.volume_resources, backups.backup_resources). Properties come
resolved (Ref to physical IDs, Fn::GetAtt where it follows from one). Pure.

  AWS::EC2::Volume, AWS::EC2::VolumeAttachment   -> aws_ebs_volume, aws_volume_attachment
  AWS::DLM::LifecyclePolicy                      -> aws_dlm_lifecycle_policy
  AWS::Backup::BackupVault                       -> aws_backup_vault (+ its LockConfiguration as
                                                    aws_backup_vault_lock_configuration)
  AWS::Backup::BackupPlan, BackupSelection       -> aws_backup_plan, aws_backup_selection
"""
from .cloudformation_values import number, tag_map, truth

BACKUP_TYPES = ("AWS::EC2::Volume", "AWS::EC2::VolumeAttachment", "AWS::DLM::LifecyclePolicy",
                "AWS::Backup::BackupVault", "AWS::Backup::BackupPlan", "AWS::Backup::BackupSelection")
_LIFECYCLE = {"delete_after": "DeleteAfterDays", "cold_storage_after": "MoveToColdStorageAfterDays"}


def _of(declared, type_):
    return [(lid, p, pid) for lid, t, p, _, pid in declared if t == type_]


def _renamed(p, names):
    """{Terraform attribute: the property it is} of the properties p gives (numbers as numbers)."""
    return {tf: number(p[cfn]) for tf, cfn in names.items() if p.get(cfn) is not None}


def _volumes(declared):
    return [*(("aws_ebs_volume", {"id": pid, **_renamed(p, {
                  "availability_zone": "AvailabilityZone", "size": "Size", "type": "VolumeType", "iops": "Iops",
                  "throughput": "Throughput", "kms_key_id": "KmsKeyId", "snapshot_id": "SnapshotId"}),
                  "encrypted": truth(p.get("Encrypted")), "tags": tag_map(p.get("Tags"))})
              for _, p, pid in _of(declared, "AWS::EC2::Volume")),
            *(("aws_volume_attachment", {"id": pid, "volume_id": p.get("VolumeId"), "instance_id": p.get("InstanceId"),
                                         "device_name": p.get("Device")})
              for _, p, pid in _of(declared, "AWS::EC2::VolumeAttachment"))]


def _schedule(s):
    """A Lifecycle Manager schedule as the Terraform block (rules as one-element lists)."""
    return {"name": s.get("Name"), "copy_tags": truth(s.get("CopyTags")),
            "tags_to_add": tag_map(s.get("TagsToAdd")),
            "create_rule": [_renamed(s.get("CreateRule") or {}, {
                "interval": "Interval", "interval_unit": "IntervalUnit", "times": "Times",
                "cron_expression": "CronExpression", "location": "Location"})],
            "retain_rule": [_renamed(s.get("RetainRule") or {}, {"count": "Count", "interval": "Interval",
                                                                 "interval_unit": "IntervalUnit"})],
            "cross_region_copy_rule": [{**_renamed(c, {"target": "Target", "cmk_arn": "CmkArn"}),
                                        "encrypted": truth(c.get("Encrypted")), "copy_tags": truth(c.get("CopyTags")),
                                        "retain_rule": [_renamed(c.get("RetainRule") or {}, {
                                            "interval": "Interval", "interval_unit": "IntervalUnit"})]}
                                       for c in s.get("CrossRegionCopyRules") or ()]}


def _snapshot_policies(declared, names):
    return [("aws_dlm_lifecycle_policy", {
        "id": pid, "arn": names.get(f"{lid}.Arn"), "description": p.get("Description"),
        "execution_role_arn": p.get("ExecutionRoleArn"), "state": p.get("State"), "tags": tag_map(p.get("Tags")),
        "policy_details": [{"resource_types": d.get("ResourceTypes") or [], "policy_type": d.get("PolicyType"),
                            "target_tags": tag_map(d.get("TargetTags")),
                            "schedule": [_schedule(s) for s in d.get("Schedules") or ()]}
                           for d in (p.get("PolicyDetails") or {},)]})
        for lid, p, pid in _of(declared, "AWS::DLM::LifecyclePolicy")]


def _vaults(declared, names):
    vaults = [(lid, p, p.get("BackupVaultName") or pid) for lid, p, pid in _of(declared, "AWS::Backup::BackupVault")]
    return [*(("aws_backup_vault", {"id": name, "name": name, "arn": names.get(f"{lid}.BackupVaultArn"),
                                    "kms_key_arn": p.get("EncryptionKeyArn"), "tags": p.get("BackupVaultTags") or {}})
              for lid, p, name in vaults),
            *(("aws_backup_vault_lock_configuration", {"backup_vault_name": name, **_renamed(
                p["LockConfiguration"], {"min_retention_days": "MinRetentionDays",
                                         "max_retention_days": "MaxRetentionDays",
                                         "changeable_for_days": "ChangeableForDays"})})
              for _, p, name in vaults if p.get("LockConfiguration"))]


def _rule(r):
    """A backup plan rule as the Terraform block (lifecycles and copy actions as lists)."""
    return {**_renamed(r, {"rule_name": "RuleName", "target_vault_name": "TargetBackupVault",
                           "schedule": "ScheduleExpression",
                           "schedule_expression_timezone": "ScheduleExpressionTimezone",
                           "start_window": "StartWindowMinutes", "completion_window": "CompletionWindowMinutes"}),
            "enable_continuous_backup": truth(r.get("EnableContinuousBackup")),
            "recovery_point_tags": r.get("RecoveryPointTags") or {},
            "lifecycle": [_renamed(r["Lifecycle"], _LIFECYCLE)] if r.get("Lifecycle") else [],
            "copy_action": [{**_renamed(c, {"destination_vault_arn": "DestinationBackupVaultArn"}),
                             "lifecycle": [_renamed(c["Lifecycle"], _LIFECYCLE)] if c.get("Lifecycle") else []}
                            for c in r.get("CopyActions") or ()]}


def _plans(declared, names):
    return [*(("aws_backup_plan", {"id": pid, "arn": names.get(f"{lid}.BackupPlanArn"),
                                   "name": (p.get("BackupPlan") or {}).get("BackupPlanName"),
                                   "tags": p.get("BackupPlanTags") or {},
                                   "rule": [_rule(r) for r in (p.get("BackupPlan") or {}).get("BackupPlanRule") or ()]})
              for lid, p, pid in _of(declared, "AWS::Backup::BackupPlan")),
            *(("aws_backup_selection", {
                "id": pid, "plan_id": p.get("BackupPlanId"), "name": s.get("SelectionName"),
                "iam_role_arn": s.get("IamRoleArn"), "resources": s.get("Resources") or [],
                "not_resources": s.get("NotResources") or [],
                "selection_tag": [{"type": t.get("ConditionType"), "key": t.get("ConditionKey"),
                                   "value": t.get("ConditionValue")} for t in s.get("ListOfTags") or ()]})
              for _, p, pid in _of(declared, "AWS::Backup::BackupSelection")
              for s in (p.get("BackupSelection") or {},))]


def backup_stack_pairs(declared, names):
    """(Terraform resource type, attributes) pairs of volumes, snapshot policies and backups among a stack's declared
    resources."""
    return [*_volumes(declared), *_snapshot_policies(declared, names), *_vaults(declared, names),
            *_plans(declared, names)]
