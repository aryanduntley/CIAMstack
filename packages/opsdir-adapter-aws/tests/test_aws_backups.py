"""AWS Backup: each backup vault the stack keeps an aws_backup_vault (its key, its lock: compliance with AWS's grace,
governance without), each backup plan an aws_backup_plan (cron from its schedule, start window, retention, copies to
each copy region's vault, an input) with a selection by tag Role of what it protects; others' named; adopted ones
imported. Read back from Terraform state and the CLI, named by tag Name."""
import json

from opsdir_adapter_aws.backups import backup_cron, cron_schedule, render_backups
from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.inventory import state_resources
from network_fixtures import BETA, entry, model

ARN = "arn:aws:kms:us-east-1:111122223333:key/mrk-1234"
KEY = entry(BETA, "key-disk", "ciamKeyRef", ciamBindingRole="disk-encryption", ciamRefUri=f"aws-kms://{ARN}")
VAULT = entry(BETA, "vault-main", "ciamBackupVault", ciamBindingRole="vault-main", ciamEncryptedByRole="disk-encryption",
              ciamStorageImmutability="compliance", ciamStorageLockDays="35",
              ciamProviderRef="arn:aws:backup:us-east-1:111122223333:backup-vault:ciam-prod-vault-main")
PLAN = entry(BETA, "backup-daily", "ciamBackupPlan", ciamBindingRole="backup-daily",
             ciamProtectsRole=("volume-ds-data", "pf-grants-db"), ciamBackupVaultRole="vault-main",
             ciamBackupAt="05:00", ciamBackupWindowHours="2", ciamRetentionDays="35", ciamCopyRegion="us-west-2")
VAULT_ARN = "arn:aws:backup:us-east-1:111122223333:backup-vault:ciam-prod-vault-main"
PLAN_ARN = "arn:aws:backup:us-east-1:111122223333:backup-plan:plan-1"


def _m(*records):
    return model(beta=records)[2]


def _flat(text):
    return " ".join(text.split())


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": f"r{i}", "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
         "instances": [{"attributes": a}]} for i, (t, a) in enumerate(resources)]})


def _by(resources):
    return {(r.kind, r.ref): r for r in resources}


def test_schedules_as_aws_backup_cron():
    assert backup_cron(24, "05:00") == "cron(0 5 ? * * *)" and cron_schedule("cron(0 5 ? * * *)") == (24, "05:00")
    assert backup_cron(6, "01:30") == "cron(30 1/6 ? * * *)" and cron_schedule("cron(30 1/6 ? * * *)") == (6, "01:30")
    assert backup_cron(48, "02:00") == "cron(0 2 */2 * ? *)" and cron_schedule("cron(0 2 */2 * ? *)") == (48, "02:00")
    assert backup_cron(36, "02:00") is None and cron_schedule("rate(1 day)") == (None, None)
    assert cron_schedule("cron(0 5 * * ? *)") == (24, "05:00")


def test_a_vault_and_a_plan_render_as_aws_backup():
    out = _flat("\n\n".join(render_backups(_m(KEY, VAULT, PLAN))))
    for text in ('variable "backup_iam_role_arn"',
                 'resource "aws_backup_vault" "vault_main" { name = "ciam-prod-vault-main" kms_key_arn = '
                 f'"{ARN}" tags = {{ Name = "vault-main" Role = "vault-main" ManagedBy = "opsdir" }} }}',
                 'resource "aws_backup_vault_lock_configuration" "vault_main" { backup_vault_name = '
                 'aws_backup_vault.vault_main.name min_retention_days = 35 changeable_for_days = 3 }',
                 'to = aws_backup_vault.vault_main id = "ciam-prod-vault-main"',
                 'variable "backup_daily_us_west_2_vault_arn"',
                 'resource "aws_backup_plan" "backup_daily" { name = "ciam-prod-backup-daily" rule { rule_name = '
                 '"backup_daily" target_vault_name = aws_backup_vault.vault_main.name schedule = "cron(0 5 ? * * *)" '
                 'start_window = 120 lifecycle { delete_after = 35 } copy_action { destination_vault_arn = '
                 'var.backup_daily_us_west_2_vault_arn lifecycle { delete_after = 35 } } }',
                 'resource "aws_backup_selection" "backup_daily" { name = "ciam-prod-backup-daily" iam_role_arn = '
                 'var.backup_iam_role_arn plan_id = aws_backup_plan.backup_daily.id selection_tag { type = '
                 '"STRINGEQUALS" key = "Role" value = "volume-ds-data" } selection_tag { type = "STRINGEQUALS" key = '
                 '"Role" value = "pf-grants-db" } }'):
        assert _flat(text) in out, text


def test_what_it_can_t_render_is_said():
    governance = entry(BETA, "vault-main", "ciamBackupVault", ciamBindingRole="vault-main",
                       ciamStorageImmutability="governance", ciamStorageLockDays="7", ciamCrossRegionRestore="TRUE")
    out = "\n".join(render_backups(_m(governance)))
    assert "AWS Backup's own key encrypts it" in out and "through the plans' copies" in out
    assert "changeable_for_days" not in out
    odd = entry(BETA, "backup-odd", "ciamBackupPlan", ciamBindingRole="backup-odd", ciamProtectsRole="x",
                ciamBackupVaultRole="vault-none", ciamRetentionDays="7", ciamBackupEveryHours="36")
    lost = entry(BETA, "backup-lost", "ciamBackupPlan", ciamBindingRole="backup-lost", ciamProtectsRole="x",
                 ciamBackupVaultRole="vault-none", ciamRetentionDays="7")
    out = "\n".join(render_backups(_m(odd, lost)))
    assert "every 36 hours isn't a whole number of days: not rendered" in out
    assert "no backup vault binding for role vault-none in this environment: not rendered" in out
    kept = entry(BETA, "backup-dba", "ciamBackupPlan", ciamBindingRole="backup-dba", ciamProtectsRole="x",
                 ciamBackupVaultRole="vault-main", ciamRetentionDays="7",
                 ciamManagedBy="cn=network-security,ou=owners,dc=ciam-ops")
    assert "Backup plan 'backup-dba' (role backup-dba) is kept by cn=network-security,ou=owners,dc=ciam-ops: not " \
        "rendered here" in \
        "\n".join(render_backups(_m(kept)))


VAULT_STATE = ("aws_backup_vault", {"name": "ciam-prod-vault-main", "arn": VAULT_ARN, "kms_key_arn": ARN,
                                    "tags": {"Name": "vault-main", "Role": "vault-main"}})
LOCK_STATE = ("aws_backup_vault_lock_configuration", {"backup_vault_name": "ciam-prod-vault-main",
                                                      "min_retention_days": 35, "changeable_for_days": 3})
PLAN_STATE = ("aws_backup_plan", {
    "id": "plan-1", "arn": PLAN_ARN, "name": "ciam-prod-backup-daily",
    "tags": {"Name": "backup-daily", "Role": "backup-daily"},
    "rule": [{"rule_name": "backup_daily", "target_vault_name": "ciam-prod-vault-main",
              "schedule": "cron(0 5 ? * * *)", "start_window": 120, "lifecycle": [{"delete_after": 35}],
              "copy_action": [{"destination_vault_arn": "arn:aws:backup:us-west-2:111122223333:backup-vault:copy",
                               "lifecycle": [{"delete_after": 35}]}]}]})
SELECTION_STATE = ("aws_backup_selection", {"id": "sel-1", "plan_id": "plan-1", "name": "ciam-prod-backup-daily",
                                            "selection_tag": [{"type": "STRINGEQUALS", "key": "Role",
                                                               "value": "volume-ds-data"}]})


def test_vaults_and_plans_are_read_back_from_state():
    resources, notices = state_resources(_state(VAULT_STATE, LOCK_STATE, PLAN_STATE, SELECTION_STATE))
    by = _by(resources)
    vault = by[("backup-vault", VAULT_ARN)]
    assert (vault.name, vault.role) == ("vault-main", "vault-main")
    assert vault.attrs == {"ciamStorageImmutability": ("compliance",), "ciamStorageLockDays": ("35",)}
    assert vault.links == {"ciamEncryptedByRole": ARN}
    plan = by[("backup-plan", PLAN_ARN)]
    assert plan.name == "backup-daily" and plan.links == {"ciamBackupVaultRole": VAULT_ARN}
    assert plan.attrs == {"ciamBackupEveryHours": ("24",), "ciamBackupAt": ("05:00",), "ciamBackupWindowHours": ("2",),
                          "ciamRetentionDays": ("35",), "ciamCopyRegion": ("us-west-2",),
                          "ciamProtectsRole": ("volume-ds-data",)}
    assert notices == ()


def test_what_the_reader_can_t_tell_is_named():
    two_rules = ("aws_backup_plan", {**PLAN_STATE[1], "rule": [*PLAN_STATE[1]["rule"], PLAN_STATE[1]["rule"][0]]})
    by_arn = ("aws_backup_selection", {"id": "sel-2", "plan_id": "plan-1", "name": "by-arn",
                                       "resources": ["arn:aws:ec2:us-east-1:111122223333:volume/vol-1"]})
    _, notices = state_resources(_state(VAULT_STATE, two_rules, by_arn))
    assert notices == ("backup plan backup-daily: 2 rules; the first is read",
                       "backup plan backup-daily: selection by-arn chooses resources by ARN, not by tag Role: what it "
                       "protects not read")


def test_the_cli_reads_the_same():
    texts = {"backup-vaults.json": json.dumps({"BackupVaultList": [
                 {"BackupVaultName": "ciam-prod-vault-main", "BackupVaultArn": VAULT_ARN, "EncryptionKeyArn": ARN,
                  "Locked": True, "MinRetentionDays": 35, "LockDate": "2026-09-01T00:00:00Z"}]}),
             "backup-plans/plan-1.json": json.dumps({"BackupPlanId": "plan-1", "BackupPlanArn": PLAN_ARN, "BackupPlan": {
                 "BackupPlanName": "ciam-prod-backup-daily", "Rules": [{
                     "RuleName": "backup_daily", "TargetBackupVaultName": "ciam-prod-vault-main",
                     "ScheduleExpression": "cron(0 5 ? * * *)", "StartWindowMinutes": 120,
                     "Lifecycle": {"DeleteAfterDays": 35},
                     "CopyActions": [{"DestinationBackupVaultArn":
                                      "arn:aws:backup:us-west-2:111122223333:backup-vault:copy",
                                      "Lifecycle": {"DeleteAfterDays": 35}}]}]}}),
             "backup-plans/plan-1-selection.json": json.dumps({"SelectionId": "sel-1", "BackupPlanId": "plan-1",
                 "BackupSelection": {"SelectionName": "ciam-prod-backup-daily", "IamRoleArn": "arn:aws:iam::1:role/b",
                                     "ListOfTags": [{"ConditionType": "STRINGEQUALS", "ConditionKey": "Role",
                                                     "ConditionValue": "volume-ds-data"}]}}),
             "backup-tags/ciam-prod-vault-main.json": json.dumps({"Tags": {"Name": "vault-main", "Role": "vault-main"}}),
             "backup-tags/ciam-prod-backup-daily.json": json.dumps({"Tags": {"Name": "backup-daily",
                                                                             "Role": "backup-daily"}})}
    resources, notices = cli_resources(texts)
    by = _by(resources)
    assert by[("backup-vault", VAULT_ARN)].attrs["ciamStorageImmutability"] == ("compliance",)
    assert by[("backup-vault", VAULT_ARN)].name == "vault-main"
    plan = by[("backup-plan", PLAN_ARN)]
    assert (plan.name, plan.attrs["ciamProtectsRole"], plan.links) == ("backup-daily", ("volume-ds-data",),
                                                                       {"ciamBackupVaultRole": VAULT_ARN})
    assert not [n for n in notices if "backup" in n], notices


def test_what_it_renders_reads_back_as_recorded():
    """The rendered vault, lock and plan, as Terraform would hold them, read back to the record's values."""
    out = _flat("\n\n".join(render_backups(_m(KEY, VAULT, PLAN))))
    assert "min_retention_days = 35 changeable_for_days = 3" in out and 'schedule = "cron(0 5 ? * * *)"' in out
    plan = _by(state_resources(_state(VAULT_STATE, LOCK_STATE, PLAN_STATE, SELECTION_STATE))[0])[("backup-plan",
                                                                                                  PLAN_ARN)]
    assert plan.attrs["ciamBackupAt"] == ("05:00",) and plan.attrs["ciamBackupWindowHours"] == ("2",)
