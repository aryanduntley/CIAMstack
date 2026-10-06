"""Google Backup and DR: each backup vault the stack keeps a Backup and DR vault (in its plans' copy region, else the
environment's; its lock as the minimum enforced retention), each backup plan a plan for disks in the environment's
region (its rule: retention, HOURLY or DAILY schedule, window) with an association per disk it backs up; what Backup
and DR can't do said. Read back from state and Cloud Asset Inventory / gcloud; an association links its disk's volume
to the plan."""
import json

from opsdir_adapter_gcp.backups import backup_rule, render_backups, rule_schedule
from opsdir_adapter_gcp.cli import cli_resources
from opsdir_adapter_gcp.inventory import state_resources
from network_fixtures import BETA, entry, model

VAULT = entry(BETA, "vault-main", "ciamBackupVault", ciamBindingRole="vault-main",
              ciamStorageImmutability="governance", ciamStorageLockDays="7", ciamCrossRegionRestore="TRUE")
DATA = entry(BETA, "vol-ds-data", "ciamVolume", ciamBindingRole="volume-ds-data", ciamTargetRole="ds",
             ciamVolumeKind="data", ciamVolumeSizeGb="500", ciamVolumeClass="ssd")
PLAN = entry(BETA, "backup-daily", "ciamBackupPlan", ciamBindingRole="backup-daily",
             ciamProtectsRole=("volume-ds-data", "pf-grants-db"), ciamBackupVaultRole="vault-main",
             ciamBackupAt="03:00", ciamRetentionDays="14", ciamCopyRegion=("us-east1", "us-west1"))


def _m(*records):
    return model(beta=records)[2]


def _flat(text):
    return " ".join(text.split())


def test_a_rule_s_schedule():
    rule = dict(backup_rule(_plan()).body)
    schedule = dict(rule["standard_schedule"].body)
    assert (rule["backup_retention_days"], schedule["recurrence_type"]) == (14, "DAILY")
    assert dict(schedule["backup_window"].body) == {"start_hour_of_day": 3, "end_hour_of_day": 9}
    hourly = dict(dict(backup_rule(_plan(ciamBackupEveryHours="6", ciamBackupWindowHours="4")).body)
                  ["standard_schedule"].body)
    assert (hourly["recurrence_type"], hourly["hourly_frequency"]) == ("HOURLY", 6)
    assert dict(hourly["backup_window"].body) == {"start_hour_of_day": 3, "end_hour_of_day": 7}
    assert backup_rule(_plan(ciamBackupEveryHours="48")) is None
    assert rule_schedule({"recurrence_type": "HOURLY", "hourly_frequency": 6,
                          "backup_window": [{"start_hour_of_day": 1, "end_hour_of_day": 7}]}) == (6, "01:00", 6)
    assert rule_schedule({"recurrenceType": "DAILY", "backupWindow": {"startHourOfDay": 3, "endHourOfDay": 9}}) == \
        (24, "03:00", 6)
    assert rule_schedule({"recurrence_type": "WEEKLY"}) == (None, None, None)


def _plan(**change):
    m = _m(VAULT, DATA, entry(BETA, "backup-daily", "ciamBackupPlan", **{
        **dict(ciamBindingRole="backup-daily", ciamProtectsRole="volume-ds-data", ciamBackupVaultRole="vault-main",
               ciamBackupAt="03:00", ciamRetentionDays="14"), **change}))
    return next(b for b in m.bindings if "ciamBackupPlan" in b.classes)


def test_a_vault_a_plan_and_an_association_per_disk():
    out = _flat("\n\n".join(render_backups(_m(VAULT, DATA, PLAN))))
    for text in ('resource "google_backup_dr_backup_vault" "vault_main" { location = "us-east1" backup_vault_id = '
                 '"ciam-prod-vault-main" backup_minimum_enforced_retention_duration = "604800s" labels = { name = '
                 '"vault-main" role = "vault-main" managed_by = "opsdir" } }',
                 "# Backup plan 'backup-daily': copies go to its vault's location, us-east1; us-west1 not rendered",
                 "# Backup plan 'backup-daily' protects pf-grants-db, which isn't a volume: not rendered here",
                 'resource "google_backup_dr_backup_plan" "backup_daily" { location = var.region backup_plan_id = '
                 '"backup-daily" resource_type = "compute.googleapis.com/Disk" backup_vault = '
                 'google_backup_dr_backup_vault.vault_main.id backup_rules { rule_id = "ciam" backup_retention_days = '
                 '14 standard_schedule { recurrence_type = "DAILY" time_zone = "UTC" backup_window { '
                 'start_hour_of_day = 3 end_hour_of_day = 9 } } } }',
                 'resource "google_backup_dr_backup_plan_association" "backup_daily_ds_2_vol_ds_data" { location = '
                 'var.region backup_plan_association_id = "ds-2-vol-ds-data" resource = '
                 'google_compute_disk.ds_2_vol_ds_data.id resource_type = "compute.googleapis.com/Disk" backup_plan = '
                 'google_backup_dr_backup_plan.backup_daily.name }'):
        assert _flat(text) in out, text


def test_what_it_can_t_render_is_said():
    loose = entry(BETA, "vault-main", "ciamBackupVault", ciamBindingRole="vault-main", ciamCrossRegionRestore="TRUE")
    odd = entry(BETA, "backup-odd", "ciamBackupPlan", ciamBindingRole="backup-odd", ciamProtectsRole="x",
                ciamBackupVaultRole="vault-main", ciamRetentionDays="7", ciamBackupEveryHours="48")
    short = entry(BETA, "backup-short", "ciamBackupPlan", ciamBindingRole="backup-short", ciamProtectsRole="x",
                  ciamBackupVaultRole="vault-locked", ciamRetentionDays="3")
    locked = entry(BETA, "vault-locked", "ciamBackupVault", ciamBindingRole="vault-locked",
                   ciamStorageImmutability="compliance", ciamStorageLockDays="7")
    out = "\n".join(render_backups(_m(loose, odd, short, locked)))
    assert "nothing locked; Backup and DR enforces at least a day" in out and '"86400s"' in out
    assert "name the region in its plans' ciamCopyRegion" in out
    assert "Backup and DR backs up every 6 to 23 hours or daily, not every 48 hours: not rendered" in out
    assert backup_rule(_plan(ciamBackupEveryHours="4")) is None              # six hours at least
    assert "keeps backups 3 days, less than its vault enforces (7), which Backup and DR refuses: not rendered" in out
    assert "a compliance lock is the vault's effective_time" in out


VAULT_ID = "projects/p/locations/us-east1/backupVaults/ciam-prod-vault-main"
PLAN_ID = "projects/p/locations/us-central1/backupPlans/backup-daily"
VAULT_STATE = ("google_backup_dr_backup_vault", {
    "id": VAULT_ID, "name": VAULT_ID, "location": "us-east1",
    "backup_minimum_enforced_retention_duration": "604800s",
    "labels": {"name": "vault-main", "role": "vault-main", "managed_by": "opsdir"}})
PLAN_STATE = ("google_backup_dr_backup_plan", {
    "id": PLAN_ID, "name": PLAN_ID, "location": "us-central1", "resource_type": "compute.googleapis.com/Disk",
    "backup_vault": VAULT_ID, "backup_rules": [{"rule_id": "ciam", "backup_retention_days": 14, "standard_schedule": [{
        "recurrence_type": "DAILY", "time_zone": "UTC",
        "backup_window": [{"start_hour_of_day": 3, "end_hour_of_day": 9}]}]}]})
DISK_STATE = ("google_compute_disk", {
    "id": "projects/p/zones/us-central1-a/disks/ds-1-vol-ds-data", "name": "ds-1-vol-ds-data", "size": 500,
    "type": "pd-ssd", "labels": {"volume": "vol-ds-data", "role": "volume-ds-data", "snapshot_policy": "backup-daily"}})
ASSOCIATION_STATE = ("google_backup_dr_backup_plan_association", {
    "id": "projects/p/locations/us-central1/backupPlanAssociations/ds-1-vol-ds-data",
    "resource": "projects/p/zones/us-central1-a/disks/ds-1-vol-ds-data",
    "resource_type": "compute.googleapis.com/Disk", "backup_plan": PLAN_ID})


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": f"r{i}", "provider": 'provider["registry.terraform.io/hashicorp/google"]',
         "instances": [{"attributes": a}]} for i, (t, a) in enumerate(resources)]})


def _by(resources):
    return {(r.kind, r.ref): r for r in resources}


def test_vaults_plans_and_the_disks_they_back_up_are_read_back_from_state():
    by = _by(state_resources(_state(VAULT_STATE, PLAN_STATE, DISK_STATE, ASSOCIATION_STATE))[0])
    vault = by[("backup-vault", VAULT_ID)]
    assert (vault.name, vault.role) == ("vault-main", "vault-main")
    assert vault.attrs == {"ciamStorageImmutability": ("governance",), "ciamStorageLockDays": ("7",),
                           "ciamCrossRegionRestore": ("TRUE",)}
    plan = by[("backup-plan", PLAN_ID)]
    assert (plan.name, plan.role, plan.links) == ("backup-daily", "backup-daily", {"ciamBackupVaultRole": VAULT_ID})
    assert plan.attrs == {"ciamBackupEveryHours": ("24",), "ciamBackupAt": ("03:00",), "ciamRetentionDays": ("14",),
                          "ciamCopyRegion": ("us-east1",), "ciamProtectsRole": ("volume-ds-data",)}
    assert by[("volume", "vol-ds-data")].links["ciamSnapshotPolicyRole"] == PLAN_ID


def test_the_asset_inventory_reads_the_same():
    assets = [{"name": f"//backupdr.googleapis.com/{VAULT_ID}", "assetType": "backupdr.googleapis.com/BackupVault",
               "resource": {"data": {"name": VAULT_ID, "backupMinimumEnforcedRetentionDuration": "604800s",
                                     "labels": {"name": "vault-main", "role": "vault-main"}}}},
              {"name": f"//backupdr.googleapis.com/{PLAN_ID}", "assetType": "backupdr.googleapis.com/BackupPlan",
               "resource": {"data": {"name": PLAN_ID, "resourceType": "compute.googleapis.com/Disk",
                                     "backupVault": VAULT_ID, "backupRules": [{
                                         "ruleId": "ciam", "backupRetentionDays": 14, "standardSchedule": {
                                             "recurrenceType": "HOURLY", "hourlyFrequency": 6, "timeZone": "UTC",
                                             "backupWindow": {"startHourOfDay": 0, "endHourOfDay": 6}}}]}}}]
    by = _by(cli_resources({"assets.jsonl": "\n".join(json.dumps(a) for a in assets)})[0])
    assert by[("backup-vault", VAULT_ID)].attrs["ciamStorageLockDays"] == ("7",)
    plan = by[("backup-plan", PLAN_ID)]
    assert plan.attrs["ciamBackupEveryHours"] == ("6",) and plan.attrs["ciamBackupAt"] == ("00:00",)
    assert "ciamBackupWindowHours" not in plan.attrs                 # the default window isn't recorded


def test_items_being_deleted_or_inactive_are_named_not_read():
    gone_plan = ("google_backup_dr_backup_plan", {**PLAN_STATE[1], "state": "DELETED"})
    gone_association = ("google_backup_dr_backup_plan_association", {**ASSOCIATION_STATE[1], "state": "DELETING"})
    resources, notices = state_resources(_state(VAULT_STATE, gone_plan, DISK_STATE, gone_association))
    assert not [r for r in resources if r.kind == "backup-plan"]
    assert "ciamSnapshotPolicyRole" not in _by(resources)[("volume", "vol-ds-data")].links
    assert notices == ("backup plan backup-daily: DELETED; not read",
                       "backup plan association ds-1-vol-ds-data: DELETING; not read")


def test_the_shapes_an_asset_export_holds():
    """resource.data as Google's API and an asset export give them (an example of each, anonymized): extra fields
    (uid, createTime, backupCount, dataSource) ignored; an association may leave its resourceType out."""
    vault = {"name": "projects/my-project-123/locations/us-east1/backupVaults/my-secure-vault",
             "uid": "12345678-abcd", "createTime": "2026-01-15T10:00:00Z", "state": "ACTIVE",
             "backupMinimumEnforcedRetentionDuration": "604800s", "backupCount": "5", "totalStoredBytes": "1073741824"}
    plan = {"name": "projects/my-project-123/locations/us-central1/backupPlans/my-daily-plan", "uid": "98765432-fedc",
            "resourceType": "compute.googleapis.com/Disk", "backupVault": vault["name"],
            "backupRules": [{"ruleId": "daily-retention-rule", "backupRetentionDays": 30, "standardSchedule": {
                "recurrenceType": "DAILY", "timeZone": "UTC", "backupWindow": {"startHourOfDay": 1, "endHourOfDay": 5}}}]}
    association = {"name": "projects/my-project-123/locations/us-central1/backupPlanAssociations/my-disk-association",
                   "resource": "projects/my-project-123/zones/us-central1-a/disks/my-app-disk",
                   "backupPlan": plan["name"], "state": "ACTIVE",
                   "dataSource": f"{vault['name']}/dataSources/ds-98765"}
    disk = {"kind": "compute#disk", "name": "my-app-disk", "sizeGb": "100",
            "selfLink": "https://www.googleapis.com/compute/v1/projects/my-project-123/zones/us-central1-a/disks/my-app-disk",
            "labels": {"volume": "vol-app", "role": "volume-app"}}
    assets = [{"name": f"//backupdr.googleapis.com/{d['name']}", "assetType": f"backupdr.googleapis.com/{t}",
               "resource": {"version": "v1", "data": d}}
              for t, d in (("BackupVault", vault), ("BackupPlan", plan), ("BackupPlanAssociation", association))]
    by = _by(cli_resources({"assets.jsonl": "\n".join(json.dumps(a) for a in assets),
                            "disks.json": json.dumps([disk])})[0])
    found = by[("backup-plan", plan["name"])]
    assert found.attrs == {"ciamBackupEveryHours": ("24",), "ciamBackupAt": ("01:00",), "ciamBackupWindowHours": ("4",),
                           "ciamRetentionDays": ("30",), "ciamCopyRegion": ("us-east1",),
                           "ciamProtectsRole": ("volume-app",)}
    assert by[("backup-vault", vault["name"])].attrs["ciamCrossRegionRestore"] == ("TRUE",)
