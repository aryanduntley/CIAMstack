"""Azure Backup: each backup vault the stack keeps a Data Protection backup vault (redundancy and cross-region restore,
immutability from its lock, its identity, its customer-managed key); each backup plan a disk backup policy in its
vault with a backup instance per disk of the volumes it protects, after the vault identity's grants; what Azure can't
do (copies to another region, lock days, roles that aren't volumes, other intervals) said. Read back from state, the
CLI and ARM; a disk's backup instance links its volume to the plan."""
import json

from opsdir_adapter_azure.arm import arm_resources
from opsdir_adapter_azure.backups import disk_interval, interval_schedule, render_backups
from opsdir_adapter_azure.cli import cli_resources
from opsdir_adapter_azure.inventory import state_resources
from network_fixtures import BETA, entry, model

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam/providers"
DP = f"{SUB}/Microsoft.DataProtection/backupVaults/ciam-prod-vault-main"
KEY = entry(BETA, "key-disk", "ciamKeyRef", ciamBindingRole="disk-encryption", ciamRefUri="azkv-key://kv-ciam/keys/disk")
VAULT = entry(BETA, "vault-main", "ciamBackupVault", ciamBindingRole="vault-main", ciamEncryptedByRole="disk-encryption",
              ciamStorageImmutability="compliance", ciamStorageLockDays="35", ciamCrossRegionRestore="TRUE")
DATA = entry(BETA, "vol-ds-data", "ciamVolume", ciamBindingRole="volume-ds-data", ciamTargetRole="ds",
             ciamVolumeKind="data", ciamVolumeSizeGb="256", ciamVolumeClass="ssd",
             ciamSnapshotPolicyRole="snapshots-daily")
PLAN = entry(BETA, "snapshots-daily", "ciamBackupPlan", ciamBindingRole="snapshots-daily",
             ciamProtectsRole=("volume-ds-data", "pf-grants-db"), ciamBackupVaultRole="vault-main",
             ciamBackupAt="03:00", ciamRetentionDays="7", ciamCopyRegion="westus2")


def _m(*records):
    return model(beta=records)[2]


def _flat(text):
    return " ".join(text.split())


def test_schedules_as_repeating_intervals():
    assert disk_interval(24, "03:00") == "R/2024-01-01T03:00:00+00:00/P1D"
    assert disk_interval(4, "01:30") == "R/2024-01-01T01:30:00+00:00/PT4H"
    assert disk_interval(3, "01:00") is None
    assert interval_schedule("R/2021-05-19T06:33:16+00:00/PT4H") == (4, "06:33")
    assert interval_schedule("R/2024-01-01T03:00:00+00:00/P1D") == (24, "03:00")
    assert interval_schedule("R/2024-01-01T03:00:00+00:00/P1W") == (None, None)


def test_a_vault_and_a_disk_backup_plan():
    out = _flat("\n\n".join(render_backups(_m(KEY, VAULT, DATA, PLAN))))
    for text in ("# Vault 'vault-main': a locked vault keeps each recovery point as long as its policy says; 35 days "
                 "isn't a setting of its own",
                 "# Vault 'vault-main': immutability Locked can't be turned off once set",
                 'resource "azurerm_data_protection_backup_vault" "vault_main" { name = "ciam-prod-vault-main" '
                 'resource_group_name = data.azurerm_resource_group.main.name location = '
                 'data.azurerm_resource_group.main.location datastore_type = "VaultStore" redundancy = "GeoRedundant" '
                 'cross_region_restore_enabled = true immutability = "Locked" identity { type = "SystemAssigned" }',
                 'resource "azurerm_data_protection_backup_vault_customer_managed_key" "vault_main" { '
                 'data_protection_backup_vault_id = azurerm_data_protection_backup_vault.vault_main.id '
                 'key_vault_key_id = data.azurerm_key_vault_key.vault_main_cmk.versionless_id',
                 'resource "azurerm_role_assignment" "vault_main_snapshots" { scope = '
                 'data.azurerm_resource_group.main.id role_definition_name = "Disk Snapshot Contributor"',
                 "disk backup keeps snapshots in the disk's region; copies to westus2 aren't rendered",
                 "# Backup plan 'snapshots-daily' protects pf-grants-db, which isn't a volume: not rendered here",
                 'resource "azurerm_data_protection_backup_policy_disk" "snapshots_daily" { name = "snapshots-daily" '
                 'vault_id = azurerm_data_protection_backup_vault.vault_main.id backup_repeating_time_intervals = '
                 '["R/2024-01-01T03:00:00+00:00/P1D"] default_retention_duration = "P7D" time_zone = "UTC" }',
                 'resource "azurerm_role_assignment" "snapshots_daily_ds_1_vol_ds_data_reader" { scope = '
                 'azurerm_managed_disk.ds_1_vol_ds_data.id role_definition_name = "Disk Backup Reader"',
                 'resource "azurerm_data_protection_backup_instance_disk" "snapshots_daily_ds_2_vol_ds_data" { '
                 'name = "ds-2-vol-ds-data"'):
        assert _flat(text) in out, text


def test_what_it_can_t_render_is_said():
    odd = entry(BETA, "backup-odd", "ciamBackupPlan", ciamBindingRole="backup-odd", ciamProtectsRole="volume-ds-data",
                ciamBackupVaultRole="vault-main", ciamRetentionDays="7", ciamBackupEveryHours="3")
    lost = entry(BETA, "backup-lost", "ciamBackupPlan", ciamBindingRole="backup-lost", ciamProtectsRole="x",
                 ciamBackupVaultRole="vault-none", ciamRetentionDays="7")
    out = "\n".join(render_backups(_m(VAULT, odd, lost)))
    assert "disk backup runs every 1, 2, 4, 6, 8 or 12 hours or daily, not every 3 hours: not rendered" in out
    assert "its vault (role vault-none) isn't one this environment's stack keeps: not rendered" in out
    assert "vault_main_snapshots" not in out                      # no plan backs up disks into it


VAULT_STATE = ("azurerm_data_protection_backup_vault", {
    "id": DP, "name": "ciam-prod-vault-main", "redundancy": "GeoRedundant", "cross_region_restore_enabled": True,
    "immutability": "Locked", "tags": {"Name": "vault-main", "Role": "vault-main"}})
CMK_STATE = ("azurerm_data_protection_backup_vault_customer_managed_key", {
    "data_protection_backup_vault_id": DP, "key_vault_key_id": "https://kv-ciam.vault.azure.net/keys/disk"})
POLICY_ID = f"{DP}/backupPolicies/snapshots-daily"
POLICY_STATE = ("azurerm_data_protection_backup_policy_disk", {
    "id": POLICY_ID, "name": "snapshots-daily", "vault_id": DP,
    "backup_repeating_time_intervals": ["R/2024-01-01T03:00:00+00:00/P1D"], "default_retention_duration": "P7D"})
DISK_ID = f"{SUB}/Microsoft.Compute/disks/disk-ds-1-vol-ds-data"
DISK_STATE = ("azurerm_managed_disk", {"id": DISK_ID, "name": "disk-ds-1-vol-ds-data", "storage_account_type": "Premium_LRS",
                                       "disk_size_gb": 256, "tags": {"Volume": "vol-ds-data", "Role": "volume-ds-data",
                                                                     "SnapshotPolicy": "snapshots-daily"}})
INSTANCE_STATE = ("azurerm_data_protection_backup_instance_disk", {
    "id": f"{DP}/backupInstances/ds-1", "disk_id": DISK_ID, "backup_policy_id": POLICY_ID.upper(), "vault_id": DP})


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": f"r{i}", "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": a}]} for i, (t, a) in enumerate(resources)]})


def _by(resources):
    return {(r.kind, r.ref): r for r in resources}


def test_vaults_plans_and_the_disks_they_back_up_are_read_back_from_state():
    by = _by(state_resources(_state(VAULT_STATE, CMK_STATE, POLICY_STATE, DISK_STATE, INSTANCE_STATE))[0])
    vault = by[("backup-vault", DP)]
    assert (vault.name, vault.role) == ("vault-main", "vault-main")
    assert vault.attrs == {"ciamStorageImmutability": ("compliance",), "ciamCrossRegionRestore": ("TRUE",)}
    assert vault.links == {"ciamEncryptedByRole": "azkv-key://kv-ciam/keys/disk"}
    plan = by[("backup-plan", POLICY_ID)]
    assert (plan.name, plan.role, plan.links) == ("snapshots-daily", "snapshots-daily", {"ciamBackupVaultRole": DP})
    assert plan.attrs == {"ciamBackupEveryHours": ("24",), "ciamBackupAt": ("03:00",), "ciamRetentionDays": ("7",),
                          "ciamProtectsRole": ("volume-ds-data",)}
    # the disk's backup instance names the policy in another case: the volume links to the policy as it reports itself
    assert by[("volume", "vol-ds-data")].links["ciamSnapshotPolicyRole"] == POLICY_ID


def test_the_cli_and_an_arm_template_read_the_same():
    vault = {"id": DP, "name": "ciam-prod-vault-main", "type": "Microsoft.DataProtection/backupVaults",
             "tags": {"Name": "vault-main", "Role": "vault-main"},
             "properties": {"storageSettings": [{"datastoreType": "VaultStore", "type": "GeoRedundant"}],
                            "featureSettings": {"crossRegionRestoreSettings": {"state": "Enabled"}},
                            "securitySettings": {"immutabilitySettings": {"state": "Unlocked"}}}}
    policy = {"id": POLICY_ID, "name": "snapshots-daily", "type": "Microsoft.DataProtection/backupVaults/backupPolicies",
              "properties": {"datasourceTypes": ["Microsoft.Compute/disks"], "policyRules": [
                  {"objectType": "AzureBackupRule", "name": "BackupDaily", "trigger": {
                      "objectType": "ScheduleBasedTriggerContext",
                      "schedule": {"repeatingTimeIntervals": ["R/2024-01-01T03:00:00+00:00/P1D"]}}},
                  {"objectType": "AzureRetentionRule", "name": "Default", "isDefault": True, "lifecycles": [
                      {"deleteAfter": {"objectType": "AbsoluteDeleteOption", "duration": "P7D"}}]}]}}
    instance = {"id": f"{DP}/backupInstances/ds-1", "name": "ds-1",
                "type": "Microsoft.DataProtection/backupVaults/backupInstances",
                "properties": {"dataSourceInfo": {"resourceID": DISK_ID, "datasourceType": "Microsoft.Compute/disks"},
                               "policyInfo": {"policyId": POLICY_ID}}}
    disk = {"id": DISK_ID, "name": "disk-ds-1-vol-ds-data", "type": "Microsoft.Compute/disks", "sku": {"name": "Premium_LRS"},
            "diskSizeGB": 256, "tags": {"Volume": "vol-ds-data", "Role": "volume-ds-data",
                                        "SnapshotPolicy": "snapshots-daily"}}
    resources, notices = cli_resources({"backup.json": json.dumps([vault, policy, instance]),
                                        "disks.json": json.dumps([disk])})
    by = _by(resources)
    assert by[("backup-vault", DP)].attrs["ciamStorageImmutability"] == ("governance",)
    assert by[("backup-plan", POLICY_ID)].attrs["ciamRetentionDays"] == ("7",)
    assert by[("backup-plan", POLICY_ID)].attrs["ciamProtectsRole"] == ("volume-ds-data",)
    template = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0", "resources": [
                    {"type": "Microsoft.DataProtection/backupVaults", "apiVersion": "2023-05-01",
                     "name": "ciam-prod-vault-main", "location": "eastus2", "tags": vault["tags"],
                     "properties": vault["properties"]}]}
    arm, _ = arm_resources({"backup/azuredeploy.json": json.dumps(template)})
    assert [r.name for r in arm if r.kind == "backup-vault"] == ["vault-main"]
