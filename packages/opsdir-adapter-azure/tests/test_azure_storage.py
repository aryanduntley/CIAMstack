"""Object stores on Azure: the containers the record describes and the stack keeps are rendered with their storage
account (versioning, public access, the customer-managed key, a lifecycle rule per container, object replication) and
their immutability policies, adopted when they exist; a container someone else keeps is named with what to ask them
for. Read back from Terraform state, the CLI and ARM templates: each container with its account's settings."""
import json

from opsdir_adapter_azure.cli import cli_resources
from opsdir_adapter_azure.inventory import state_resources
from opsdir_adapter_azure.storage import kept_containers, render_object_stores
from network_fixtures import ALPHA, entry, model

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam/providers"
ACCOUNT = f"{SUB}/Microsoft.Storage/storageAccounts/stciambackups"
CONTAINER = f"{ACCOUNT}/blobServices/default/containers/ds-backups"
KEY_URL = "https://kv-ciam.vault.azure.net/keys/disk-cmk"
STORE = dict(ciamBindingRole="backup-target", ciamStorageRef="azblob://stciambackups/ds-backups",
             ciamRetentionDays="35", ciamStorageVersioning="TRUE", ciamStorageImmutability="compliance",
             ciamStorageLockDays="35", ciamEncryptedByRole="disk-encryption", ciamStoragePublicBlocked="TRUE",
             ciamStorageReplicaRef="azblob://stciambackupsdr/ds-backups",
             ciamStorageLifecycle=("30 cold", "400 delete", "noncurrent 30 delete"))
KEY = entry(ALPHA, "key-disk", "ciamKeyRef", ciamBindingRole="disk-encryption",
            ciamRefUri="azkv-key://kv-ciam/keys/disk-cmk")


def _render(*records):
    return "\n\n".join(render_object_stores(model(alpha=records)[1]))


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": "x", "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": a}]} for t, a in resources]})


def test_a_kept_container_renders_its_account_with_every_setting():
    out = _render(KEY, entry(ALPHA, "backup", "ciamBackupTarget", **STORE, ciamProviderRef=CONTAINER))
    for text in ('resource "azurerm_storage_account" "stciambackups"', 'account_replication_type        = "ZRS"',
                 "allow_nested_items_to_be_public = false", "versioning_enabled  = true",
                 "change_feed_enabled = true", 'resource "azurerm_storage_account_customer_managed_key"',
                 'key_name                  = data.azurerm_key_vault_key.stciambackups_storage_cmk.name',
                 'prefix_match = ["ds-backups/"]', "tier_to_cold_after_days_since_modification_greater_than = 30",
                 "delete_after_days_since_modification_greater_than      = 400",
                 "delete_after_days_since_creation = 30", 'resource "azurerm_storage_container" "backup"',
                 'role      = "backup-target"', 'resource "azurerm_storage_container_immutability_policy" "backup"',
                 "immutability_period_in_days           = 35", "locked                                = true",
                 'variable "backup_replica_account_id"', 'destination_container_name = "ds-backups"',
                 "to = azurerm_storage_account.stciambackups", f'id = "{ACCOUNT}"',
                 "to = azurerm_storage_container.backup", f'id = "{CONTAINER}"'):
        assert " ".join(text.split()) in " ".join(out.split()), text


def test_others_containers_are_named_with_what_to_ask_and_references_are_left_alone():
    out = _render(entry(ALPHA, "backup", "ciamBackupTarget", **STORE,
                        ciamManagedBy="cn=storage-team,ou=owners,dc=ciam-ops"))
    assert out == ("# Object store 'backup' (role backup-target) "
                   "is kept by cn=storage-team,ou=owners,dc=ciam-ops, with "
                   "its storage account: not rendered here. Ask them for: versioning; compliance lock 35 days; key "
                   "disk-encryption; lifecycle 30 cold, 400 delete, noncurrent 30 delete; public access blocked; "
                   "copied to azblob://stciambackupsdr/ds-backups")
    referenced = entry(ALPHA, "backup", "ciamBackupTarget", ciamBindingRole="backup-target",
                       ciamStorageRef="azblob://stciambackups/ds-backups")
    assert _render(referenced) == "" and kept_containers(model(alpha=(referenced,))[1]) == ()


STATE = (("azurerm_storage_account", {"id": ACCOUNT, "name": "stciambackups", "allow_nested_items_to_be_public": False,
                                      "blob_properties": [{"versioning_enabled": True, "change_feed_enabled": True}]}),
         ("azurerm_storage_account_customer_managed_key", {"storage_account_id": ACCOUNT, "key_name": "disk-cmk",
                                                           "key_vault_id": f"{SUB}/Microsoft.KeyVault/vaults/kv-ciam"}),
         ("azurerm_storage_container", {"id": CONTAINER, "resource_manager_id": CONTAINER, "name": "ds-backups",
                                        "storage_account_id": ACCOUNT, "metadata": {"role": "backup-target"}}),
         ("azurerm_storage_container_immutability_policy", {"storage_container_resource_manager_id": CONTAINER,
                                                            "immutability_period_in_days": 35, "locked": True}),
         ("azurerm_storage_management_policy", {"storage_account_id": ACCOUNT, "rule": [
             {"name": "ciam-ds-backups", "enabled": True, "filters": [{"prefix_match": ["ds-backups/"]}],
              "actions": [{"base_blob": [{"tier_to_cold_after_days_since_modification_greater_than": 30,
                                          "delete_after_days_since_modification_greater_than": 400}],
                           "version": [{"delete_after_days_since_creation": 30}]}]},
             {"name": "other", "enabled": True, "filters": [{"prefix_match": ["exports/"]}],
              "actions": [{"base_blob": [{"delete_after_days_since_modification_greater_than": 1}]}]}]}),
         ("azurerm_storage_object_replication", {"source_storage_account_id": ACCOUNT,
                                                 "destination_storage_account_id": f"{SUB}/Microsoft.Storage/"
                                                                                   "storageAccounts/stciambackupsdr",
                                                 "rules": [{"source_container_name": "ds-backups",
                                                            "destination_container_name": "ds-backups"}]}))
READ = {"ciamStorageRef": ("azblob://stciambackups/ds-backups",), "ciamStorageVersioning": ("TRUE",),
        "ciamStoragePublicBlocked": ("TRUE",), "ciamStorageImmutability": ("compliance",),
        "ciamStorageLockDays": ("35",), "ciamStorageLifecycle": ("30 cold", "400 delete", "noncurrent 30 delete"),
        "ciamStorageReplicaRef": ("azblob://stciambackupsdr/ds-backups",)}


def test_a_container_is_read_back_from_state_with_its_accounts_settings():
    resources, _ = state_resources(_state(*STATE))
    (store,) = (r for r in resources if r.kind == "storage")
    assert (store.ref, store.role) == (CONTAINER, "backup-target")
    assert store.attrs == READ and store.links == {"ciamEncryptedByRole": "azkv-key://kv-ciam/keys/disk-cmk"}
    (bare,) = (r for r in state_resources(_state(STATE[2]))[0] if r.kind == "storage")
    assert bare.attrs == {"ciamStorageRef": ("azblob://stciambackups/ds-backups",)}


def test_the_cli_outputs_read_the_same():
    texts = {
        "accounts.json": json.dumps([{"id": ACCOUNT, "name": "stciambackups",
                                      "type": "Microsoft.Storage/storageAccounts",
                                      "allowBlobPublicAccess": False, "encryption": {
                                          "keySource": "Microsoft.Keyvault", "keyVaultProperties": {
                                              "keyVaultUri": "https://kv-ciam.vault.azure.net/",
                                              "keyName": "disk-cmk"}}}]),
        "blob-service.json": json.dumps({"id": f"{ACCOUNT}/blobServices/default", "isVersioningEnabled": True,
                                         "changeFeed": {"enabled": True},
                                         "type": "Microsoft.Storage/storageAccounts/blobServices"}),
        "containers.json": json.dumps([{"id": CONTAINER, "name": "ds-backups", "metadata": {"role": "backup-target"},
                                        "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
                                        "immutabilityPolicy": {"immutabilityPeriodSinceCreationInDays": 35,
                                                               "state": "Locked"}}]),
        "management-policy.json": json.dumps({"id": f"{ACCOUNT}/managementPolicies/default",
                                              "type": "Microsoft.Storage/storageAccounts/managementPolicies",
                                              "policy": {"rules": [{"name": "ciam-ds-backups", "enabled": True,
                                                                    "definition": {
                                                  "filters": {"prefixMatch": ["ds-backups/"],
                                                              "blobTypes": ["blockBlob"]},
                                                  "actions": {
                                                      "baseBlob": {
                                                          "tierToCold": {"daysAfterModificationGreaterThan": 30},
                                                          "delete": {"daysAfterModificationGreaterThan": 400}},
                                                      "version": {
                                                          "delete": {"daysAfterCreationGreaterThan": 30}}}}}]}}),
        "or-policies.json": json.dumps([{"id": f"{ACCOUNT}/objectReplicationPolicies/p1",
                                         "type": "Microsoft.Storage/storageAccounts/objectReplicationPolicies",
                                         "sourceAccount": "stciambackups", "destinationAccount": "stciambackupsdr",
                                         "rules": [{"sourceContainer": "ds-backups",
                                                    "destinationContainer": "ds-backups"}]}])}
    resources, notices = cli_resources(texts)
    (store,) = (r for r in resources if r.kind == "storage")
    assert store.attrs == READ and store.links == {"ciamEncryptedByRole": "azkv-key://kv-ciam/keys/disk-cmk"}
    assert not any("storage" in n.lower() for n in notices)
