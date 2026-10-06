"""The Azure CLI's Data Protection (Azure Backup) resources, and an ARM template's read the same way, normalized to the
attribute names of the matching hashicorp/azurerm resources (opsdir_adapter_azure.backups reads both). Properties may
be nested (`az dataprotection … -o json`) or flattened into the resource (the ARM reader). Pure.

  az dataprotection backup-vault list       Microsoft.DataProtection/backupVaults -> azurerm_data_protection_
                                            backup_vault (redundancy, cross-region restore, immutability), and its
                                            customer-managed key as azurerm_data_protection_backup_vault_customer_
                                            managed_key
  az dataprotection backup-policy list      …/backupVaults/backupPolicies (disk ones) -> azurerm_data_protection_
     --vault-name V                         backup_policy_disk (its repeating interval, default retention)
  az dataprotection backup-instance list    …/backupVaults/backupInstances (disk ones) -> azurerm_data_protection_
     --vault-name V                         backup_instance_disk (the disk, its policy)
"""
VAULTS = "microsoft.dataprotection/backupvaults"
POLICIES = "microsoft.dataprotection/backupvaults/backuppolicies"
INSTANCES = "microsoft.dataprotection/backupvaults/backupinstances"
READ = (VAULTS, POLICIES, INSTANCES)    # what an ARM template's reader reads of these
DISKS = "microsoft.compute/disks"


def _props(item):
    return {**item, **(item.get("properties") or {})}


def _vault_of(child_id):
    return (child_id or "").rsplit("/backupPolicies/", 1)[0].rsplit("/backupInstances/", 1)[0]


def _vault(item):
    p = _props(item)
    storage = (p.get("storageSettings") or [{}])[0]
    security = p.get("securitySettings") or {}
    key = ((security.get("encryptionSettings") or {}).get("keyVaultProperties") or {}).get("keyUri")
    return [("azurerm_data_protection_backup_vault", {
                "id": p.get("id"), "name": p.get("name"), "redundancy": storage.get("type"),
                "cross_region_restore_enabled": ((p.get("featureSettings") or {}).get("crossRegionRestoreSettings")
                                                 or {}).get("state") == "Enabled",
                "immutability": (security.get("immutabilitySettings") or {}).get("state"),
                "tags": p.get("tags") or {}}),
            *((("azurerm_data_protection_backup_vault_customer_managed_key", {
                "data_protection_backup_vault_id": p.get("id"), "key_vault_key_id": key}),) if key else ())]


def _policy(item):
    p = _props(item)
    if DISKS not in [t.lower() for t in p.get("datasourceTypes") or ()]:
        return []
    rules = p.get("policyRules") or ()
    intervals = [i for r in rules if r.get("objectType") == "AzureBackupRule"
                 for i in (((r.get("trigger") or {}).get("schedule") or {}).get("repeatingTimeIntervals") or ())]
    default = next((r for r in rules if r.get("objectType") == "AzureRetentionRule" and r.get("isDefault")), {})
    keep = ((((default.get("lifecycles") or [{}])[0]).get("deleteAfter") or {}).get("duration"))
    return [("azurerm_data_protection_backup_policy_disk", {
        "id": p.get("id"), "name": p.get("name"), "vault_id": _vault_of(p.get("id")),
        "backup_repeating_time_intervals": intervals, "default_retention_duration": keep})]


def _instance(item):
    p = _props(item)
    source = p.get("dataSourceInfo") or {}
    if (source.get("datasourceType") or "").lower() != DISKS:
        return []
    return [("azurerm_data_protection_backup_instance_disk", {
        "id": p.get("id"), "name": p.get("name"), "vault_id": _vault_of(p.get("id")),
        "disk_id": source.get("resourceID"), "backup_policy_id": (p.get("policyInfo") or {}).get("policyId")})]


def backup_items(items):
    """(azurerm type, attributes) pairs of the backup vaults (and their keys), disk backup policies and disk backup
    instances among (kind, item) pairs."""
    convert = {VAULTS: _vault, POLICIES: _policy, INSTANCES: _instance}
    return [pair for kind, item in items if kind in convert for pair in convert[kind](item)]
