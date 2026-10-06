"""The Azure CLI's storage items (and an ARM template's, read the same way), normalized to the attribute names of the
matching hashicorp/azurerm resources (opsdir_adapter_azure.storage reads both). Pure. Recognized by ARM type:

  az storage account list                          Microsoft.Storage/storageAccounts: public access, the
                                                   customer-managed key (Key Vault URI and key name)
  az storage account blob-service-properties show  Microsoft.Storage/storageAccounts/blobServices: versioning, change
                                                   feed (merged into the account)
  az storage container-rm list / show              Microsoft.Storage/storageAccounts/blobServices/containers: its
                                                   immutability policy when the output carries one (read by cli.py
                                                   as the container itself)
  az storage container immutability-policy show    .../containers/immutabilityPolicies: period and state
  az storage account management-policy show        Microsoft.Storage/storageAccounts/managementPolicies: lifecycle
                                                   rules
  az storage account or-policy list                Microsoft.Storage/storageAccounts/objectReplicationPolicies:
                                                   which containers are copied where
No key, no secret and no data is in these outputs.
"""
from .arm_ids import arm_segment

ACCOUNT = "microsoft.storage/storageaccounts"
BLOB_SERVICE = f"{ACCOUNT}/blobservices"
CONTAINER = f"{BLOB_SERVICE}/containers"
POLICY = f"{CONTAINER}/immutabilitypolicies"
MANAGEMENT = f"{ACCOUNT}/managementpolicies"
REPLICATION = f"{ACCOUNT}/objectreplicationpolicies"
READ = (ACCOUNT, BLOB_SERVICE, POLICY, MANAGEMENT, REPLICATION)   # what an ARM template's reader reads of these
# base blob actions and version actions as the CLI names them -> azurerm's arguments
BASE = (("tierToCool", "tier_to_cool_after_days_since_modification_greater_than"),
        ("tierToCold", "tier_to_cold_after_days_since_modification_greater_than"),
        ("tierToArchive", "tier_to_archive_after_days_since_modification_greater_than"),
        ("delete", "delete_after_days_since_modification_greater_than"))
VERSION = (("tierToCool", "change_tier_to_cool_after_days_since_creation"),
           ("tierToCold", "tier_to_cold_after_days_since_creation_greater_than"),
           ("tierToArchive", "change_tier_to_archive_after_days_since_creation"),
           ("delete", "delete_after_days_since_creation"))


def _account_name(arm_id):
    return arm_segment(arm_id, "storageAccounts")


def _accounts(items):
    """azurerm_storage_account attributes by account name: the account's own settings, its blob service's merged in."""
    accounts = {}
    for k, a in items:
        if k == ACCOUNT:
            vault = (a.get("encryption") or {}).get("keyVaultProperties") or {}
            uri, key = (vault.get("keyVaultUri") or "").rstrip("/"), vault.get("keyName")
            accounts.setdefault(a.get("name"), {}).update({
                "id": a.get("id"), "name": a.get("name"),
                **({"allow_nested_items_to_be_public": a["allowBlobPublicAccess"]}
                   if a.get("allowBlobPublicAccess") is not None else {}),
                "customer_managed_key": [{"key_vault_key_id": f"{uri}/keys/{key}"}] if uri and key else [],
                "tags": a.get("tags") or {}})
    for k, s in items:
        if k == BLOB_SERVICE and _account_name(s.get("id")):
            name = _account_name(s.get("id"))
            accounts.setdefault(name, {"name": name}).update({"blob_properties": [{
                "versioning_enabled": s.get("isVersioningEnabled") is True,
                "change_feed_enabled": (s.get("changeFeed") or {}).get("enabled") is True}]})
    return accounts


def _policy(container_id, p):
    return "azurerm_storage_container_immutability_policy", {
        "storage_container_resource_manager_id": container_id,
        "immutability_period_in_days": p.get("immutabilityPeriodSinceCreationInDays"),
        "locked": (p.get("state") or "").lower() == "locked"}


def _actions(definition, names):
    return [{tf: days for cli, tf in names
             for days in ((definition.get(cli) or {}).get("daysAfterModificationGreaterThan")
                          if tf.endswith("modification_greater_than")
                          else (definition.get(cli) or {}).get("daysAfterCreationGreaterThan"),) if days is not None}]


def _rule(r):
    d = r.get("definition") or {}
    actions = d.get("actions") or {}
    return {"name": r.get("name"), "enabled": r.get("enabled", True) is not False,
            "filters": [{"prefix_match": (d.get("filters") or {}).get("prefixMatch") or []}],
            "actions": [{"base_blob": _actions(actions.get("baseBlob") or {}, BASE),
                         "version": _actions(actions.get("version") or {}, VERSION)}]}


def storage_items(items):
    """(azurerm type, attributes) pairs of the storage accounts (blob service merged), the containers' immutability
    policies, the management (lifecycle) policies and object replication policies."""
    return [*(("azurerm_storage_account", a) for a in _accounts(items).values()),
            *(_policy(c.get("id"), c["immutabilityPolicy"]) for k, c in items
              if k == CONTAINER and isinstance(c.get("immutabilityPolicy"), dict)),
            *(_policy(p.get("id", "").split("/immutabilityPolicies/", 1)[0], p) for k, p in items if k == POLICY),
            *(("azurerm_storage_management_policy", {
                "storage_account_id": m.get("id", "").split("/managementPolicies/", 1)[0],
                "rule": [_rule(r) for r in (m.get("policy") or {}).get("rules") or ()]})
              for k, m in items if k == MANAGEMENT),
            *(("azurerm_storage_object_replication", {
                "source_storage_account_id": o.get("sourceAccount"),
                "destination_storage_account_id": o.get("destinationAccount"),
                "rules": [{"source_container_name": r.get("sourceContainer"),
                           "destination_container_name": r.get("destinationContainer")} for r in o.get("rules") or ()]})
              for k, o in items if k == REPLICATION)]
