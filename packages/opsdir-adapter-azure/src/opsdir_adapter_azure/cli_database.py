"""The Azure CLI's database items (and an ARM template's, read the same way), normalized to the attribute names of the
matching hashicorp/azurerm resources (opsdir_adapter_azure.databases reads both). Pure.

  az postgres flexible-server list                Microsoft.DBforPostgreSQL/flexibleServers
  az postgres flexible-server parameter list      Microsoft.DBforPostgreSQL/flexibleServers/configurations: the values
                                                  set on the server (source user-override) only
  az mysql flexible-server list                   Microsoft.DBforMySQL/flexibleServers
  az mysql flexible-server parameter list         Microsoft.DBforMySQL/flexibleServers/configurations
  az lock list                                    Microsoft.Authorization/locks: a CanNotDelete or ReadOnly lock on a
                                                  server is its deletion protection
The administrator password is never in these outputs.
"""
from .databases import SERVERS

TYPES = {"microsoft.dbforpostgresql/flexibleservers": SERVERS["postgresql"],
         "microsoft.dbformysql/flexibleservers": SERVERS["mysql"]}
LOCK = "microsoft.authorization/locks"
READ = (*TYPES, *(f"{t}/configurations" for t in TYPES), LOCK)     # what an ARM template's reader reads of these
_USER_SET = ("user-override", "user")


def _server(s):
    storage, ha = s.get("storage") or {}, s.get("highAvailability") or {}
    network, key = s.get("network") or {}, (s.get("dataEncryption") or {}).get("primaryKeyURI")
    return {"id": s.get("id"), "name": s.get("name"), "version": s.get("version"),
            "sku_name": (s.get("sku") or {}).get("name"),
            **({"storage_mb": storage["storageSizeGb"] * 1024} if storage.get("storageSizeGb") else {}),
            "zone": s.get("availabilityZone"), "fqdn": s.get("fullyQualifiedDomainName"),
            "high_availability": [{"mode": ha.get("mode"), "standby_availability_zone":
                                   ha.get("standbyAvailabilityZone")}] if ha.get("mode") not in (None, "Disabled")
            else [],
            "backup_retention_days": (s.get("backup") or {}).get("backupRetentionDays"),
            "geo_redundant_backup_enabled": (s.get("backup") or {}).get("geoRedundantBackup") == "Enabled",
            "location": s.get("location"),
            "delegated_subnet_id": network.get("delegatedSubnetResourceId"),
            "customer_managed_key": [{"key_vault_key_id": key}] if key else [], "tags": s.get("tags") or {}}


def _scope(lock_id):
    """What a lock (its ARM ID) is on: the ID before its /providers/Microsoft.Authorization/locks/ part."""
    at = lock_id.lower().find("/providers/microsoft.authorization/locks/")
    return lock_id[:at] if at > 0 else None


def database_items(items):
    """(azurerm type, attributes) pairs of the database servers, their user-set parameters and the locks."""
    return [*((TYPES[k], _server(s)) for k, s in items if k in TYPES),
            *((f"{TYPES[k[:-len('/configurations')]]}_configuration", {
                "name": c.get("name"), "value": c.get("value"),
                "server_id": (c.get("id") or "").split("/configurations/", 1)[0]})
              for k, c in items if k.endswith("/configurations") and k[:-len("/configurations")] in TYPES
              and c.get("source") in _USER_SET),
            *(("azurerm_management_lock", {"scope": _scope(lk.get("id") or ""),
                                           "lock_level": lk.get("level") or lk.get("lockLevel")})
              for k, lk in items if k == LOCK)]
