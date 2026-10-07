"""Managed databases on Azure: PostgreSQL and MySQL rendered as Flexible Servers (major version, SKU, storage, zone,
zone-redundant standby, delegated subnet with its private DNS zone an input, customer-managed key through a
user-assigned identity, the administrator password written write-only from an ephemeral Key Vault read, parameters
and TLS as configurations, deletion protection as a lock, adopted when it exists); engines Flexible Server doesn't run
and databases others keep named. Read back from Terraform state and the CLI; the password is never read."""
import json
import re

from opsdir_adapter_azure.arm import arm_resources
from opsdir_adapter_azure.cli import cli_resources
from opsdir.core.directory import make_entry
from opsdir_adapter_azure.databases import render_databases
from opsdir_adapter_azure.pairs import paired_region
from opsdir_adapter_azure.inventory import state_resources
from network_fixtures import ALPHA, entry, model

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam/providers"
PG = f"{SUB}/Microsoft.DBforPostgreSQL/flexibleServers/db-grants"
SNET = f"{SUB}/Microsoft.Network/virtualNetworks/vnet-ciam/subnets/snet-db"
KEY_URL = "https://kv-ciam.vault.azure.net/keys/db-key/0123456789abcdef"
DB = dict(ciamBindingRole="pf-grants-db", ciamDbEngine="postgresql", ciamDbEngineVersion="16",
          ciamInstanceSize="GP_Standard_D2ds_v4", ciamDbStorageGb="128", ciamZone="1",
          ciamDbHighAvailability="zone-redundant", ciamDbTlsRequired="TRUE", ciamRetentionDays="14",
          ciamDbPointInTime="TRUE", ciamDbDeletionProtection="TRUE", ciamEncryptedByRole="db-key",
          ciamDbCredentialRole="db-admin", ciamDbParameter="log_min_duration_statement=500",
          ciamSubnetRole="subnet-ds")
KEY = entry(ALPHA, "key-db", "ciamKeyRef", ciamBindingRole="db-key", ciamRefUri="azkv-key://kv-ciam/keys/db-key")
SECRET = entry(ALPHA, "sec-db", "ciamSecretRef", ciamBindingRole="db-admin", ciamRefUri="azkv://kv-ciam/db-admin")


def _render(*records):
    return "\n\n".join(render_databases(model(alpha=records)[1]))


def test_a_postgresql_flexible_server_with_its_key_password_parameters_and_lock():
    out = _render(KEY, SECRET, entry(ALPHA, "db-grants", "ciamDatabase", **DB, ciamProviderRef=PG))
    assert 'resource "azurerm_postgresql_flexible_server" "db_grants"' in out
    for line in ('version               = "16"', 'sku_name              = "GP_Standard_D2ds_v4"',
                 "storage_mb            = 131072", 'zone                  = "1"', "backup_retention_days = 14",
                 'mode = "ZoneRedundant"', "delegated_subnet_id               = data.azurerm_subnet.subnet_ds.id",
                 "private_dns_zone_id               = var.db_grants_private_dns_zone_id",
                 "public_network_access_enabled     = false",
                 "administrator_password_wo         = ephemeral.azurerm_key_vault_secret.db_grants_admin.value",
                 "administrator_password_wo_version = 1",
                 "key_vault_key_id                  = data.azurerm_key_vault_key.db_grants_cmk.id",
                 'role_definition_name = "Key Vault Crypto Service Encryption User"',
                 'lock_level = "CanNotDelete"', f'id = "{PG}"'):
        assert line in out, line
    assert 'ephemeral "azurerm_key_vault_secret" "db_grants_admin"' in out
    assert not re.search(r"\n\s+administrator_password\s+=", out)          # never a plain password
    assert 'name      = "log_min_duration_statement"' in out and "require_secure_transport" not in out


def test_a_network_security_group_named_by_its_role_on_its_delegated_subnet():
    out = _render(KEY, SECRET, entry(ALPHA, "db-grants", "ciamDatabase", **DB, ciamSourceCidr="10.1.4.0/24"))
    assert 'resource "azurerm_network_security_group" "pf_grants_db"' in out
    assert 'name                = "nsg-ciam-prod-pf-grants-db"' in out and 'Role      = "pf-grants-db"' in out
    assert 'resource "azurerm_subnet_network_security_group_association" "pf_grants_db"' in out
    assert "subnet_id                 = data.azurerm_subnet.subnet_ds.id" in out
    assert "network_security_group_id = azurerm_network_security_group.pf_grants_db.id" in out
    assert 'resource "azurerm_network_security_rule" "pf_grants_db_clients"' in out
    for line in ('name                        = "pf-grants-db-clients"', "priority                    = 100",
                 'destination_port_ranges     = ["5432"]', 'source_address_prefixes     = ["10.1.4.0/24"]',
                 "network_security_group_name = azurerm_network_security_group.pf_grants_db.name"):
        assert line in out, line
    no_subnet = _render(entry(ALPHA, "db-x", "ciamDatabase", ciamBindingRole="x-db", ciamDbEngine="postgresql"))
    assert 'resource "azurerm_network_security_group" "x_db"' in no_subnet
    assert "azurerm_subnet_network_security_group_association" not in no_subnet
    assert "azurerm_network_security_rule" not in no_subnet           # it admits no ranges


def test_the_rules_of_the_group_on_its_delegated_subnet_are_its_ranges_not_firewall_rules():
    nsg = f"{SUB}/Microsoft.Network/networkSecurityGroups/nsg-ciam-prod-pf-grants-db"
    resources, _ = state_resources(_state(
        ("azurerm_postgresql_flexible_server", "grants", SERVER),
        ("azurerm_network_security_group", "db", {"id": nsg, "name": "nsg-ciam-prod-pf-grants-db",
                                                   "resource_group_name": "rg-ciam"}),
        ("azurerm_subnet_network_security_group_association", "db", {"subnet_id": SNET,
                                                                     "network_security_group_id": nsg}),
        ("azurerm_network_security_rule", "db", {
            "name": "pf-grants-db-clients", "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
            "source_address_prefixes": ["10.1.4.0/24"], "destination_port_ranges": ["5432"],
            "resource_group_name": "rg-ciam", "network_security_group_name": "nsg-ciam-prod-pf-grants-db"})))
    (db,) = (r for r in resources if r.kind == "database")
    assert db.attrs["ciamSourceCidr"] == ("10.1.4.0/24",)
    assert not [r for r in resources if r.kind == "firewall"]


def test_mysql_storage_tls_off_and_what_flexible_server_doesnt_run():
    out = _render(SECRET, entry(ALPHA, "db-sess", "ciamDatabase", ciamBindingRole="sessions-db", ciamDbEngine="mysql",
                                ciamDbEngineVersion="8.0.35", ciamDbStorageGb="64", ciamDbTlsRequired="FALSE",
                                ciamDbCredentialRole="db-admin"),
                  entry(ALPHA, "db-sql", "ciamDatabase", ciamBindingRole="legacy-db", ciamDbEngine="sqlserver"),
                  entry(ALPHA, "db-dba", "ciamDatabase", ciamBindingRole="reports-db", ciamDbEngine="postgresql",
                        ciamManagedBy="cn=dba,ou=parties,dc=ciam-ops"))
    assert 'resource "azurerm_mysql_flexible_server" "db_sess"' in out and 'version             = "8.0.21"' in out
    assert "storage {\n    size_gb = 64\n  }" in out
    assert 'name      = "require_secure_transport"' in out and 'value     = "off"' in out
    assert "azurerm_management_lock" not in out and "import {" not in out and "delegated_subnet_id" not in out
    assert "# Database 'db-sql' runs sqlserver, which Azure Database Flexible Server doesn't" in out
    assert "# Database 'db-dba' (role reports-db) is kept by cn=dba,ou=parties,dc=ciam-ops: not rendered here" in out


def test_no_credential_role_or_an_unbound_key_is_said():
    out = _render(entry(ALPHA, "db-x", "ciamDatabase", ciamBindingRole="x", ciamDbEngine="postgresql",
                        ciamEncryptedByRole="nowhere"))
    assert "# no ciamDbCredentialRole: no administrator password is set" in out
    assert "# UNBOUND:nowhere: no key binding for role nowhere in this environment" in out


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


SERVER = {"id": PG, "name": "db-grants", "version": "16", "sku_name": "GP_Standard_D2ds_v4", "storage_mb": 131072,
          "zone": "1", "high_availability": [{"mode": "ZoneRedundant", "standby_availability_zone": "2"}],
          "backup_retention_days": 14, "fqdn": "db-grants.postgres.database.azure.com", "delegated_subnet_id": SNET,
          "customer_managed_key": [{"key_vault_key_id": KEY_URL}], "administrator_login": "ciam_admin",
          "administrator_password": "never-read-this", "tags": {"Role": "pf-grants-db"}}


def test_a_flexible_server_is_read_back_from_state_without_its_password():
    resources, notices = state_resources(_state(
        ("azurerm_postgresql_flexible_server", "grants", SERVER),
        ("azurerm_postgresql_flexible_server_configuration", "log", {"name": "log_min_duration_statement",
                                                                     "server_id": PG, "value": "500"}),
        ("azurerm_management_lock", "lock", {"scope": PG, "lock_level": "CanNotDelete"})))
    (db,) = (r for r in resources if r.kind == "database")
    assert (db.ref, db.name, db.role) == (PG, "db-grants", "pf-grants-db")
    expected = {k: (v,) for k, v in DB.items() if k not in ("ciamBindingRole", "ciamEncryptedByRole",
                                                           "ciamDbCredentialRole", "ciamSubnetRole")}
    assert {k: db.attrs[k] for k in expected} == expected
    assert (db.attrs["ciamDbService"], db.attrs["ciamPort"], db.attrs["ciamFqdn"]) == (
        ("flexible-server",), ("5432",), ("db-grants.postgres.database.azure.com",))
    assert db.links == {"ciamSubnetRole": "vnet-ciam/snet-db", "ciamEncryptedByRole": "azkv-key://kv-ciam/keys/db-key"}
    assert "never-read-this" not in repr(resources) and "ciam_admin" not in repr(resources)
    assert not any("flexible_server" in n for n in notices)


def test_the_cli_reads_the_same_with_user_set_parameters_only_and_the_lock():
    server = {"id": PG, "name": "db-grants", "type": "Microsoft.DBforPostgreSQL/flexibleServers", "version": "16",
              "sku": {"name": "GP_Standard_D2ds_v4", "tier": "GeneralPurpose"}, "storage": {"storageSizeGb": 128},
              "availabilityZone": "1", "highAvailability": {"mode": "ZoneRedundant", "standbyAvailabilityZone": "2"},
              "backup": {"backupRetentionDays": 14, "geoRedundantBackup": "Disabled"},
              "fullyQualifiedDomainName": "db-grants.postgres.database.azure.com",
              "network": {"delegatedSubnetResourceId": SNET, "publicNetworkAccess": "Disabled"},
              "dataEncryption": {"type": "AzureKeyVault", "primaryKeyURI": KEY_URL}, "administratorLogin": "ciam_admin",
              "tags": {"Role": "pf-grants-db"}}
    params = [{"id": f"{PG}/configurations/{n}", "name": n, "value": v, "source": s,
               "type": "Microsoft.DBforPostgreSQL/flexibleServers/configurations"}
              for n, v, s in (("log_min_duration_statement", "500", "user-override"),
                              ("require_secure_transport", "on", "system-default"),
                              ("max_connections", "859", "system-default"))]
    lock = {"id": f"{PG}/providers/Microsoft.Authorization/locks/db-grants-no-delete", "level": "CanNotDelete",
            "name": "db-grants-no-delete", "type": "Microsoft.Authorization/locks"}
    resources, notices = cli_resources({"pg.json": json.dumps([server]), "pg-params.json": json.dumps(params),
                                        "locks.json": json.dumps([lock])})
    (db,) = (r for r in resources if r.kind == "database")
    assert (db.attrs["ciamDbParameter"], db.attrs["ciamDbTlsRequired"], db.attrs["ciamDbDeletionProtection"],
            db.attrs["ciamDbStorageGb"], db.attrs["ciamDbHighAvailability"]) == (
        ("log_min_duration_statement=500",), ("TRUE",), ("TRUE",), ("128",), ("zone-redundant",))
    assert db.links["ciamEncryptedByRole"] == "azkv-key://kv-ciam/keys/db-key"
    assert not any("pg" in n and "not read" in n for n in notices), notices


def test_an_arm_template_deploys_the_same_and_its_password_parameter_is_never_evaluated():
    template = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0", "parameters": {"pw": {"type": "securestring", "defaultValue": "s3cr3t"}},
                "resources": [
                    {"type": "Microsoft.DBforPostgreSQL/flexibleServers", "apiVersion": "2023-06-01-preview",
                     "name": "db-grants", "location": "eastus", "tags": {"Role": "pf-grants-db"},
                     "sku": {"name": "GP_Standard_D2ds_v4", "tier": "GeneralPurpose"},
                     "properties": {"version": "16", "storage": {"storageSizeGb": 128},
                                    "highAvailability": {"mode": "ZoneRedundant"}, "backup": {"backupRetentionDays": 14},
                                    "administratorLoginPassword": "[parameters('pw')]"}},
                    {"type": "Microsoft.DBforPostgreSQL/flexibleServers/configurations",
                     "apiVersion": "2023-06-01-preview", "name": "db-grants/log_min_duration_statement",
                     "properties": {"value": "500", "source": "user-override"}}]}
    resources, _ = arm_resources({"db/azuredeploy.json": json.dumps(template)})
    (db,) = (r for r in resources if r.kind == "database")
    assert (db.role, db.attrs["ciamDbParameter"], db.attrs["ciamDbHighAvailability"]) == (
        "pf-grants-db", ("log_min_duration_statement=500",), ("zone-redundant",))
    assert "s3cr3t" not in repr(resources)


def _in_region(m, region):
    """Model m with its cloud in region."""
    return m._replace(cloud=make_entry(m.cloud.dn, m.cloud.classes, {**m.cloud.attrs, "ciamRegion": (region,)}))


def test_a_copy_region_is_geo_redundant_backup_to_the_region_s_pair():
    assert (paired_region("eastus2"), paired_region("usgovvirginia"), paired_region("usgovtexas")) == (
        "centralus", "usgovtexas", None)
    db = entry(ALPHA, "db-grants", "ciamDatabase", **DB, ciamCopyRegion="centralus", ciamProviderRef=PG)
    _, alpha, _ = model(alpha=(KEY, SECRET, db))
    out = "\n\n".join(render_databases(_in_region(alpha, "eastus2")))
    assert "geo_redundant_backup_enabled = true" in out and "not centralus" not in out
    assert "# db-grants: geo-redundant backup is chosen when a server is created" in out
    other = "\n\n".join(render_databases(_in_region(model(alpha=(KEY, SECRET, entry(
        ALPHA, "db-grants", "ciamDatabase", **DB, ciamCopyRegion="westus3")))[1], "eastus2")))
    assert "# db-grants: Azure copies geo-redundant backups to eastus2's pair, centralus, not westus3: record " \
           "centralus as its ciamCopyRegion" in other
    unknown = _render(KEY, SECRET, entry(ALPHA, "db-grants", "ciamDatabase", **DB, ciamCopyRegion="region-2"))
    assert "paired region, which isn't known here" in unknown and "geo_redundant_backup_enabled = true" in unknown


def test_geo_redundant_backup_is_read_back_as_the_location_s_pair():
    resources, _ = state_resources(_state(("azurerm_postgresql_flexible_server", "grants",
                                           {**SERVER, "location": "eastus2", "geo_redundant_backup_enabled": True})))
    (db,) = (r for r in resources if r.kind == "database")
    assert db.attrs["ciamCopyRegion"] == ("centralus",)
    server = {"id": PG, "name": "db-grants", "type": "Microsoft.DBforPostgreSQL/flexibleServers", "version": "16",
              "location": "usgovvirginia", "backup": {"backupRetentionDays": 14, "geoRedundantBackup": "Enabled"}}
    resources, _ = cli_resources({"pg.json": json.dumps([server])})
    (db,) = (r for r in resources if r.kind == "database")
    assert db.attrs["ciamCopyRegion"] == ("usgovtexas",)
