"""Managed databases on Google Cloud: rendered as Cloud SQL (database version from engine, major version and edition,
tier, disk, zone, REGIONAL when zone-redundant, backups with point-in-time recovery or the binary log, private IP only,
ssl_mode, flags, CMEK, deletion protection), the administrator password written write-only from an ephemeral Secret
Manager read (a SQL user, or SQL Server's root password), adopted when it exists; engines Cloud SQL doesn't run and
databases others keep named. Read back from Terraform state, Cloud Asset Inventory and gcloud; no password is read."""
import copy
import json
import re

from opsdir_adapter_gcp.cli import cli_resources
from opsdir_adapter_gcp.databases import database_version, neutral_version, render_databases
from opsdir_adapter_gcp.inventory import state_resources
from network_fixtures import ALPHA, entry, model

KEY = "projects/p-ciam/locations/us-east1/keyRings/ciam/cryptoKeys/db"
DB = dict(ciamBindingRole="pf-grants-db", ciamDbEngine="postgresql", ciamDbEngineVersion="16",
          ciamInstanceSize="db-custom-2-7680", ciamDbStorageGb="100", ciamZone="us-east1-b",
          ciamDbHighAvailability="zone-redundant", ciamDbTlsRequired="TRUE", ciamRetentionDays="14",
          ciamDbPointInTime="TRUE", ciamDbDeletionProtection="TRUE", ciamEncryptedByRole="db-key",
          ciamDbCredentialRole="db-admin", ciamDbParameter="log_min_duration_statement=500")
KEY_REF = entry(ALPHA, "key-db", "ciamKeyRef", ciamBindingRole="db-key", ciamRefUri=f"gcp-kms://{KEY}")
SECRET = entry(ALPHA, "sec-db", "ciamSecretRef", ciamBindingRole="db-admin",
               ciamRefUri="gcp-sm://projects/p-ciam/secrets/db-admin")


def _render(*records):
    return "\n\n".join(render_databases(model(alpha=records)[1]))


def test_database_versions_both_ways():
    assert [database_version(e, v, ed) for e, v, ed in (("postgresql", "16.4", None), ("mysql", "8.0.35", None),
                                                        ("sqlserver", "15.0.4365", "enterprise"),
                                                        ("sqlserver", "13.0", None), ("oracle", "19", None))] == \
        ["POSTGRES_16", "MYSQL_8_0", "SQLSERVER_2019_ENTERPRISE", None, None]
    assert [neutral_version(v) for v in ("POSTGRES_16", "MYSQL_8_0_31", "SQLSERVER_2022_WEB", "ORACLE_19")] == [
        ("postgresql", "16", None), ("mysql", "8.0", None), ("sqlserver", "16", "web"), (None, None, None)]


def test_a_cloud_sql_instance_with_its_key_password_flags_and_import():
    out = _render(KEY_REF, SECRET, entry(ALPHA, "db-grants", "ciamDatabase", **DB,
                                         ciamProviderRef="projects/p-ciam/instances/db-grants"))
    for line in ('database_version    = "POSTGRES_16"', f'encryption_key_name = "{KEY}"',
                 "deletion_protection = true", 'availability_type           = "REGIONAL"',
                 "deletion_protection_enabled = true", 'zone = "us-east1-b"',
                 "point_in_time_recovery_enabled = true", "retained_backups = 14", "ipv4_enabled    = false",
                 "private_network = data.google_compute_network.main.self_link", 'ssl_mode        = "ENCRYPTED_ONLY"',
                 'name  = "log_min_duration_statement"',
                 "password_wo         = ephemeral.google_secret_manager_secret_version.db_grants_admin.secret_data",
                 'id = "projects/p-ciam/instances/db-grants"'):
        assert line in out, line
    assert 'ephemeral "google_secret_manager_secret_version" "db_grants_admin"' in out
    assert "roles/cloudkms.cryptoKeyEncrypterDecrypter" in out
    assert not re.search(r"\n\s+(password|root_password)\s+=", out)


def test_mysql_binary_log_sql_server_root_password_and_what_cloud_sql_doesnt_run():
    out = _render(SECRET,
                  entry(ALPHA, "db-sess", "ciamDatabase", ciamBindingRole="sessions-db", ciamDbEngine="mysql",
                        ciamDbEngineVersion="8.0.35", ciamDbTlsRequired="FALSE", ciamRetentionDays="7",
                        ciamDbPointInTime="TRUE", ciamDbCredentialRole="db-admin"),
                  entry(ALPHA, "db-sql", "ciamDatabase", ciamBindingRole="legacy-db", ciamDbEngine="sqlserver",
                        ciamDbEdition="enterprise", ciamDbEngineVersion="15.0.4365", ciamDbCredentialRole="db-admin"),
                  entry(ALPHA, "db-ora", "ciamDatabase", ciamBindingRole="ora-db", ciamDbEngine="oracle"),
                  entry(ALPHA, "db-dba", "ciamDatabase", ciamBindingRole="reports-db", ciamDbEngine="postgresql",
                        ciamManagedBy="cn=dba,ou=parties,dc=ciam-ops"))
    assert 'database_version    = "MYSQL_8_0"' in out and "binary_log_enabled = true" in out
    assert 'ssl_mode        = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"' in out
    assert 'database_version         = "SQLSERVER_2019_ENTERPRISE"' in out
    assert "root_password_wo         = ephemeral.google_secret_manager_secret_version.db_sql_admin.secret_data" in out
    assert out.count('resource "google_sql_user"') == 1                    # SQL Server's is its root password
    assert "# Database 'db-ora' runs oracle, which Cloud SQL doesn't: not rendered" in out
    assert "# Database 'db-dba' (role reports-db) is kept by cn=dba,ou=parties,dc=ciam-ops: not rendered here" in out


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/google"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


INSTANCE = {"id": "projects/p-ciam/instances/db-grants", "name": "db-grants", "database_version": "POSTGRES_16",
            "region": "us-east1", "dns_name": "db-grants.p-ciam.us-east1.sql.goog.", "encryption_key_name": KEY,
            "root_password": "never-read-this", "deletion_protection": True,
            "settings": [{"tier": "db-custom-2-7680", "availability_type": "REGIONAL", "disk_size": 100,
                          "deletion_protection_enabled": True, "user_labels": {"role": "pf-grants-db"},
                          "location_preference": [{"zone": "us-east1-b"}],
                          "backup_configuration": [{"enabled": True, "point_in_time_recovery_enabled": True,
                                                    "backup_retention_settings": [{"retained_backups": 14}]}],
                          "ip_configuration": [{"ssl_mode": "ENCRYPTED_ONLY", "ipv4_enabled": False}],
                          "database_flags": [{"name": "log_min_duration_statement", "value": "500"}]}]}


def test_an_instance_is_read_back_from_state_as_rendered_without_its_root_password():
    resources, notices = state_resources(_state(("google_sql_database_instance", "grants", INSTANCE),
                                                ("google_sql_user", "admin", {"name": "x", "password": "nope"})))
    (db,) = (r for r in resources if r.kind == "database")
    assert (db.ref, db.name, db.role) == ("projects/p-ciam/instances/db-grants", "db-grants", "pf-grants-db")
    expected = {k: (v,) for k, v in DB.items() if k not in ("ciamBindingRole", "ciamEncryptedByRole",
                                                           "ciamDbCredentialRole")}
    assert {k: db.attrs[k] for k in expected} == expected
    assert (db.attrs["ciamFqdn"], db.attrs["ciamPort"], db.attrs["ciamDbService"]) == (
        ("db-grants.p-ciam.us-east1.sql.goog",), ("5432",), ("cloud-sql",))
    assert db.links == {"ciamEncryptedByRole": KEY}
    assert "never-read-this" not in repr(resources) and "nope" not in repr(resources)
    assert "google_sql_user (1): not read (holds secret values, or isn't modeled yet)" in notices


def test_cloud_asset_inventory_and_gcloud_read_the_same():
    api = {"name": "db-grants", "project": "p-ciam", "databaseVersion": "POSTGRES_16", "region": "us-east1",
           "dnsName": "db-grants.p-ciam.us-east1.sql.goog.", "diskEncryptionConfiguration": {"kmsKeyName": KEY},
           "settings": {"tier": "db-custom-2-7680", "availabilityType": "REGIONAL", "dataDiskSizeGb": "100",
                        "deletionProtectionEnabled": True, "userLabels": {"role": "pf-grants-db"},
                        "locationPreference": {"zone": "us-east1-b"},
                        "backupConfiguration": {"enabled": True, "pointInTimeRecoveryEnabled": True,
                                                "backupRetentionSettings": {"retainedBackups": 14}},
                        "ipConfiguration": {"sslMode": "ENCRYPTED_ONLY", "ipv4Enabled": False},
                        "databaseFlags": [{"name": "log_min_duration_statement", "value": "500"}]}}
    asset = {"name": "//cloudsql.googleapis.com/projects/p-ciam/instances/db-grants",
             "assetType": "sqladmin.googleapis.com/Instance", "resource": {"data": api}}
    from_assets, _ = cli_resources({"assets.json": json.dumps([asset])})
    from_gcloud, _ = cli_resources({"sql.json": json.dumps([{**api, "kind": "sql#instance"}])})
    (a,), (g,) = ([r for r in rs if r.kind == "database"] for rs in (from_assets, from_gcloud))
    assert a == g and a.ref == "projects/p-ciam/instances/db-grants"
    assert (a.attrs["ciamDbStorageGb"], a.attrs["ciamDbTlsRequired"], a.attrs["ciamRetentionDays"]) == (
        ("100",), ("TRUE",), ("14",))


def test_the_ranges_it_admits_are_a_comment_the_peering_carries_them():
    out = _render(KEY_REF, SECRET, entry(ALPHA, "db-grants", "ciamDatabase", **DB, ciamSourceCidr="10.1.4.0/24"))
    assert ("# db-grants admits 10.1.4.0/24: Cloud SQL's private IP is in Google's service producer network, which "
            "this network's firewall rules don't reach") in out
    assert "google_compute_firewall" not in out


def test_a_copy_region_is_where_cloud_sql_stores_its_backups_and_is_read_back():
    out = _render(KEY_REF, SECRET, entry(ALPHA, "db-grants", "ciamDatabase", **DB, ciamCopyRegion=("us", "us-west1")))
    assert 'location                       = "us"' in out and "one location: us-west1 not rendered" in out
    moved = copy.deepcopy(INSTANCE)
    moved["settings"][0]["backup_configuration"][0]["location"] = "us-west1"
    (db,) = (r for r in state_resources(_state(("google_sql_database_instance", "grants", moved)))[0]
             if r.kind == "database")
    assert db.attrs["ciamCopyRegion"] == ("us-west1",)
    (same,) = (r for r in state_resources(_state(("google_sql_database_instance", "grants", INSTANCE)))[0]
               if r.kind == "database")
    assert "ciamCopyRegion" not in same.attrs
    api = {"name": "db-grants", "project": "p-ciam", "databaseVersion": "POSTGRES_16", "region": "us-east1",
           "settings": {"backupConfiguration": {"enabled": True, "location": "us"}}, "kind": "sql#instance"}
    (g,) = (r for r in cli_resources({"sql.json": json.dumps([api])})[0] if r.kind == "database")
    assert g.attrs["ciamCopyRegion"] == ("us",)
