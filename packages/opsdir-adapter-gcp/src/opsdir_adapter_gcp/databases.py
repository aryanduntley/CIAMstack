"""Google Cloud: the managed databases (opsdir.domains.data) an environment runs, rendered as Terraform and read back.
Pure.

Rendered into the stack's main.tf, for each database the stack keeps (one naming ciamManagedBy is someone else's: a
comment names them). PostgreSQL, MySQL and SQL Server run on Cloud SQL; other engines are a comment.

  google_sql_database_instance: database_version from the engine, major version and edition (POSTGRES_16, MYSQL_8_0,
  SQLSERVER_2019_STANDARD: Cloud SQL keeps minor versions current), tier (ciamInstanceSize), disk size, its zone as
  the location preference, REGIONAL availability when zone-redundant, backups (retained backups from
  ciamRetentionDays, point-in-time recovery or MySQL's binary log), a private IP on the environment's network with no
  public IPv4, ssl_mode ENCRYPTED_ONLY when TLS is required, a database flag per parameter, the CMEK of its key role
  (the Cloud SQL service agent needs Encrypter/Decrypter on the key: a comment), deletion protection both in
  Terraform and the API, labels role and managed_by
  the administrator password read from its credential role's Secret Manager secret by an ephemeral resource and
  written write-only: a google_sql_user (PostgreSQL, MySQL; the login an input) or SQL Server's root password. No
  Terraform state holds it and the record holds only the reference
  an import block when its provider ref is recorded
The ranges the record admits to a database (ciamSourceCidr) are a comment: Cloud SQL's private address is in
Google's service producer network, which the network's firewall rules and policies don't reach; the private services
access peering carries the traffic (under an egress allowlist, its range is among the private ranges).

Read back from (google type, attributes) pairs, Terraform state as it is or Cloud Asset Inventory and gcloud
normalized to it (sql_instance). The root password (root_password) is never read.
"""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import UNBOUND, bound, of_class
from opsdir.core.inventory import of_types, resource
from opsdir.domains.data.naming import DEFAULT_PORTS
from opsdir.domains.data.databases import major_version
from opsdir.domains.network.plumbing import adopted
from opsdir.domains.network.stack import kept_by, owned
from opsdir_format_terraform.hcl import Block, block, import_block, ref, tf_name
from opsdir_format_terraform.state import first_block
from .names import NETWORK, REGION, label, name_parts, resource_id

PORTS = {e: DEFAULT_PORTS[e] for e in ("postgresql", "mysql", "sqlserver")}    # the engines Cloud SQL runs
SQLSERVER_YEARS = {"14": "2017", "15": "2019", "16": "2022"}
EDITIONS = {"standard": "STANDARD", "enterprise": "ENTERPRISE", "express": "EXPRESS", "web": "WEB"}
TLS_ONLY = ("ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED")


# ------------------------------------------------------------------ versions
def database_version(engine, version, edition):
    """Cloud SQL's database_version of an engine, version and edition; None when Cloud SQL doesn't run it."""
    if not version:
        return None
    major = major_version(engine, version)
    if engine == "postgresql":
        return f"POSTGRES_{major}"
    if engine == "mysql":
        return f"MYSQL_{major.replace('.', '_')}"
    if engine == "sqlserver" and major in SQLSERVER_YEARS:
        return f"SQLSERVER_{SQLSERVER_YEARS[major]}_{EDITIONS[edition or 'standard']}"
    return None


def neutral_version(version):
    """(engine, version, edition) of a Cloud SQL database_version; (None, None, None) when unknown."""
    parts = (version or "").split("_")
    years = {y: m for m, y in SQLSERVER_YEARS.items()}
    editions = {v: k for k, v in EDITIONS.items()}
    if parts[0] == "POSTGRES" and len(parts) == 2:
        return "postgresql", parts[1], None
    if parts[0] == "MYSQL" and len(parts) >= 3:
        return "mysql", ".".join(parts[1:3]), None
    if parts[0] == "SQLSERVER" and len(parts) == 3 and parts[1] in years and parts[2] in editions:
        return "sqlserver", years[parts[1]], editions[parts[2]]
    return None, None, None


# ------------------------------------------------------------------ render
def _given(*pairs):
    return tuple((k, v) for k, v in pairs if v is not None)


def _labels(b):
    return {"role": label(one(b, "ciamBindingRole")), "managed_by": "opsdir"}


def _uri(m, role, what):
    if not role:
        return None, None
    uri = bound(m, role, "ciamRefUri")
    return (None, ("#", f"{uri}: no {what} binding for role {role} in this environment")) \
        if uri.startswith(UNBOUND) else (uri, None)


def _password(m, b, n, engine):
    """(blocks before the instance, instance body, blocks after it): the administrator password, written write-only
    from an ephemeral read of the credential role's Secret Manager secret."""
    uri, note = _uri(m, one(b, "ciamDbCredentialRole"), "credential")
    if uri is None:
        return (), (note or ("#", "no ciamDbCredentialRole: no administrator password is set"),), ()
    path = name_parts(uri.split("://", 1)[1])
    if "locations" in path:
        return (), (("#", f"{uri}: a regional secret has no ephemeral read; set the password by hand"),), ()
    secret = f"ephemeral.google_secret_manager_secret_version.{n}_admin.secret_data"
    read = (f"# {rdn_value(b)}: its administrator password is read when applied and written write-only: no "
            "Terraform state holds it",
            block("ephemeral", ["google_secret_manager_secret_version", f"{n}_admin"], [
                ("secret", path.get("secrets")), *_given(("project", path.get("projects")))]))
    if engine == "sqlserver":
        return read, (("root_password_wo", ref(secret)), ("root_password_wo_version", 1)), ()
    return read, (), (block("resource", ["google_sql_user", f"{n}_admin"], [
        ("name", ref(f"var.{n}_admin_login")), ("instance", ref(f"google_sql_database_instance.{n}.name")),
        ("password_wo", ref(secret)), ("password_wo_version", 1)]),
        block("variable", [f"{n}_admin_login"], [("type", ref("string")),
                                                  ("description", f"The administrator login of database "
                                                                  f"{rdn_value(b)}")]))


def _key(m, b):
    uri, note = _uri(m, one(b, "ciamEncryptedByRole"), "key")
    if uri is None:
        return (), (note,) if note else ()
    return ((f"# {rdn_value(b)}: the Cloud SQL service agent (service-<project number>@gcp-sa-cloud-sql.iam."
             "gserviceaccount.com) needs roles/cloudkms.cryptoKeyEncrypterDecrypter on its key",),
            (("encryption_key_name", uri.split("://", 1)[1]),))


def _backups(b, engine):
    retention, pitr = one(b, "ciamRetentionDays"), one(b, "ciamDbPointInTime")
    kept = bool(retention and retention != "0")
    if not kept and pitr is None:
        return ()
    log = "binary_log_enabled" if engine == "mysql" else "point_in_time_recovery_enabled"
    return (("backup_configuration", Block((
        ("enabled", kept or pitr == "TRUE"), *_given((log, {"TRUE": True, "FALSE": False}.get(pitr))),
        *((("backup_retention_settings", Block((("retained_backups", int(retention)),))),) if kept else ())))),)


def _database(m, b):
    n, cn, engine = tf_name(rdn_value(b)), rdn_value(b), one(b, "ciamDbEngine")
    version = database_version(engine, one(b, "ciamDbEngineVersion"), one(b, "ciamDbEdition"))
    if engine not in PORTS:
        return (f"# Database '{cn}' runs {engine}, which Cloud SQL doesn't: not rendered",)
    before, secret_body, after = _password(m, b, n, engine)
    key_notes, key_body = _key(m, b)
    protected = one(b, "ciamDbDeletionProtection") == "TRUE"
    tls = one(b, "ciamDbTlsRequired")
    settings = Block((
        *_given(("tier", one(b, "ciamInstanceSize"))),
        ("availability_type", "REGIONAL" if one(b, "ciamDbHighAvailability") == "zone-redundant" else "ZONAL"),
        *_given(("disk_size", int(one(b, "ciamDbStorageGb")) if one(b, "ciamDbStorageGb") else None)),
        ("deletion_protection_enabled", protected), ("user_labels", _labels(b)),
        *((("location_preference", Block((("zone", one(b, "ciamZone")),))),) if one(b, "ciamZone") else ()),
        *_backups(b, engine),
        ("ip_configuration", Block((
            ("ipv4_enabled", False), ("private_network", NETWORK),
            *_given(("ssl_mode", {"TRUE": "ENCRYPTED_ONLY", "FALSE": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}.get(tls)))))),
        *(("database_flags", Block((("name", k), ("value", v))))
          for k, v in sorted(dict(p.split("=", 1) for p in values(b, "ciamDbParameter") if "=" in p).items()))))
    instance = block("resource", ["google_sql_database_instance", n], [
        ("name", cn), *_given(("database_version", version)), ("region", REGION), *key_body, *secret_body,
        ("deletion_protection", protected), ("settings", settings)])
    cidrs = values(b, "ciamSourceCidr")
    return (*((f"# {cn}: no ciamDbEngineVersion Cloud SQL runs: set database_version",) if not version else ()),
            *((f"# {cn} admits {', '.join(cidrs)}: Cloud SQL's private IP is in Google's service producer network, "
               "which this network's firewall rules don't reach; the private services access peering carries the "
               "traffic",) if cidrs else ()),
            *key_notes, *before, instance, *after,
            *((import_block(f"google_sql_database_instance.{n}", resource_id(one(b, "ciamProviderRef"))),)
              if adopted(b) else ()))


def render_databases(m):
    """HCL for environment m's managed databases: those the stack keeps, then comments naming who keeps the others."""
    dbs = of_class(m, "ciamDatabase")
    return (*(f"# Database '{rdn_value(b)}' (role {one(b, 'ciamBindingRole')}) is kept by {kept_by(m, b)}: not "
              "rendered here" for b in dbs if not owned(b)),
            *(x for b in dbs if owned(b) for x in _database(m, b)))


# ------------------------------------------------------------------ read back
def sql_instance(d):
    """A Cloud SQL instance as Cloud Asset Inventory or gcloud prints it, as google_sql_database_instance's
    attributes."""
    s = d.get("settings") or {}
    backup, ip = s.get("backupConfiguration") or {}, s.get("ipConfiguration") or {}
    retained = (backup.get("backupRetentionSettings") or {}).get("retainedBackups")
    project, name = d.get("project"), d.get("name")
    return "google_sql_database_instance", {
        "id": f"projects/{project}/instances/{name}" if project and name else name, "name": name,
        "self_link": d.get("selfLink"), "database_version": d.get("databaseVersion"), "region": d.get("region"),
        "dns_name": d.get("dnsName"),
        "encryption_key_name": (d.get("diskEncryptionConfiguration") or {}).get("kmsKeyName"),
        "settings": [{
            "tier": s.get("tier"), "availability_type": s.get("availabilityType"),
            "disk_size": s.get("dataDiskSizeGb"), "deletion_protection_enabled": s.get("deletionProtectionEnabled"),
            "user_labels": s.get("userLabels") or {},
            "location_preference": [{"zone": (s.get("locationPreference") or {}).get("zone")}],
            "backup_configuration": [{
                "enabled": backup.get("enabled"), "binary_log_enabled": backup.get("binaryLogEnabled"),
                "point_in_time_recovery_enabled": backup.get("pointInTimeRecoveryEnabled"),
                "backup_retention_settings": [{"retained_backups": retained}] if retained else []}],
            "ip_configuration": [{"ssl_mode": ip.get("sslMode"), "require_ssl": ip.get("requireSsl"),
                                  "private_network": ip.get("privateNetwork")}],
            "database_flags": [{"name": f.get("name"), "value": f.get("value")} for f in s.get("databaseFlags") or ()
                               if f.get("name")]}]}


def _instance(a):
    engine, version, edition = neutral_version(a.get("database_version"))
    if engine is None:
        return None
    s = first_block(a.get("settings"))
    backup, ip = first_block(s.get("backup_configuration")), first_block(s.get("ip_configuration"))
    kept = backup.get("enabled") is True
    retained = first_block(backup.get("backup_retention_settings")).get("retained_backups")
    pitr = backup.get("binary_log_enabled" if engine == "mysql" else "point_in_time_recovery_enabled") is True
    tls = ip.get("ssl_mode") in TLS_ONLY or (ip.get("ssl_mode") is None and ip.get("require_ssl") is True)
    labels = s.get("user_labels") or {}
    return resource("database", resource_id(a.get("id") or a.get("self_link")) or a.get("name"), {
        "ciamDbEngine": engine, "ciamDbEngineVersion": version, "ciamDbEdition": edition,
        "ciamDbService": "cloud-sql", "ciamFqdn": (a.get("dns_name") or "").rstrip(".") or None,
        "ciamPort": PORTS[engine], "ciamInstanceSize": s.get("tier"), "ciamDbStorageGb": s.get("disk_size"),
        "ciamZone": first_block(s.get("location_preference")).get("zone"),
        "ciamDbHighAvailability": "zone-redundant" if s.get("availability_type") == "REGIONAL" else "none",
        "ciamDbTlsRequired": "TRUE" if tls else "FALSE",
        "ciamRetentionDays": (retained or 7) if kept else 0, "ciamDbPointInTime": "TRUE" if pitr else "FALSE",
        "ciamDbDeletionProtection": "TRUE" if s.get("deletion_protection_enabled") is True else "FALSE",
        "ciamDbParameter": sorted(f"{f.get('name')}={f.get('value')}" for f in s.get("database_flags") or ()
                                  if f.get("name"))},
        links={"ciamEncryptedByRole": a.get("encryption_key_name") or None},
        name=a.get("name"), role=labels.get("role") or labels.get("bindingrole") or None)


def database_resources(pairs):
    """Database resources of (google type, attributes) pairs: Cloud SQL instances."""
    return tuple(r for r in (_instance(a) for a in of_types(pairs, "google_sql_database_instance")) if r is not None)
