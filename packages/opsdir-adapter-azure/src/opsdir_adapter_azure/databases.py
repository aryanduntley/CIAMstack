"""Azure: the managed databases (opsdir.domains.data) an environment runs, rendered as Terraform and read back. Pure.

Rendered into the stack's main.tf, for each database the stack keeps (one naming ciamManagedBy is someone else's: a
comment names them). PostgreSQL and MySQL run on Azure Database Flexible Server; other engines have no Flexible
Server (SQL Server is Azure SQL, a different offering): a comment.

  azurerm_postgresql_flexible_server / azurerm_mysql_flexible_server: its version (Flexible Server takes PostgreSQL's
  major version and MySQL's 5.7 or 8.0.21: Azure keeps the minor version current), SKU (ciamInstanceSize), storage,
  zone, a zone-redundant standby, backup retention, geo-redundant backups when the record copies them to another
  region (ciamCopyRegion: Azure copies them, and the logs point-in-time restore replays, to the region's pair; a
  recorded region that isn't the pair is named, and so is the setting being fixed when a server is created); in the
  delegated subnet its first subnet role names, with the private DNS zone an input and no public access
  a network security group named by its role on that subnet, admitting the ranges the record does (ciamSourceCidr)
  to its port (ciamPort, else the engine's)
  the customer-managed key of its key role, through a user-assigned identity granted Key Vault Crypto Service
  Encryption User on the key
  the administrator password read from its credential role's Key Vault secret by an ephemeral resource and written
  write-only (administrator_password_wo): it is in no Terraform state and never in the record; the login is a variable
  a configuration per parameter, and require_secure_transport off where TLS isn't required (both engines require it
  by default); a CanNotDelete management lock where deletion protection is on
  an import block when its provider ref (its ARM ID) is recorded

Read back from (azurerm type, attributes) pairs, Terraform state as it is or the CLI and ARM templates normalized to
it (cli_database.py): the servers (geo-redundant backups: their location's pair as the copy region), their
configurations and the locks on them (a server with geo-redundant backups in a region whose pair isn't known:
a notice), the ranges the inbound rules of the
network security groups on their delegated subnets admit (database_security_groups keeps those out of the firewall
rules). The administrator password (administrator_password) is never read.
"""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import of_class
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.data.naming import DEFAULT_PORTS
from opsdir.domains.data.databases import database_port, major_version
from opsdir.domains.network.plumbing import adopted
from opsdir.domains.network.stack import kept_by, owned, subnets
from opsdir_format_terraform.hcl import Block, block, import_block, ref, tf_name
from .arm_ids import subnet_ref
from .cmk import customer_key, key_ref, role_uri, vault_object
from .identities import LOC, RG
from .network import binding_tags
from .nsg_rules import admitted_ranges
from .pairs import paired_region
from .account import tagged

SERVERS = {"postgresql": "azurerm_postgresql_flexible_server", "mysql": "azurerm_mysql_flexible_server"}
ENGINES = {v: k for k, v in SERVERS.items()}
PORTS = {e: DEFAULT_PORTS[e] for e in ("postgresql", "mysql")}    # the engines Flexible Server runs
TLS = "require_secure_transport"                         # both engines' parameter; on by default
MYSQL_VERSIONS = {"5.7": "5.7", "8.0": "8.0.21"}
_OFF = frozenset({"off", "0", "false"})


def _version(engine, version):
    """The version Flexible Server takes: PostgreSQL's major version, MySQL's 5.7 or 8.0.21."""
    if not version:
        return None
    major = major_version(engine, version)
    return MYSQL_VERSIONS.get(major, version) if engine == "mysql" else major


def _given(*pairs):
    return tuple((k, v) for k, v in pairs if v is not None)


def _key(m, b, n):
    """(blocks, server body) for the customer-managed key: its key, a user-assigned identity and its grant."""
    k = customer_key(m, b, n)
    if k.identity is None:
        return (), (k.note,) if k.note else ()
    return k.blocks, (("identity", Block((("type", "UserAssigned"), ("identity_ids", [ref(f"{k.identity}.id")])))),
                      ("customer_managed_key", Block((
                          ("key_vault_key_id", ref(f"{k.key}.id")),
                          ("primary_user_assigned_identity_id", ref(f"{k.identity}.id"))))),
                      ("depends_on", [ref(k.grant)]))


def _password(m, b, n):
    """(blocks, server body) for the administrator password: written write-only from an ephemeral read of the
    credential role's Key Vault secret."""
    uri, note = role_uri(m, one(b, "ciamDbCredentialRole"), "credential")
    if uri is None:
        return (), (note or ("#", "no ciamDbCredentialRole: no administrator password is set"),)
    vault, name = vault_object(uri)
    return ((f"# {rdn_value(b)}: its administrator password is read when applied and written write-only: no "
             "Terraform state holds it",
             block("data", ["azurerm_key_vault", f"{n}_admin"], [("name", vault), ("resource_group_name", RG)]),
             block("ephemeral", ["azurerm_key_vault_secret", f"{n}_admin"], [
                 ("name", name), ("key_vault_id", ref(f"data.azurerm_key_vault.{n}_admin.id"))])),
            (("administrator_password_wo", ref(f"ephemeral.azurerm_key_vault_secret.{n}_admin.value")),
             ("administrator_password_wo_version", 1)))


def _settings(b, engine):
    """{name: value} of the configurations: its parameters, and TLS off where it isn't required."""
    params = dict(v.split("=", 1) for v in values(b, "ciamDbParameter") if "=" in v)
    return {**params, TLS: "off"} if one(b, "ciamDbTlsRequired") == "FALSE" else params


def _security_group(m, b, nets):
    """The network security group named by the database's role on its delegated subnet, its rule admitting the ranges
    the record does to its port."""
    role, cidrs, port = one(b, "ciamBindingRole"), values(b, "ciamSourceCidr"), database_port(b)
    nsg, name = tf_name(role), f"nsg-ciam-{rdn_value(m.env)}-{role}"
    rule = (block("resource", ["azurerm_network_security_rule", f"{nsg}_clients"], [
        ("name", f"{role}-clients"), ("description", f"clients of database {rdn_value(b)}"), ("priority", 100),
        ("direction", "Inbound"), ("access", "Allow"), ("protocol", "Tcp"), ("source_port_range", "*"),
        ("destination_port_ranges", [str(port)]), ("source_address_prefixes", list(cidrs)),
        ("destination_address_prefix", "*"), ("resource_group_name", RG),
        ("network_security_group_name", ref(f"azurerm_network_security_group.{nsg}.name"))]),) if cidrs else ()
    return (block("resource", ["azurerm_network_security_group", nsg], [
                ("name", name), ("location", LOC), ("resource_group_name", RG), ("tags", tagged(m, binding_tags(b)))]),
            *rule,
            *((block("resource", ["azurerm_subnet_network_security_group_association", nsg], [
                ("subnet_id", ref(f"data.azurerm_subnet.{tf_name(rdn_value(nets[0]))}.id")),
                ("network_security_group_id", ref(f"azurerm_network_security_group.{nsg}.id"))]),) if nets else ()))


def _geo(m, b):
    """(notes, server arguments) of geo-redundant backups: on when the record copies the backups to another region."""
    cn, regions = rdn_value(b), values(b, "ciamCopyRegion")
    if not regions:
        return (), ()
    region = one(m.cloud, "ciamRegion")
    pair = paired_region(region)
    where = (f"# {cn}: Azure copies geo-redundant backups to {region}'s pair, {pair}, not "
             f"{', '.join(regions)}: record {pair} as its ciamCopyRegion" if pair and tuple(regions) != (pair,) else
             f"# {cn}: Azure copies geo-redundant backups to {region}'s paired region, which isn't known here: "
             "check it is the recorded ciamCopyRegion" if not pair else None)
    fixed = (f"# {cn}: geo-redundant backup is chosen when a server is created: an existing server without it is "
             "restored into a new server that has it" if adopted(b) else None)
    return tuple(x for x in (where, fixed) if x), (("geo_redundant_backup_enabled", True),)


def _database(m, b):
    n, cn, engine = tf_name(rdn_value(b)), rdn_value(b), one(b, "ciamDbEngine")
    kind = SERVERS.get(engine)
    if kind is None:
        return (f"# Database '{cn}' runs {engine}, which Azure Database Flexible Server doesn't (SQL Server is Azure "
                "SQL, a different offering): not rendered",)
    nets, storage = subnets(m, b), one(b, "ciamDbStorageGb")
    key_blocks, key_body = _key(m, b, n)
    pw_blocks, pw_body = _password(m, b, n)
    login = f"{n}_admin_login"
    dns = f"{n}_private_dns_zone_id"
    geo_notes, geo = _geo(m, b)
    server = block("resource", [kind, n], [
        ("name", cn), ("resource_group_name", RG), ("location", LOC),
        *_given(("version", _version(engine, one(b, "ciamDbEngineVersion"))),
                ("sku_name", one(b, "ciamInstanceSize")),
                ("storage_mb" if engine == "postgresql" else "storage", None if not storage else
                 int(storage) * 1024 if engine == "postgresql" else Block((("size_gb", int(storage)),))),
                ("zone", one(b, "ciamZone")),
                ("backup_retention_days", int(one(b, "ciamRetentionDays")) if one(b, "ciamRetentionDays") else None)),
        *geo,
        *((("high_availability", Block((("mode", "ZoneRedundant"),))),)
          if one(b, "ciamDbHighAvailability") == "zone-redundant" else ()),
        *((("delegated_subnet_id", ref(f"data.azurerm_subnet.{tf_name(rdn_value(nets[0]))}.id")),
           ("private_dns_zone_id", ref(f"var.{dns}")), ("public_network_access_enabled", False)) if nets else ()),
        ("administrator_login", ref(f"var.{login}")), *pw_body, *key_body, ("tags", tagged(m, binding_tags(b)))])
    settings = tuple(block("resource", [f"{kind}_configuration", tf_name(f"{cn}_{k}")], [
        ("name", k), ("server_id", ref(f"{kind}.{n}.id")), ("value", v)])
        for k, v in sorted(_settings(b, engine).items()))
    lock = (block("resource", ["azurerm_management_lock", n], [
        ("name", f"{cn}-no-delete"), ("scope", ref(f"{kind}.{n}.id")), ("lock_level", "CanNotDelete"),
        ("notes", f"Deletion protection of database {cn} (role {one(b, 'ciamBindingRole')})")]),) \
        if one(b, "ciamDbDeletionProtection") == "TRUE" else ()
    return (block("variable", [login], [("type", ref("string")),
                                        ("description", f"The administrator login of database {cn}")]),
            *((block("variable", [dns], [("type", ref("string")), ("description", (
                f"The private DNS zone ID database {cn} registers in (privatelink.{engine}.database.azure.com)"))]),)
              if nets else ()),
            *key_blocks, *pw_blocks, *_security_group(m, b, nets), *geo_notes, server, *settings, *lock,
            *((import_block(f"{kind}.{n}", one(b, "ciamProviderRef")),) if adopted(b) else ()))


def render_databases(m):
    """HCL for environment m's managed databases: those the stack keeps, then comments naming who keeps the others."""
    dbs = of_class(m, "ciamDatabase")
    return (*(f"# Database '{rdn_value(b)}' (role {one(b, 'ciamBindingRole')}) is kept by {kept_by(m, b)}: not "
              "rendered here" for b in dbs if not owned(b)),
            *(x for b in dbs if owned(b) for x in _database(m, b)))


# ------------------------------------------------------------------ read back
def _first(v):
    return v[0] if isinstance(v, list) and v else v if isinstance(v, dict) else {}


def _low(v):
    return (v or "").lower()


def database_security_groups(pairs):
    """{network security group id (lower case): the delegated subnets (lower case) of the Flexible Servers it guards}:
    theirs, not the firewall rules'."""
    delegated = {_low(a.get("delegated_subnet_id")) for kind in SERVERS.values() for a in of_types(pairs, kind)
                 if a.get("delegated_subnet_id")}
    links = [(_low(a.get("network_security_group_id")), _low(a.get("subnet_id")))
             for a in of_types(pairs, "azurerm_subnet_network_security_group_association")
             if _low(a.get("subnet_id")) in delegated]
    return {g: frozenset(s for g2, s in links if g2 == g) for g in dict.fromkeys(g for g, _ in links)}


def _server(kind, a, settings, locked, admitted=()):
    engine = ENGINES[kind]
    own = settings.get((a.get("id") or "").lower(), {})
    tls = own.get(TLS)
    retention = a.get("backup_retention_days")
    storage = a.get("storage_mb") and int(a["storage_mb"]) // 1024 or _first(a.get("storage")).get("size_gb")
    return resource("database", a.get("id") or a.get("name"), {
        "ciamDbEngine": engine, "ciamDbEngineVersion": a.get("version"), "ciamDbService": "flexible-server",
        "ciamFqdn": a.get("fqdn"), "ciamPort": PORTS[engine], "ciamInstanceSize": a.get("sku_name"),
        "ciamDbStorageGb": storage, "ciamZone": a.get("zone"),
        "ciamDbHighAvailability": "zone-redundant" if _first(a.get("high_availability")).get("mode")
        == "ZoneRedundant" else "none",
        "ciamDbTlsRequired": "FALSE" if tls is not None and tls.lower() in _OFF else "TRUE",
        "ciamRetentionDays": retention, "ciamDbPointInTime": "TRUE" if retention else "FALSE",
        "ciamCopyRegion": [paired_region(a.get("location"))] if a.get("geo_redundant_backup_enabled") is True
        and paired_region(a.get("location")) else None,
        "ciamDbDeletionProtection": "TRUE" if (a.get("id") or "").lower() in locked else "FALSE",
        "ciamDbParameter": sorted(f"{k}={v}" for k, v in own.items() if k != TLS),
        "ciamSourceCidr": sorted(set(admitted))},
        links={"ciamSubnetRole": subnet_ref(a.get("delegated_subnet_id")),
               "ciamEncryptedByRole": key_ref(_first(a.get("customer_managed_key")).get("key_vault_key_id"))},
        name=a.get("name"), role=tagged_role(a.get("tags") or {}), tags=a.get("tags") or {})


def geo_backup_notices(pairs):
    """Notices for Flexible Servers whose geo-redundant backup is on in a region whose pair isn't known here: where
    the copies go can't be told, so no copy region is recorded."""
    return tuple(f"{kind} {a.get('name') or a.get('id')}: geo-redundant backup is on in {a.get('location')}, whose "
                 "paired region isn't known here: its copy region (ciamCopyRegion) isn't recorded; record it"
                 for kind in SERVERS.values() for a in of_types(pairs, kind)
                 if (a.get("id") or a.get("name")) and a.get("geo_redundant_backup_enabled") is True
                 and not paired_region(a.get("location")))


def database_resources(pairs):
    """Database resources of (azurerm type, attributes) pairs: PostgreSQL and MySQL Flexible Servers, with the ranges
    the network security groups on their delegated subnets admit."""
    guards = database_security_groups(pairs)
    admitted = admitted_ranges(pairs, guards)

    def ranges(a):
        subnet = _low(a.get("delegated_subnet_id"))
        return tuple(c for g, subnets in guards.items() if subnet in subnets for c in admitted.get(g, ()))
    configs = [((c.get("server_id") or "").lower(), c.get("name"), str(c.get("value")))
               for kind in SERVERS.values() for c in of_types(pairs, f"{kind}_configuration")]
    settings = {sid: {n: v for s, n, v in configs if s == sid} for sid in {s for s, _, _ in configs}}
    locked = {(lk.get("scope") or "").lower() for lk in of_types(pairs, "azurerm_management_lock")
              if lk.get("lock_level") in ("CanNotDelete", "ReadOnly")}
    return tuple(_server(kind, a, settings, locked, ranges(a)) for kind in SERVERS.values()
                 for a in of_types(pairs, kind) if a.get("id") or a.get("name"))
