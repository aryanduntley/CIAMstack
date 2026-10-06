"""AWS: the managed databases (opsdir.domains.data) an environment runs, rendered as Terraform and read back. Pure.

Rendered into the stack's main.tf, for each database the stack keeps (one naming ciamManagedBy is someone else's: a
comment names them):

  an RDS instance (aws_db_instance), or on Aurora (ciamDbService aurora) a cluster (aws_rds_cluster) with one
  instance, two in different zones when it is zone-redundant (multi_az on RDS)
  a subnet group of the subnets it names by role, a security group named by its role with an ingress rule to its
  port (ciamPort, else the engine's) from each range the record admits (ciamSourceCidr), and a parameter group
  (family from the engine, edition and major version) holding its parameters and, where it differs from the engine's
  default, the parameter that makes TLS required (rds.force_ssl, require_secure_transport)
  the KMS key of its key role, its backup retention and deletion protection; RDS keeps the master password in Secrets
  Manager (manage_master_user_password): no password is in the Terraform or the record, and the credential role names
  that secret. The master user name is a variable. A database whose provider ref is recorded is adopted (an import
  block); its subnet and parameter groups are adopted by hand, or Terraform creates new ones and moves it to them.

Read back from (Terraform type, attributes) pairs, Terraform state as it is or the CLI normalized to it
(cli_database.py): aws_db_instance (one that is an Aurora cluster's member is read with its cluster), aws_rds_cluster
(+ aws_rds_cluster_instance), aws_db_subnet_group, aws_db_parameter_group and aws_rds_cluster_parameter_group, the
ingress rules on its security groups (their IPv4 ranges: ciamSourceCidr; database_security_groups keeps them out of
the firewall rules). Named fields only: the master password (password, master_password) is never read.
"""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import UNBOUND, bound, of_class
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.data.databases import database_port, major_version
from opsdir.domains.network.plumbing import adopted
from opsdir.domains.network.stack import kept_by, owned, subnets
from opsdir_format_terraform.hcl import Block, block, import_block, ref, tf_name
from opsdir_format_terraform.state import blocks
from .network import binding_tags

_ENGINES = {"postgresql": "postgres", "mysql": "mysql", "mariadb": "mariadb", "sqlserver": "sqlserver",
            "oracle": "oracle"}
_NEUTRAL = {v: k for k, v in _ENGINES.items()}
_AURORA = ("postgresql", "mysql")                        # the engines Aurora runs
_EDITIONS = {"sqlserver": {"enterprise": "ee", "standard": "se", "express": "ex", "web": "web"},
             "oracle": {"enterprise": "ee", "standard2": "se2"}}
_DEFAULT_EDITION = {"sqlserver": "standard", "oracle": "standard2"}
# the parameter that makes TLS required, per engine (Oracle needs an option group: not rendered)
_TLS = {"postgresql": "rds.force_ssl", "sqlserver": "rds.force_ssl", "mysql": "require_secure_transport",
        "mariadb": "require_secure_transport"}
_ON = frozenset({"1", "on", "true"})
_TLS_BY_DEFAULT = 15                                      # PostgreSQL major version from which RDS requires TLS


# ------------------------------------------------------------------ engines
def aws_engine(engine, edition, service):
    """The RDS engine name of a neutral engine, edition and service."""
    if service == "aurora" and engine in _AURORA:
        return f"aurora-{engine}"
    editions = _EDITIONS.get(engine)
    return f"{engine}-{editions[edition or _DEFAULT_EDITION[engine]]}" if editions else _ENGINES[engine]


def neutral_engine(aws):
    """(engine, edition or None, service) of an RDS engine name; (None, None, None) when the record has no name for
    it."""
    name = aws or ""
    if name.startswith("aurora-") and name[len("aurora-"):] in _AURORA:
        return name[len("aurora-"):], None, "aurora"
    base, _, code = name.partition("-")
    editions = {v: k for k, v in _EDITIONS.get(base, {}).items()}
    if editions:
        return (base, editions[code], "rds") if code in editions else (None, None, None)
    return (_NEUTRAL[name], None, "rds") if name in _NEUTRAL else (None, None, None)


def parameter_family(aws, version):
    """The parameter group family of an RDS engine name and version."""
    engine, edition, _ = neutral_engine(aws)
    major = major_version(engine, version)
    if engine == "sqlserver":
        return f"{aws}-{major}.0"
    return f"{aws}-{major}" if edition else f"{aws}{major}"


def _tls_by_default(engine, version):
    return engine == "postgresql" and (version or "0").split(".")[0].isdigit() and \
        int(version.split(".")[0]) >= _TLS_BY_DEFAULT


# ------------------------------------------------------------------ render
def _parameters(b, engine, version):
    """{name: value} the database's parameter group sets: its parameters, and TLS where it isn't the default."""
    params = dict(v.split("=", 1) for v in values(b, "ciamDbParameter") if "=" in v)
    tls, default = one(b, "ciamDbTlsRequired"), _tls_by_default(engine, version)
    wanted = {"TRUE": True, "FALSE": False}.get(tls)
    if engine in _TLS and wanted is not None and wanted != default:
        params[_TLS[engine]] = "1" if wanted else "0"
    return params


def _key(m, b):
    role = one(b, "ciamEncryptedByRole")
    uri = bound(m, role, "ciamRefUri") if role else None
    if uri is None:
        return ()
    if uri.startswith(UNBOUND):
        return (("#", f"{uri}: no key binding for role {role} in this environment"),)
    return (("kms_key_id", uri.split("://", 1)[1]),)


def _identifier(b):
    """The RDS identifier of an adopted database: its provider ref's last part (an ARN's ...:db:<id> or
    ...:cluster:<id>)."""
    return one(b, "ciamProviderRef").rsplit(":", 1)[-1]


def _given(*pairs):
    """The (key, value) pairs whose value the record gives (None: left out of the block)."""
    return tuple((k, v) for k, v in pairs if v is not None)


def _int(b, attr):
    return int(one(b, attr)) if one(b, attr) else None


def _notes(b, engine, version):
    cn, retention = rdn_value(b), one(b, "ciamRetentionDays")
    return (*((f"# {cn}: point-in-time restore can't be turned off while RDS keeps backups",)
              if one(b, "ciamDbPointInTime") == "FALSE" and retention not in (None, "0") else ()),
            *((f"# {cn}: Oracle requires TLS through an option group (SSL), not rendered",)
              if engine == "oracle" and one(b, "ciamDbTlsRequired") == "TRUE" else ()),
            *((f"# {cn}: no ciamDbEngineVersion: RDS picks its default version",) if not version else ()))


def _ingress(m, b):
    """The security group's ingress rules: the database's port from each range the record admits."""
    role, cidrs, port = one(b, "ciamBindingRole"), values(b, "ciamSourceCidr"), database_port(b)
    if cidrs and port is None:
        return (f"# {rdn_value(b)}: no ciamPort and no default port for its engine: ingress not rendered",)
    return tuple(block("resource", ["aws_vpc_security_group_ingress_rule", tf_name(f"{role}_{i}")], [
        ("security_group_id", ref(f"aws_security_group.{tf_name(role)}.id")), ("cidr_ipv4", cidr),
        ("from_port", port), ("to_port", port), ("ip_protocol", "tcp"),
        ("description", f"clients of database {rdn_value(b)} ({role})")]) for i, cidr in enumerate(cidrs))


def _database(m, b):
    n, cn, role = tf_name(rdn_value(b)), rdn_value(b), one(b, "ciamBindingRole")
    engine, version = one(b, "ciamDbEngine"), one(b, "ciamDbEngineVersion")
    aurora = one(b, "ciamDbService") == "aurora" and engine in _AURORA
    aws = aws_engine(engine, one(b, "ciamDbEdition"), one(b, "ciamDbService"))
    params, nets = _parameters(b, engine, version), subnets(m, b)
    ha, user = one(b, "ciamDbHighAvailability") == "zone-redundant", f"{n}_admin_username"
    group_type = "aws_rds_cluster_parameter_group" if aurora else "aws_db_parameter_group"
    placed = _given(("engine", aws), ("engine_version", version))
    network = (*((("db_subnet_group_name", ref(f"aws_db_subnet_group.{n}.name")),) if nets else ()),
               ("vpc_security_group_ids", [ref(f"aws_security_group.{tf_name(role)}.id")]),
               *(((("db_cluster_parameter_group_name" if aurora else "parameter_group_name"),
                  ref(f"{group_type}.{n}.name")),) if params else ()))
    kept = (*_given(("manage_master_user_password", True), ("port", _int(b, "ciamPort"))),
            ("storage_encrypted", True), *_key(m, b),
            *_given(("backup_retention_period", _int(b, "ciamRetentionDays"))),
            ("deletion_protection", one(b, "ciamDbDeletionProtection") == "TRUE"), ("tags", binding_tags(b)))
    if aurora:
        main = (block("resource", ["aws_rds_cluster", n], [
                    ("cluster_identifier", cn), *placed, *network, ("master_username", ref(f"var.{user}")), *kept]),
                *(block("resource", ["aws_rds_cluster_instance", f"{n}_{i}"], [
                    ("identifier", f"{cn}-{i}"), ("cluster_identifier", ref(f"aws_rds_cluster.{n}.id")),
                    *_given(("instance_class", one(b, "ciamInstanceSize"))),
                    ("engine", ref(f"aws_rds_cluster.{n}.engine")),
                    ("engine_version", ref(f"aws_rds_cluster.{n}.engine_version")), ("tags", binding_tags(b))])
                  for i in range(1, 3 if ha else 2)))
        adopt = (import_block(f"aws_rds_cluster.{n}", _identifier(b)),) if adopted(b) else ()
    else:
        main = (block("resource", ["aws_db_instance", n], [
            ("identifier", cn), *placed,
            *_given(("instance_class", one(b, "ciamInstanceSize")), ("allocated_storage", _int(b, "ciamDbStorageGb"))),
            *network, ("username", ref(f"var.{user}")), ("multi_az", ha),
            *_given(("availability_zone", None if ha else one(b, "ciamZone"))), ("publicly_accessible", False),
            *kept]),)
        adopt = (import_block(f"aws_db_instance.{n}", _identifier(b)),) if adopted(b) else ()
    return (*_notes(b, engine, version),
            block("variable", [user], [("type", ref("string")),
                                       ("description", f"The master user name of database {cn} (role {role})")]),
            *((block("resource", ["aws_db_subnet_group", n], [
                ("name", cn), ("subnet_ids", [ref(f"data.aws_subnet.{tf_name(rdn_value(s))}.id") for s in nets]),
                ("tags", binding_tags(b))]),) if nets else ()),
            block("resource", ["aws_security_group", tf_name(role)], [
                ("name", f"ciam-{rdn_value(m.env)}-{role}"), ("description", f"CIAM database {role} ({m.label})"),
                ("vpc_id", ref("data.aws_vpc.main.id")), ("tags", binding_tags(b))]),
            *_ingress(m, b),
            *((block("resource", [group_type, n], [
                ("name", cn), ("family", parameter_family(aws, version or "0")),
                *(("parameter", Block((("name", k), ("value", v)))) for k, v in sorted(params.items())),
                ("tags", binding_tags(b))]),) if params else ()),
            *main, *adopt)


def render_databases(m):
    """HCL for environment m's managed databases: those the stack keeps, then comments naming who keeps the others."""
    dbs = of_class(m, "ciamDatabase")
    return (*(f"# Database '{rdn_value(b)}' (role {one(b, 'ciamBindingRole')}) is kept by {kept_by(m, b)}: not "
              "rendered here" for b in dbs if not owned(b)),
            *(x for b in dbs if owned(b) for x in _database(m, b)))


# ------------------------------------------------------------------ read back
def _tags(a):
    return a.get("tags") or a.get("tags_all") or {}


def _bool(v):
    return "TRUE" if v is True or str(v).lower() == "true" else "FALSE"


def _secret(a):
    return next((s.get("secret_arn") for s in blocks(a.get("master_user_secret")) if s.get("secret_arn")), None)


def _read(kind_ref, a, name, engine_name, version, group, params, members=(), admitted=()):
    """The database resource of an RDS instance or Aurora cluster's attributes (admitted: the ranges its security
    groups' rules let in)."""
    engine, edition, service = neutral_engine(engine_name)
    if engine is None:
        return None
    tls_param = params.get(_TLS.get(engine, ""))
    tls = tls_param.lower() in _ON if tls_param is not None else _tls_by_default(engine, version)
    retention = a.get("backup_retention_period")
    zones = {i.get("availability_zone") for i in members if i.get("availability_zone")}
    ha = (len(members) > 1 and len(zones) > 1) if service == "aurora" else a.get("multi_az") is True
    return resource("database", kind_ref, {
        "ciamDbEngine": engine, "ciamDbEngineVersion": version, "ciamDbEdition": edition, "ciamDbService": service,
        "ciamFqdn": a.get("address") or a.get("endpoint"), "ciamPort": a.get("port"),
        "ciamInstanceSize": a.get("instance_class") or next((i.get("instance_class") for i in members), None),
        "ciamDbStorageGb": a.get("allocated_storage") or None,
        "ciamZone": a.get("availability_zone") if not ha and service != "aurora" else None,
        "ciamDbHighAvailability": "zone-redundant" if ha else "none", "ciamDbTlsRequired": _bool(tls),
        "ciamRetentionDays": retention, "ciamDbPointInTime": _bool(bool(retention)),
        "ciamDbDeletionProtection": _bool(a.get("deletion_protection")),
        "ciamDbParameter": sorted(f"{k}={v}" for k, v in params.items() if k != _TLS.get(engine)),
        "ciamSourceCidr": sorted(set(admitted))},
        links={"ciamSubnetRole": tuple(group), "ciamEncryptedByRole": a.get("kms_key_id") or None,
               "ciamDbCredentialRole": _secret(a)},
        name=_tags(a).get("Name") or name, role=tagged_role(_tags(a)))


def database_security_groups(pairs):
    """The ids of the security groups RDS instances and Aurora clusters are in: theirs, not the firewall rules'."""
    return frozenset(g for a in of_types(pairs, "aws_db_instance", "aws_rds_cluster")
                     for g in a.get("vpc_security_group_ids") or ())


def _admitted(pairs):
    """{security group id: the IPv4 ranges its ingress rules admit}, separate rules and inline ones alike."""
    separate = [(r.get("security_group_id"), r.get("cidr_ipv4"))
                for r in of_types(pairs, "aws_vpc_security_group_ingress_rule")]
    inline = [(g.get("id"), c) for g in of_types(pairs, "aws_security_group") for rule in g.get("ingress") or ()
              for c in rule.get("cidr_blocks") or ()]
    ranges = [(g, c) for g, c in (*separate, *inline) if g and c]
    return {g: tuple(c for g2, c in ranges if g2 == g) for g in dict.fromkeys(g for g, _ in ranges)}


def _admits(admitted, a):
    return tuple(c for g in a.get("vpc_security_group_ids") or () for c in admitted.get(g, ()))


def database_resources(pairs):
    """Database resources of (Terraform type, attributes) pairs: RDS instances and Aurora clusters."""
    admitted = _admitted(pairs)
    groups = {a.get("name"): tuple(a.get("subnet_ids") or ()) for a in of_types(pairs, "aws_db_subnet_group")}
    params = {a.get("name"): {p.get("name"): str(p.get("value")) for p in blocks(a.get("parameter"))}
              for a in of_types(pairs, "aws_db_parameter_group", "aws_rds_cluster_parameter_group")}
    members = of_types(pairs, "aws_rds_cluster_instance")
    instances = (_read(a.get("arn") or a.get("identifier"), a, a.get("identifier"), a.get("engine"),
                       a.get("engine_version_actual") or a.get("engine_version"),
                       groups.get(a.get("db_subnet_group_name"), ()), params.get(a.get("parameter_group_name"), {}),
                       admitted=_admits(admitted, a))
                 for a in of_types(pairs, "aws_db_instance") if not a.get("cluster_identifier"))
    clusters = (_read(c.get("arn") or c.get("cluster_identifier"), c, c.get("cluster_identifier"), c.get("engine"),
                      c.get("engine_version_actual") or c.get("engine_version"),
                      groups.get(c.get("db_subnet_group_name"), ()),
                      params.get(c.get("db_cluster_parameter_group_name"), {}),
                      tuple(i for i in members if i.get("cluster_identifier") == c.get("cluster_identifier")),
                      _admits(admitted, c))
                for c in of_types(pairs, "aws_rds_cluster"))
    return tuple(r for r in (*instances, *clusters) if r is not None)
