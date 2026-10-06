"""Managed databases (the data domain): a database each environment runs, compared by role. A move carries the engine
and its major version unchanged (blockers), and keeps availability, TLS, point-in-time restore, deletion protection,
backup retention, encryption and parameters (actions with fixes carrying the source's values); a credential role the
target doesn't bind blocks. Products name a database by its endpoint; a cloud's inventory places it by provider ref."""
from opsdir.connectors.fixes import chosen
from opsdir.core.directory import make_directory, values
from opsdir.core.environment import published_role
from opsdir.core.inventory import environment_groups, resource
from opsdir.domains.data.databases import check_databases, database_rows, major_version
from network_fixtures import ALPHA, BETA, context, entry, model
from support import imported_directory

SOURCE = dict(ciamBindingRole="pf-grants-db", ciamDbEngine="postgresql", ciamDbEngineVersion="16.4",
              ciamFqdn="grants.alpha.example.test", ciamPort="5432", ciamDbHighAvailability="zone-redundant",
              ciamDbTlsRequired="TRUE", ciamDbPointInTime="TRUE", ciamDbDeletionProtection="TRUE",
              ciamRetentionDays="14", ciamEncryptedByRole="db-key", ciamDbCredentialRole="pf-grants-db-admin",
              ciamDbParameter=("log_min_duration_statement=500", "max_connections=400"))
SECRET = "ciamSecretRef", dict(ciamBindingRole="pf-grants-db-admin", ciamRefUri="fake://db-admin")
KEY = "ciamKeyRef", dict(ciamBindingRole="db-key-beta", ciamRefUri="fake://db-key")


def _pair(target=None, beta_extra=()):
    """(ctx) with alpha's database as SOURCE and beta's as SOURCE changed by target (None values left out)."""
    attrs = {k: v for k, v in {**SOURCE, "ciamFqdn": "grants.beta.example.test", **(target or {})}.items()
             if v is not None}
    d, alpha, beta = model(alpha=(entry(ALPHA, "db-grants", "ciamDatabase", **SOURCE),
                                  entry(ALPHA, "secret-db", SECRET[0], **SECRET[1])),
                           beta=(entry(BETA, "db-grants", "ciamDatabase", **attrs),
                                 entry(BETA, "secret-db", SECRET[0], **SECRET[1]), *beta_extra))
    return context(d, alpha, beta)


def _texts(rows):
    return [r[1] for r in rows]


def test_the_same_database_in_both_is_ok():
    f = check_databases(_pair())
    assert (f.blockers, f.actions, f.fixes) == ((), (), ())
    assert f.ok == ("1 managed database(s) keep their engine, version, availability, encryption and backups in "
                    "beta/prod.",)


def test_another_engine_or_major_version_blocks_and_a_minor_version_is_an_action():
    assert (major_version("postgresql", "16.4"), major_version("mysql", "8.0.35"), major_version(None, "15")) == \
        ("16", "8.0", "15")
    engine = check_databases(_pair({"ciamDbEngine": "mysql", "ciamDbEngineVersion": "8.0.35"}))
    assert _texts(engine.blockers) == [
        "Database `pf-grants-db` runs postgresql in alpha/prod but mysql in beta/prod: moving it means converting "
        "the data, not a move. Record the target with the source's engine, or plan the conversion as its own change."]
    assert [m for r in engine.fixes[0].records for m in r.mods] == [
        ("replace", "ciamDbEngine", ("postgresql",)), ("replace", "ciamDbEngineVersion", ("16.4",))]
    major = check_databases(_pair({"ciamDbEngineVersion": "17.2"}))
    assert _texts(major.blockers) == ["Database `pf-grants-db` runs postgresql 16.4 in alpha/prod but 17.2 in "
                                      "beta/prod: a move carries the major version unchanged; an upgrade is its own "
                                      "change."]
    edition = check_databases(_pair({"ciamDbEdition": "standard"}))
    assert edition.actions == () and edition.fixes == ()             # the source records none: nothing to keep
    minor = check_databases(_pair({"ciamDbEngineVersion": "16.2"}))
    assert minor.blockers == () and [k.key for k in minor.fixes] == ["database:pf-grants-db:ciamDbEngineVersion"]
    assert "the same major version, but test the products against the target's" in minor.actions[0][1]
    # a service that keeps the minor version current is recorded by its major version: nothing to compare
    assert check_databases(_pair({"ciamDbEngineVersion": "16"})).actions == ()
    assert check_databases(_pair({"ciamDbEngineVersion": "17"})).blockers != ()


def test_what_the_source_had_is_kept_or_named_with_a_fix_carrying_it():
    f = check_databases(_pair({"ciamDbHighAvailability": "none", "ciamDbTlsRequired": None,
                               "ciamDbPointInTime": "FALSE", "ciamDbDeletionProtection": None,
                               "ciamRetentionDays": "7", "ciamEncryptedByRole": None,
                               "ciamDbParameter": ("max_connections=200", "work_mem=64MB")},
                              beta_extra=(entry(BETA, "key-db", KEY[0], **KEY[1]),)))
    assert f.blockers == ()
    assert _texts(f.actions) == [
        "Database `pf-grants-db` has high availability in alpha/prod but not in beta/prod: no standby to fail over "
        "to when its zone fails.",
        "Database `pf-grants-db` has required TLS in alpha/prod but not in beta/prod: connections without TLS are "
        "accepted.",
        "Database `pf-grants-db` has point-in-time restore in alpha/prod but not in beta/prod: it can only be "
        "restored to a nightly backup, not to a point in time.",
        "Database `pf-grants-db` has deletion protection in alpha/prod but not in beta/prod: nothing stops it being "
        "deleted by mistake.",
        "Database `pf-grants-db` keeps backups 14 days in alpha/prod but 7 in beta/prod: restores reach back less far.",
        "Database `pf-grants-db` is encrypted with key `db-key` in alpha/prod; in beta/prod nothing names its key, "
        "so the provider's own default key encrypts it, which nobody here controls or can revoke.",
        "Database `pf-grants-db` sets log_min_duration_statement=500, max_connections=400 in alpha/prod; beta/prod "
        "sets max_connections=200."]
    fixes = {x.key: x for x in f.fixes}
    assert [o.key for o in fixes["database:pf-grants-db:ciamEncryptedByRole"].options] == ["db-key-beta"]
    (params,) = fixes["database:pf-grants-db:ciamDbParameter"].records
    assert params.mods == (("replace", "ciamDbParameter", ("log_min_duration_statement=500", "max_connections=400",
                                                          "work_mem=64MB")),)
    (ha,) = fixes["database:pf-grants-db:ciamDbHighAvailability"].records
    assert ha.mods == (("replace", "ciamDbHighAvailability", ("zone-redundant",)),)
    assert chosen(fixes["database:pf-grants-db:ciamEncryptedByRole"], "db-key-beta").records[0].mods == (
        ("replace", "ciamEncryptedByRole", ("db-key-beta",)),)


def test_a_credential_role_the_target_doesnt_bind_blocks_and_a_missing_one_is_named():
    unbound = check_databases(_pair({"ciamDbCredentialRole": "beta-db-admin"}))
    assert _texts(unbound.blockers) == ["Database `pf-grants-db` keeps its credentials in role `beta-db-admin`, "
                                        "which beta/prod doesn't bind."]
    missing = check_databases(_pair({"ciamDbCredentialRole": None}))
    assert missing.blockers == () and [x.key for x in missing.fixes] == ["database:pf-grants-db:ciamDbCredentialRole"]


def test_the_report_lists_every_environments_databases_and_products_name_them_by_endpoint():
    ctx = _pair({"ciamDbHighAvailability": "none", "ciamDbService": "flexible-server"})
    assert database_rows(ctx.d) == [
        ("alpha/prod", "pf-grants-db", "postgresql", "16.4", "", "", "", "zone-redundant", "db-key", "yes", "14", "yes",
         "yes", "grants.alpha.example.test:5432", "pf-grants-db-admin"),
        ("beta/prod", "pf-grants-db", "postgresql", "16.4", "", "flexible-server", "", "none", "db-key", "yes", "14",
         "yes", "yes", "grants.beta.example.test:5432", "pf-grants-db-admin")]
    assert published_role(ctx.d, "GRANTS.beta.example.test") == "pf-grants-db"


ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"


def test_a_cloud_inventory_places_a_database_by_provider_ref_with_its_secret_and_key_as_roles():
    d = imported_directory((), {}, (
        ("cloud=main,ou=environments,dc=ciam-ops", ("top", "ciamCloud"), {"cloud": ["main"]}),
        (ENV, ("top", "ciamEnvironment"), {"env": ["prod"]}),
        (B, ("top", "organizationalUnit"), {"ou": ["bindings"]}),
        (f"cn=db-admin,{B}", ("top", "ciamSecretRef"), {"cn": ["db-admin"], "ciamBindingRole": ["pf-grants-db-admin"],
                                                         "ciamRefUri": ["aws-sm://arn:aws:secretsmanager:x:1:secret:a"]}),
        (f"cn=db-key,{B}", ("top", "ciamKeyRef"), {"cn": ["db-key"], "ciamBindingRole": ["db-key"],
                                                    "ciamRefUri": ["aws-kms://arn:aws:kms:x:1:key/k"]})))
    db = resource("database", "arn:aws:rds:x:1:db:pf-grants",
                  {"ciamDbEngine": "postgresql", "ciamDbEngineVersion": "16.4", "ciamFqdn": "pf-grants.x.rds.test"},
                  links={"ciamDbCredentialRole": "arn:aws:secretsmanager:x:1:secret:a",
                         "ciamEncryptedByRole": "arn:aws:kms:x:1:key/k"}, name="pf-grants", role="pf-grants-db")
    secret = resource("secret", "arn:aws:secretsmanager:x:1:secret:a",
                      {"ciamRefUri": "aws-sm://arn:aws:secretsmanager:x:1:secret:a"})
    key = resource("key", "arn:aws:kms:x:1:key/k", {"ciamRefUri": "aws-kms://arn:aws:kms:x:1:key/k"})
    groups, _ = environment_groups(d, "main/prod", (db, secret, key))
    placed = {e.dn: e for _, (e,) in groups}
    e = placed[f"cn=pf-grants,{B}"]
    assert e.classes[-1] == "ciamDatabase" and values(e, "ciamProviderRef") == ("arn:aws:rds:x:1:db:pf-grants",)
    assert (values(e, "ciamDbCredentialRole"), values(e, "ciamEncryptedByRole")) == (("pf-grants-db-admin",),
                                                                                      ("db-key",))
