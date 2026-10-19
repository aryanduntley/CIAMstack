"""The database roles' SQL (store.roles): the admin's script, the owner switch and the runtime's grants, and the
roles read from the environment."""
import pytest

from opsdir.store.roles import Roles, db_roles, db_roles_sql, owner_sql, runtime_grants


def test_the_admins_script_creates_three_roles_and_their_database_rights():
    script = db_roles_sql("opsdir_owner", "opsdir_migrate", "opsdir_app", "opsdir", "certificate")
    for line in ("create role opsdir_owner nologin;", "create role opsdir_migrate login;",
                 "grant opsdir_owner to opsdir_migrate with inherit false, set true;",
                 "create role opsdir_app login;", "grant connect on database opsdir to opsdir_migrate, opsdir_app;",
                 "grant create on database opsdir to opsdir_owner;", "revoke create on schema public from public;",
                 "--   hostssl opsdir opsdir_app 0.0.0.0/0 cert"):
        assert line in script.splitlines(), line
    assert "superuser" not in script and "createrole" not in script


@pytest.mark.parametrize("login, method", [("password", "scram-sha-256"), ("kerberos", "gss include_realm=0")])
def test_each_login_method_has_its_pg_hba_line(login, method):
    assert f"--   hostssl opsdir opsdir_app 0.0.0.0/0 {method}" in db_roles_sql("o", "m", "opsdir_app", "opsdir", login)


@pytest.mark.parametrize("args, message", [
    (("Owner", "m", "r", "d"), "role name 'Owner'"),
    (("o", "m", "r", "my-db"), "database name 'my-db'"),
    (("o", "o", "r", "d"), "three different roles"),
    (("o", "m", "r", "d", "ldap"), "login method 'ldap'")])
def test_bad_names_and_methods_are_refused(args, message):
    with pytest.raises(ValueError, match=message):
        db_roles_sql(*args)


def test_the_runtime_gets_rows_never_the_schema_the_patterns_or_the_history():
    grants = runtime_grants(Roles("opsdir_owner", "opsdir_app"))
    assert "grant select, insert, update, delete on all tables in schema opsdir to opsdir_app" in grants
    assert ("revoke insert, update, delete on opsdir.schema_migration, opsdir.secret_pattern, opsdir.vocabulary, "
            "opsdir.ref_scheme from opsdir_app") in grants
    assert "revoke insert, update, delete, truncate on opsdir.entry_history from opsdir_app" in grants
    assert not any("create" in g or "owner" in g for g in grants)
    assert runtime_grants(None) == () and runtime_grants(Roles("o", None)) == ()


def test_the_owner_switch():
    assert owner_sql(Roles("opsdir_owner", None)) == ("set role opsdir_owner",)
    assert owner_sql(None) == () and owner_sql(Roles(None, "r")) == ()


def test_roles_from_the_environment():
    assert db_roles({}) is None
    assert db_roles({"OPSDIR_DB_OWNER": "o", "OPSDIR_DB_RUNTIME": "r"}) == Roles("o", "r")
    assert db_roles({"OPSDIR_DB_RUNTIME": "r"}) == Roles(None, "r")
    with pytest.raises(ValueError, match="role name 'o; drop'"):
        db_roles({"OPSDIR_DB_OWNER": "o; drop"})
