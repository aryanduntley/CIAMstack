"""Test support shared by every suite (core, packages, showcase): in-memory directories built with the store's own
pure preparation (no Postgres), change records applied to their rows, trees read back, and which test databases to
use. The store's rules (R1-R10) run in Postgres triggers and are not applied in memory; integration tests cover them.
"""
import os
from functools import reduce

import psycopg
import pytest

from opsdir.core.directory import make_directory, norm_dn
from opsdir.core.paths import SCHEMA_FILE
from opsdir.store.postgres import apply_mods, entry_rows, schema_rows, split_record

SCHEMA = SCHEMA_FILE
# the test database on the local dev server (README, Database); the integration suite drops its opsdir schema
TEST_DSN = "host=localhost port=5432 user=opsdir password=testpass dbname=opsdir_test"
TEST_WORKSPACE_DSN = "host=localhost port=5432 user=opsdir password=testpass dbname=opsdir_test_workspace"
CREATE_TEST_DB = "sudo -u postgres createdb -O opsdir -T template0 opsdir_test"
CREATE_TEST_WORKSPACE_DB = "sudo -u postgres createdb -O opsdir -T template0 opsdir_test_workspace"


# ------------------------------------------------------------------ pure
def _has(rows, n):
    return any(norm_dn(dn) == n for dn, _, _ in rows)


def _modified(canon, row, mods):
    dn, classes, attrs = row
    return (dn, *apply_mods(canon, classes, attrs, mods))


def apply_record(canon, rows, r):
    """Entry rows after one LDIF change record (add / modify / delete); the store's rules are not checked."""
    n = norm_dn(r.dn)
    if r.changetype == "add":
        return (*rows, (r.dn, *split_record(canon, r.attrs)))
    if not _has(rows, n):
        raise KeyError(f"no such entry: {r.dn}")
    if r.changetype == "delete":
        return tuple(row for row in rows if norm_dn(row[0]) != n)
    if r.changetype == "modify":
        return tuple(_modified(canon, row, r.mods) if norm_dn(row[0]) == n else row for row in rows)
    raise ValueError(f"unsupported changetype {r.changetype}")


def build_directory(schema_text, records, change_records=()):
    """Directory snapshot from schema LDIF text and content records, after the change records in order."""
    ats, ocs = schema_rows(schema_text)
    canon = {a["name"].lower(): a["name"] for a in ats}
    rows = reduce(lambda acc, r: apply_record(canon, acc, r), change_records, entry_rows(canon, records))
    return make_directory([(a["name"], a["value_type"], a["portability"]) for a in ats],
                          [(o["name"], o["sup"]) for o in ocs], rows)


def integration_dsn(env):
    """The database the integration suite uses: OPSDIR_TEST_DSN, else the local test database. Never
    OPSDIR_DSN, which may point at a database someone cares about: the suite drops the opsdir schema."""
    return env.get("OPSDIR_TEST_DSN") or TEST_DSN


def integration_workspace_dsn(env):
    """The migration workspace database the integration suite uses: OPSDIR_TEST_WORKSPACE_DSN, else the local one."""
    return env.get("OPSDIR_TEST_WORKSPACE_DSN") or TEST_WORKSPACE_DSN




# ------------------------------------------------------------------ effects


def read_tree(root):
    """{path relative to root: text} for every file under root."""
    return {str(p.relative_to(root)): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


def database_error(dsn):
    """Effect: None when dsn accepts a connection, else the reason it doesn't."""
    try:
        with psycopg.connect(dsn, connect_timeout=3):
            return None
    except psycopg.Error as e:
        return str(e).strip()


def reachable(target, variable, create):
    """The DSN if it accepts connections; else a skip with the reason (a failure when OPSDIR_TEST_REQUIRE_DB=1)."""
    error = database_error(target)
    if error and os.environ.get("OPSDIR_TEST_REQUIRE_DB") == "1":
        pytest.fail(f"integration database unreachable: {error} (default database: {create})")
    if error:
        pytest.skip(f"integration database unreachable ({error}); set {variable}, or create the default one: {create}")
    return target
