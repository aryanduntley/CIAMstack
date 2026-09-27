"""Test support: the synthetic estate as an in-memory directory, built with the store's own pure preparation
(no Postgres), approved change records applied to its rows, and golden trees and command outputs read back.

The store's rules (R1-R10) run in Postgres triggers and are not applied here; the integration test covers them.
"""
import importlib.util
import os
import subprocess
from functools import reduce

import psycopg

from opsdir.core.directory import make_directory, norm_dn
from opsdir.core.paths import ROOT, SCHEMA_FILE
from opsdir.store.postgres import apply_mods, entry_rows, read_ldif_files, schema_rows, split_record

SCHEMA = SCHEMA_FILE
DATA = ROOT / "data"
GOLDEN = ROOT / "tests" / "golden"
# the test database on the local dev server (README, Database); the integration suite drops its opsdir schema
TEST_DSN = "host=localhost port=5432 user=opsdir password=testpass dbname=opsdir_test"
TEST_WORKSPACE_DSN = "host=localhost port=5432 user=opsdir password=testpass dbname=opsdir_test_workspace"
CREATE_TEST_DB = "sudo -u postgres createdb -O opsdir -T template0 opsdir_test"
CREATE_TEST_WORKSPACE_DB = "sudo -u postgres createdb -O opsdir -T template0 opsdir_test_workspace"
# the approved changes the showcase applies, in order: (change id, LDIF file)
APPROVED = (("CHG-2001", ROOT / "changes" / "CHG-2001-mro-firewall-target.ldif"),
            ("CHG-2003", ROOT / "changes" / "CHG-2003-stable-ldaps-name.ldif"))


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


def cmd_output(text, status=0):
    """What the snapshot script captures for a command that printed text and exited with status."""
    return f"{text}\nexit {status}\n"


# ------------------------------------------------------------------ effects: read files
def fixture_directory(changes=()):
    """The synthetic estate (schema/ and data/*.ldif) as a Directory, after (change id, LDIF file) changes."""
    return build_directory(SCHEMA.read_text(), read_ldif_files(sorted(DATA.glob("*.ldif"))),
                           read_ldif_files([path for _, path in changes]))


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


def run_snapshot(dsn, out):
    """Effect: scripts/snapshot-outputs.sh against dsn into out (drops and reloads dsn's opsdir schema;
    regenerates schema/ and data/ in place, which must reproduce the committed files)."""
    return subprocess.run([str(ROOT / "scripts" / "snapshot-outputs.sh"), str(out)], capture_output=True,
                          text=True, env={**os.environ, "OPSDIR_DSN": dsn}, check=False)


def load_script(name):
    """A script from scripts/ (file names with dashes) as a module."""
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
