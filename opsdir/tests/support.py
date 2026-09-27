"""Test support: the synthetic estate as an in-memory directory, built with the store's own pure preparation
(no Postgres), approved change records applied to its rows, and golden trees and command outputs read back.

The store's rules (R1-R10) run in Postgres triggers and are not applied here; the integration test covers them.
"""
import importlib.util
from functools import reduce

from opsdir.core.directory import make_directory, norm_dn
from opsdir.core.paths import ROOT
from opsdir.store.postgres import apply_mods, entry_rows, read_ldif_files, schema_rows, split_record

SCHEMA = ROOT / "schema" / "ciam-ops.schema.ldif"
DATA = ROOT / "data"
GOLDEN = ROOT / "tests" / "golden"
# the approved changes the showcase applies, in order: (change id, LDIF file)
APPROVED = (("CHG-2001", ROOT / "changes" / "CHG-2001-mro-firewall-rtx-next.ldif"),
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


def load_script(name):
    """A script from scripts/ (file names with dashes) as a module."""
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
