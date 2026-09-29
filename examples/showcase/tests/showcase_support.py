"""Showcase test support: where the example estate lives, the approved changes it applies, the estate as an
in-memory directory, the snapshot of every command, and its scripts as modules."""
import importlib.util
from functools import reduce
import os
import pathlib
import subprocess

from opsdir import operations as ops
from opsdir.connectors.importing import preview_import
from opsdir.store.postgres import read_ldif_files
from support import build_directory, schema_for

SHOWCASE = pathlib.Path(__file__).resolve().parents[1]
DATA = SHOWCASE / "data"
GOLDEN = SHOWCASE / "golden"
SCRIPTS = SHOWCASE / "scripts"
# the approved changes the showcase applies, in order: (change id, LDIF file)
APPROVED = (("CHG-2001", SHOWCASE / "changes" / "CHG-2001-mro-firewall-target.ldif"),
            ("CHG-2003", SHOWCASE / "changes" / "CHG-2003-stable-ldaps-name.ldif"),
            ("CHG-2005", SHOWCASE / "changes" / "CHG-2005-idm-connector-credentials.ldif"))
# the product exports the demo imports right after loading: (change id, importer, export directory)
IMPORTS = (("CHG-2004", "pingam", SHOWCASE / "exports" / "amster"),
           ("CHG-2004", "pingidm", SHOWCASE / "exports" / "idm"),
           ("CHG-2004", "pinggateway", SHOWCASE / "exports" / "ig"))


def cmd_output(text, status=0):
    """What the snapshot script captures for a command that printed text and exited with status."""
    return f"{text}\nexit {status}\n"


def export_files(root):
    """Effect: a product export's files, {relative path: text}."""
    return {p.relative_to(root).as_posix(): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


def import_records(schema, records):
    """Effect (reads the exports): the change records importing the product exports (IMPORTS) into the loaded
    estate makes, one after the other (each import sees what the ones before it added, as in the store)."""
    def step(done, imported):
        _, spec, root = imported
        return (*done, *preview_import(build_directory(schema, records, done), spec, export_files(root))[0])
    return reduce(step, IMPORTS, ())


def import_exports(conn):
    """Effect: import the product exports (IMPORTS) into a store that holds the loaded estate, as the demo does."""
    return [ops.apply_preview(conn, ops.preview_import(conn, spec, export_files(root)), change_id)
            for change_id, spec, root in IMPORTS]


def fixture_directory(changes=()):
    """Effect (reads files): the example estate as a Directory, as the demo builds it: loaded, the product exports
    imported (IMPORTS), then after (change id, LDIF file) changes."""
    records = read_ldif_files(sorted(DATA.glob("*.ldif")))
    schema = schema_for(records)
    return build_directory(schema, records, (*import_records(schema, records),
                                             *read_ldif_files([path for _, path in changes])))


def run_snapshot(dsn, out):
    """Effect: scripts/snapshot-outputs.sh against dsn into out (drops and reloads dsn's opsdir schema;
    regenerates the published schema and data/ in place, which must reproduce the committed files)."""
    return subprocess.run([str(SCRIPTS / "snapshot-outputs.sh"), str(out)], capture_output=True,
                          text=True, env={**os.environ, "OPSDIR_DSN": dsn}, check=False)


def load_script(name):
    """Effect: a script from scripts/ (file names with dashes) as a module."""
    path = SCRIPTS / name
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
