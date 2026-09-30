"""Showcase test support: where the example estate lives, the approved changes it applies, the estate as an
in-memory directory, the snapshot of every command, and its scripts as modules."""
import importlib.util
from functools import reduce
import os
import pathlib
import subprocess

from opsdir import operations as ops
from opsdir.cli import import_time, read_texts
from opsdir.connectors.capture import census_changes
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
# the product exports the demo imports right after loading: (change id, importer, export directory, when taken)
IMPORTS = (("CHG-2004", "pingam", SHOWCASE / "exports" / "amster", None),
           ("CHG-2004", "pingidm", SHOWCASE / "exports" / "idm", None),
           ("CHG-2004", "pinggateway", SHOWCASE / "exports" / "ig", None),
           ("CHG-2006", "pingds/config", SHOWCASE / "exports" / "ds-config", "20260920030000Z"),
           ("CHG-2007", "pingds/access-log", SHOWCASE / "exports" / "ds-access-logs", None),
           ("CHG-2008", "pingfederate", SHOWCASE / "exports" / "pingfederate", None))
# then the census of files that copy the record's values (change id, directory)
CENSUS = ("CHG-2009", SHOWCASE / "exports" / "census")


def cmd_output(text, status=0):
    """What the snapshot script captures for a command that printed text and exited with status."""
    return f"{text}\nexit {status}\n"


def export_files(root):
    """Effect: a product export's files, {relative path: text}, as `opsdir import` reads them (.gz decompressed)."""
    return read_texts(root)[0]


def import_records(schema, records):
    """Effect (reads the exports): the change records importing the product exports (IMPORTS) into the loaded
    estate makes, one after the other (each import sees what the ones before it added, as in the store)."""
    def step(done, imported):
        _, spec, root, at = imported
        return (*done, *preview_import(build_directory(schema, records, done), spec, export_files(root),
                                       at=import_time(at) if at else None)[0])
    imported = reduce(step, IMPORTS, ())
    return (*imported, *census_changes(build_directory(schema, records, imported), export_files(CENSUS[1]))[0])


def import_exports(conn):
    """Effect: import the product exports (IMPORTS) into a store that holds the loaded estate, then take the census
    (CENSUS), as the demo does."""
    return [*(ops.apply_preview(conn, ops.preview_import(conn, spec, export_files(root),
                                                         import_time(at) if at else None), change_id)
              for change_id, spec, root, at in IMPORTS),
            ops.apply_preview(conn, ops.preview_census(conn, export_files(CENSUS[1])), CENSUS[0])]


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
