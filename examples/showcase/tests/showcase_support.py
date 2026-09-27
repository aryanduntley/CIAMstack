"""Showcase test support: where the example estate lives, the approved changes it applies, the estate as an
in-memory directory, the snapshot of every command, and its scripts as modules."""
import importlib.util
import os
import pathlib
import subprocess

from opsdir.store.postgres import read_ldif_files
from support import SCHEMA, build_directory

SHOWCASE = pathlib.Path(__file__).resolve().parents[1]
DATA = SHOWCASE / "data"
GOLDEN = SHOWCASE / "golden"
SCRIPTS = SHOWCASE / "scripts"
# the approved changes the showcase applies, in order: (change id, LDIF file)
APPROVED = (("CHG-2001", SHOWCASE / "changes" / "CHG-2001-mro-firewall-target.ldif"),
            ("CHG-2003", SHOWCASE / "changes" / "CHG-2003-stable-ldaps-name.ldif"))


def cmd_output(text, status=0):
    """What the snapshot script captures for a command that printed text and exited with status."""
    return f"{text}\nexit {status}\n"


def fixture_directory(changes=()):
    """Effect (reads files): the example estate as a Directory, after (change id, LDIF file) changes."""
    return build_directory(SCHEMA.read_text(), read_ldif_files(sorted(DATA.glob("*.ldif"))),
                           read_ldif_files([path for _, path in changes]))


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
