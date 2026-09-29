"""A gateway configuration imported into the store, against Postgres: the store accepts every entry, and importing
the same configuration again changes nothing."""
import os
from pathlib import Path

import pytest

import support
from opsdir import operations as ops
from opsdir.core.interchange.ldif import parse
from opsdir.store import postgres as db

pytestmark = pytest.mark.integration

CONFIG = Path(__file__).resolve().parent / "gateway-config"
BASE = """dn: dc=ciam-ops
objectClass: top
objectClass: domain
dc: ciam-ops

dn: ou=changes,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: changes

dn: cn=CHG-IG-1,ou=changes,dc=ciam-ops
objectClass: top
objectClass: ciamChange
cn: CHG-IG-1
ciamTitle: Import the gateway routes
ciamChangeStatus: approved
"""


def files_of(root):
    return {p.relative_to(root).as_posix(): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


@pytest.fixture
def conn():
    c = db.connect(support.reachable(support.integration_dsn(os.environ), "OPSDIR_TEST_DSN", support.CREATE_TEST_DB))
    ops.init(c)
    db.load_records(c, parse(BASE))
    yield c
    c.close()


def test_a_configuration_is_imported_under_a_change_and_again_changes_nothing(conn):
    preview = ops.preview_import(conn, "pinggateway", files_of(CONFIG))
    applied = ops.apply_preview(conn, preview, "CHG-IG-1")
    assert len(applied.lines) == len(preview.changes) >= 6
    assert ops.preview_import(conn, "pinggateway", files_of(CONFIG)).changes == ()
