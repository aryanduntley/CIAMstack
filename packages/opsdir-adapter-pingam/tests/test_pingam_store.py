"""An Amster export imported into the store, against Postgres: `opsdir import`'s operation previews it and applies it
under an approved change, the store accepts every entry (values, JSON settings, outcomes), nothing secret is stored,
and importing the same export again changes nothing."""
import os
from pathlib import Path

import pytest

import support
from opsdir import operations as ops
from opsdir.core.interchange.ldif import parse
from opsdir.store import postgres as db

pytestmark = pytest.mark.integration

EXPORT = Path(__file__).resolve().parent / "amster-export"
BASE = """dn: dc=ciam-ops
objectClass: top
objectClass: domain
dc: ciam-ops

dn: ou=identity-services,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: identity-services

dn: cn=customers,ou=identity-services,dc=ciam-ops
objectClass: top
objectClass: ciamIdentityService
objectClass: pingamRealm
cn: customers
ciamBaseUrl: https://login.example.test
pingamRealmPath: /customers
"""


def files_of(root):
    return {p.relative_to(root).as_posix(): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}

CHANGE = """dn: ou=changes,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: changes

dn: cn=CHG-AM-1,ou=changes,dc=ciam-ops
objectClass: top
objectClass: ciamChange
cn: CHG-AM-1
ciamTitle: Import the customers realm from Amster
ciamChangeStatus: approved
"""


@pytest.fixture
def conn():
    c = db.connect(support.reachable(support.integration_dsn(os.environ), "OPSDIR_TEST_DSN", support.CREATE_TEST_DB))
    ops.init(c)
    db.load_records(c, parse(BASE + "\n" + CHANGE))
    yield c
    c.close()


def test_an_export_is_imported_under_a_change_and_again_changes_nothing(conn):
    preview = ops.preview_import(conn, "pingam", files_of(EXPORT))
    applied = ops.apply_preview(conn, preview, "CHG-AM-1")
    assert len(applied.lines) == len(preview.changes) > 10
    stored = conn.execute("select count(*) from opsdir.entry where 'pingamNode' = any (object_classes)").fetchone()[0]
    assert stored == 5
    dump = str(conn.execute("select jsonb_agg(attrs) from opsdir.entry").fetchone()[0])
    assert "Sm7p-Not-Real-2026" not in dump and "client-secret-value-1" not in dump
    assert ops.preview_import(conn, "pingam", files_of(EXPORT)).changes == ()
