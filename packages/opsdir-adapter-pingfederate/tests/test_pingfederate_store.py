"""A PingFederate bulk export imported into the store, against Postgres: `opsdir import pingfederate` previews it and
applies it under an approved change, the store accepts every integration, claim and certificate (vocabularies,
dates, references), no secret reaches it, and importing the same export again changes nothing."""
import os
from pathlib import Path

import pytest

import support
from opsdir import operations as ops
from opsdir.core.interchange.ldif import parse
from opsdir.store import postgres as db

pytestmark = pytest.mark.integration

EXPORT = Path(__file__).resolve().parent / "bulk-export"
BASE = """dn: dc=ciam-ops
objectClass: top
objectClass: domain
dc: ciam-ops

dn: ou=user-schema,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: user-schema

dn: cn=mail,ou=user-schema,dc=ciam-ops
objectClass: top
objectClass: ciamUserAttribute
cn: mail
ciamLdapName: mail
ciamPiiClass: moderate

dn: cn=companyId,ou=user-schema,dc=ciam-ops
objectClass: top
objectClass: ciamUserAttribute
cn: companyId
ciamLdapName: companyId
ciamPiiClass: none

dn: ou=identity-services,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: identity-services

dn: cn=sso,ou=identity-services,dc=ciam-ops
objectClass: top
objectClass: ciamIdentityService
cn: sso
ciamBaseUrl: https://sso.example.test
ciamTargetRole: pf-engine

dn: ou=changes,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: changes

dn: cn=CHG-PF-1,ou=changes,dc=ciam-ops
objectClass: top
objectClass: ciamChange
cn: CHG-PF-1
ciamTitle: Import PingFederate's configuration (bulk export)
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


def test_a_bulk_export_is_imported_under_a_change_and_again_changes_nothing(conn):
    preview = ops.preview_import(conn, "pingfederate/bulk", files_of(EXPORT))
    assert ops.apply_preview(conn, preview, "CHG-PF-1").lines
    kinds = dict(conn.execute("select attrs->'ciamProtocolType'->>0, count(*) from opsdir.entry "
                              "where 'ciamIntegration' = any (object_classes) group by 1").fetchall())
    assert kinds == {"saml2-sp": 1, "saml2-idp": 1, "oidc-client": 2}
    certs = conn.execute("select count(*) from opsdir.entry "
                         "where 'ciamCertificate' = any (object_classes)").fetchone()[0]
    assert certs == 3
    dump = str(conn.execute("select jsonb_agg(attrs) from opsdir.entry").fetchone()[0])
    assert "OBF:" not in dump
    assert ops.preview_import(conn, "pingfederate/bulk", files_of(EXPORT)).changes == ()
