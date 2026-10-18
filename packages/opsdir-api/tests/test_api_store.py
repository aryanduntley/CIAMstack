"""The API against the real store (integration: OPSDIR_TEST_DSN, else the local test database): a token signed by the
identity provider becomes a recorded person, and the store attributes what the API writes to that person because the
record's api-login setting names the API's database login: the author of a change is the person who proposed it, its
own author can't approve it, someone else can, and the history says who."""
import os

import pytest
import support
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import RSAKey

from opsdir import operations as ops
from opsdir.core.directory import get, one
from opsdir.core.interchange.ldif import parse
from opsdir.domains.governance.changes import change_dn
from opsdir.store import postgres as db
from opsdir_api.app import create_app
from opsdir_api.config import Config

pytestmark = pytest.mark.integration

ISSUER, AUDIENCE, NOW = "https://idp.example.com/realms/ops", "opsdir-api", 1_800_000_000
KEY = RSAKey.generate_key(2048, parameters={"kid": "k1"})
JWKS = {"keys": [KEY.as_dict(private=False)]}
BASE = """dn: dc=ciam-ops
objectClass: top
objectClass: domain
dc: ciam-ops

dn: ou=changes,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: changes

dn: cn=CHG-1,ou=changes,dc=ciam-ops
objectClass: top
objectClass: ciamChange
cn: CHG-1
ciamTitle: Loaded as approved
ciamChangeStatus: approved

dn: ou=owners,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: owners

dn: cn=platform,ou=owners,dc=ciam-ops
objectClass: top
objectClass: ciamParty
cn: platform
ciamOwnerKind: team
"""


def bearer(sub):
    body = {"iss": ISSUER, "aud": AUDIENCE, "sub": sub, "iat": NOW, "exp": NOW + 300}
    return {"Authorization": "Bearer " + jwt.encode({"alg": "RS256", "kid": "k1"}, body, KEY, algorithms=["RS256"])}


@pytest.fixture
def client():
    dsn = support.reachable(support.integration_dsn(os.environ), "OPSDIR_TEST_DSN", support.CREATE_TEST_DB)
    conn = db.connect(dsn)
    ops.init(conn)
    ops.load(conn, parse(BASE))
    login = conn.execute("select session_user").fetchone()[0]
    ops.apply_preview(conn, ops.preview_setting(conn, "api-login", login), "CHG-1")      # this login is the API's
    for person in ("alice", "bob"):
        ops.apply_preview(conn, ops.preview_person(conn, person, subjects=(f"{ISSUER} sub-{person}",)), "CHG-1")
    config = Config(dsn, ISSUER, AUDIENCE, None, ("RS256",), 60)
    yield TestClient(create_app(config, connect=lambda: db.connect(dsn), jwks=JWKS, clock=lambda: NOW)), conn
    conn.close()


def change(conn, change_id):
    return get(db.load_directory(conn), change_dn(change_id))


def test_the_person_behind_the_token_is_who_the_store_records(client):
    http, conn = client
    proposed = http.post("/v1/changes", json={"id": "CHG-2", "title": "Rotate the signing key"},
                         headers=bearer("sub-alice"))
    assert proposed.status_code == 201, proposed.text
    assert one(change(conn, "CHG-2"), "ciamAuthor") == "alice"
    own = http.post("/v1/changes/CHG-2/approve", headers=bearer("sub-alice"))
    assert own.status_code in (403, 409) and "alice wrote change CHG-2 and can't approve it" in own.text
    approved = http.post("/v1/changes/CHG-2/approve", headers=bearer("sub-bob"))
    assert approved.status_code == 200, approved.text
    assert (one(change(conn, "CHG-2"), "ciamChangeStatus"), one(change(conn, "CHG-2"), "ciamApprovedBy")) == (
        "approved", "bob")
    written = conn.execute("select db_user from opsdir.entry_history where dn = 'cn=CHG-2,ou=changes,dc=ciam-ops' "
                           "order by id").fetchall()
    assert [w for (w,) in written] == ["alice", "bob"]


def test_an_identity_no_person_records_is_refused_and_writes_nothing(client):
    http, conn = client
    refused = http.post("/v1/changes", json={"id": "CHG-3", "title": "Anything"}, headers=bearer("sub-mallory"))
    assert refused.status_code == 403 and "no recorded person" in refused.text
    assert change(conn, "CHG-3") is None
