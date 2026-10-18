"""The person behind the API server's login, against Postgres with one login (the test database's): once the record's
api-login setting names the login, the person a context acts for (store.postgres.requesting) is who the store
attributes writes to: a change's author and approver, history and modified_by, the approval rules; a login the setting
doesn't name acts as itself whatever it says. (The grant check, which the schema owner skips: test_record_roles.py.)"""
import psycopg
import pytest

from opsdir import operations as ops
from opsdir.core.directory import get, one
from opsdir.core.interchange.ldif import parse
from opsdir.domains.governance.changes import change_dn
from opsdir.store import postgres as db

pytestmark = pytest.mark.integration

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
ISSUER = "https://login.example.com/tenant"


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    ops.init(c)
    ops.load(c, parse(BASE))
    yield c
    c.close()


def login(conn):
    return conn.execute("select session_user").fetchone()[0]


def trust(conn, api_login):
    """Name the API login in the record (a governed write like any setting)."""
    ops.apply_preview(conn, ops.preview_setting(conn, "api-login", api_login), "CHG-1")


def change(conn, change_id):
    return get(db.load_directory(conn), change_dn(change_id))


def modified_by(conn, dn):
    return conn.execute("select modified_by from opsdir.entry where dn_norm = %s", (dn.lower(),)).fetchone()[0]


def test_the_api_login_writes_as_the_person_it_names(conn):
    trust(conn, login(conn))
    with db.requesting("alice"):
        ops.new_change(conn, "CHG-2", "Open the LDAPS port")
        assert db.requester(conn) == "alice"
    assert one(change(conn, "CHG-2"), "ciamAuthor") == "alice"
    assert ops.history(conn).rows[-1][1:] == ("CHG-2", "insert", "alice", "", "", "cn=CHG-2,ou=changes,dc=ciam-ops")
    assert modified_by(conn, "cn=CHG-2,ou=changes,dc=ciam-ops") == "alice"
    ops.new_change(conn, "CHG-3", "Without a person")                  # no requester: the login acts as itself
    assert one(change(conn, "CHG-3"), "ciamAuthor") == login(conn)
    assert modified_by(conn, "cn=CHG-3,ou=changes,dc=ciam-ops") == login(conn)


def test_approval_separation_holds_between_the_people_behind_the_api_login(conn):
    trust(conn, login(conn))
    with db.requesting("alice"):
        ops.new_change(conn, "CHG-2", "Open the LDAPS port")
        with pytest.raises(psycopg.errors.RaiseException, match="alice wrote change CHG-2 and can't approve it"):
            ops.change_status(conn, "CHG-2", "approved")
    with db.requesting("bob"):
        ops.change_status(conn, "CHG-2", "approved")
    assert (one(change(conn, "CHG-2"), "ciamAuthor"), one(change(conn, "CHG-2"), "ciamApprovedBy")) == (
        "alice", "bob")


def test_once_people_are_recorded_the_requester_must_be_one_to_approve(conn):
    trust(conn, login(conn))
    ops.apply_preview(conn, ops.preview_person(conn, "alice", "Alice", subjects=(f"{ISSUER} a-1",)), "CHG-1")
    ops.apply_preview(conn, ops.preview_person(conn, "bob", "Bob"), "CHG-1")
    assert ops.person_for_subject(conn, ISSUER, "a-1") == "alice"
    assert ops.person_for_subject(conn, ISSUER, "b-1") is None
    with db.requesting("alice"):
        ops.new_change(conn, "CHG-2", "Open the LDAPS port")
    with db.requesting("carol"):
        with pytest.raises(psycopg.errors.RaiseException, match="carol approves change CHG-2 but isn't a recorded"):
            ops.change_status(conn, "CHG-2", "approved")
    with pytest.raises(psycopg.errors.RaiseException, match=f"{login(conn)} approves change CHG-2 but isn't"):
        ops.change_status(conn, "CHG-2", "approved")                  # the API login itself is nobody
    with db.requesting("bob"):
        ops.change_status(conn, "CHG-2", "approved")
    assert one(change(conn, "CHG-2"), "ciamApprovedBy") == "bob"


def test_a_login_the_setting_doesnt_name_acts_as_itself(conn):
    trust(conn, "opsdir_api")                                          # another login
    with db.requesting("alice"):
        ops.new_change(conn, "CHG-2", "Open the LDAPS port")
    assert one(change(conn, "CHG-2"), "ciamAuthor") == login(conn)
    assert ops.history(conn).rows[-1][3] == login(conn)
    with db.requesting("bob"):                                         # still its own change: refused
        with pytest.raises(psycopg.errors.RaiseException, match=f"{login(conn)} wrote change CHG-2"):
            ops.change_status(conn, "CHG-2", "approved")


def test_without_the_setting_nobody_is_trusted(conn):
    with db.requesting("alice"):
        ops.new_change(conn, "CHG-2", "Open the LDAPS port")
    assert one(change(conn, "CHG-2"), "ciamAuthor") == login(conn)


def test_a_requester_that_isnt_a_login_name_is_refused(conn):
    trust(conn, login(conn))
    with db.requesting("Alice,ou=people"):
        with pytest.raises(psycopg.errors.RaiseException, match="requester Alice,ou=people isn't a login name"):
            ops.new_change(conn, "CHG-2", "Open the LDAPS port")
