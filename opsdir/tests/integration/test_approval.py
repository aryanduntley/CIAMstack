"""Approval enforced by the store, against Postgres with one login (the test database's): the store writes who wrote a
change and who approved it, refuses an approval by the change's own author unless approval-separation is off, refuses
applied without approval, keeps the approver from being rewritten, and, once people are recorded, refuses an approval
by a login that isn't one. (Several logins: test_record_roles.py, on a scratch server.)"""
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


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    ops.init(c)
    ops.load(c, parse(BASE))
    yield c
    c.close()


def change(conn, change_id):
    return get(db.load_directory(conn), change_dn(change_id))


def login(conn):
    return conn.execute("select session_user").fetchone()[0]


def waive(conn):
    ops.apply_preview(conn, ops.preview_setting(conn, "approval-separation", "FALSE"), "CHG-1")


def test_the_author_is_the_login_and_cant_approve_their_own_change(conn):
    ops.new_change(conn, "CHG-2", "Open the LDAPS port")
    assert (one(change(conn, "CHG-2"), "ciamAuthor"), one(change(conn, "CHG-2"), "ciamChangeStatus")) == (
        login(conn), "proposed")
    with pytest.raises(psycopg.errors.RaiseException, match=f"{login(conn)} wrote change CHG-2 and can't approve it"):
        ops.change_status(conn, "CHG-2", "approved")
    ops.change_status(conn, "CHG-2", "rejected")                          # rejecting isn't approving
    assert one(change(conn, "CHG-2"), "ciamChangeStatus") == "rejected"


def test_with_the_waiver_one_person_approves_and_is_recorded_as_the_approver(conn):
    waive(conn)
    ops.new_change(conn, "CHG-2", "Open the LDAPS port")
    ops.change_status(conn, "CHG-2", "approved")
    assert one(change(conn, "CHG-2"), "ciamApprovedBy") == login(conn)
    forged = ("dn: cn=CHG-2,ou=changes,dc=ciam-ops\nchangetype: modify\nreplace: ciamApprovedBy\n"
              "ciamApprovedBy: someone-else\n-\nreplace: ciamAuthor\nciamAuthor: someone-else\n-\n")
    ops.modify(conn, parse(forged), "CHG-2")
    assert (one(change(conn, "CHG-2"), "ciamApprovedBy"), one(change(conn, "CHG-2"), "ciamAuthor")) == (
        login(conn), login(conn))                                          # the store keeps its own


def test_applied_needs_approval_first(conn):
    ops.new_change(conn, "CHG-2", "Open the LDAPS port")
    with pytest.raises(ValueError, match="is proposed: it can't become applied"):
        ops.change_status(conn, "CHG-2", "applied")
    straight = ("dn: cn=CHG-2,ou=changes,dc=ciam-ops\nchangetype: modify\nreplace: ciamChangeStatus\n"
                "ciamChangeStatus: applied\n-\n")
    with pytest.raises(psycopg.errors.RaiseException, match="is proposed, not approved"):   # the store too
        ops.modify(conn, parse(straight), "CHG-2")


def test_a_change_created_approved_counts_as_approved_by_its_author(conn):
    approved = ("dn: cn=CHG-3,ou=changes,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: ciamChange\n"
                "cn: CHG-3\nciamTitle: Self-approved\nciamChangeStatus: approved\n")
    with pytest.raises(psycopg.errors.RaiseException, match="can't approve it"):
        ops.modify(conn, parse(approved), "CHG-3")


def test_once_people_are_recorded_only_a_recorded_person_approves(conn):
    waive(conn)                                                           # isolates the person rule
    ops.apply_preview(conn, ops.preview_person(conn, "someone_else", "Someone Else", teams=("platform",)), "CHG-1")
    ops.new_change(conn, "CHG-2", "Open the LDAPS port")
    with pytest.raises(psycopg.errors.RaiseException, match=f"{login(conn)} approves change CHG-2 but isn't a "
                                                            "recorded person"):
        ops.change_status(conn, "CHG-2", "approved")
    ops.apply_preview(conn, ops.preview_person(conn, login(conn), "The Tester"), "CHG-1")
    ops.change_status(conn, "CHG-2", "approved")
    assert ops.person_lines(conn, "someone_else") == ("login  someone_else", "name   Someone Else",
                                                      "teams  platform")


def test_history_records_the_login(conn):
    ops.new_change(conn, "CHG-2", "Open the LDAPS port")
    assert ops.history(conn).rows[-1][1:] == ("CHG-2", "insert", login(conn), "cn=CHG-2,ou=changes,dc=ciam-ops")


def test_posture_reports_the_waiver(conn):
    checks = {c: s for c, s, _ in ops.posture(conn)[0].rows}
    assert checks["approval separation"] == "ok"
    waive(conn)
    assert {c: s for c, s, _ in ops.posture(conn)[0].rows}["approval separation"] == "warn"


SHADOW = ("create temp table entry as select * from opsdir.entry where dn_norm in ('ou=owners,dc=ciam-ops', "
          "'dc=ciam-ops')",
          "insert into pg_temp.entry (id, dn, dn_norm, rdn, object_classes, attrs, change_id) values (-1, "
          "'cn=fake-1,ou=changes,dc=ciam-ops', 'cn=fake-1,ou=changes,dc=ciam-ops', 'cn=fake-1', '{top,ciamChange}', "
          "'{\"ciamChangeStatus\": [\"approved\"]}', 'x')",
          "set local opsdir.change_id = 'FAKE-1'")


def test_a_temporary_table_cant_stand_in_for_the_record_inside_the_stores_rules(conn):
    """A login allowed to create temporary tables can't shadow entry with a fake approved change: the store's own
    functions run with their search path pinned, the temporary schema last."""
    with pytest.raises(psycopg.errors.RaiseException, match="FAKE-1 is not an approved change record"):
        with conn.transaction():
            for statement in SHADOW:
                conn.execute(statement)
            conn.execute("update opsdir.entry set attrs = attrs || '{\"description\": [\"shadowed\"]}'::jsonb "
                         "where dn_norm = 'cn=platform,ou=owners,dc=ciam-ops'")
    assert conn.execute("select count(*) from opsdir.entry_history where change_id = 'FAKE-1'").fetchone() == (0,)


def test_an_approval_covers_the_change_as_it_was_approved(conn):
    """The records an approved change proposes can't change afterwards, whoever writes: an approval can't be reused
    for other records (its title stays writable: change records are mirrored from ITSM)."""
    waive(conn)
    ops.propose_edit(conn, ops.preview_edit(conn, "cn=platform,ou=owners,dc=ciam-ops", sets=(("mail", "a@x.test"),)),
                     "CHG-2", "Platform's mail")
    ops.change_status(conn, "CHG-2", "approved")
    swapped = ("dn: cn=CHG-2,ou=changes,dc=ciam-ops\nchangetype: modify\nreplace: ciamChangeRecords\n"
               "ciamChangeRecords: dn: cn=platform,ou=owners,dc=ciam-ops\n-\n")
    with pytest.raises(psycopg.errors.RaiseException, match="CHG-2 was approved as it stood"):
        ops.modify(conn, parse(swapped), "CHG-1")
    retitled = "dn: cn=CHG-2,ou=changes,dc=ciam-ops\nchangetype: modify\nreplace: ciamTitle\nciamTitle: Renamed\n-\n"
    ops.modify(conn, parse(retitled), "CHG-1")
    ops.apply_proposed(conn, "CHG-2")                                       # the approved records still apply
    assert one(get(db.load_directory(conn), "cn=platform,ou=owners,dc=ciam-ops"), "mail") == "a@x.test"
