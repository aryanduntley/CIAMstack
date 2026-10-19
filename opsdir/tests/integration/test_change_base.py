"""A proposed change applies only to what it was proposed against, against Postgres with one login (the test
database's, which owns the schema: the rule holds for it too): the store notes what each entry the proposed records
touch looked like (ciamChangeBase), never taken from the writer, and refuses applying the records once another change
wrote one of those entries since, so they are proposed again; a proposal nothing touched meanwhile applies."""
import psycopg
import pytest

from opsdir import operations as ops
from opsdir.connectors.fixes import change_dn
from opsdir.core.directory import get, one, values
from opsdir.core.interchange.ldif import LdifRecord, parse
from opsdir.domains.governance.changes import proposal_record
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
ciamTitle: Settings for a one-person install
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

PLATFORM = "cn=platform,ou=owners,dc=ciam-ops"


def mail(address):
    return LdifRecord(PLATFORM, "modify", {}, (("replace", "mail", (address,)),))


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    ops.init(c)
    ops.load(c, parse(BASE))
    ops.apply_preview(c, ops.preview_setting(c, "approval-separation", "FALSE"), "CHG-1")   # one person here
    yield c
    c.close()


def propose(conn, change_id, records):
    ops.modify(conn, (proposal_record(change_id, "Platform team's mail", records),), change_id)
    ops.change_status(conn, change_id, "approved")


def test_the_store_notes_what_a_proposal_was_proposed_against(conn):
    last = conn.execute("select max(id) from opsdir.entry_history where dn = %s", (PLATFORM,)).fetchone()[0]
    propose(conn, "CHG-2", (mail("platform@example.test"),))
    assert values(get(db.load_directory(conn), change_dn("CHG-2")), "ciamChangeBase") == (f"{PLATFORM} {last}",)


def test_the_writer_can_t_set_the_base(conn):
    ops.modify(conn, (LdifRecord(change_dn("CHG-2"), "add", {
        "objectClass": ("top", "ciamChange"), "cn": ("CHG-2",), "ciamTitle": ("Hand-made",),
        "ciamChangeStatus": ("proposed",), "ciamChangeBase": (f"{PLATFORM} 999999",)}, ()),), "CHG-2")
    assert values(get(db.load_directory(conn), change_dn("CHG-2")), "ciamChangeBase") == ()


def test_a_proposal_nothing_touched_meanwhile_applies(conn):
    propose(conn, "CHG-2", (mail("platform@example.test"),))
    ops.apply_proposed(conn, "CHG-2")
    d = db.load_directory(conn)
    assert (one(get(d, PLATFORM), "mail"), one(get(d, change_dn("CHG-2")), "ciamChangeStatus")) == (
        "platform@example.test", "applied")


def test_a_proposal_whose_entry_changed_since_is_refused(conn):
    propose(conn, "CHG-2", (mail("platform@example.test"),))
    ops.modify(conn, (mail("ciam-platform@example.test"),), "CHG-1")        # someone else's change, meanwhile
    with pytest.raises(psycopg.errors.RaiseException,
                       match=f"{PLATFORM} was written by change CHG-1 after change CHG-2 was proposed"):
        ops.apply_proposed(conn, "CHG-2")
    conn.rollback()
    d = db.load_directory(conn)
    assert (one(get(d, PLATFORM), "mail"), one(get(d, change_dn("CHG-2")), "ciamChangeStatus")) == (
        "ciam-platform@example.test", "approved")
    propose(conn, "CHG-3", (mail("platform@example.test"),))                # proposed again: applies
    ops.apply_proposed(conn, "CHG-3")
    assert one(get(db.load_directory(conn), PLATFORM), "mail") == "platform@example.test"
