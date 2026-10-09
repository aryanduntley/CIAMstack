"""Assisted fixes through the store: proposing writes only a change record with status proposed (holding the records
the fix applies); the store refuses those records under a change nobody approved; once a person approves it, the
proposal's records apply unchanged and the change is marked applied."""
import psycopg
import pytest

from opsdir import operations as ops
from opsdir.connectors.fixes import change_dn, proposal
from opsdir.core.directory import get, one
from opsdir.core.findings import Fix
from opsdir.core.interchange.ldif import LdifRecord, parse
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

dn: ou=owners,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: owners
"""
FIX = Fix("owners:net-team", "Owners", "Record the network team", (LdifRecord(
    "cn=net-team,ou=owners,dc=ciam-ops", "add",
    {"objectClass": ("top", "ciamParty"), "cn": ("net-team",), "ciamOwnerKind": ("team",)}, ()),),
    ("Tell the team.",), ())


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    ops.init(c)
    ops.load(c, parse(BASE))
    yield c
    c.close()


def _change(conn, change_id):
    return get(db.load_directory(conn), change_dn(change_id))


def test_a_proposal_waits_for_a_person_then_applies_unchanged(conn):
    ops.modify(conn, (proposal(FIX, "CHG-9"),), "CHG-9")                  # what an AI may do
    change = _change(conn, "CHG-9")
    assert (one(change, "ciamChangeStatus"), one(change, "ciamTitle")) == ("proposed", "Record the network team")
    assert tuple(parse(one(change, "ciamChangeRecords"))) == FIX.records
    with pytest.raises(ValueError, match="CHG-9 is proposed, not approved"):
        ops.apply_proposed(conn, "CHG-9")
    with pytest.raises(psycopg.Error, match="not an approved change"):     # the store enforces it too
        ops.modify(conn, FIX.records, "CHG-9")
    conn.rollback()
    approve = (f"dn: {change_dn('CHG-9')}\nchangetype: modify\nreplace: ciamChangeStatus\n"
               "ciamChangeStatus: approved\n-\n")
    ops.modify(conn, parse(approve), "CHG-9")                              # a person approves (ITSM mirror)
    applied = ops.apply_proposed(conn, "CHG-9")
    assert applied.change_id == "CHG-9" and len(applied.lines) == 2
    d = db.load_directory(conn)
    assert get(d, "cn=net-team,ou=owners,dc=ciam-ops") is not None
    assert one(get(d, change_dn("CHG-9")), "ciamChangeStatus") == "applied"
    with pytest.raises(ValueError, match="applied, not approved"):         # applied once
        ops.apply_proposed(conn, "CHG-9")


def test_a_fix_with_only_manual_steps_can_t_be_proposed():
    with pytest.raises(ValueError, match="changes nothing in the record"):
        proposal(FIX._replace(records=()), "CHG-10")


def test_the_store_says_what_it_would_refuse_before_anything_is_proposed(conn):
    assert db.record_problems(conn, FIX.records) == ()
    (add,) = FIX.records
    twice = add._replace(attrs={**add.attrs, "ciamOwnerKind": ("team", "vendor")})
    assert db.record_problems(conn, (twice,)) == (
        'opsdir: "ciamOwnerKind" is SINGLE-VALUE on "cn=net-team,ou=owners,dc=ciam-ops"',)
    ops.modify(conn, FIX.records, "BOOTSTRAP")
    bad = LdifRecord(add.dn, "modify", {}, (("replace", "ciamContactUrl", ("not a url",)),))
    (problem,) = db.record_problems(conn, (bad,))
    assert "ciamContactUrl" in problem and "not a url" in problem
    assert db.record_problems(conn, (LdifRecord(add.dn, "delete", {}, ()),)) == ()
    assert get(db.load_directory(conn), add.dn).attrs.get("ciamContactUrl") is None     # nothing was written
