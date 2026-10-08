"""Imports through the store: an import that would replace what the record holds is refused until each conflict is
decided; the record's value stays where it is kept; every applied import records its run of each scope it read, with
how its export was collected when opsdir collected it."""
import datetime as dt

import psycopg
import pytest

from opsdir import operations as ops
from opsdir.connectors.importing import ImportPlan, import_conflicts
from opsdir.core.directory import get, one, values
from opsdir.core.interchange.ldif import LdifRecord, parse
from opsdir.domains.governance.imports import import_rows, run_dn
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
ciamTitle: read the parties back
ciamChangeStatus: approved

dn: ou=owners,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: owners

dn: cn=net-team,ou=owners,dc=ciam-ops
objectClass: top
objectClass: ciamParty
cn: net-team
ciamOwnerKind: team
ciamContactUrl: https://wiki.example.test/net
"""
TEAM, SCOPE = "cn=net-team,ou=owners,dc=ciam-ops", "ou=owners,dc=ciam-ops"
AT = dt.datetime(2026, 9, 20, 3, 0, tzinfo=dt.timezone.utc)


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    ops.init(c)
    ops.load(c, parse(BASE))
    yield c
    c.close()


def _plan(conn, *mods):
    changes = (LdifRecord(TEAM, "modify", {}, mods),)
    return ImportPlan("parties/directory", changes, (), import_conflicts(db.load_directory(conn), changes),
                      (SCOPE,), AT)


def test_a_conflict_is_decided_and_the_run_recorded(conn):
    plan = _plan(conn, ("replace", "ciamContactUrl", ("https://chat.example.test/net",)),
                 ("add", "ciamDisplayName", ("Network team",)))
    (conflict,) = plan.conflicts
    assert (conflict.key, conflict.held, conflict.live) == (
        f"{TEAM}|ciamContactUrl", ("https://wiki.example.test/net",), ("https://chat.example.test/net",))
    with pytest.raises(ValueError, match="1 conflict\\(s\\) undecided"):
        ops.apply_import(conn, plan, "CHG-1")
    ops.apply_import(conn, plan, "CHG-1", keep=(conflict.key,))
    d = db.load_directory(conn)
    team = get(d, TEAM)
    assert (one(team, "ciamContactUrl"), one(team, "ciamDisplayName")) == (
        "https://wiki.example.test/net", "Network team")                   # kept; what it lacked was added
    run = get(d, run_dn("parties/directory"))
    assert (one(run, "ciamImportedAt"), values(run, "ciamChangeRef")) == (
        "20260920030000Z", ("cn=CHG-1,ou=changes,dc=ciam-ops",))
    assert import_rows(d) == [("parties/directory", "shared", 1, "20260920030000Z", "CHG-1")]
    again = _plan(conn, ("replace", "ciamContactUrl", ("https://chat.example.test/net",)))
    ops.apply_import(conn, again._replace(at=AT + dt.timedelta(days=1)), "CHG-1", take=("all",))
    d = db.load_directory(conn)
    assert one(get(d, TEAM), "ciamContactUrl") == "https://chat.example.test/net"
    assert one(get(d, run_dn("parties/directory")), "ciamImportedAt") == "20260921030000Z"


def test_an_import_with_nothing_to_change_still_records_its_run(conn):
    ops.apply_import(conn, _plan(conn)._replace(changes=()), "CHG-1")
    assert get(db.load_directory(conn), run_dn("parties/directory")) is not None


def test_a_collected_export_leaves_its_evidence_on_the_run_and_a_file_import_clears_it(conn):
    proof = {"ciamCollectionIdentity": ("arn:aws:sts::111122223333:assumed-role/reader/op",),
             "ciamCollectedCall": ("9f86d081 parties.json <- tool list-parties",),
             "ciamCollectionCredential": ("vault://kv/reader",)}
    ops.apply_import(conn, _plan(conn)._replace(changes=()), "CHG-1", evidence=proof)
    run = get(db.load_directory(conn), run_dn("parties/directory"))
    assert {a: values(run, a) for a in proof} == proof
    ops.apply_import(conn, _plan(conn)._replace(changes=()), "CHG-1")             # an export read off disk
    run = get(db.load_directory(conn), run_dn("parties/directory"))
    assert not any(values(run, a) for a in proof)


def test_runs_are_written_under_an_approved_change_only(conn):
    with pytest.raises(psycopg.Error, match="not an approved change"):
        ops.apply_import(conn, _plan(conn)._replace(changes=()), "CHG-9")


def test_the_last_change_to_entries_leaves_out_the_load_and_the_changes_named(conn):
    assert db.last_change(conn, (TEAM,)) is None                         # loaded under BOOTSTRAP only
    ops.apply_import(conn, _plan(conn, ("add", "ciamDisplayName", ("Network team",))), "CHG-1")
    when = db.last_change(conn, (TEAM, SCOPE))
    assert when is not None and db.last_change(conn, (TEAM,), ("CHG-1",)) is None
