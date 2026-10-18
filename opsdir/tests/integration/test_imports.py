"""Imports through the store: an import that would replace what the record holds is refused until each conflict is
decided; the record's value stays where it is kept; every applied import records its run of the scope set it read, with
how its export was collected when opsdir collected it."""
import datetime as dt

import psycopg
import pytest

from opsdir import operations as ops
from opsdir.connectors.importing import ImportPlan, import_conflicts
from opsdir.core.directory import get, one, values
from opsdir.core.interchange.ldif import LdifRecord, parse
from opsdir.domains.governance.attempts import Attempt, attempt_dn, attempt_rows
from opsdir.domains.governance.imports import import_rows, misnamed_runs, renamed_run_records, run_dn, scope_set_key
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
RUN = run_dn("parties/directory", (SCOPE,))
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
    run = get(d, RUN)
    assert (one(run, "ciamImportedAt"), values(run, "ciamChangeRef")) == (
        "20260920030000Z", ("cn=CHG-1,ou=changes,dc=ciam-ops",))
    assert import_rows(d) == [("parties/directory", "shared", scope_set_key((SCOPE,)), 1, "20260920030000Z", "CHG-1")]
    again = _plan(conn, ("replace", "ciamContactUrl", ("https://chat.example.test/net",)))
    ops.apply_import(conn, again._replace(at=AT + dt.timedelta(days=1)), "CHG-1", take=("all",))
    d = db.load_directory(conn)
    assert one(get(d, TEAM), "ciamContactUrl") == "https://chat.example.test/net"
    assert one(get(d, RUN), "ciamImportedAt") == "20260921030000Z"


def test_an_import_with_nothing_to_change_still_records_its_run(conn):
    ops.apply_import(conn, _plan(conn)._replace(changes=()), "CHG-1")
    assert get(db.load_directory(conn), RUN) is not None


def test_a_collected_export_leaves_its_evidence_on_the_run_and_a_file_import_clears_it(conn):
    proof = {"ciamCollectionIdentity": ("arn:aws:sts::111122223333:assumed-role/reader/op",),
             "ciamCollectedCall": ("9f86d081 parties.json <- tool list-parties",),
             "ciamCollectionCredential": ("vault://kv/reader",)}
    ops.apply_import(conn, _plan(conn)._replace(changes=()), "CHG-1", evidence=proof)
    run = get(db.load_directory(conn), RUN)
    assert {a: values(run, a) for a in proof} == proof
    ops.apply_import(conn, _plan(conn)._replace(changes=()), "CHG-1")             # an export read off disk
    run = get(db.load_directory(conn), RUN)
    assert not any(values(run, a) for a in proof)


def test_a_failed_collection_is_recorded_then_replaced_by_the_next_attempt_and_history_keeps_both(conn):
    env = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
    failed = Attempt("gw/config", env, "incomplete",
                     ("k8s/cm (kubectl get configmap cm): exit 1: error: context was not found",),
                     {"ciamCollectionIdentity": (), "ciamCollectedCall": ("failed k8s/cm <- kubectl get configmap cm",),
                      "ciamCollectionCredential": ("vault://kv/reader",)})
    ops.record_attempts(conn, (failed,), AT, "CHG-1")
    d = db.load_directory(conn)
    assert attempt_rows(d) == [("gw/config", "alpha/prod", "incomplete", "20260920030000Z",
                                "k8s/cm (kubectl get configmap cm): exit 1: error: context was not found", "CHG-1")]
    assert values(get(d, attempt_dn("gw/config", env)), "ciamCollectionCredential") == ("vault://kv/reader",)
    assert import_rows(d) == []                                            # nothing imported, but not forgotten
    ops.record_attempts(conn, (failed._replace(outcome="complete", problems=(), evidence={}),),
                        AT + dt.timedelta(hours=1), "CHG-1")
    held = get(db.load_directory(conn), attempt_dn("gw/config", env))
    assert (one(held, "ciamCollectionOutcome"), values(held, "ciamCollectionProblem"),
            values(held, "ciamCollectedCall")) == ("complete", (), ())
    assert [row[2] for row in ops.history(conn, attempt_dn("gw/config", env)).rows] == ["insert", "update"]
    with pytest.raises(psycopg.Error, match="not an approved change"):
        ops.record_attempts(conn, (failed,), AT, "CHG-9")


def test_runs_are_written_under_an_approved_change_only(conn):
    with pytest.raises(psycopg.Error, match="not an approved change"):
        ops.apply_import(conn, _plan(conn)._replace(changes=()), "CHG-9")


def test_the_last_change_to_entries_leaves_out_the_load_and_the_changes_named(conn):
    assert db.last_change(conn, (TEAM,)) is None                         # loaded under BOOTSTRAP only
    ops.apply_import(conn, _plan(conn, ("add", "ciamDisplayName", ("Network team",))), "CHG-1")
    when = db.last_change(conn, (TEAM, SCOPE))
    assert when is not None and db.last_change(conn, (TEAM,), ("CHG-1",)) is None


LEGACY = """dn: ou=imports,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: imports

dn: cn=parties.directory.shared,ou=imports,dc=ciam-ops
objectClass: top
objectClass: ciamObject
objectClass: ciamImportRun
cn: parties.directory.shared
ciamImporter: parties/directory
ciamImportScope: ou=owners,dc=ciam-ops
ciamImportedAt: 20260919030000Z
ciamChangeRef: cn=CHG-1,ou=changes,dc=ciam-ops
"""


def test_a_run_named_the_old_way_is_renamed_under_an_approved_change_once(conn):
    ops.load(conn, parse(LEGACY))
    legacy = "cn=parties.directory.shared,ou=imports,dc=ciam-ops"
    ops.modify(conn, renamed_run_records(db.load_directory(conn)), "CHG-1")
    d = db.load_directory(conn)
    assert get(d, legacy) is None and misnamed_runs(d) == () and renamed_run_records(d) == ()
    assert (one(get(d, RUN), "ciamImportedAt"), values(get(d, RUN), "ciamChangeRef")) == (
        "20260919030000Z", ("cn=CHG-1,ou=changes,dc=ciam-ops",))                # the original time and change
    assert [row[2] for row in ops.history(conn, legacy).rows][-1] == "delete"
