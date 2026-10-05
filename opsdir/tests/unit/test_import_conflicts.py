"""Where an import and the record disagree, neither is assumed right: each value the record holds that the import
would replace or remove, and each entry it would delete, is a conflict the operator decides (take the live value or
keep the record's). What the record lacks is simply added. An applied import records when each scope it read was
last imported."""
import datetime as dt

import pytest

from opsdir.connectors.importing import ImportPlan, confirmations, decided, import_conflicts, import_records
from opsdir.core.changeset import new_entry
from opsdir.core.directory import get
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.governance.imports import (environment_of_scope, import_rows, run_dn, run_records,
                                               runs_covering)
from opsdir.domains.governance.naming import IMPORTS
from network_fixtures import ALPHA, BETA, model, rule

FW = f"cn=fw-a,ou=bindings,{BETA}"
AT = dt.datetime(2026, 9, 20, 3, 0, tzinfo=dt.timezone.utc)


def _d():
    d, _, _ = model(beta=(rule(BETA, "fw-a", ("10.0.0.0/24", "10.0.1.0/24"), "1636", "ds"),))
    return d


def _mod(*mods):
    return LdifRecord(FW, "modify", {}, tuple(mods))


def test_only_what_the_record_holds_and_would_lose_is_a_conflict():
    d = _d()
    changes = (_mod(("replace", "ciamPort", ("636",)),                                   # 1636 goes: conflict
                    ("replace", "ciamSourceCidr", ("10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24")),  # only added
                    ("delete", "ciamTargetRole", ()),                                     # removed: conflict
                    ("add", "description", ("rule a",)),                                  # the record lacks it
                    ("replace", "objectClass", ("top", "ciamFirewallRule", "ciamObject"))),
               LdifRecord(f"cn=subnet-ds,ou=bindings,{BETA}", "delete", {}, ()),
               LdifRecord(f"cn=nothing,ou=bindings,{BETA}", "modify", {}, (("replace", "ciamPort", ("1",)),)),
               new_entry(f"cn=fw-b,ou=bindings,{BETA}", ("top", "ciamFirewallRule"), {"cn": ("fw-b",)}))
    assert [(c.key, c.attr, c.held, c.live) for c in import_conflicts(d, changes)] == [
        (f"{FW}|ciamPort", "ciamPort", ("1636",), ("636",)),
        (f"{FW}|ciamTargetRole", "ciamTargetRole", ("ds",), ()),
        (f"cn=subnet-ds,ou=bindings,{BETA}", None, ("the entry",), ())]


def test_every_conflict_is_decided_before_anything_applies():
    d = _d()
    changes = (_mod(("replace", "ciamPort", ("636",)), ("delete", "ciamTargetRole", ())),
               LdifRecord(f"cn=subnet-ds,ou=bindings,{BETA}", "delete", {}, ()))
    conflicts = import_conflicts(d, changes)
    port, role, subnet = (c.key for c in conflicts)
    with pytest.raises(ValueError, match="3 conflict\\(s\\) undecided"):
        decided(changes, conflicts)
    with pytest.raises(ValueError, match="no conflict nope"):
        decided(changes, conflicts, take=("nope",), keep=("all",))
    with pytest.raises(ValueError, match="taken and kept"):
        decided(changes, conflicts, take=(port,), keep=("all",))
    assert decided(changes, conflicts, take=("all",)) == changes
    assert decided(changes, conflicts, keep=("all",)) == ()                      # the record wins everywhere
    assert decided(changes, conflicts, take=(port, subnet), keep=(role,)) == (
        _mod(("replace", "ciamPort", ("636",))), changes[1])


def test_an_applied_import_records_its_run_of_each_environment_it_read():
    d = _d()
    bindings, servers, shared = f"ou=bindings,{BETA}", f"cn=ds-1,{BETA}", "ou=owners,dc=ciam-ops"
    first = run_records(d, "cloud/inventory", (bindings, servers, bindings, shared), AT, "CHG-1")
    assert [(r.changetype, r.dn) for r in first] == [
        ("add", IMPORTS), ("add", f"cn=cloud.inventory.beta.prod,{IMPORTS}"),
        ("add", f"cn=cloud.inventory.shared,{IMPORTS}")]
    assert (first[1].attrs["ciamImportScope"], first[1].attrs["ciamImportedAt"], first[1].attrs["ciamChangeRef"]) == (
        (bindings, servers), ("20260920030000Z",), ("cn=CHG-1,ou=changes,dc=ciam-ops",))
    d, _, _ = model(beta=(rule(BETA, "fw-a", "10.0.0.0/24", "1636", "ds"),),
                    tree=(f"dn: cn=CHG-1,ou=changes,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamChange\n"
                          "cn: CHG-1\nciamTitle: import\nciamChangeStatus: approved\n",), changes=first)
    assert import_rows(d) == [("cloud/inventory", "beta/prod", 2, "20260920030000Z", "CHG-1"),
                              ("cloud/inventory", "shared", 1, "20260920030000Z", "CHG-1")]
    assert [r.dn for r in runs_covering(d, FW)] == [run_dn("cloud/inventory", BETA)]
    assert runs_covering(d, f"cn=x,ou=bindings,{ALPHA}") == ()
    later = run_records(d, "cloud/inventory", (bindings,), AT + dt.timedelta(days=1), "CHG-2")
    assert later == (LdifRecord(run_dn("cloud/inventory", BETA), "modify", {}, (
        ("replace", "ciamImportScope", (bindings,)), ("replace", "ciamImportedAt", ("20260921030000Z",)),
        ("replace", "ciamChangeRef", ("cn=CHG-2,ou=changes,dc=ciam-ops",)))),)


def test_scopes_name_their_environment():
    assert environment_of_scope(f"ou=bindings,{BETA}") == BETA
    assert environment_of_scope(BETA) == BETA
    assert environment_of_scope("ou=data-stores,ou=pingfederate,dc=ciam-ops") is None


def test_the_records_an_import_applies():
    d = _d()
    changes = (_mod(("replace", "ciamPort", ("636",))),)
    plan = ImportPlan("cloud/inventory", changes, (), import_conflicts(d, changes), (f"ou=bindings,{BETA}",), AT)
    with pytest.raises(ValueError, match="undecided"):
        import_records(d, plan, "CHG-1")
    records = import_records(d, plan, "CHG-1", keep=("all",))
    assert [r.dn for r in records] == [IMPORTS, run_dn("cloud/inventory", BETA)]
    assert get(d, IMPORTS) is None


def test_an_import_by_the_adapter_named_confirms_what_was_set_ahead_of_it():
    d, _, _ = model(beta=(rule(BETA, "fw-a", "10.0.0.0/24", "1636", "ds") + "ciamVerifyPending: ciamPort cloud\n"
                          "ciamVerifyPending: ciamTargetRole other\nciamVerifyPending: ciamSourceCidr\n",))
    plan = ImportPlan("cloud/inventory", (), (), (), (f"ou=bindings,{BETA}",), AT)
    (cleared,) = confirmations(d, plan)
    assert cleared.mods == (("delete", "ciamVerifyPending", ("ciamPort cloud", "ciamSourceCidr")),)
    changes = (_mod(("replace", "ciamPort", ("636",))),)
    differing = plan._replace(changes=changes, conflicts=import_conflicts(d, changes))
    (kept,) = confirmations(d, differing, keep=("all",))                   # the record's port kept: still pending
    assert kept.mods == (("delete", "ciamVerifyPending", ("ciamSourceCidr",)),)
    assert confirmations(d, plan._replace(scopes=(f"ou=bindings,{ALPHA}",))) == ()
