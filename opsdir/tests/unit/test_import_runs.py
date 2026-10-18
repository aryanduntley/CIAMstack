"""Import runs are keyed by the scope set an import read: an import of another set (fewer scopes, more, others, an
ancestor) records its own run beside the earlier ones, so what an earlier import proved it read stays; the same set
again replaces its own run. Runs named the old way (importer and environment only) are renamed by an approved fix."""
import datetime as dt

import pytest

from opsdir.connectors.fixes import unmet
from opsdir.core.changeset import new_entry
from opsdir.core.directory import get, values
from opsdir.domains.governance.imports import (check_import_runs, file_evidence, import_rows, import_scope_rows,
                                               imported_files, misnamed_runs, renamed_run_records, run_dn, run_records,
                                               runs_covering, scope_set, scope_set_key)
from opsdir.domains.governance.naming import IMPORTS
from opsdir.domains.infrastructure.firewall import priority_check
from network_fixtures import ALPHA, BETA, context, model, rule

AT = dt.datetime(2026, 9, 20, 3, 0, tzinfo=dt.timezone.utc)
LATER = AT + dt.timedelta(days=1)
BINDINGS, SERVERS = f"ou=bindings,{BETA}", f"cn=ds-1,{BETA}"
FW_A, FW_B = f"cn=fw-a,{BINDINGS}", f"cn=fw-b,{BINDINGS}"
INV = "cloud/inventory"
CONTAINER = new_entry(IMPORTS, ("top", "organizationalUnit"), {"ou": ("imports",)})
CHANGES = tuple(f"dn: cn={c},ou=changes,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamChange\ncn: {c}\n"
                f"ciamTitle: import\nciamChangeStatus: approved\n" for c in ("CHG-1", "CHG-2", "CHG-3"))
RULES = (rule(BETA, "fw-a", "10.0.0.0/24", "1636", "ds") + "ciamRulePriority: 100\n",
         rule(BETA, "fw-b", "10.0.0.0/24", "1636", "ds"))


def _d(*changes):
    return model(beta=RULES, tree=CHANGES, changes=tuple(r for c in changes for r in c))[0]


def _legacy(importer, env_label, scopes, at, change, **attrs):
    cn = f"{importer.replace('/', '.')}.{env_label}"
    return new_entry(f"cn={cn},{IMPORTS}", ("top", "ciamObject", "ciamImportRun"), {
        "cn": (cn,), "ciamImporter": (importer,), "ciamImportScope": scopes, "ciamImportedAt": (at,),
        "ciamChangeRef": (f"cn={change},ou=changes,dc=ciam-ops",), **attrs})


# ------------------------------------------------------------------ identity
def test_a_scope_set_is_named_the_same_whatever_its_order_case_spacing_or_repeats():
    a, b = BINDINGS, SERVERS
    key = scope_set_key((a, b))
    assert key.startswith("s1-") and len(key) == 3 + 16
    assert scope_set_key((b, a)) == scope_set_key((a.upper(), b, a)) == scope_set_key((b.replace(",", " , "), a)) == key
    assert scope_set((b, a, a.upper())) == tuple(sorted((a.lower(), b.lower())))
    assert scope_set_key((a,)) != key and scope_set_key((a, b, f"ou=x,{BETA}")) != key
    assert run_dn(INV, (a, b)) == f"cn=cloud.inventory.beta.prod.{key},{IMPORTS}"
    assert run_dn(INV, ("ou=owners,dc=ciam-ops",)).startswith(f"cn=cloud.inventory.shared.s1-")
    with pytest.raises(ValueError, match="one environment"):
        run_dn(INV, (a, f"ou=bindings,{ALPHA}"))


def test_an_import_partitions_its_scopes_by_environment_before_naming_each_set():
    shared = "ou=owners,dc=ciam-ops"
    records = run_records(_d(), INV, (BINDINGS, f"ou=bindings,{ALPHA}", shared, BINDINGS.upper()), AT, "CHG-1")
    assert [(r.dn, r.attrs["ciamImportScope"]) for r in records[1:]] == [
        (run_dn(INV, (BINDINGS,)), (BINDINGS,)), (run_dn(INV, (f"ou=bindings,{ALPHA}",)), (f"ou=bindings,{ALPHA}",)),
        (run_dn(INV, (shared,)), (shared,))]


# ------------------------------------------------------------------ other sets keep their runs
def _covering(d, dn):
    return [(values(r, "ciamImportScope"), values(r, "ciamImportedAt")[0]) for r in runs_covering(d, dn)]


def test_a_subset_superset_or_overlap_records_its_own_run_and_the_earlier_ones_stay():
    first = run_records(_d(), INV, (BINDINGS, SERVERS), AT, "CHG-1")
    d = _d(first)
    subset = run_records(d, INV, (SERVERS,), LATER, "CHG-2")
    assert [r.changetype for r in subset] == ["add"]
    d = _d(first, subset)
    assert _covering(d, FW_A) == [((BINDINGS, SERVERS), "20260920030000Z")]      # the subset never read the rules
    assert _covering(d, SERVERS) == [((SERVERS,), "20260921030000Z"), ((BINDINGS, SERVERS), "20260920030000Z")]
    other = f"ou=hosts,{BETA}"
    overlap = run_records(d, INV, (BINDINGS, other), LATER + dt.timedelta(hours=1), "CHG-3")
    superset = run_records(d, INV, (BINDINGS, SERVERS, other), LATER + dt.timedelta(hours=1), "CHG-3")
    assert [r.changetype for r in overlap + superset] == ["add", "add"]
    assert len({r.dn for r in (*first, *subset, *overlap, *superset)} - {IMPORTS}) == 4


def test_an_ancestor_and_a_descendant_scope_each_keep_their_own_time():
    first = run_records(_d(), INV, (BETA,), AT, "CHG-1")
    narrow = run_records(_d(first), INV, (BINDINGS,), LATER, "CHG-2")
    d = _d(first, narrow)
    assert _covering(d, FW_A) == [((BINDINGS,), "20260921030000Z"), ((BETA,), "20260920030000Z")]
    assert _covering(d, SERVERS) == [((BETA,), "20260920030000Z")]


def test_a_scope_whose_export_held_nothing_stays_in_its_run():
    empty = f"ou=gone,{BETA}"                                      # everything under it was deleted by the import
    records = run_records(_d(), INV, (empty,), AT, "CHG-1")
    assert records[-1].attrs["ciamImportScope"] == (empty,)
    assert _covering(_d(records), f"cn=x,{empty}") == [((empty,), "20260920030000Z")]


def test_equal_export_times_are_ordered_by_dn():
    one_set = run_records(_d(), INV, (BINDINGS,), AT, "CHG-1")
    other = run_records(_d(one_set), "cloud/other", (BETA,), AT, "CHG-2")
    d = _d(one_set, other)
    assert [r.dn for r in runs_covering(d, FW_A)] == sorted((one_set[-1].dn, other[-1].dn), key=str.lower)


def test_evidence_is_cleared_only_on_the_run_of_the_same_set():
    proof = {"ciamCollectionIdentity": ("arn:x",), "ciamCollectedCall": ("abc f.json <- tool list",)}
    collected = run_records(_d(), INV, (BINDINGS,), AT, "CHG-1", proof)
    other = run_records(_d(collected), INV, (BINDINGS, SERVERS), AT, "CHG-2", proof)
    d = _d(collected, other)
    (again,) = run_records(d, INV, (BINDINGS,), LATER, "CHG-3")              # read off disk: no evidence
    assert again.dn == collected[-1].dn and [m for m in again.mods if m[1].startswith("ciamCollect")] == [
        ("replace", "ciamCollectionIdentity", ()), ("replace", "ciamCollectedCall", ())]
    assert get(_d(collected, other, (again,)), other[-1].dn).attrs["ciamCollectionIdentity"] == ("arn:x",)


def test_a_run_read_off_disk_records_each_file_and_its_hash_and_replaces_collected_evidence():
    files = {"b/state.json": "{}\n", "a.json": "[]"}
    evidence = file_evidence(files)
    assert evidence == {"ciamImportedFile": (
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 a.json",
        "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356 b/state.json")}
    proof = {"ciamCollectionIdentity": ("arn:x",), "ciamCollectedCall": ("abc f.json <- tool list",
                                                                         "absent g.json <- tool get")}
    collected = run_records(_d(), INV, (BINDINGS,), AT, "CHG-1", proof)
    assert imported_files(get(_d(collected), collected[-1].dn)) == {"f.json": "abc"}
    (again,) = run_records(_d(collected), INV, (BINDINGS,), LATER, "CHG-2", evidence)
    run = get(_d(collected, (again,)), collected[-1].dn)
    assert values(run, "ciamCollectedCall") == () and values(run, "ciamCollectionIdentity") == ()
    assert imported_files(run) == {"a.json": evidence["ciamImportedFile"][0].split()[0],
                                   "b/state.json": evidence["ciamImportedFile"][1].split()[0]}
    (collected_again,) = run_records(_d(collected, (again,)), INV, (BINDINGS,), LATER, "CHG-3", proof)
    assert ("replace", "ciamImportedFile", ()) in collected_again.mods


def test_two_sets_sharing_a_name_are_refused():
    forged = new_entry(run_dn(INV, (BINDINGS,)), ("top", "ciamObject", "ciamImportRun"), {
        "cn": ("x",), "ciamImporter": (INV,), "ciamImportScope": (SERVERS,), "ciamImportedAt": ("20260920030000Z",)})
    with pytest.raises(ValueError, match="another scope set"):
        run_records(_d((forged,)), INV, (BINDINGS,), AT, "CHG-1")


# ------------------------------------------------------------------ prerequisites
CHECK = priority_check(100, 10, 4096)


def _fix(d):
    alpha, beta = model(beta=RULES, tree=CHANGES)[1:]
    (fix,) = CHECK(context(d, alpha, beta)).fixes
    return fix


def test_a_partial_re_run_leaves_the_run_proving_every_entry_a_fix_needs():
    full = run_records(_d(), INV, (BINDINGS,), AT, "CHG-1")
    partial = run_records(_d(full), INV, (FW_A,), LATER, "CHG-2")              # one rule re-read later
    d = _d(full, partial)
    fix = _fix(d)
    assert fix.requires[0].entries == (FW_A, FW_B)
    assert unmet(fix, d, lambda dns, excluded: None) == ()                       # the full read still covers both
    (waits,) = unmet(fix, d, lambda dns, excluded: AT + dt.timedelta(hours=1))  # a change after the full read
    assert "last read it from an export of 20260920030000Z" in waits


# ------------------------------------------------------------------ reports
def test_the_reports_show_each_run_s_set_newest_first_within_importer_and_environment():
    first = run_records(_d(), INV, (BINDINGS, SERVERS), AT, "CHG-1")
    later = run_records(_d(first), INV, (BINDINGS,), LATER, "CHG-2")
    d = _d(first, later)
    big, small = scope_set_key((BINDINGS, SERVERS)), scope_set_key((BINDINGS,))
    assert import_rows(d) == [(INV, "beta/prod", small, 1, "20260921030000Z", "CHG-2"),
                              (INV, "beta/prod", big, 2, "20260920030000Z", "CHG-1")]
    assert import_scope_rows(d) == [(INV, "beta/prod", small, "20260921030000Z", BINDINGS),
                                    (INV, "beta/prod", big, "20260920030000Z", BINDINGS),
                                    (INV, "beta/prod", big, "20260920030000Z", SERVERS)]


# ------------------------------------------------------------------ runs named the old way
def test_an_import_of_the_same_set_retires_the_run_named_the_old_way():
    legacy = _legacy(INV, "beta.prod", (BINDINGS,), "20260919030000Z", "CHG-1")
    d = _d((CONTAINER, legacy))
    assert [(r.changetype, r.dn) for r in run_records(d, INV, (BINDINGS.upper(),), AT, "CHG-2")] == [
        ("add", run_dn(INV, (BINDINGS,))), ("delete", legacy.dn)]
    assert [r.changetype for r in run_records(d, INV, (SERVERS,), AT, "CHG-2")] == ["add"]  # another set: it stays


def test_runs_named_the_old_way_are_an_action_with_a_fix_renaming_them_as_they_were():
    proof = {"ciamCollectionIdentity": ("arn:x",)}
    legacy = _legacy(INV, "beta.prod", (BINDINGS, SERVERS), "20260919030000Z", "CHG-1", **proof)
    d = _d((CONTAINER, legacy))
    alpha, beta = model()[1:]
    found = check_import_runs(context(d, alpha, beta))
    ((area, text, owner, by),) = found.actions
    assert area == "Import runs" and by is None and owner
    assert text.startswith("Import run `cloud.inventory.beta.prod` (cloud/inventory, 2 scope(s) of beta/prod, an "
                           "export of 20260919030000Z applied under CHG-1) is still named by importer and environment")
    assert f"rename it to `{run_dn(INV, (BINDINGS, SERVERS)).split(',')[0][3:]}`" in text
    (fix,) = found.fixes
    assert fix.key == "imports/scope-set-names" and fix.risks
    added, deleted = fix.records
    assert (added.changetype, added.dn, deleted.changetype, deleted.dn) == (
        "add", run_dn(INV, (BINDINGS, SERVERS)), "delete", legacy.dn)
    assert {k: v for k, v in added.attrs.items() if k != "cn"} == {
        k: v for k, v in legacy.attrs.items() if k != "cn"}                   # time, change and evidence as they were
    renamed = _d((CONTAINER, legacy), fix.records)
    assert misnamed_runs(renamed) == () and renamed_run_records(renamed) == ()   # applied once: nothing left to do
    assert not check_import_runs(context(renamed, alpha, beta)).actions


def test_where_the_set_already_has_its_run_the_newer_export_wins():
    legacy = _legacy(INV, "beta.prod", (BINDINGS,), "20260919030000Z", "CHG-1", ciamCollectionIdentity=("arn:x",))
    newer = run_records(_d(), INV, (BINDINGS,), AT, "CHG-2")[-1:]
    assert renamed_run_records(_d((CONTAINER, legacy), newer)) == (
        type(newer[0])(legacy.dn, "delete", {}, ()),)                           # the newer run stays as it is
    older = run_records(_d(), INV, (BINDINGS,), AT - dt.timedelta(days=2), "CHG-2")[-1:]
    replaced, deleted = renamed_run_records(_d((CONTAINER, legacy), older))
    assert (replaced.dn, replaced.changetype, deleted.dn) == (older[0].dn, "modify", legacy.dn)
    assert replaced.mods == (("replace", "ciamImportScope", (BINDINGS,)),
                             ("replace", "ciamImportedAt", ("20260919030000Z",)),
                             ("replace", "ciamChangeRef", ("cn=CHG-1,ou=changes,dc=ciam-ops",)),
                             ("replace", "ciamCollectionIdentity", ("arn:x",)))
    assert misnamed_runs(_d((CONTAINER, legacy), older, (replaced, deleted))) == ()
