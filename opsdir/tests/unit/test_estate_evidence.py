"""Compliance evidence (core estate, connectors.evidence): which controls a boundary's package covers (customer or
shared under its environments' authorizations, named by a query), how outputs are cut to the boundary and laid out, the
manifest and the recorded run, the evidence report; the planner check (no query, an unknown report, no or an old
package, evidence that changes between source and target); the package over the store, the operation and the command."""
import datetime as dt
import json

import pytest

from opsdir import cli, operations as ops
from opsdir.connectors import evidence as connector
from opsdir.core.contract import directory_report, sql_report
from opsdir.core.directory import get, rdn_value, subtree, values
from opsdir.core.environment import environment_of
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.core.naming import SUFFIX, env_label
from opsdir.domains.estate.evidence import (boundary_labels, boundary_named, collected_at, control_folder,
                                            controls_covered, due, evidence_queries, evidence_rows, last_run, manifest,
                                            package_files, package_plan, queries_for, run_records, scoped_rows,
                                            search_table, sha256, table_csv, table_json)
from network_fixtures import ALPHA, BETA, context, model
from support import applied

OU = "dn: ou={0},dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: {0}\n"
AUTH = "ou=authorizations,dc=ciam-ops"
QUERIES = "ou=evidence-queries,dc=ciam-ops"
SSP = "cn=ssp,ou=boundaries,dc=ciam-ops"
AS_OF = dt.date(2026, 10, 1)


def _ldif(dn, classes, attrs):
    lines = "".join(f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,)) if v)
    return f"dn: {dn}\nobjectClass: top\n" + "".join(f"objectClass: {c}\n" for c in classes) + lines


def authorization(cn):
    return _ldif(f"cn={cn},{AUTH}", ("ciamCloudAuthorization",), {"cn": cn, "ciamPackageId": cn,
                                                                   "ciamAuthorizationLevel": "fedramp-high",
                                                                   "ciamAuthorizationStatus": "certified"})


def responsibility(cn, auth, control, who):
    return _ldif(f"cn={cn},ou=responsibilities,dc=ciam-ops", ("ciamControlResponsibility",),
                 {"cn": cn, "ciamAuthorizationRef": f"cn={auth},{AUTH}", "ciamControlRef": control,
                  "ciamResponsibility": who, "ciamImplementation": "done"})


def query(cn, controls, source, dn=None, cadence=None, **more):
    return _ldif(f"cn={cn},{QUERIES}", ("ciamEvidenceQuery",),
                 {"cn": cn, "ciamControlRef": tuple(controls), "ciamEvidenceSource": source, "ciamEvidenceDn": dn,
                  "ciamEvidenceCadenceDays": str(cadence) if cadence else None, **more})


def relies(env, auth):
    return LdifRecord(env, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                          ("replace", "ciamAuthorizationRef", (f"cn={auth},{AUTH}",))))


def boundary(*envs):
    return _ldif(SSP, ("ciamSystemBoundary",), {"cn": "ssp", "ciamSspRef": "SSP v1", "ciamAffectedEnvironment": envs})


TREE = (OU.format("authorizations"), OU.format("responsibilities"), OU.format("boundaries"),
        OU.format("evidence-queries"), authorization("SRC"), authorization("DST"),
        responsibility("dst-ac-2", "DST", "nist:AC-2", "customer"),
        responsibility("dst-au-2", "DST", "nist:AU-2", "shared"),
        responsibility("dst-sc-12", "DST", "nist:SC-12", "inherited"),
        responsibility("dst-ia-2", "DST", "nist:IA-2", "customer"),
        responsibility("src-ac-2", "SRC", "nist:AC-2", "customer"))


def subnets(d, dn=None):
    """A report with an environment column: each environment's subnets."""
    return [(env_label(environment_of(e)), rdn_value(e)) for e in subtree(d, SUFFIX, "ciamSubnetBinding")]


def networks(d, dn=None):
    """A report without one."""
    return [(e.dn,) for e in subtree(d, SUFFIX, "ciamNetwork")]


REPORTS = {"subnets": directory_report(("environment", "subnet"), subnets),
           "networks": directory_report(("dn",), networks), "rows": sql_report(("a",), "select 1")}


def _estate(queries=(), tree=(), changes=(), beta=()):
    d, a, b = model(tree=(*TREE, *queries, *tree), beta=beta,
                    changes=(relies(ALPHA, "SRC"), relies(BETA, "DST"), *changes))
    return d, a, b


@pytest.fixture
def reports(monkeypatch):
    monkeypatch.setattr(connector, "catalogue", lambda: REPORTS)
    return REPORTS


# ------------------------------------------------------------------ the estate's part (pure)
def test_a_package_covers_the_customer_and_shared_controls_some_query_names():
    d, _, _ = _estate((query("q-subnets", ("nist:AC-2", "nist:AU-2"), "subnets"),
                       query("q-sc-12", ("nist:SC-12",), "networks")), (boundary(BETA),))
    assert list(controls_covered(d, (BETA,))) == ["nist:AC-2", "nist:AU-2", "nist:IA-2"]
    assert [rdn_value(q) for q in queries_for(d, "nist:AU-2")] == ["q-subnets"]
    b = boundary_named(d, "ssp")
    assert b is boundary_named(d, SSP) and boundary_named(d, "nope") is None and boundary_labels(b) == ("beta/prod",)
    assert [(c, [rdn_value(q) for q in qs]) for c, qs in package_plan(d, b)] == [
        ("nist:AC-2", ["q-subnets"]), ("nist:AU-2", ["q-subnets"])]     # SC-12 inherited, IA-2 named by none
    assert [c for c, _ in package_plan(d, b, ("nist:AU-2",))] == ["nist:AU-2"]
    assert control_folder("nist-800-53-r5:AC-2") == "nist-800-53-r5_AC-2"


def test_outputs_are_cut_to_the_boundary_and_written_as_csv_and_json():
    rows = (("alpha/prod", "a"), ("beta/prod", "b"))
    assert scoped_rows(("environment", "x"), rows, ("beta/prod",)) == (("beta/prod", "b"),)
    assert scoped_rows(("dn", "x"), rows, ("beta/prod",)) == rows
    assert table_csv(("a", "b"), ((1, None), ("x,y", dt.date(2026, 1, 2)))) == 'a,b\n1,\n"x,y",2026-01-02\n'
    assert json.loads(table_json(("a",), ((dt.date(2026, 1, 2),), (None,)))) == {"headers": ["a"],
                                                                                 "rows": [["2026-01-02"], [None]]}


def test_a_search_query_shows_the_dn_and_the_attributes_it_names():
    d, _, _ = _estate((query("q-search", ("nist:CM-3",), "search", dn=f"ou=bindings,{BETA}",
                             ciamEvidenceFilter="(objectClass=ciamNetwork)",
                             ciamEvidenceAttribute=("ciamCidr", "ciamBindingRole")),))
    assert search_table(d, evidence_queries(d)[0]) == (("dn", "ciamCidr", "ciamBindingRole"),
                                                       ((f"cn=net,ou=bindings,{BETA}", "10.1.0.0/16", "network"),))


def test_the_manifest_and_the_recorded_run_hash_every_file():
    d, _, _ = _estate((query("q-subnets", ("nist:AC-2",), "subnets", cadence=30),), (boundary(BETA),))
    b = boundary_named(d, "ssp")
    plan = package_plan(d, b)
    q = plan[0][1][0]
    files = package_files(plan, {q.dn: (("environment", "subnet"), (("beta/prod", "subnet-ds"),))})
    assert sorted(files) == ["nist_AC-2/q-subnets.csv", "nist_AC-2/q-subnets.json"]
    doc = json.loads(manifest(b, AS_OF, {"change": "CHG-9", "entry": 4}, plan, files))
    assert doc == {"boundary": SSP, "as_of": "2026-10-01", "history_point": {"change": "CHG-9", "entry": 4},
                   "controls": [{"control": "nist:AC-2", "queries": [
                       {"query": "q-subnets", "source": "subnets", "dn": None,
                        "files": {p: sha256(files[p]) for p in sorted(files)}}]}]}
    assert last_run(d, b) is None
    (add,) = run_records(d, b, AS_OF, files, plan, "CHG-9", "https://evidence.example.test/ssp")
    assert add.changetype == "add" and add.dn == f"cn=evidence,{SSP}" and add.attrs["ciamEvidenceAt"] == (
        "20261001000000Z",) and add.attrs["ciamEvidenceOutput"] == tuple(f"{p} {sha256(files[p])}"
                                                                           for p in sorted(files))
    assert add.attrs["ciamEvidenceQueryRef"] == (q.dn,) and add.attrs["ciamChangeRef"] == (
        "cn=CHG-9,ou=changes,dc=ciam-ops",)
    ran = applied(d, (add,))
    run = last_run(ran, boundary_named(ran, "ssp"))
    assert collected_at(run) == AS_OF and due(AS_OF, 30) == dt.date(2026, 10, 31) and due(None, 30) is None
    (mod,) = run_records(ran, boundary_named(ran, "ssp"), dt.date(2026, 11, 2), files, plan, "CHG-10")
    assert mod.changetype == "modify" and ("replace", "ciamEvidenceRef", ()) in mod.mods  # kept-at cleared
    assert ("replace", "ciamEvidenceAt", ("20261102000000Z",)) in mod.mods


def test_the_evidence_report_says_when_each_query_was_last_collected():
    d, _, _ = _estate((query("q-subnets", ("nist:AC-2", "nist:AU-2"), "subnets", cadence=30,
                             ciamManagedBy="cn=ssp,ou=boundaries,dc=ciam-ops"),
                       query("q-networks", ("nist:AC-2",), "networks")), (boundary(BETA),))
    assert evidence_rows(d, None, AS_OF) == [
        ("nist:AC-2", "q-networks", "networks", "", "", "", "", "never collected"),
        ("nist:AC-2", "q-subnets", "subnets", "", "30", "ssp", "", "never collected"),
        ("nist:AU-2", "q-subnets", "subnets", "", "30", "ssp", "", "never collected")]
    b = boundary_named(d, "ssp")
    plan = package_plan(d, b)
    ran = applied(d, run_records(d, b, dt.date(2026, 8, 1), {"x": "y"}, plan, "CHG-9"))
    assert [r[6:] for r in evidence_rows(ran, None, AS_OF)] == [
        ("ssp 2026-08-01", "current"), ("ssp 2026-08-01", "due since 2026-08-31"),
        ("ssp 2026-08-01", "due since 2026-08-31")]


# ------------------------------------------------------------------ the planner's check
def _check(d, a, b):
    return connector.evidence_check()(context(d, a, b, cutover="2026-12-01"))


def test_nothing_without_queries_or_controls_to_show(reports):
    d, a, b = model()
    assert _check(d, a, b) == connector.findings()


def test_a_control_no_query_shows_and_an_unknown_report_are_found(reports):
    d, a, b = _estate((query("q-subnets", ("nist:AC-2", "nist:AU-2"), "subnets"),
                       query("q-typo", ("nist:AC-2",), "subnet")))
    f = _check(d, a, b)
    assert [x[1] for x in f.blockers] == [
        "Evidence query `q-typo` runs `subnet`, which is no report of the catalogue: name an `opsdir report` report, "
        "`history` or `search`."]
    assert [x[1] for x in f.actions] == [
        "Control `nist:IA-2` is the operator's (customer) under `DST`, which beta/prod relies on, and no evidence "
        "query shows it met: record one (ciamEvidenceQuery under ou=evidence-queries)."]
    assert f.actions[0][2:] == ("**NO OWNER**", "2026-12-01")
    assert list(f.ok) == ["Evidence not compared between alpha/prod and beta/prod (history, searches, and reports "
                          "without an environment column): `q-typo`."]


def test_evidence_that_changes_between_source_and_target_is_collected_again(reports):
    extra = ("dn: cn=subnet-extra,ou=bindings,env=prod,cloud=beta,ou=environments,dc=ciam-ops\nobjectClass: top\n"
             "objectClass: ciamSubnetBinding\ncn: subnet-extra\nciamBindingRole: subnet-extra\n"
             "ciamCidr: 10.1.9.0/24\n",)
    qs = (query("q-subnets", ("nist:AC-2", "nist:AU-2"), "subnets"), query("q-networks", ("nist:AC-2",), "networks"),
          query("q-rows", ("nist:AU-2",), "rows"), query("q-history", ("nist:IA-2",), "history"))
    d, a, b = _estate(qs)
    assert [x[1] for x in _check(d, a, b).actions] == []            # the same subnets on both sides
    d, a, b = _estate(qs, beta=extra)
    f = _check(d, a, b)
    assert [x[1] for x in f.actions] == [
        f"Control `nist:{c}`: its evidence changes in beta/prod (`q-subnets`): collect it again there after the "
        "cutover (`opsdir evidence`)." for c in ("AC-2", "AU-2")]
    assert list(f.ok) == ["Evidence not compared between alpha/prod and beta/prod (history, searches, and reports "
                          "without an environment column): `q-history`, `q-networks`, `q-rows`."]


def test_the_targets_boundary_without_a_package_or_with_an_old_one_is_an_action(reports):
    qs = (query("q-subnets", ("nist:AC-2", "nist:AU-2", "nist:IA-2"), "subnets", cadence=30),
          query("q-networks", ("nist:AC-2",), "networks", cadence=90))
    d, a, b = _estate(qs, (boundary(ALPHA),))
    assert _check(d, a, b).actions == ()                            # the target is in no boundary
    d, a, b = _estate(qs, (boundary(ALPHA, BETA),))
    assert [x[1] for x in _check(d, a, b).actions] == [
        "Boundary `ssp` (beta/prod is inside it) has no recorded evidence package: take one "
        "(`opsdir evidence --boundary ssp --change ...`)."]
    bd = boundary_named(d, "ssp")
    for taken, found in ((dt.date(2026, 9, 15), []), (dt.date(2026, 8, 1), [
            "Boundary `ssp`'s evidence was taken on 2026-08-01, past its queries' 30-day cadence (due 2026-08-31): "
            "take it again."])):
        ran = applied(d, run_records(d, bd, taken, {"x": "y"}, package_plan(d, bd), "CHG-9"))
        ctx = context(ran, a._replace(d=ran), b._replace(d=ran), cutover="2026-12-01")
        assert [x[1] for x in connector.evidence_check()(ctx).actions] == found


# ------------------------------------------------------------------ over the store: the package, the operation, the CLI
HISTORY = [(dt.datetime(2026, 9, 1, 12), "CHG-1", "modify", BETA), (dt.datetime(2026, 9, 2, 12), "CHG-2", "add", SSP)]


@pytest.fixture
def store(monkeypatch, reports):
    """A store faked over a directory: reports run on it, the history is HISTORY, applied records are kept."""
    state = {}
    monkeypatch.setattr(connector, "run_report",
                        lambda conn, report, dn=None, as_of=None: report.from_directory(state["d"], dn))
    monkeypatch.setattr(connector, "fetch_history",
                        lambda conn, dn=None: [r for r in HISTORY if dn is None or r[3] == dn])
    monkeypatch.setattr(ops.db, "load_directory", lambda conn: state["d"])
    monkeypatch.setattr(ops.db, "apply_records",
                        lambda conn, records, change_id, sync: state.setdefault("applied", []).extend(records) or
                        [f"{r.changetype} {r.dn}" for r in records])
    return state


def test_the_package_runs_each_query_cut_to_the_boundary(store):
    d, _, _ = _estate((query("q-subnets", ("nist:AC-2",), "subnets"), query("q-history", ("nist:AU-2",), "history"),
                       query("q-search", ("nist:AU-2",), "search", dn=f"ou=bindings,{BETA}",
                             ciamEvidenceFilter="(objectClass=ciamNetwork)", ciamEvidenceAttribute="ciamCidr")),
                      (boundary(BETA),))
    store["d"] = d
    p = connector.evidence_package(None, d, boundary_named(d, "ssp"), (), AS_OF)
    assert sorted(p.files) == [f"nist_{c}/{q}.{k}" for c, q in (("AC-2", "q-subnets"), ("AU-2", "q-history"),
                                                                 ("AU-2", "q-search")) for k in ("csv", "json")]
    assert p.files["nist_AC-2/q-subnets.csv"] == "environment,subnet\nbeta/prod,subnet-ds\nbeta/prod,subnet-web\n"
    assert p.files["nist_AU-2/q-history.csv"].splitlines() == [
        "at,change,op,dn", f'2026-09-01 12:00:00,CHG-1,modify,"{BETA}"', f'2026-09-02 12:00:00,CHG-2,add,"{SSP}"']
    assert p.files["nist_AU-2/q-search.csv"] == f'dn,ciamCidr\n"cn=net,ou=bindings,{BETA}",10.1.0.0/16\n'
    assert p.history_point == {"change": "CHG-2", "entry": 2}
    assert json.loads(p.manifest)["history_point"] == p.history_point


def test_a_package_with_a_query_naming_no_report_is_refused(store):
    d, _, _ = _estate((query("q-typo", ("nist:AC-2",), "subnet"),), (boundary(BETA),))
    with pytest.raises(ValueError, match="evidence queries naming no report: q-typo"):
        connector.evidence_package(None, d, boundary_named(d, "ssp"), (), AS_OF)


def test_the_operation_records_the_run_only_under_a_change(store):
    d, _, _ = _estate((query("q-subnets", ("nist:AC-2",), "subnets"),), (boundary(BETA),))
    store["d"] = d
    r = ops.evidence(None, "ssp", AS_OF)
    assert r.boundary == SSP and r.applied is None and "MANIFEST.json" in r.files and "applied" not in store
    r = ops.evidence(None, SSP, AS_OF, ("nist:AC-2",), "CHG-9", "https://evidence.example.test/ssp")
    (run,) = store["applied"]
    assert r.applied.lines == (f"add cn=evidence,{SSP}",) and values(get(applied(d, (run,)), run.dn),
                                                                         "ciamEvidenceRef") == (
        "https://evidence.example.test/ssp",)
    assert {o.split(" ")[0] for o in run.attrs["ciamEvidenceOutput"]} == set(r.files)
    with pytest.raises(ValueError, match="no system boundary nope"):
        ops.evidence(None, "nope", AS_OF)


def test_the_command_writes_the_package(store, tmp_path, monkeypatch):
    d, _, _ = _estate((query("q-subnets", ("nist:AC-2",), "subnets"),), (boundary(BETA),))
    store["d"] = d
    a = cli.parser().parse_args(["evidence", "--boundary", "ssp", "-o", str(tmp_path), "--change", "CHG-9"])
    text = cli.COMMANDS["evidence"](None, a, AS_OF)
    assert text.splitlines() == [f"evidence of {SSP} as of 2026-10-01: 2 files and MANIFEST.json → {tmp_path}",
                                 f"CHG-9: add cn=evidence,{SSP}"]
    assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*") if p.is_file()) == [
        "MANIFEST.json", "nist_AC-2/q-subnets.csv", "nist_AC-2/q-subnets.json"]
    a = cli.parser().parse_args(["evidence", "--boundary", "nope", "-o", str(tmp_path)])
    with pytest.raises(SystemExit, match="no system boundary nope"):
        cli.COMMANDS["evidence"](None, a, AS_OF)


def test_the_directory_alone_answers_directory_reports_and_searches(reports):
    d, _, _ = _estate((query("q-subnets", ("nist:AC-2",), "subnets"), query("q-history", ("nist:AU-2",), "history"),
                       query("q-rows", ("nist:AU-2",), "rows"),
                       query("q-search", ("nist:AU-2",), "search", dn=f"ou=bindings,{BETA}",
                             ciamEvidenceFilter="(objectClass=ciamNetwork)", ciamEvidenceAttribute="ciamCidr")),
                      (boundary(BETA),))
    by_name = {rdn_value(q): q for q in evidence_queries(d)}
    assert connector.directory_output(d, by_name["q-subnets"], AS_OF, reports)[1][0] == ("alpha/prod", "subnet-ds")
    assert connector.directory_output(d, by_name["q-search"], AS_OF, reports)[0] == ("dn", "ciamCidr")
    assert [connector.directory_output(d, by_name[n], AS_OF, reports) for n in ("q-history", "q-rows")] == [None, None]
    asked = []
    p = connector.assemble_package(d, boundary_named(d, "ssp"), ("nist:AC-2",), AS_OF,
                                   lambda q: asked.append(rdn_value(q)) or (("environment", "subnet"), ()), None,
                                   reports)
    assert asked == ["q-subnets"] and p.history_point is None and json.loads(p.manifest)["history_point"] is None
