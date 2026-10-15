"""The OSCAL readers: a document opsdir wrote read back changes nothing; another tool's POA&M items and assessment
results go in the document's own container, matched again on the next import and dropped when the document drops them,
while record-owned items are merged in place and never deleted; the estate's reports and checks see the containers'
items; a POA&M naming no boundary is refused; other versions and files are named; a catalog is checked, not imported."""
import json

import pytest

from opsdir.connectors.importing import import_changes
from opsdir.core.contract import SecretPattern
from opsdir.core.directory import get, one, values
from opsdir.core.environment import env_model
from opsdir.domains.estate.poam import assessment_rows, check_poam, poam_rows
from opsdir_format_oscal.adapter import render_oscal
from opsdir_format_oscal.common import NS
from opsdir_format_oscal.readers import read_assessment_results, read_catalog, read_poam
from network_fixtures import context
from support import after_import

ITEM_UUID = "11111111-1111-4111-8111-111111111111"
RISK_UUID = "22222222-2222-4222-8222-222222222222"
RESULT_UUID = "33333333-3333-4333-8333-333333333333"
FINDING_UUID = "44444444-4444-4444-8444-444444444444"
CONTAINER = "ou=oscal-poam-ssp-enclave-v2,ou=poam,dc=ciam-ops"


def _meta(version="1.2.3"):
    return {"title": "x", "last-modified": "2026-10-01T00:00:00Z", "version": "1", "oscal-version": version}


def _poam(items, risks=(), system="SSP-ENCLAVE v2", version="1.2.3"):
    return json.dumps({"plan-of-action-and-milestones": {
        "uuid": "55555555-5555-4555-8555-555555555555", "metadata": _meta(version),
        "system-id": {"identifier-type": "x", "id": system}, "risks": list(risks), "poam-items": list(items)}})


def _foreign_item(description="Audit logs not reviewed weekly", status="open"):
    item = {"uuid": ITEM_UUID, "title": "AU-6 gap", "description": description,
            "props": [{"name": "control", "ns": NS, "value": "nist-800-53-r5:AU-6"}],
            "related-risks": [{"risk-uuid": RISK_UUID}]}
    risk = {"uuid": RISK_UUID, "title": "AU-6", "description": "x", "statement": "x", "status": status,
            "deadline": "2027-03-01T00:00:00Z"}
    return item, risk


def test_reading_back_what_opsdir_wrote_changes_nothing(oscal_record):
    d = oscal_record.d
    files = render_oscal(d)
    poam = read_poam({"poam.json": files["oscal/enclave/poam.json"]}, d, ())
    ar = read_assessment_results({"ar.json": files["oscal/assessment-results-cmmc-2026.json"]}, d, ())
    assert import_changes(d, poam) == () and import_changes(d, ar) == ()
    assert "2 deviation risk(s) not imported" in poam.notices[-1]


def test_another_tools_items_go_in_the_documents_container_and_record_items_stay(oscal_record):
    d = oscal_record.d
    item, risk = _foreign_item()
    after = after_import(d, read_poam({"p.json": _poam((item,), (risk,))}, d, ()))
    made = get(after, f"cn=oscal-{ITEM_UUID},{CONTAINER}")
    assert one(made, "ciamWeakness") == "Audit logs not reviewed weekly" and one(made, "ciamPoamStatus") == "open"
    assert values(made, "ciamControlRef") == ("nist-800-53-r5:AU-6",)
    assert sorted(values(made, "ciamAffectedEnvironment")) == sorted((oscal_record.ALPHA, oscal_record.BETA))
    assert one(made, "ciamFindingRef") == f"oscal:poam-item:{ITEM_UUID}"
    assert one(made, "ciamScheduledCompletion") == "20270301000000Z"
    assert get(after, f"cn=keys-fips,{oscal_record.POAM}") is not None           # record-owned: never deleted
    again = read_poam({"p.json": _poam((item,), (risk,))}, after, ())
    assert import_changes(after, again) == ()                                    # matched again: nothing changes
    closed = after_import(after, read_poam({"p.json": _poam(*map(lambda x: (x,), _foreign_item(status="closed")))},
                                           after, ()))
    assert one(get(closed, f"cn=oscal-{ITEM_UUID},{CONTAINER}"), "ciamPoamStatus") == "closed"
    dropped = after_import(after, read_poam({"p.json": _poam(())}, after, ()))
    assert get(dropped, f"cn=oscal-{ITEM_UUID},{CONTAINER}") is None and get(dropped, CONTAINER) is not None
    assert get(dropped, f"cn=keys-fips,{oscal_record.POAM}") is not None


def test_a_record_item_is_merged_in_place_keeping_what_the_document_doesnt_state(oscal_record):
    d = oscal_record.d
    poam = json.loads(render_oscal(d)["oscal/enclave/poam.json"])
    doc = poam["plan-of-action-and-milestones"]
    next(r for r in doc["risks"] if r["title"] == "keys-fips")["status"] = "closed"
    item = next(i for i in doc["poam-items"] if i["title"] == "keys-fips")
    item["props"] = [p for p in item["props"] if p["name"] in ("record-dn",)]       # another tool kept only its id
    after = after_import(d, read_poam({"p.json": json.dumps(poam)}, d, ()))
    keys = get(after, f"cn=keys-fips,{oscal_record.POAM}")
    assert one(keys, "ciamPoamStatus") == "closed"
    assert one(keys, "ciamPointValue") == "3" and one(keys, "ciamAssessmentRef") == "cmmc-2026"    # kept
    assert values(keys, "ciamAffectedEnvironment") == (oscal_record.BETA,)


def test_the_estates_reports_and_check_see_items_in_the_containers(oscal_record):
    d = oscal_record.d
    item, risk = _foreign_item()
    result = {"uuid": RESULT_UUID, "title": "Annual assessment", "description": "x", "start": "2026-09-01T00:00:00Z",
              "props": [{"name": "framework", "ns": NS, "value": "nist-800-171-r2"},
                        {"name": "assessment-kind", "ns": NS, "value": "self"},
                        {"name": "environment", "ns": NS, "value": oscal_record.BETA}],
              "reviewed-controls": {"control-selections": [{"include-all": {}}]},
              "findings": [{"uuid": FINDING_UUID, "title": "Session lock", "description": "No session lock",
                            "target": {"type": "objective-id", "target-id": "_3.1.10",
                                       "status": {"state": "not-satisfied"}}},
                           {"uuid": ITEM_UUID, "title": "ok", "description": "x",
                            "target": {"type": "objective-id", "target-id": "_3.1.1",
                                       "status": {"state": "satisfied"}}}]}
    ar = json.dumps({"assessment-results": {"uuid": "66666666-6666-4666-8666-666666666666", "metadata": _meta(),
                                            "import-ap": {"href": "#"}, "results": [result]}})
    after = after_import(d, read_poam({"p.json": _poam((item,), (risk,))}, d, ()))
    after = after_import(after, read_assessment_results({"ar.json": ar}, after, ()))
    session = get(after, f"cn=oscal-{FINDING_UUID},ou=oscal-ar-66666666-6666-4666-8666-666666666666,ou=poam,"
                         "dc=ciam-ops")
    assert values(session, "ciamControlRef") == ("nist-800-171-r2:3.1.10",)
    assert one(session, "ciamAssessmentRef") == f"oscal-{RESULT_UUID}"
    rows = {r[0] for r in poam_rows(after)}
    assert {f"oscal-{ITEM_UUID}", f"oscal-{FINDING_UUID}", "keys-fips"} <= rows
    assert f"oscal-{RESULT_UUID}" in {r[0] for r in assessment_rows(after)}
    found = check_poam(context(after, env_model(after, "alpha/prod"), env_model(after, "beta/prod")))
    assert any(f"oscal-{FINDING_UUID}" in a[1] for a in found.actions)


def test_a_result_without_framework_records_no_assessment_but_its_findings(oscal_record):
    d = oscal_record.d
    result = {"uuid": RESULT_UUID, "title": "Scan", "description": "x", "start": "2026-09-01T00:00:00Z",
              "props": [{"name": "environment", "ns": NS, "value": oscal_record.BETA}],
              "reviewed-controls": {"control-selections": [{"include-all": {}}]},
              "findings": [{"uuid": FINDING_UUID, "title": "Weak TLS", "description": "TLS 1.0 enabled",
                            "target": {"type": "objective-id", "target-id": "sc-8", "status": {"state":
                                                                                              "not-satisfied"}}}]}
    ar = json.dumps({"assessment-results": {"uuid": "77777777-7777-4777-8777-777777777777", "metadata": _meta(),
                                            "import-ap": {"href": "#"}, "results": [result]}})
    imported = read_assessment_results({"ar.json": ar}, d, ())
    after = after_import(d, imported)
    assert not [a for a in after.entries.values() if "oscal-ar-7777" in a.dn and "ciamComplianceAssessment"
                in a.classes]
    item = get(after, f"cn=oscal-{FINDING_UUID},ou=oscal-ar-77777777-7777-4777-8777-777777777777,ou=poam,dc=ciam-ops")
    assert one(item, "ciamAssessmentRef") == f"oscal:result:{RESULT_UUID}" and not values(item, "ciamControlRef")
    assert "no framework and assessment kind stated" in imported.notices[0]


def test_a_poam_naming_no_boundary_is_refused_and_other_files_are_named(oscal_record):
    d = oscal_record.d
    with pytest.raises(SystemExit, match="system-id SSP-OTHER names no system boundary"):
        read_poam({"p.json": _poam((), system="SSP-OTHER")}, d, ())
    with pytest.raises(SystemExit, match="no OSCAL 1.x plan of action"):
        read_poam({"p.json": _poam((), version="2.0.0"), "x.txt": "hi"}, d, ())
    imported = read_poam({"p.json": _poam(()), "x.txt": "hi"}, d, ())
    assert imported.notices[-1] == "x.txt: not an OSCAL plan of action and milestones; not read"


def test_values_that_look_like_secrets_are_withheld(oscal_record):
    d = oscal_record.d
    item, risk = _foreign_item(description="password is AKIAABCDEFGHIJKLMNOP")
    pattern = SecretPattern("aws-key", r"AKIA[0-9A-Z]{16}", "an AWS access key")
    imported = read_poam({"p.json": _poam((item,), (risk,))}, d, (pattern,))
    assert any("ciamWeakness withheld" in n for n in imported.notices)
    entries = [e for _, es in imported.groups for e in es if e.dn.startswith("cn=oscal-")]
    assert entries and all("ciamWeakness" not in e.attrs for e in entries)


def test_a_catalog_is_checked_against_the_records_controls_not_imported(oscal_record):
    catalog = json.dumps({"catalog": {"uuid": "88888888-8888-4888-8888-888888888888", "metadata": {
        **_meta(), "title": "SP 800-53 Rev 5"}, "groups": [{"id": "sc", "title": "SC", "controls": [
            {"id": "sc-13", "title": "x"},
            {"id": "ac-2", "title": "x", "controls": [{"id": "ac-2.1", "title": "x"}]}]}]}})
    imported = read_catalog({"c.json": catalog}, oscal_record.d, ())
    assert imported.groups == () and imported.notices == (
        "c.json: catalog SP 800-53 Rev 5: nist-800-53-r5: 2 of 3 controls found; not in it: nist-800-53-r5:IA-2(1)",)
