"""The OSCAL writers: a system boundary's POA&M (its items, their risks and milestones, its exceptions as deviation
risks) and SSP (who meets each control), an assessment's results (its open items as findings, the evidence package's
files as back-matter), each the same every time from the same record (uuid5 from DNs, last-modified from the
entries); UNBOUND fields named in notes; control ids between the record's form and OSCAL's; the adapter's render."""
import json
import uuid

import pytest

from opsdir.connectors.registry import ADAPTERS
from opsdir.core.directory import get
from opsdir_format_oscal.adapter import ADAPTER, oscal_notes, render_oscal
from opsdir_format_oscal.common import OSCAL_VERSION, control_id, control_ref, is_token
from opsdir_format_oscal.format import FORMAT
from opsdir_format_oscal.poam import poam_document
from opsdir_format_oscal.results import assessment_results_document
from opsdir_format_oscal.ssp import ssp_document


def _props(obj):
    return {p["name"]: [q["value"] for q in obj["props"] if q["name"] == p["name"]] for p in obj.get("props", ())}


def test_the_adapter_and_format_are_installed_and_target_oscal_1_2_3():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "compliance" and ADAPTER.applies is None
    assert OSCAL_VERSION == "1.2.3" and FORMAT.name == "oscal-json" and ADAPTER.formats == (("oscal/*.json",
                                                                                             "oscal-json"),)


@pytest.mark.parametrize("ref, oscal", [("nist-800-53-r5:SC-13", "sc-13"), ("nist-800-53-r5:AC-2(1)", "ac-2.1"),
                                        ("fedramp-moderate:IA-2(12)", "ia-2.12"), ("cmmc-l2:SC.L2-3.13.11",
                                                                                   "SC.L2-3.13.11"),
                                        ("nist-800-171-r2:3.13.11", "_3.13.11")])
def test_control_ids_are_written_in_oscal_form_and_read_back(ref, oscal):
    framework = ref.split(":")[0]
    assert control_id(ref) == (framework, oscal) and is_token(oscal) and control_ref(framework, oscal) == ref


def test_the_poam_holds_the_boundarys_items_and_deviations(oscal_record):
    d = oscal_record.d
    poam = poam_document(d, get(d, oscal_record.ENCLAVE)).document["plan-of-action-and-milestones"]
    assert poam["system-id"]["id"] == "SSP-ENCLAVE v2"
    assert poam["metadata"]["last-modified"] == "2026-09-10T00:00:00Z" == poam["metadata"]["version"]
    assert [i["title"] for i in poam["poam-items"]] == ["keys-fips", "mfa-gap"]
    risks = {r["title"]: r for r in poam["risks"]}
    assert {t: r["status"] for t, r in risks.items()} == {"keys-fips": "open", "mfa-gap": "closed",
                                                          "keys-deviation": "deviation-approved",
                                                          "lab-acceptance": "deviation-requested"}    # not rejected
    keys = poam["poam-items"][0]
    assert _props(keys)["control"] == ["nist-800-171-r2:3.13.11", "nist-800-53-r5:SC-13"]
    assert _props(keys)["points"] == ["3"] and _props(keys)["discovered"] == ["2026-08-01T12:00:00Z"]
    assert [r["risk-uuid"] for r in keys["related-risks"]] == [risks["keys-fips"]["uuid"],
                                                               risks["keys-deviation"]["uuid"]]
    assert risks["keys-fips"]["deadline"] == "2026-12-31T00:00:00Z"
    assert [(t["title"], t.get("timing")) for t in risks["keys-fips"]["remediations"][0]["tasks"]] == [
        ("keys moved to the HSM", {"on-date": {"date": "2026-11-30T00:00:00Z"}}), ("vendor sign-off", None)]
    assert risks["lab-acceptance"]["description"] == "UNBOUND:justification"
    assert all(uuid.UUID(r["uuid"]).version == 5 for r in poam["risks"])


def test_a_document_is_the_same_every_time_and_names_its_unbound_fields(oscal_record):
    d, b = oscal_record.d, get(oscal_record.d, oscal_record.ENCLAVE)
    first, again = poam_document(d, b), poam_document(d, b)
    assert json.dumps(first.document) == json.dumps(again.document)
    (n,) = first.notes
    assert (n.severity, n.entry) == ("action", oscal_record.ENCLAVE)
    assert "each risk's statement" in n.text and "exceptions lab-acceptance (no ciamJustification)" in n.text


def test_the_ssp_says_who_meets_each_control(oscal_record):
    d = oscal_record.d
    doc = ssp_document(d, get(d, oscal_record.ENCLAVE))
    ssp = doc.document["system-security-plan"]
    assert ssp["metadata"]["version"] == "SSP-ENCLAVE v2" and ssp["import-profile"]["href"] == "UNBOUND:profile"
    assert ssp["system-characteristics"]["authorization-boundary"]["description"] == (
        "Environments inside the boundary: alpha/prod, beta/prod.")
    reqs = {r["control-id"]: r for r in ssp["control-implementation"]["implemented-requirements"]}
    assert sorted(reqs) == ["_3.5.3", "ac-2", "ia-2.1", "sc-13"]
    components = {c["uuid"]: c["title"] for c in ssp["system-implementation"]["components"]}
    who = {cid: [(components[b["component-uuid"]], b["description"], b.get("implementation-status"))
                 for b in r["by-components"]] for cid, r in reqs.items()}
    assert who["ac-2"] == [("Example Gov", "Met by Example Gov (inherited).", None)]
    assert who["sc-13"] == [("Example Gov", "Met by Example Gov (shared).", None),
                            ("enclave", "Keys in the HSM", {"state": "implemented"})]
    assert who["ia-2.1"] == [("enclave", "Enforce MFA", None)]
    assert "import-profile href" in doc.notes[0].text


def test_assessment_results_hold_the_open_items_and_the_evidence_package(oscal_record):
    d = oscal_record.d
    a = get(d, "cn=cmmc-2026,ou=assessments,dc=ciam-ops")
    ar = assessment_results_document(d, a, evidence=(("MANIFEST.json", "ab" * 32),)).document["assessment-results"]
    (result,) = ar["results"]
    assert result["start"] == "2026-08-01T00:00:00Z" and _props(result)["framework"] == ["cmmc-l2"]
    assert (_props(result)["score"], _props(result)["max-score"]) == (["100"], ["110"])
    ((finding),) = result["findings"]                  # keys-fips: open, from cmmc-2026; mfa-gap is closed
    assert finding["title"] == "keys-fips" and finding["target"]["target-id"] == "_3.13.11"
    assert finding["target"]["status"] == {"state": "not-satisfied"}
    assert [r["rlinks"] for r in ar["back-matter"]["resources"]] == [
        [{"href": "MANIFEST.json", "hashes": [{"algorithm": "SHA-256", "value": "ab" * 32}]}],
        [{"href": "https://evidence.example/cmmc-2026"}]]


def test_a_boundary_without_items_has_no_poam(oscal_record):
    d = oscal_record.d
    with pytest.raises(SystemExit, match="boundary empty has no POA&M item"):
        poam_document(d, get(d, "cn=empty,ou=boundaries,dc=ciam-ops"))


def test_the_render_writes_each_document_and_its_notes(oscal_record):
    files = render_oscal(oscal_record.d)
    assert sorted(files) == ["oscal/assessment-results-cmmc-2026.json", "oscal/enclave/poam.json",
                             "oscal/enclave/ssp.json"]
    assert json.loads(files["oscal/enclave/poam.json"])["plan-of-action-and-milestones"]["metadata"][
        "oscal-version"] == "1.2.3"
    notes = oscal_notes(oscal_record.beta, None)
    assert [(n.severity, n.subject) for n in notes if n.severity == "note"] == [
        ("note", "OSCAL POA&M of empty"), ("note", "OSCAL SSP of empty"),
        ("note", "OSCAL control ids of nist-800-171-r2")]
