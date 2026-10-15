"""A compliance assessment as OSCAL assessment results: one result (the framework, who assessed, the score of the
maximum, the status, when; the controls reviewed: all of the framework's), its findings the assessment's open POA&M
items (not satisfied, each targeting its first control), and the evidence: the files of an evidence package with their
SHA-256 (as its MANIFEST lists them: evidence) and where the assessment's own evidence is kept (ciamEvidenceRef), as
back-matter resources. Pure.

The record holds no assessment plan: import-ap is written UNBOUND and named in a note. An item without a control whose
id is an OSCAL token can't be a finding (OSCAL's finding targets one): it is left out and named in a note."""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.notes import note

from .common import (AREA, OscalDoc, control_id, entry_uid, is_token, iso, last_modified, metadata, props, uid,
                     unbound, unbound_note)
from .record import assessment_items, environments, labels


def _target(item):
    """(record control ref, OSCAL id) of an item's first control whose id is an OSCAL token, or None."""
    return next(((ref, control_id(ref)[1]) for ref in sorted(values(item, "ciamControlRef"))
                 if is_token(control_id(ref)[1])), None)


def _finding(item, target):
    ref, oscal = target
    return {"uuid": entry_uid("finding", item), "title": rdn_value(item), "description": one(item, "ciamWeakness"),
            "props": props((("record-dn", item.dn), *(("control", c) for c in sorted(values(item, "ciamControlRef"))),
                            ("risk-rating", one(item, "ciamRiskRating")), ("points", one(item, "ciamPointValue")))),
            "target": {"type": "objective-id", "target-id": oscal, "status": {"state": "not-satisfied"},
                       "props": props((("control", ref),))}}


def _resources(a, evidence):
    files = [{"uuid": uid("evidence", path, digest), "title": path,
              "rlinks": [{"href": path, "hashes": [{"algorithm": "SHA-256", "value": digest}]}]}
             for path, digest in sorted(evidence)]
    kept = [{"uuid": entry_uid("evidence", a, url), "title": "Where the assessment's evidence is kept",
             "rlinks": [{"href": url}]} for url in sorted(values(a, "ciamEvidenceRef"))]
    return [*files, *kept]


def assessment_results_document(d, a, as_of=None, evidence=()):
    """OscalDoc of a compliance assessment's results (a: its entry). evidence: ((path, sha256), ...) of an evidence
    package's files (its MANIFEST's), written as back-matter resources. last-modified is when it was assessed, else
    the day given (as_of)."""
    items = assessment_items(d, a)
    targets = {i.norm: _target(i) for i in items}
    resources = _resources(a, evidence)
    result = {"uuid": entry_uid("result", a), "title": rdn_value(a),
              "description": f"{one(a, 'ciamFramework')} assessment ({one(a, 'ciamAssessmentKind')}) of "
                             f"{', '.join(labels(environments(a))) or 'the environments it names'}.",
              "start": iso(one(a, "ciamAssessedAt")),
              "props": props((("record-dn", a.dn), ("framework", one(a, "ciamFramework")),
                              ("assessment-kind", one(a, "ciamAssessmentKind")),
                              ("score", one(a, "ciamAssessmentScore")), ("max-score", one(a, "ciamAssessmentMaxScore")),
                              ("assessment-status", one(a, "ciamAssessmentStatus")),
                              *(("environment", env) for env in sorted(values(a, "ciamAffectedEnvironment"))))),
              "reviewed-controls": {"control-selections": [{"include-all": {}}]},
              **({"findings": f} if (f := [_finding(i, targets[i.norm]) for i in items if targets[i.norm]]) else {})}
    document = {"assessment-results": {
        "uuid": entry_uid("assessment-results", a),
        "metadata": metadata(f"Assessment results: {rdn_value(a)}", last_modified((a,), ("ciamAssessedAt",), as_of)),
        "import-ap": {"href": unbound("assessment-plan")},
        "results": [result],
        **({"back-matter": {"resources": resources}} if resources else {})}}
    untargeted = sorted(rdn_value(i) for i in items if not targets[i.norm])
    left_out = (note(AREA, "action", f"OSCAL assessment results of {rdn_value(a)}",
                     f"POA&M items left out of the findings: {', '.join(untargeted)} (no control whose id is an OSCAL "
                     "token)", ("Record the items' controls as their catalog names them",), entry=a.dn),) \
        if untargeted else ()
    return OscalDoc(document, (unbound_note(f"OSCAL assessment results of {rdn_value(a)}", a.dn, (
        "import-ap href (the assessment plan)",), ("Name the assessment plan in the OSCAL assessment results before "
                                                   "submitting them: the record doesn't hold it",)), *left_out))
