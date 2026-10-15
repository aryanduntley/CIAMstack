"""A system boundary's plan of action and milestones as an OSCAL POA&M: one poam-item per POA&M item naming an
environment inside the boundary (its weakness, controls, risk rating, points, how and when found), each with one risk
(open or closed, its deadline the scheduled completion, its milestones the planned remediation's tasks), and the
boundary's requested and approved exceptions as deviation risks, related to the items they belong to. The system-id is
the boundary's SSP (ciamSspRef), else its name. Pure.

The record doesn't state a risk's impact (OSCAL's required risk statement): it is written UNBOUND and named in a note.
The opsdir properties (namespace NS) carry what OSCAL has no field for, and what the reader needs to match an item back
to its entry (record-dn)."""
from opsdir.core.directory import gtime_of_iso, one, rdn_value, values

from .common import OscalDoc, entry_uid, iso, last_modified, metadata, props, unbound, unbound_note
from .record import (DEVIATIONS, boundary_exceptions, boundary_items, environments, item_exceptions, labels,
                     system_id)

SYSTEM_ID_TYPE = "urn:opsdir:oscal:system-id"      # the identifier type of a boundary's SSP reference or name
_DATED = ("ciamLastReviewedAt", "ciamDiscoveredAt", "ciamApprovedAt")


def _milestone(text):
    """(date-time or None, what) of a ciamMilestone value ('2026-11-30: keys moved to the HSM'; undated: all text)."""
    day, sep, what = text.partition(": ")
    return (f"{day}T00:00:00Z", what) if sep and len(day) == 10 and gtime_of_iso(day) and what else (None, text)


def _task(item, text):
    when, what = _milestone(text)
    return {"uuid": entry_uid("milestone", item, text), "type": "milestone", "title": what,
            **({"timing": {"on-date": {"date": when}}} if when else {})}


def _remediation(item):
    """The planned remediation of an item: its milestones as tasks, or none when it records no milestone."""
    tasks = [_task(item, text) for text in sorted(values(item, "ciamMilestone"))]
    return [{"uuid": entry_uid("remediation", item), "lifecycle": "planned",
             "title": f"Remediation of {rdn_value(item)}",
             "description": "The milestones the POA&M item schedules.", "tasks": tasks}] if tasks else []


def _item_risk(item):
    deadline = iso(one(item, "ciamScheduledCompletion"))
    return {"uuid": entry_uid("risk", item), "title": rdn_value(item), "description": one(item, "ciamWeakness"),
            "statement": unbound("risk-statement"),
            "props": props((("record-dn", item.dn), ("risk-rating", one(item, "ciamRiskRating")))),
            "status": "closed" if one(item, "ciamPoamStatus") == "closed" else "open",
            **({"deadline": deadline} if deadline else {}),
            **({"remediations": r} if (r := _remediation(item)) else {})}


def _deviation_risk(exc):
    expires = iso(one(exc, "ciamExpiresAt"))
    return {"uuid": entry_uid("risk", exc), "title": rdn_value(exc),
            "description": one(exc, "ciamJustification") or unbound("justification"),
            "statement": unbound("risk-statement"),
            "props": props((("record-dn", exc.dn), ("exception-kind", one(exc, "ciamExceptionKind")),
                            *(("control", c) for c in sorted(values(exc, "ciamControlRef"))),
                            *(("compensating-control", c) for c in sorted(values(exc, "ciamCompensatingControl"))))),
            "status": DEVIATIONS[one(exc, "ciamExceptionStatus")], **({"deadline": expires} if expires else {})}


def _poam_item(item, exceptions):
    return {"uuid": entry_uid("poam-item", item), "title": rdn_value(item), "description": one(item, "ciamWeakness"),
            "props": props((("record-dn", item.dn), *(("control", c) for c in sorted(values(item, "ciamControlRef"))),
                            ("risk-rating", one(item, "ciamRiskRating")), ("points", one(item, "ciamPointValue")),
                            ("discovery-source", one(item, "ciamDiscoverySource")),
                            ("discovered", iso(one(item, "ciamDiscoveredAt"))),
                            ("vendor-dependency", one(item, "ciamVendorDependency")),
                            *(("environment", env) for env in sorted(values(item, "ciamAffectedEnvironment"))))),
            "related-risks": [{"risk-uuid": u} for u in (entry_uid("risk", item),
                                                         *sorted(entry_uid("risk", e) for e in exceptions))]}


def poam_document(d, b, as_of=None):
    """OscalDoc of a system boundary's POA&M (b: its entry); last-modified is when its items and exceptions were last
    reviewed, found or approved, else the day given (as_of). Refused when the boundary has no POA&M item (OSCAL
    requires one)."""
    items, exceptions = boundary_items(d, b), boundary_exceptions(d, b)
    if not items:
        raise SystemExit(f"oscal: system boundary {rdn_value(b)} has no POA&M item naming its environments "
                         f"({', '.join(labels(environments(b))) or 'none named'}); OSCAL's POA&M needs one")
    modified = last_modified((*items, *exceptions), _DATED, as_of)
    document = {"plan-of-action-and-milestones": {
        "uuid": entry_uid("poam", b),
        "metadata": metadata(f"Plan of action and milestones: {rdn_value(b)}", modified),
        "system-id": {"identifier-type": SYSTEM_ID_TYPE, "id": system_id(b)},
        "risks": [*(_item_risk(i) for i in items), *(_deviation_risk(e) for e in exceptions)],
        "poam-items": [_poam_item(i, item_exceptions(exceptions, i)) for i in items]}}
    unjustified = sorted(rdn_value(e) for e in exceptions if not one(e, "ciamJustification"))
    fields = ("each risk's statement", *((f"the description of exceptions {', '.join(unjustified)} (no "
                                          "ciamJustification)",) if unjustified else ()))
    return OscalDoc(document, (unbound_note(f"OSCAL POA&M of {rdn_value(b)}", b.dn, fields, (
        "Write each risk's impact on the system into the OSCAL POA&M before submitting it: the record doesn't hold "
        "it", *(("Record why each exception named is justified (ciamJustification)",) if unjustified else ()))),))
