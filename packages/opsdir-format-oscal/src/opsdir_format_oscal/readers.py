"""OSCAL documents read into the record: a POA&M's items as POA&M items of the system boundary it names, assessment
results as compliance assessments and their not-satisfied findings as open POA&M items, and a catalog checked against
the controls the record names (nothing imported). Any OSCAL 1.x is read; what isn't read is named. Pure.

Each document's own items go in its own container (ou=oscal-poam-<system id> under ou=poam; ou=oscal-ar-<document
uuid> under ou=assessments and ou=poam), replaced as a whole on each import of it. An item the record already holds
(one opsdir wrote: its record-dn property; or one an earlier import made elsewhere: its ciamFindingRef
oscal:<kind>:<uuid>) is merged in place: the attributes the document states replace the record's, all else is kept,
and a record-owned item is never deleted. Reading back a document opsdir wrote from the record changes nothing.
Deviation risks aren't imported (an exception is approved in the record); satisfied findings neither."""
import re

from opsdir.core.contract import Imported
from opsdir.core.directory import (get, gtime_of_iso, is_a, make_entry, merged_attrs, one, ou_entry, rdn_value,
                                   subtree, values, within)
from opsdir.core.naming import SUFFIX
from opsdir.core.secrets import scan
from opsdir.core.sources import json_document
from opsdir.domains.estate.naming import (ASSESSMENT_KINDS, ASSESSMENT_STATUSES, ASSESSMENTS, CONTROL_REF,
                                          DISCOVERY_SOURCES, POAM, RISK_RATINGS, STANDARD_ID)

from .common import control_id, control_ref, oscal_version_major, prop_value, prop_values, slug, uid
from .record import ASSESSMENT, ITEM, boundaries, system_id

ITEM_CLASSES = ("top", "ciamObject", ITEM)
ASSESSMENT_CLASSES = ("top", "ciamObject", ASSESSMENT)
_DEVIATED = ("deviation-requested", "deviation-approved")
_CONTROL = re.compile(f"^{CONTROL_REF}$")
_FRAMEWORK = re.compile(f"^{STANDARD_ID}$")
_POINTS = ("1", "2", "3", "4", "5")


# ------------------------------------------------------------------ documents
def _documents(files, root, what):
    """({path: the document's root object} of the files holding an OSCAL 1.x document of a root key, notices for the
    rest)."""
    found = {p: doc.get(root) for p, t in sorted(files.items()) for doc in (json_document(t, dict),)
             if doc is not None and isinstance(doc.get(root), dict)}
    other = [f"{p}: OSCAL {(obj.get('metadata') or {}).get('oscal-version')}; only OSCAL 1.x is read"
             for p, obj in found.items() if oscal_version_major(obj) != "1"]
    skipped = [f"{p}: not an OSCAL {what}; not read" for p in sorted(files) if p not in found]
    return {p: obj for p, obj in found.items() if oscal_version_major(obj) == "1"}, (*other, *skipped)


def _refused(name, what, notices):
    raise SystemExit(f"oscal/{name}: no OSCAL 1.x {what} (JSON) among the files; nothing imported"
                     + (f" ({'; '.join(notices)})" if notices else ""))


# ------------------------------------------------------------------ attributes
def _clean(attrs, where, patterns):
    """(the attributes without values that look like secret material, notices naming what was withheld)."""
    bad = {k for k, vs in attrs.items() for v in vs or () if scan(v, patterns)}
    return ({k: v for k, v in attrs.items() if k not in bad},
            tuple(f"{where}: {k} withheld (it looks like secret material)" for k in sorted(bad)))


def _one(value, allowed=None):
    return (value,) if value and (allowed is None or value in allowed) else None


def _controls(refs):
    held = tuple(sorted(r for r in refs if _CONTROL.match(r)))
    return held or None


def _merged(found, dn, classes, owned):
    """The entry at dn: what the document states (owned, None values not stated) over what the record holds."""
    stated = {k: v for k, v in owned.items() if v}
    return make_entry(dn, found.classes if found is not None else classes, merged_attrs(found, stated, tuple(stated)))


def _indexed(d, base, oc, attr):
    """{value: entry} of a reference attribute over a branch's entries of a class."""
    return {v: e for e in subtree(d, base, oc) for v in values(e, attr)}


def _held(d, obj, oc, index, ref):
    """The record entry an OSCAL object is: the one its record-dn names (of the class), else the one carrying its
    reference."""
    by_dn = get(d, prop_value(obj, "record-dn") or "")
    return by_dn if by_dn is not None and is_a(by_dn, oc) else index.get(ref)


def _placed(found, container, cn, classes, owned):
    """(group scope or None, entry): a held entry outside the container is merged in place (its own group); one inside
    it, or a new one (cn), goes in the container's group."""
    if found is not None and not within(found.norm, container):
        return found.dn, _merged(found, found.dn, classes, owned)
    return None, _merged(found, found.dn if found is not None else f"cn={cn},{container}", classes, owned)


def _groups(d, container, placed):
    """In-place groups, and the container's (its entry and every entry placed in it) when it holds or held any."""
    in_place = tuple((scope, (e,)) for scope, e in placed if scope is not None)
    inside = tuple(e for scope, e in placed if scope is None)
    return (*in_place, *(((container, (ou_entry(container), *inside)),) if inside or get(d, container) else ()))


# ------------------------------------------------------------------ POA&M
def _boundary_of(d, poam, path):
    sid = str((poam.get("system-id") or {}).get("id") or "")
    found = next((b for b in boundaries(d) if sid and sid in (system_id(b), rdn_value(b))), None)
    if found is None:
        raise SystemExit(f"oscal/poam: {path}: its system-id {sid or '(none)'} names no system boundary; record the "
                         f"boundary (ciamSystemBoundary under ou=boundaries, ciamSspRef {sid or 'its SSP id'}) first")
    return found


def _primary(item, risks):
    """The item's own risk: the first related risk that isn't a deviation (an exception's)."""
    related = (risks.get(r.get("risk-uuid")) for r in item.get("related-risks") or () if isinstance(r, dict))
    return next((r for r in related if r is not None and r.get("status") not in _DEVIATED), {})


def _milestones(risk):
    tasks = (t for rem in risk.get("remediations") or () for t in rem.get("tasks") or () if t.get("title"))
    return tuple(sorted(f"{(t['timing']['on-date']['date'])[:10]}: {t['title']}"
                        if ((t.get("timing") or {}).get("on-date") or {}).get("date") else t["title"]
                        for t in tasks)) or None


def _item_attrs(item, risk, envs):
    return {"ciamWeakness": _one(item.get("description") or item.get("title")),
            "ciamPoamStatus": ("closed",) if risk.get("status") == "closed" else ("open",),
            "ciamControlRef": _controls(prop_values(item, "control")),
            "ciamRiskRating": _one(prop_value(item, "risk-rating") or prop_value(risk, "risk-rating"), RISK_RATINGS),
            "ciamPointValue": _one(prop_value(item, "points"), _POINTS),
            "ciamDiscoverySource": _one(prop_value(item, "discovery-source"), DISCOVERY_SOURCES),
            "ciamDiscoveredAt": _one(gtime_of_iso(prop_value(item, "discovered"))),
            "ciamVendorDependency": _one(prop_value(item, "vendor-dependency"), ("TRUE", "FALSE")),
            "ciamScheduledCompletion": _one(gtime_of_iso(risk.get("deadline"))),
            "ciamMilestone": _milestones(risk),
            "ciamAffectedEnvironment": tuple(prop_values(item, "environment")) or envs}


def _poam_import(d, path, poam, patterns):
    b = _boundary_of(d, poam, path)
    sid = system_id(b)
    container = f"ou=oscal-poam-{slug(sid)},{POAM}"
    risks = {r.get("uuid"): r for r in poam.get("risks") or () if isinstance(r, dict)}
    index = _indexed(d, SUFFIX, ITEM, "ciamFindingRef")
    placed, notices = [], []
    for item in (i for i in poam.get("poam-items") or () if isinstance(i, dict)):
        key = item.get("uuid") or uid("poam-item", sid, str(item.get("title")))
        ref = f"oscal:poam-item:{key}"
        found = _held(d, item, ITEM, index, ref)
        stated = _item_attrs(item, _primary(item, risks), tuple(values(b, "ciamAffectedEnvironment")) or None)
        new = {"cn": (f"oscal-{key}",), "ciamFindingRef": (ref,)} if found is None else {}
        if found is not None and not prop_values(item, "environment"):
            stated = {**stated, "ciamAffectedEnvironment": None}     # the record's own, unless the document names them
        attrs, withheld = _clean({**new, **stated}, f"{path}: {item.get('title')}", patterns)
        placed.append(_placed(found, container, f"oscal-{key}", ITEM_CLASSES, attrs))
        notices.extend(withheld)
    deviations = sum(1 for r in risks.values() if r.get("status") in _DEVIATED)
    notices.extend((f"{path}: {deviations} deviation risk(s) not imported: exceptions are approved in the record "
                    "(ciamRiskException under ou=exceptions)",) if deviations else ())
    return _groups(d, container, placed), (f"{path}: POA&M of system boundary {rdn_value(b)}", *notices)


def read_poam(files, d, patterns, at=None):
    """Imported: each OSCAL POA&M's items as POA&M items of the system boundary its system-id names (refused when it
    names none: the boundary is recorded first)."""
    docs, skipped = _documents(files, "plan-of-action-and-milestones", "plan of action and milestones")
    if not docs:
        _refused("poam", "plan of action and milestones", skipped)
    parts = [_poam_import(d, p, poam, patterns) for p, poam in docs.items()]
    return Imported(containers=(ou_entry(POAM),), groups=tuple(g for groups, _ in parts for g in groups),
                    notices=(*(n for _, notices in parts for n in notices), *skipped))


# ------------------------------------------------------------------ assessment results
def _assessment_attrs(result):
    framework, kind = prop_value(result, "framework"), prop_value(result, "assessment-kind")
    stated = framework and _FRAMEWORK.match(framework) and kind in ASSESSMENT_KINDS and gtime_of_iso(
        result.get("start"))
    return {"ciamFramework": (framework,), "ciamAssessmentKind": (kind,),
            "ciamAssessedAt": (gtime_of_iso(result.get("start")),),
            "ciamAssessmentScore": _one(prop_value(result, "score")),
            "ciamAssessmentMaxScore": _one(prop_value(result, "max-score")),
            "ciamAssessmentStatus": _one(prop_value(result, "assessment-status"), ASSESSMENT_STATUSES),
            "ciamAffectedEnvironment": tuple(prop_values(result, "environment")) or None} if stated else None


def _finding_controls(finding, framework):
    stated = prop_values(finding, "control") or prop_values(finding.get("target") or {}, "control")
    target = (finding.get("target") or {}).get("target-id")
    return _controls(stated or ((control_ref(framework, target),) if framework and target else ()))


def _finding_attrs(finding, framework, assessment, envs, start):
    return {"ciamWeakness": _one(finding.get("description") or finding.get("title")), "ciamPoamStatus": ("open",),
            "ciamControlRef": _finding_controls(finding, framework),
            "ciamRiskRating": _one(prop_value(finding, "risk-rating"), RISK_RATINGS),
            "ciamPointValue": _one(prop_value(finding, "points"), _POINTS),
            "_new": {"ciamAssessmentRef": (assessment,), "ciamDiscoverySource": ("assessment",),
                     "ciamDiscoveredAt": _one(start), "ciamAffectedEnvironment": envs}}


def _result_import(d, path, result, containers, indexes, patterns):
    """(placed assessments, placed items, notices) of one result."""
    rid, title = result.get("uuid") or uid("result", path, str(result.get("title"))), result.get("title")
    a_container, i_container = containers
    a_index, i_index = indexes
    held = _held(d, result, ASSESSMENT, a_index, f"oscal:result:{rid}")
    stated = _assessment_attrs(result)
    notices = [] if stated or held is not None else [
        f"{path}: result {title}: no framework and assessment kind stated (opsdir properties framework, "
        "assessment-kind) or no start: no compliance assessment recorded"]
    if stated and held is None:
        stated = {**stated, "cn": (f"oscal-{rid}",), "ciamAssessmentRef": (f"oscal:result:{rid}",)}
    placed_a = [_placed(held, a_container, f"oscal-{rid}", ASSESSMENT_CLASSES, stated)] if stated else []
    name = rdn_value(held) if held is not None else f"oscal-{rid}" if stated else f"oscal:result:{rid}"
    envs = tuple(prop_values(result, "environment")) or (tuple(values(held, "ciamAffectedEnvironment"))
                                                          if held is not None else ()) or None
    framework = prop_value(result, "framework") or (one(held, "ciamFramework") if held is not None else None)
    placed_i = []
    for finding in (f for f in result.get("findings") or () if isinstance(f, dict)):
        if ((finding.get("target") or {}).get("status") or {}).get("state") != "not-satisfied":
            continue
        ref = f"oscal:finding:{finding.get('uuid')}"
        found = _held(d, finding, ITEM, i_index, ref)
        attrs = _finding_attrs(finding, framework, name, envs, gtime_of_iso(result.get("start")))
        new = attrs.pop("_new")
        if found is None and not envs:
            notices.append(f"{path}: finding {finding.get('title')}: the result names no environment (opsdir property "
                           "environment); not imported")
            continue
        attrs = {**attrs, **({"cn": (f"oscal-{finding.get('uuid')}",), "ciamFindingRef": (ref,), **new}
                             if found is None else {})}
        attrs, withheld = _clean(attrs, f"{path}: {finding.get('title')}", patterns)
        placed_i.append(_placed(found, i_container, f"oscal-{finding.get('uuid')}", ITEM_CLASSES, attrs))
        notices.extend(withheld)
    return placed_a, placed_i, notices


def _results_import(d, path, ar, patterns):
    key = slug(ar.get("uuid") or path)
    containers = (f"ou=oscal-ar-{key},{ASSESSMENTS}", f"ou=oscal-ar-{key},{POAM}")
    indexes = (_indexed(d, ASSESSMENTS, ASSESSMENT, "ciamAssessmentRef"), _indexed(d, SUFFIX, ITEM, "ciamFindingRef"))
    parts = [_result_import(d, path, r, containers, indexes, patterns)
             for r in ar.get("results") or () if isinstance(r, dict)]
    groups = (*_groups(d, containers[0], [p for a, _, _ in parts for p in a]),
              *_groups(d, containers[1], [p for _, i, _ in parts for p in i]))
    return groups, tuple(n for _, _, notices in parts for n in notices)


def read_assessment_results(files, d, patterns, at=None):
    """Imported: each OSCAL assessment results' results as compliance assessments (those stating their framework and
    assessment kind) and their not-satisfied findings as open POA&M items."""
    docs, skipped = _documents(files, "assessment-results", "assessment results")
    if not docs:
        _refused("assessment-results", "assessment results", skipped)
    parts = [_results_import(d, p, ar, patterns) for p, ar in docs.items()]
    return Imported(containers=(ou_entry(ASSESSMENTS), ou_entry(POAM)),
                    groups=tuple(g for groups, _ in parts for g in groups),
                    notices=(*(n for _, notices in parts for n in notices), *skipped))


# ------------------------------------------------------------------ catalog
def catalog_ids(node):
    """The ids of every control in a catalog (its groups' and controls' controls, at any depth)."""
    return frozenset((*(c["id"] for c in node.get("controls") or () if isinstance(c, dict) and c.get("id")),
                      *(i for part in (*(node.get("groups") or ()), *(node.get("controls") or ()))
                        if isinstance(part, dict) for i in catalog_ids(part))))


def _record_refs(d):
    """{framework: the record's control refs under it}, over every entry naming controls."""
    refs = sorted({r for e in d.entries.values() for r in values(e, "ciamControlRef") if ":" in r})
    return {fw: tuple(r for r in refs if r.startswith(f"{fw}:")) for fw in sorted({r.split(":")[0] for r in refs})}


def _catalog_notices(d, path, catalog):
    ids, title = catalog_ids(catalog), (catalog.get("metadata") or {}).get("title") or path
    checked = {fw: (refs, [r for r in refs if control_id(r)[1] not in ids]) for fw, refs in _record_refs(d).items()}
    matched = {fw: found for fw, found in checked.items() if len(found[1]) < len(found[0])}
    if not matched:
        return (f"{path}: catalog {title} ({len(ids)} controls) holds none of the controls the record names",)
    return tuple(f"{path}: catalog {title}: {fw}: {len(refs) - len(missing)} of {len(refs)} controls found"
                 + (f"; not in it: {', '.join(missing)}" if missing else "") for fw, (refs, missing) in matched.items())


def read_catalog(files, d, patterns, at=None):
    """Imported nothing: each OSCAL catalog checked against the controls the record names, its notices naming, per
    framework whose controls it holds, those it doesn't."""
    docs, skipped = _documents(files, "catalog", "catalog")
    if not docs:
        _refused("catalog", "catalog", skipped)
    return Imported(containers=(), groups=(),
                    notices=(*(n for p, cat in docs.items() for n in _catalog_notices(d, p, cat)), *skipped))
