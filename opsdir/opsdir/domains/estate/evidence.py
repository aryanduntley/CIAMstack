"""Compliance evidence from the record: which record queries show which controls met (ciamEvidenceQuery under
ou=evidence-queries: a report of the catalogue, the change history or an LDAP search, how often its evidence is
collected again and who keeps it), what a system boundary's evidence package holds, and its last run
(ciamEvidenceRun, the child cn=evidence of the boundary: when, its files and their hashes, the queries it ran, where it
is kept, the change it was recorded under). Pure.

A boundary's package covers the controls its environments' authorizations leave to the operator (customer or shared:
ciamControlResponsibility) that some query names. A report with an environment column is cut to the boundary's
environments, so an estate-wide report never carries another boundary's rows; every other output goes whole. Entry
names and DNs are evidence; secret values never are (the record holds none). connectors.evidence runs the queries
(reports need the store) and the planner's check; the operation writes the package."""
import csv
import datetime as dt
import hashlib
import io
import json

from ...core.changeset import new_entry
from ...core.directory import children, date_of, get, gtime, is_a, norm_dn, one, rdn_value, subtree, values
from ...core.interchange.ldif import LdifRecord
from ...core.naming import SUFFIX, env_label
from ...core.search import search
from .authorizations import responsibilities_under
from .naming import EVIDENCE_QUERIES, EVIDENCE_RUN

QUERY, RUN, BOUNDARY = "ciamEvidenceQuery", "ciamEvidenceRun", "ciamSystemBoundary"
COVERING = ("customer", "shared")       # the responsibilities the operator must show met
ENVIRONMENT_COLUMN = "environment"      # a report column naming the environment a row is about
EVIDENCE_HEADERS = ("control", "query", "source", "on", "cadence (days)", "kept by", "last collected", "status")


def evidence_queries(d):
    """Every evidence query, by name."""
    return sorted(children(d, EVIDENCE_QUERIES, QUERY), key=rdn_value)


def queries_for(d, control):
    """The evidence queries that name a control (framework:control), by name."""
    return [q for q in evidence_queries(d) if control in values(q, "ciamControlRef")]


def boundary_named(d, name):
    """A system boundary by its cn or DN, or None."""
    found = get(d, name) if "=" in name else None
    return found if found is not None and is_a(found, BOUNDARY) else next(
        (b for b in subtree(d, SUFFIX, BOUNDARY) if rdn_value(b) == name), None)


def boundary_labels(boundary):
    """The cloud/env labels of the environments inside a boundary, in the order it names them."""
    return tuple(env_label(e) for e in values(boundary, "ciamAffectedEnvironment"))


def controls_covered(d, env_dns):
    """{control: (responsibility entry, ...)} of the controls the authorizations these environments rely on leave to the
    operator (customer or shared), in the order recorded."""
    auths = dict.fromkeys(norm_dn(a) for e in env_dns for a in (one(get(d, e), "ciamAuthorizationRef"),) if a)
    found = [(c, r) for a in auths for r in responsibilities_under(d, get(d, a))
             if one(r, "ciamResponsibility") in COVERING for c in values(r, "ciamControlRef")]
    return {c: tuple(r for k, r in found if k == c) for c in dict.fromkeys(c for c, _ in found)}


def package_plan(d, boundary, wanted=()):
    """((control, (query, ...)), ...): the controls of a boundary's scope some evidence query names (wanted: only
    these), by control, each with its queries."""
    scope = controls_covered(d, values(boundary, "ciamAffectedEnvironment"))
    named = {c for q in evidence_queries(d) for c in values(q, "ciamControlRef")}
    return tuple((c, tuple(queries_for(d, c))) for c in sorted(scope)
                 if c in named and (not wanted or c in wanted))


def control_folder(control):
    """The package folder of a control: framework_control (nist-800-53-r5:AC-2 -> nist-800-53-r5_AC-2)."""
    return control.replace(":", "_")


def scoped_rows(headers, rows, labels):
    """A report's rows cut to the environments labelled (when it has an environment column), else all of them."""
    if ENVIRONMENT_COLUMN not in headers:
        return tuple(rows)
    at = headers.index(ENVIRONMENT_COLUMN)
    return tuple(r for r in rows if r[at] in labels)


def search_table(d, q):
    """(headers, rows) of an evidence query's LDAP search: the DN, then each attribute it shows (values joined)."""
    attrs = tuple(values(q, "ciamEvidenceAttribute"))
    found = search(d, one(q, "ciamEvidenceDn") or SUFFIX, one(q, "ciamEvidenceFilter") or "(objectClass=*)")
    return ("dn", *attrs), tuple((e.dn, *(" | ".join(values(e, a)) for a in attrs)) for e in found)


def _plain(v):
    return v if v is None or isinstance(v, (str, int, float, bool)) else str(v)


def table_csv(headers, rows):
    """A table as CSV text (a header row, then each row)."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(headers)
    writer.writerows(tuple("" if v is None else _plain(v) for v in r) for r in rows)
    return out.getvalue()


def table_json(headers, rows):
    """A table as JSON text: {headers, rows}."""
    return json.dumps({"headers": list(headers), "rows": [[_plain(v) for v in r] for r in rows]}, indent=2,
                      ensure_ascii=False) + "\n"


def sha256(text):
    """The SHA-256 of a text (UTF-8), in hex."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def package_files(plan, outputs):
    """{path: text} of a package's outputs: per control a folder holding each query's output as CSV and JSON. outputs:
    {query DN: (headers, rows)}."""
    return {f"{control_folder(c)}/{rdn_value(q)}.{kind}": write(*outputs[q.dn])
            for c, queries in plan for q in queries for kind, write in (("csv", table_csv), ("json", table_json))}


def manifest(boundary, as_of, history_point, plan, files):
    """MANIFEST.json of a package: the boundary, the day it was evaluated as of, the history point (the last recorded
    change and how many changes the history holds), and per control its queries and their files' SHA-256."""
    doc = {"boundary": boundary.dn, "as_of": str(as_of), "history_point": history_point,
           "controls": [{"control": c, "queries": [
               {"query": rdn_value(q), "source": one(q, "ciamEvidenceSource"), "dn": one(q, "ciamEvidenceDn"),
                "files": {p: sha256(files[p]) for p in sorted(files)
                          if p.startswith(f"{control_folder(c)}/{rdn_value(q)}.")}}
               for q in queries]} for c, queries in plan]}
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def run_dn(boundary):
    """The DN of a boundary's evidence run."""
    return f"cn={EVIDENCE_RUN},{boundary.dn}"


def last_run(d, boundary):
    """A boundary's last recorded evidence run, or None."""
    run = get(d, run_dn(boundary))
    return run if run is not None and is_a(run, RUN) else None


def run_records(d, boundary, as_of, files, plan, change_id, kept_at=None):
    """The record of a boundary's evidence run under change change_id: taken as of a day (at its midnight, UTC),
    each file with its SHA-256, the queries it ran, where it is kept; a new entry or the held one replaced."""
    change = f"cn={change_id},ou=changes,{SUFFIX}"
    attrs = {"ciamEvidenceAt": (gtime(dt.datetime.combine(as_of, dt.time())),),
             "ciamEvidenceOutput": tuple(f"{p} {sha256(files[p])}" for p in sorted(files)),
             "ciamEvidenceQueryRef": tuple(dict.fromkeys(q.dn for _, queries in plan for q in queries)),
             "ciamEvidenceRef": (kept_at,) if kept_at else (), "ciamChangeRef": (change,)}
    held = last_run(d, boundary)
    if held is None:
        return (new_entry(run_dn(boundary), ("top", "ciamObject", RUN),
                          {"cn": (EVIDENCE_RUN,), **{a: v for a, v in attrs.items() if v}}),)
    return (LdifRecord(held.dn, "modify", {}, tuple(("replace", a, v) for a, v in attrs.items()
                                                    if v or values(held, a))),)


def collected_at(run):
    """The day a run's evidence was taken, or None."""
    return date_of(run, "ciamEvidenceAt") if run is not None else None


def due(taken, cadence):
    """When evidence taken on a day is due again (None: never collected, or no cadence)."""
    return None if taken is None or not cadence else taken + dt.timedelta(days=int(cadence))


def evidence_rows(d, dn=None, as_of=None):
    """One row per control and query: the control, the query, what it runs and on what, its cadence, who keeps it,
    when the boundaries that ran it last collected it, and its status as of the day (never collected, current, due)."""
    day = as_of or dt.date.today()
    runs = [r for b in subtree(d, SUFFIX, BOUNDARY) for r in (last_run(d, b),) if r is not None]

    def ran(q):
        return sorted(((rdn_value(get(d, r.dn.split(",", 1)[1])), collected_at(r)) for r in runs
                       if norm_dn(q.dn) in {norm_dn(x) for x in values(r, "ciamEvidenceQueryRef")}),
                      key=lambda x: x[0])

    def status(q, taken):
        when = due(min(t for _, t in taken), one(q, "ciamEvidenceCadenceDays")) if taken else None
        return "never collected" if not taken else f"due since {when}" if when is not None and when < day \
            else "current"
    return [(c, rdn_value(q), one(q, "ciamEvidenceSource"), one(q, "ciamEvidenceDn") or "",
             one(q, "ciamEvidenceCadenceDays") or "",
             rdn_value(get(d, one(q, "ciamManagedBy"))) if one(q, "ciamManagedBy") else "",
             ", ".join(f"{b} {t}" for b, t in ran(q)), status(q, ran(q)))
            for q in evidence_queries(d) for c in values(q, "ciamControlRef")]
