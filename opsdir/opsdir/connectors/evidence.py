"""Compliance evidence across the record: a system boundary's evidence package (each evidence query run as of a day:
a report of the catalogue, the change history or an LDAP search; estate.evidence says which and how it is laid out) and
the planner's evidence check. A connector: it needs the report catalogue, which spans the domains and the installed
adapters.

The check, for the target environment: a control its authorization leaves to the operator (customer or shared) that no
evidence query shows met is an action; a query naming no report of the catalogue (nor history, nor search) is a
blocker; the last package of a boundary the target is inside, missing or older than its queries' smallest cadence, is
an action; and a control whose evidence differs between the source and the target (a directory report with an
environment column, the source's rows against the target's) is one action naming its queries: collect it again there
after the cutover. Other sources are said once as not compared."""
from typing import NamedTuple

from ..core.directory import get, one, rdn_value, values
from ..core.findings import findings, responsible
from ..domains.estate.authorizations import boundaries_holding
from ..domains.estate.evidence import (ENVIRONMENT_COLUMN, boundary_labels, collected_at, controls_covered, due,
                                       evidence_queries, last_run, manifest, package_files, package_plan,
                                       scoped_rows, search_table)
from ..domains.estate.naming import EVIDENCE_HISTORY, EVIDENCE_SEARCH
from ..domains.governance.identity import record_identity
from ..store.queries import fetch_history
from .reports import HISTORY_HEADERS, catalogue, run_report

AREA = "Evidence"

# A boundary's evidence package: the controls with their queries (estate.evidence.package_plan), {path: text} of the
# outputs, MANIFEST.json's text and the history point the package was taken at.
Package = NamedTuple("Package", [("plan", tuple), ("files", dict), ("manifest", str), ("history_point", dict)])


def history_point(conn):
    """Effect (reads the store): the record's history point, the last governed change and how many history entries
    the governed changes made ({change, entry}; None before any)."""
    rows = fetch_history(conn)
    return {"change": rows[-1][1], "entry": len(rows)} if rows else None


def query_output(conn, d, q, as_of, reports=None):
    """Effect (reads the store): (headers, rows) of one evidence query as of a day."""
    src, dn = one(q, "ciamEvidenceSource"), one(q, "ciamEvidenceDn")
    if src == EVIDENCE_HISTORY:
        return HISTORY_HEADERS, tuple(tuple(r) for r in fetch_history(conn, dn))
    if src == EVIDENCE_SEARCH:
        return search_table(d, q)
    report = (reports or catalogue())[src]
    return report.headers, tuple(tuple(r) for r in run_report(conn, report, dn, as_of))


def directory_output(d, q, as_of, reports):
    """(headers, rows) of an evidence query the directory alone answers (a directory report of the catalogue, or a
    search), or None (the change history, a report the store runs, one given the record's writes from history)."""
    report = reports.get(one(q, "ciamEvidenceSource"))
    if one(q, "ciamEvidenceSource") == EVIDENCE_SEARCH:
        return search_table(d, q)
    return (report.headers, tuple(tuple(r) for r in _directory_rows(report, d, q, as_of))) \
        if report is not None and report.from_directory is not None and not report.writes else None


def assemble_package(d, boundary, wanted, as_of, output, point, reports):
    """A boundary's evidence package as of a day (wanted: only these controls), each query's (headers, rows) from
    output(query) and point the history point it was taken at. Refused (ValueError) for a query naming no report of
    the catalogue, before any query runs."""
    plan = package_plan(d, boundary, wanted)
    unknown = sorted({rdn_value(q) for _, qs in plan for q in qs if not _known(q, reports)})
    if unknown:
        raise ValueError(f"evidence queries naming no report: {', '.join(unknown)}")
    labels = boundary_labels(boundary)
    outputs = {q.dn: _cut(*output(q), labels) for _, qs in plan for q in qs}
    files = package_files(plan, outputs)
    return Package(plan, files, manifest(boundary, as_of, point, plan, files, record_identity(d)), point)


def evidence_package(conn, d, boundary, wanted, as_of):
    """Effect (reads the store): a boundary's evidence package as of a day (assemble_package over the store)."""
    reports = catalogue()
    return assemble_package(d, boundary, wanted, as_of, lambda q: query_output(conn, d, q, as_of, reports),
                            history_point(conn), reports)


def _cut(headers, rows, labels):
    return headers, scoped_rows(headers, rows, labels)


def _known(q, reports):
    return one(q, "ciamEvidenceSource") in (EVIDENCE_HISTORY, EVIDENCE_SEARCH, *reports)


# ------------------------------------------------------------------ the planner's check
def _directory_rows(report, d, q, as_of):
    dn = one(q, "ciamEvidenceDn")
    return report.from_directory(d, dn, as_of) if report.dated else report.from_directory(d, dn)


def _without_environment(headers, rows, label):
    at = headers.index(ENVIRONMENT_COLUMN)
    return sorted(tuple(str(v) for i, v in enumerate(r) if i != at) for r in rows if r[at] == label)


def _comparable(q, reports):
    report = reports.get(one(q, "ciamEvidenceSource"))
    return report is not None and report.from_directory is not None and not report.writes \
        and ENVIRONMENT_COLUMN in report.headers and not (report.needs_dn and not one(q, "ciamEvidenceDn"))


def _changed(ctx, q, report):
    rows = _directory_rows(report, ctx.d, q, ctx.as_of)
    return _without_environment(report.headers, rows, ctx.src.label) != \
        _without_environment(report.headers, rows, ctx.dst.label)


def _missing(ctx, queries, covered):
    named = {c for q in queries for c in values(q, "ciamControlRef")}
    return [(AREA, f"Control `{c}` is the operator's ({one(r[0], 'ciamResponsibility')}) under "
                   f"`{rdn_value(get(ctx.d, one(r[0], 'ciamAuthorizationRef')))}`, "
                   f"which {ctx.dst.label} relies on, and no evidence query shows it met: record one "
                   "(ciamEvidenceQuery under ou=evidence-queries).", responsible(ctx.d, r[0], ctx.dst.env),
             ctx.cutover)
            for c, r in covered.items() if c not in named]


def _unknown(ctx, queries, reports):
    return [(AREA, f"Evidence query `{rdn_value(q)}` runs `{one(q, 'ciamEvidenceSource')}`, which is no report of the "
                   f"catalogue: name an `opsdir report` report, `{EVIDENCE_HISTORY}` or `{EVIDENCE_SEARCH}`.",
             responsible(ctx.d, q, ctx.dst.env)) for q in queries if not _known(q, reports)]


def _stale(ctx, queries, covered):
    found = []
    for b in boundaries_holding(ctx.d, ctx.dst.dn):
        mine = [q for q in queries if set(values(q, "ciamControlRef")) & set(covered)]
        if not mine:
            continue
        run = last_run(ctx.d, b)
        cadences = [int(one(q, "ciamEvidenceCadenceDays")) for q in mine if one(q, "ciamEvidenceCadenceDays")]
        when = due(collected_at(run), min(cadences)) if cadences else None
        if run is None:
            found.append((AREA, f"Boundary `{rdn_value(b)}` ({ctx.dst.label} is inside it) has no recorded evidence "
                                f"package: take one (`opsdir evidence --boundary {rdn_value(b)} --change ...`).",
                          responsible(ctx.d, b, ctx.dst.env), ctx.cutover))
        elif when is not None and when < ctx.as_of:
            found.append((AREA, f"Boundary `{rdn_value(b)}`'s evidence was taken on {collected_at(run)}, past its "
                                f"queries' {min(cadences)}-day cadence (due {when}): take it again.",
                          responsible(ctx.d, b, ctx.dst.env), ctx.cutover))
    return found


def _changes(ctx, queries, scope, reports):
    changed = [q for q in queries
               if _comparable(q, reports) and _changed(ctx, q, reports[one(q, "ciamEvidenceSource")])]
    per_control = {c: [rdn_value(q) for q in changed if c in values(q, "ciamControlRef")] for c in sorted(scope)}
    return [(AREA, f"Control `{c}`: its evidence changes in {ctx.dst.label} ({', '.join(f'`{n}`' for n in names)}): "
                   "collect it again there after the cutover (`opsdir evidence`).",
             responsible(ctx.d, next(q for q in queries if rdn_value(q) == names[0]), ctx.dst.env), ctx.cutover)
            for c, names in per_control.items() if names]


def evidence_check():
    """The planner check of evidence (see the module), over the report catalogue."""
    reports = catalogue()

    def check_evidence(ctx):
        queries = evidence_queries(ctx.d)
        covered = controls_covered(ctx.d, (ctx.dst.dn,))
        if not queries and not covered:
            return findings()
        scope = set(covered) | set(controls_covered(ctx.d, (ctx.src.dn,)))
        in_scope = [q for q in queries if set(values(q, "ciamControlRef")) & scope]
        uncompared = [rdn_value(q) for q in in_scope if not _comparable(q, reports)]
        return findings(blockers=_unknown(ctx, queries, reports),
                        actions=[*_missing(ctx, queries, covered), *_stale(ctx, queries, covered),
                                 *_changes(ctx, in_scope, scope, reports)],
                        ok=[f"Evidence not compared between {ctx.src.label} and {ctx.dst.label} (history, searches, "
                            f"and reports without an environment column): {', '.join(f'`{n}`' for n in uncompared)}."]
                        if uncompared else [])
    return check_evidence
