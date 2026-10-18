"""Onboarding verification (milestone 7.8): does the record, rendered whole, still say what the operator's original
files said? Pure: the CLI reads the files and the record, this compares.

What the originals say (A): each original export's import plan against the record as it is now, not applied
(importing.import_plan, record_after), within the scopes its importer reads. What the render says (B): every
environment rendered as `opsdir render` writes it, read back by the adapters' own importers (roundtrip.read_back),
within the scopes each read-back reads; the captured files it rebuilds (connectors.capture) are captured again, each
within its own entry. The two are compared entry by entry and attribute by attribute, with the
record (R: what the render was made from) as the tie-breaker:

  identical        A and B agree (counted, not listed)
  equivalent       the same values in another order, or an attribute about where and how an import read (meta
                   portability) or what applying assigns (roundtrip.ASSIGNED)
  gap-filled       the originals lack it; the render holds what the record holds (another source filled it)
  decided          the record differs from the originals and the render follows the record: a recorded decision
                   (a conflict kept at import, or a later approved change)
  by-design        nothing reads it back, and its importer brings reference data no render writes (Importer.reference)
  loss             the render lacks what the originals or the record hold
  altered          the render holds something neither the originals nor the record hold
  uncovered        nothing reads back what the importer read, and it isn't reference data

Any loss, altered or uncovered difference fails the verification. An environment that can't be rendered is named in
the notices, and what it would have read back counts as uncovered. Where an original file and a rendered file reach
the same importer under the same path, unchanged by a read-back's prepare, and their texts differ, both are kept
(secrets redacted with the store's patterns) for a text diff (text_diff), marked when they differ only in layout
(same_content). Each original export's files are checked against the hashes its import runs recorded
(domains.governance.imports.imported_files): a file not imported, changed since, or imported but not given is a
warning.
"""
import difflib
import hashlib
import json
from functools import reduce
from itertools import groupby
from typing import NamedTuple

from ..core.directory import children, get, norm_dn, one, portability, subtree, values, within
from ..domains.configuration.record import deployed_files
from ..domains.governance.imports import imported_files, scope_set
from ..domains.governance.naming import IMPORTS
from .capture import CAPTURED_DIR, capture_changes, rendered_config
from .collecting import redact
from .importing import import_plan, importer_named, record_after
from .registry import ADAPTERS, environment_specs, format_named, pattern_records
from .render import assemble, render_parts
from .roundtrip import ASSIGNED, RoundTrip, read_back, selected_files

FAILING = ("loss", "altered", "uncovered")
CAPTURED = "captured config"    # the read-back of the captured files a render rebuilds
KINDS = ("loss", "altered", "uncovered", "decided", "gap-filled", "equivalent", "by-design")
ENTRY = "*"                    # a Difference's attribute when the whole entry differs

# One difference between what an original export says (original) and what the render reads back (rendered) at an
# entry's attribute (ENTRY: the whole entry; its values then ('present',) or ()), with what the record holds (record).
Difference = NamedTuple("Difference", [("importer", str), ("dn", str), ("attr", str), ("kind", str),
                                       ("original", tuple), ("record", tuple), ("rendered", tuple)])
# One original export's verification: importer ('adapter/importer'), the files given, the scopes it reads, how many
# attributes agreed (identical), {kind: count} of its differences, the importer's notices and the provenance warnings.
Checked = NamedTuple("Checked", [("importer", str), ("files", tuple), ("scopes", tuple), ("identical", int),
                                 ("counts", dict), ("notices", tuple), ("warnings", tuple)])
# A rendered file and the original it should match, both as the importer is given them, secrets redacted, and
# whether they differ only in layout (same_content).
FilePair = NamedTuple("FilePair", [("importer", str), ("path", str), ("environment", str), ("original", str),
                                   ("rendered", str), ("layout_only", bool)])
# The verification: 'pass' or 'fail', each export checked, every difference but identical ones, the text pairs, and
# notices (environments that couldn't be rendered).
Verification = NamedTuple("Verification", [("status", str), ("checked", tuple), ("differences", tuple),
                                           ("pairs", tuple), ("notices", tuple)])
# What the render reads back: per scope read (normalized DN), the record as that environment saw it, the read-back
# entries in it and the environment; the rendered files each importer is given unchanged ({(importer, path): (env,
# text)}); notices.
_ReadBack = NamedTuple("_ReadBack", [("scopes", tuple), ("entries", dict), ("files", dict), ("notices", tuple)])
_PRESENT = ("present",)


def _captured(m, installed):
    """(RoundTrip, ...) of the captured files environment m receives, each rebuilt file captured again against the
    record as m sees it (its concerns accepted: nothing is stored), within the file's entry."""
    files = rendered_config(m.d, m).files
    def again(f, path):
        changes, notices = capture_changes(m.d, format_named(one(f, "ciamFormat")), files[path], one(f, "cn"),
                                           one(f, "ciamRepoPath"), one(f, "ciamTargetRole"), one(f, "ciamDeployPath"),
                                           accept_concerns=True, installed=installed)
        return RoundTrip(CAPTURED, (path,), changes, tuple(notices), (), (f.dn,))
    return tuple(again(f, path) for f in deployed_files(m.d, m)
                 for path in (f"{CAPTURED_DIR}/{one(f, 'ciamRepoPath').lstrip('/')}",) if path in files)


def _env_read_backs(d, spec, installed, at):
    """(RoundTrip, view, {(importer, path): text}) of one environment's render, or the reason it can't be rendered."""
    try:
        m, adapters, neutral, specific, targets = render_parts(d, spec, installed)
        rendered = assemble(m, adapters, neutral, specific, targets, installed=installed)
    except SystemExit as e:
        return f"{spec}: not rendered: {e}"
    trips = (*(rt for a in adapters for rt in read_back(m.d, a, rendered, installed, at, spec)),
             *_captured(m, installed))
    plain = {(f"{a.name}/{rb.importer}", p): text for a in adapters for rb in a.reads_back if rb.prepare is None
             for p, text in selected_files(rb, rendered, spec).items()}
    return trips, m.d, plain


def rendered_view(d, installed=ADAPTERS, at=None):
    """What every environment's render reads back (_ReadBack): the first read of a scope is kept (environment-neutral
    files are read again in each environment)."""
    def step(acc, spec):
        got = _env_read_backs(d, spec, installed, at)
        if isinstance(got, str):
            return acc._replace(notices=(*acc.notices, got))
        trips, view, plain = got
        held = {s for s, _, _ in acc.scopes}
        fresh = tuple((norm_dn(s), view, spec) for rt in trips for s in rt.scopes if norm_dn(s) not in held)
        read = {e.norm: e for rt in trips for after in (record_after(view, rt.changes),) for s in rt.scopes
                if norm_dn(s) not in held for e in subtree(after, s)}
        notes = tuple(f"{spec}: {rt.importer}: {n}" for rt in trips if not rt.files for n in rt.notices)
        return _ReadBack((*acc.scopes, *dict((s, (s, v, e)) for s, v, e in fresh).values()),
                         {**read, **acc.entries}, {**{k: (spec, t) for k, t in plain.items()}, **acc.files},
                         (*acc.notices, *notes))
    return reduce(step, environment_specs(d), _ReadBack((), {}, {}, ()))


def _covering(view, dn):
    """(record as the covering environment saw it, environment) of the first read-back scope holding dn, or None."""
    return next(((v, env) for s, v, env in view.scopes if within(dn, s)), None)


def _kind(d, attr, a, r, b):
    """The kind of difference between original values a, record values r and rendered values b (None: identical)."""
    if a == b:
        return None
    if set(a) == set(b) or (attr != ENTRY and (attr in ASSIGNED or portability(d, attr) == "meta")):
        return "equivalent"
    if b == r:
        return "gap-filled" if not a else "decided"
    return "loss" if (set(a) | set(r)) - set(b) else "altered"


def _attrs(e):
    if e is None:
        return {}
    return {"objectClass": tuple(e.classes), **{k: tuple(v) for k, v in e.attrs.items()}}


def _entry_differences(d, importer, dn, a, r, b):
    """(Difference, ...) and how many attributes agreed, for one entry covered by a read-back."""
    presence = tuple(_PRESENT if e is not None else () for e in (a, r, b))
    whole = _kind(d, ENTRY, *presence)
    if whole is not None or a is None or b is None:
        return ((Difference(importer, dn, ENTRY, whole, *presence),) if whole else ()), 0
    av, rv, bv = _attrs(a), _attrs(r), _attrs(b)
    names = tuple(dict.fromkeys((*av, *bv, *rv)))
    kinds = tuple((n, _kind(d, n, av.get(n, ()), rv.get(n, ()), bv.get(n, ()))) for n in names)
    found = tuple(Difference(importer, dn, n, k, av.get(n, ()), rv.get(n, ()), bv.get(n, ())) for n, k in kinds if k)
    return found, sum(1 for _, k in kinds if k is None)


def _uncovered(importer, dn, a, r, reference):
    if a is None:
        return ()
    return (Difference(importer, dn, ENTRY, "by-design" if reference else "uncovered", _PRESENT,
                       _PRESENT if r is not None else (), ()),)


def _provenance(d, importer, scopes, files):
    """Warnings comparing the files given with the hashes the importer's runs over these scopes recorded."""
    wanted = set(scope_set(scopes))
    runs = tuple(r for r in children(d, IMPORTS, "ciamImportRun")
                 if values(r, "ciamImporter") == (importer,) and set(scope_set(values(r, "ciamImportScope"))) & wanted)
    if not runs:
        return (f"{importer}: no import run of these scopes: these originals were never imported",)
    recorded = {p: h for r in runs for p, h in imported_files(r).items()}
    if not recorded:
        return (f"{importer}: its import runs recorded no file hashes (imported before they were): the files given "
                "can't be checked against what was imported",)
    given = {p: hashlib.sha256(t.encode()).hexdigest() for p, t in files.items()}
    return (*(f"{importer}: {p}: not among the files imported" for p in sorted(set(given) - set(recorded))),
            *(f"{importer}: {p}: changed since it was imported" for p in sorted(set(given) & set(recorded))
              if given[p] != recorded[p]),
            *(f"{importer}: {p}: imported but not given" for p in sorted(set(recorded) - set(given))))


def _check(d, view, spec, files, installed, at):
    """(Checked, differences) of one original export ({relative path: text}) given for importer spec."""
    adapter, imp = importer_named(spec, installed)
    plan = import_plan(d, spec, files, installed, at)
    original = record_after(d, plan.changes)
    dns = tuple(dict.fromkeys(e.norm for s in plan.scopes for x in (original, d) for e in subtree(x, s)))

    def one(dn):
        a = get(original, dn)
        covering = _covering(view, dn)
        if covering is None:
            return _uncovered(plan.importer, (a or get(d, dn)).dn, a, get(d, dn), imp.reference), 0
        seen, _ = covering
        b, r = view.entries.get(dn), get(seen, dn)
        return _entry_differences(d, plan.importer, (a or r or b).dn, a, r, b)

    results = tuple(one(dn) for dn in dns)
    found = tuple(x for diffs, _ in results for x in diffs)
    counts = {k: n for k in KINDS for n in (sum(1 for x in found if x.kind == k),) if n}
    return Checked(plan.importer, tuple(sorted(files)), plan.scopes, sum(n for _, n in results), counts,
                   plan.notices, _provenance(d, plan.importer, plan.scopes, files)), found


def _json(text):
    try:
        return True, json.loads(text)
    except ValueError:
        return False, None


def same_content(a, b):
    """Whether two texts say the same laid out differently: equal but for whitespace, or both JSON of equal value
    (another key order or indentation)."""
    if a.split() == b.split():
        return True
    (ok_a, va), (ok_b, vb) = _json(a), _json(b)
    return ok_a and ok_b and va == vb


def _pairs(view, sources, patterns):
    """FilePairs of the original files a rendered file reaches under the same importer and path, where they differ."""
    def clean(text):
        return redact(text, (), tuple(x.pattern for x in patterns))
    return tuple(FilePair(importer, p, env, clean(files[p]), clean(text), same_content(files[p], text))
                 for importer, files in sources for (who, p), (env, text) in sorted(view.files.items())
                 if who == importer and p in files and files[p] != text)


def verify(d, sources, installed=ADAPTERS, at=None):
    """The Verification of record d against the operator's original exports: sources ((spec 'adapter[/importer]',
    {relative path: text}), ...), each read by its importer at `at` (a UTC datetime, or None); every environment
    rendered and read back. 'fail' when any difference is a loss, altered or uncovered."""
    view = rendered_view(d, installed, at)
    checked = tuple(_check(d, view, spec, files, installed, at) for spec, files in sources)
    differences = tuple(x for _, found in checked for x in found)
    named = tuple((c.importer, files) for (c, _), (_, files) in zip(checked, sources))
    status = "fail" if any(x.kind in FAILING for x in differences) else "pass"
    return Verification(status, tuple(c for c, _ in checked), differences,
                        _pairs(view, named, pattern_records(installed)), view.notices)


def text_diff(pair, context=3):
    """The unified diff lines of a FilePair, original first."""
    return tuple(difflib.unified_diff(pair.original.splitlines(), pair.rendered.splitlines(),
                                      f"original/{pair.path}", f"rendered/{pair.environment}/{pair.path}",
                                      lineterm="", n=context))


SUMMARY_HEADERS = ("importer", "files", "identical", *KINDS)
DIFFERENCE_HEADERS = ("kind", "importer", "entry", "attribute", "original", "rendered", "record")
LIMIT = 10                     # differences listed per importer and kind unless every one is asked for


def _shown(vals):
    return " | ".join(vals) if vals else "-"


def summary_rows(v):
    """One row per export checked (SUMMARY_HEADERS): its importer, how many files, attributes that agreed, then the
    count of each kind of difference."""
    return [(c.importer, len(c.files), c.identical, *(c.counts.get(k, 0) for k in KINDS)) for c in v.checked]


def difference_rows(v, every=False):
    """Rows of the differences (DIFFERENCE_HEADERS), failing kinds first, then by importer and entry; LIMIT per
    importer and kind unless every one is asked for."""
    ordered = sorted(v.differences, key=lambda x: (KINDS.index(x.kind), x.importer, x.dn.lower(), x.attr.lower()))
    groups = (tuple(xs) for _, xs in groupby(ordered, key=lambda x: (x.kind, x.importer)))
    return [(x.kind, x.importer, x.dn, x.attr, _shown(x.original), _shown(x.rendered), _shown(x.record))
            for xs in groups for x in (xs if every else xs[:LIMIT])]


def failing_counts(v):
    """{kind: count} of the failing differences, in FAILING order."""
    return {k: n for k in FAILING for n in (sum(1 for x in v.differences if x.kind == k),) if n}


def report_document(v):
    """The verification as a JSON-ready document: status, each export checked, every difference, the text diffs of
    the files that differ (secrets redacted) and the notices."""
    return {"status": v.status, "failing": failing_counts(v),
            "checked": [{"importer": c.importer, "files": list(c.files), "scopes": list(c.scopes),
                         "identical": c.identical, "counts": c.counts, "notices": list(c.notices),
                         "warnings": list(c.warnings)} for c in v.checked],
            "differences": [x._asdict() | {"original": list(x.original), "record": list(x.record),
                                           "rendered": list(x.rendered)} for x in v.differences],
            "files": [{"importer": p.importer, "path": p.path, "environment": p.environment,
                       "layout_only": p.layout_only, "diff": list(text_diff(p))} for p in v.pairs],
            "notices": list(v.notices)}
