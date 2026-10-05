"""Assisted fixes: the record changes a plan's findings offer (core.findings.Fix), found by key, proposed as a change
record for a human to approve, and applied unchanged once approved. The same for an operator at the command line and
an AI through the operations layer: proposing writes only a change record with status proposed (change records are
writable under their own id); applying writes the fix's records under an approved change, which the store enforces.
A fix that is a choice is proposed or applied with an option chosen, and one that takes inputs (core.findings.Input:
a provider reference, a DNS name) with their values given; the proposal holds the records as filled.
A fix never carries secret values, observed facts or attestations (the checks that offer fixes don't offer those).
Pure: the operations apply what this returns.
"""
import re

from ..core.directory import get, gtime_at, one, values, within
from ..core.findings import filled_records, fix_inputs
from ..domains.governance.imports import runs_covering
from ..core.interchange.ldif import LdifRecord, parse, write_records
from ..domains.governance.naming import CHANGES

PROPOSED, APPROVED, APPLIED = "proposed", "approved", "applied"


def find_fix(fixes, key):
    """The fix with key among fixes; ValueError naming the keys there are."""
    found = next((f for f in fixes if f.key == key), None)
    if found is None:
        raise ValueError(f"no fix {key} in this plan (fixes: {', '.join(f.key for f in fixes) or 'none'})")
    return found


def _picked(fix, option):
    if not fix.options:
        if option:
            raise ValueError(f"fix {fix.key} offers no options")
        return fix
    found = next((o for o in fix.options if o.key == option), None)
    if found is None:
        raise ValueError(f"fix {fix.key} is a choice: name one with --option ({', '.join(o.key for o in fix.options)})")
    return fix._replace(title=f"{fix.title}: {found.label}", records=found.records, risks=(*fix.risks, *found.risks),
                        options=())


def input_values(fix, given):
    """{key: values} for each input of a fix (no options left): the values given ({key: values}), else its default;
    ValueError naming keys it has no input for, inputs given nothing that have no default, values that don't match
    an input's pattern, and keys two different inputs share (a defect of the fixer). Given no values (an empty value),
    an input leaves its attribute out."""
    inputs = fix_inputs(fix.records)
    twice = sorted({i.key for i in inputs if sum(j.key == i.key for j in inputs) > 1})
    if twice:
        raise ValueError(f"fix {fix.key} has two different inputs named {', '.join(twice)}")
    unknown = sorted(set(given) - {i.key for i in inputs})
    if unknown:
        raise ValueError(f"fix {fix.key} has no input {', '.join(unknown)} "
                         f"(inputs: {', '.join(i.key for i in inputs) or 'none'})")
    absent = [i for i in inputs if i.key not in given and not i.default]
    if absent:
        raise ValueError(f"fix {fix.key} needs values: " + ", ".join(
            f"--input {i.key}=…" + (f" (e.g. {i.example[0]})" if i.example else "") for i in absent))
    values = {i.key: tuple(given[i.key]) if i.key in given else i.default for i in inputs}
    bad = [(i, v) for i in inputs if i.pattern for v in values[i.key] if not re.fullmatch(i.pattern, v)]
    if bad:
        raise ValueError(f"fix {fix.key}: " + "; ".join(f"{i.key}={v} doesn't match {i.pattern}" for i, v in bad))
    return values


def chosen(fix, option=None, given=None):
    """The fix to propose or apply: its option chosen when it offers a choice (the option's records, the title naming
    it, its own risks too), then its inputs filled with the values given ({key: values}) or their defaults; ValueError
    when a choice is needed and none (or an unknown one) is given, or an input can't be filled (input_values)."""
    picked = _picked(fix, option)
    return picked._replace(records=filled_records(picked.records, input_values(picked, given or {})))


def previewed(records):
    """Change records for review before their inputs are given: each Input shown as <key>."""
    return filled_records(records, {i.key: (f"<{i.key}>",) for i in fix_inputs(records)})


def _covering(d, entries):
    """The newest import run one of whose scopes holds each of entries, or None."""
    runs = runs_covering(d, entries[0]) if entries else ()
    return next((r for r in runs if all(any(within(e, s) for s in values(r, "ciamImportScope")) for e in entries)),
                None)


def unmet(fix, d, last_change):
    """What a fix still waits for, in words (empty: nothing): each of its Requirements no import run meets, the run
    covering its entries missing or of an export taken before the last change anyone else made to them.
    last_change(dns, excluded change ids) -> the time of that change, or None (the store's history)."""
    def waiting(r):
        run = _covering(d, r.entries)
        if run is None:
            return f"{r.why}: import what it changes first (no import has read it back)"
        changes = tuple(c.split(",", 1)[0].split("=", 1)[1] for c in values(run, "ciamChangeRef"))
        changed, read = last_change(r.entries, changes), gtime_at(one(run, "ciamImportedAt"))
        if changed is None or read >= changed:
            return None
        return (f"{r.why}: import it again first ({one(run, 'ciamImporter')} last read it from an export of "
                f"{one(run, 'ciamImportedAt')}, before the record changed there on {changed:%Y-%m-%d %H:%M} UTC)")
    return tuple(w for w in map(waiting, fix.requires) if w)


def change_dn(change_id):
    """The DN of a change record."""
    return f"cn={change_id},{CHANGES}"


def proposal(fix, change_id, title=None):
    """The change record proposing a fix: status proposed, its title, the LDIF change records it applies once
    approved, and the steps outside the record and risks in the title's words for the approver."""
    if not fix.records:
        raise ValueError(f"fix {fix.key} changes nothing in the record (its steps are manual: "
                         + " ".join(fix.manual) + ")")
    return LdifRecord(change_dn(change_id), "add", {
        "objectClass": ("top", "ciamChange"), "cn": (change_id,), "ciamTitle": (title or fix.title,),
        "ciamChangeStatus": (PROPOSED,), "ciamChangeRecords": (write_records(fix.records),)}, ())


def proposed_records(d, change_id):
    """(the records an approved proposal applies, the record marking it applied); ValueError when the change holds no
    records or isn't approved yet."""
    change = get(d, change_dn(change_id))
    if change is None or not one(change, "ciamChangeRecords"):
        raise ValueError(f"{change_id} is no proposed change holding records")
    if one(change, "ciamChangeStatus") != APPROVED:
        raise ValueError(f"{change_id} is {one(change, 'ciamChangeStatus')}, not approved: a person approves it first")
    return (tuple(parse(one(change, "ciamChangeRecords"))),
            LdifRecord(change.dn, "modify", {}, (("replace", "ciamChangeStatus", (APPLIED,)),)))
