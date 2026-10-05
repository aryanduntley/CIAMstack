"""Importing a product's own export into the record: the adapter's importer reads the files; here what it yields
becomes change records (pure). The CLI reads the files and applies the change records under an approved change.

Where the import would replace or remove what the record holds (a value, or a whole entry), the live system and the
record disagree, and neither is assumed to be right: each disagreement is a conflict the operator decides, taking the
live value or keeping the record's (`decided`). Adding what the record lacks is no conflict. An applied import also
clears what it confirms (values a fix set ahead of the live system: `confirmations`) and records an import run of each
scope it read (domains.governance.imports).
"""
from typing import NamedTuple, Optional

from ..core.changeset import delete_values, diff
from ..core.directory import get, subtree, values, within
from ..core.findings import pending
from ..domains.governance.imports import run_records
from .registry import ADAPTERS, pattern_records

# Where an import and the record disagree: key (what to pass to --take or --keep: "<dn>|<attribute>", or the DN when
# the import would delete the entry), the entry's DN, the attribute (None: the whole entry), what the record holds and
# what the live system has (empty: nothing).
Conflict = NamedTuple("Conflict", [("key", str), ("dn", str), ("attr", Optional[str]), ("held", tuple),
                                   ("live", tuple)])
# What an import would do: the importer, its change records, notices, conflicts, the scopes it read and when the export
# was taken.
ImportPlan = NamedTuple("ImportPlan", [("importer", str), ("changes", tuple), ("notices", tuple),
                                       ("conflicts", tuple), ("scopes", tuple), ("at", object)])
ALL = "all"


def importer_named(spec, installed=ADAPTERS):
    """(adapter, importer) for 'adapter[/importer]': the adapter's only importer when none is named. Refused, with
    what there is to choose from, when the adapter isn't installed, has no importer or none of that name."""
    name, _, wanted = spec.partition("/")
    adapter = next((a for a in installed if a.name == name), None)
    offered = ", ".join(f"{a.name}/{i.name}" for a in installed for i in a.importers) or "none"
    if adapter is None or not adapter.importers:
        raise SystemExit(f"no installed adapter named {name} has importers (installed importers: {offered})")
    if not wanted and len(adapter.importers) == 1:
        return adapter, adapter.importers[0]
    found = next((i for i in adapter.importers if i.name == wanted), None)
    if found is None:
        raise SystemExit(f"name one of {name}'s importers: {', '.join(i.name for i in adapter.importers)}")
    return adapter, found


def _outside(scope, entries):
    return [e.dn for e in entries if not within(e.norm, scope)]


def import_changes(d, imported):
    """Change records turning the record into what the import says: the missing containers something imported goes
    under added, and each group's subtree made exactly its entries (entries the importer keeps are unchanged, so they
    keep their history). Refused when a group holds an entry outside its scope."""
    stray = [dn for scope, entries in imported.groups for dn in _outside(scope, entries)]
    if stray:
        raise SystemExit(f"importer produced entries outside what it imports: {', '.join(stray)}")
    needed = tuple(c for c in imported.containers
                   if any(not _outside(c.dn, (e,)) for _, entries in imported.groups for e in entries))
    containers = tuple(c for c in needed if get(d, c.dn) is None)
    before = {e.norm: e for scope, _ in imported.groups for e in subtree(d, scope)}
    after = {e.norm: e for e in (*containers, *(e for _, entries in imported.groups for e in entries))}
    return diff(d._replace(entries=before), d._replace(entries=after))


def _held(e, attr):
    return tuple(e.classes) if attr.lower() == "objectclass" else values(e, attr)


def _mod_conflict(e, op, attr, vals):
    held = _held(e, attr)
    live = {"replace": tuple(vals), "delete": tuple(v for v in held if vals and v not in vals)}.get(op)
    if live is None or not set(held) - set(live):         # nothing the record holds goes (values only added)
        return None
    return Conflict(f"{e.dn}|{attr}", e.dn, attr, held, live)


def import_conflicts(d, changes):
    """The conflicts in an import's change records: each attribute whose values the record holds a modify would
    replace or remove (one of them at least goes), and each entry a delete would remove. What the record lacks (an
    entry, an attribute, a value or an object class added) is none."""
    def of(r):
        e = get(d, r.dn)
        if e is None:
            return ()
        if r.changetype == "delete":
            return (Conflict(e.dn, e.dn, None, ("the entry",), ()),)
        return tuple(c for op, attr, vals in r.mods for c in (_mod_conflict(e, op, attr, vals),) if c)
    return tuple(c for r in changes if r.changetype in ("modify", "delete") for c in of(r))


def _picked(keys, conflicts):
    return frozenset(c.key for c in conflicts) if ALL in keys else frozenset(keys)


def decided(changes, conflicts, take=(), keep=()):
    """The change records with each conflict decided: taken (the live value goes in) or kept (the record's stays: that
    modification, or the delete, is left out; a modify left with none is dropped). take and keep are conflict keys, or
    'all'. ValueError naming keys no conflict has, keys both taken and kept, and conflicts nobody decided."""
    taken, kept = _picked(take, conflicts), _picked(keep, conflicts)
    known = {c.key for c in conflicts}
    unknown = sorted((taken | kept) - known)
    if unknown:
        raise ValueError(f"no conflict {', '.join(unknown)} in this import")
    both = sorted(taken & kept)
    if both:
        raise ValueError(f"taken and kept: {', '.join(both)}")
    open_ = [c.key for c in conflicts if c.key not in taken | kept]
    if open_:
        raise ValueError(f"{len(open_)} conflict(s) undecided: take the live value or keep the record's for each "
                         "(--take KEY, --keep KEY, or all): " + ", ".join(open_))
    dropped = {c.key for c in conflicts if c.key in kept}

    def kept_out(r):
        if r.changetype == "delete":
            return None if r.dn in dropped else r
        if r.changetype != "modify":
            return r
        mods = tuple(m for m in r.mods if f"{r.dn}|{m[1]}" not in dropped)
        return r._replace(mods=mods) if mods else None
    return tuple(x for x in (kept_out(r) for r in changes) if x is not None)


def import_plan(d, spec, files, installed=ADAPTERS, at=None):
    """What importing files ({relative path: text}) with the importer spec names would do, the import running at `at`
    (a UTC datetime; None when not given): an ImportPlan."""
    adapter, importer = importer_named(spec, installed)
    imported = importer.read(files, d, pattern_records(installed), at)
    changes = import_changes(d, imported)
    return ImportPlan(f"{adapter.name}/{importer.name}", changes, tuple(imported.notices),
                      import_conflicts(d, changes), tuple(dict.fromkeys(scope for scope, _ in imported.groups)), at)


def confirmations(d, plan, keep=()):
    """The records clearing what the import confirms: each value an entry in its scopes holds ahead of the live system
    (core.findings.pending) awaiting this importer's adapter (or any), unless the record's differing value was kept."""
    adapter, kept = plan.importer.split("/", 1)[0], _picked(keep, plan.conflicts)
    held = {e.norm: e for scope in plan.scopes for e in subtree(d, scope) if values(e, "ciamVerifyPending")}
    return tuple(delete_values(e, "ciamVerifyPending", gone) for e in held.values()
                 for gone in (tuple(v for v, (attr, by) in zip(values(e, "ciamVerifyPending"), pending(e))
                                    if by in (None, adapter) and f"{e.dn}|{attr}" not in kept),) if gone)


def import_records(d, plan, change_id, take=(), keep=()):
    """The records applying an ImportPlan under change change_id: its change records with each conflict decided
    (decided), what it confirms (confirmations), then an import run of each scope it read (even when nothing else
    changes)."""
    return (*decided(plan.changes, plan.conflicts, take, keep), *confirmations(d, plan, keep),
            *run_records(d, plan.importer, plan.scopes, plan.at, change_id))


def preview_import(d, spec, files, installed=ADAPTERS, at=None):
    """(change records, notices) of importing files ({relative path: text}) with the importer spec names, the import
    running at `at` (a UTC datetime; None when not given)."""
    p = import_plan(d, spec, files, installed, at)
    return p.changes, p.notices
