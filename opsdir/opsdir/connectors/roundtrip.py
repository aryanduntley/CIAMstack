"""Round trip (files >> db >> files): an environment's render read back by the adapters' own importers. Each adapter
declares which importer reads which of its rendered files (Adapter.reads_back); reading them back against the record
the render was made from must change nothing (drift: its changes but those to meta attributes, what an import records
about where and how it read, such as a manifest's path or the Secrets a pod reads by name). What an importer withholds
(secrets) or can't read is in its notices."""
from fnmatch import fnmatchcase
from typing import NamedTuple

from ..core.directory import norm_dn, portability
from .importing import import_plan, record_after
from .registry import ADAPTERS
from .render import assemble, render_parts

# One importer's read-back of a render: importer ('adapter/importer'), the paths it read (as given to it), the changes
# reading them back would make, its notices, drift: those changes but modifications of meta attributes (() is the
# guarantee), and the scopes it read (the subtrees those changes make what the render says).
RoundTrip = NamedTuple("RoundTrip", [("importer", str), ("files", tuple), ("changes", tuple), ("notices", tuple),
                                     ("drift", tuple), ("scopes", tuple)])


def _roles(e_classes, attrs):
    return {(c, r) for c in e_classes if c != "top" for a in ("ciamBindingRole", "ciamServerRole")
            for r in attrs.get(a, ())}


def _copy(d, c):
    """Whether an add change copies an entry the record holds: same parent, an object class and role in common."""
    parent = norm_dn(c.dn.split(",", 1)[1])
    held = {cr for e in d.entries.values() if e.norm.split(",", 1)[-1] == parent
            for cr in _roles(e.classes, e.attrs)}
    return bool(_roles(c.attrs.get("objectClass", ()), c.attrs) & held)


def _drift(d, changes, intent=False):
    if intent:
        return tuple(c for c in changes if c.changetype == "delete" or (c.changetype == "add" and _copy(d, c)))
    kept = (c._replace(mods=tuple(m for m in c.mods if portability(d, m[1]) != "meta")) if c.changetype == "modify"
            else c for c in changes)
    return tuple(c for c in kept if c.changetype != "modify" or c.mods)


def _path(rb, path, environment):
    if "{environment}" in rb.place and not environment:
        raise ValueError(f"{rb.importer} reads its files from an environment's folder: name the environment")
    rest = path[len(rb.strip):] if rb.strip and path.startswith(rb.strip) else path
    return rb.place.replace("{environment}", environment or "") + rest


def selected_files(rb, rendered, environment=None):
    """{path as the importer is given it: text} of the rendered files ({path: text}) a ReadBack reads: those matching
    its glob, with its strip prefix removed and its place prefix put in front, before any prepare (ValueError when it
    places them in an environment's folder and none is given)."""
    return {_path(rb, p, environment): text for p, text in rendered.items() if fnmatchcase(p, rb.paths)}


def _one(d, spec, rb, rendered, installed, at, environment):
    selected = selected_files(rb, rendered, environment)
    if not selected:
        return None if rb.optional else RoundTrip(spec, (), (), (f"nothing rendered matches {rb.paths}",), (), ())
    files = rb.prepare(selected, d, environment) if rb.prepare else selected
    plan = import_plan(d, spec, files, installed, at)
    return RoundTrip(spec, tuple(sorted(files)), plan.changes, plan.notices, _drift(d, plan.changes, rb.intent),
                     plan.scopes)


def read_back(d, adapter, rendered, installed=ADAPTERS, at=None, environment=None):
    """(RoundTrip, ...): the rendered files ({path: text}) read back by each of adapter's ReadBacks against record d
    (the record the render was made from); environment: the cloud/env rendered, for ReadBacks placing the files in its
    folder (ValueError without it). An optional ReadBack nothing rendered matches gives no RoundTrip. A ReadBack's
    prepare turns the selected files into what its importer reads (a cloud's Terraform roots into states)."""
    trips = (_one(d, f"{adapter.name}/{rb.importer}", rb, rendered, installed, at, environment)
             for rb in adapter.reads_back)
    return tuple(rt for rt in trips if rt is not None)


# What applying a render assigns rather than what it says: a resource's provider reference. A read-back of an intent
# render gives synthetic ones; they are checked as identity (drift), never fed back into a render.
ASSIGNED = ("ciamProviderRef",)


def _replayed(changes, known):
    """The changes a second render is made from: without modifications of what the provider assigns (ASSIGNED) or of
    the (DN, attribute) pairs known not to survive a render."""
    kept = (c._replace(mods=tuple(m for m in c.mods if m[1] not in ASSIGNED and (norm_dn(c.dn), m[1]) not in known))
            if c.changetype == "modify" else c for c in changes)
    return tuple(c for c in kept if c.changetype != "modify" or c.mods)


def fixed_point(d, spec, installed=ADAPTERS, wanted=None, at=None, known=()):
    """(path, ...) of the files rendering environment spec gives differently once every read-back's changes are applied
    to record d (files >> db >> files): () when the render is a fixed point. A read-back of a render that is intent
    records what applying it would change; those changes must leave the render as it was, but for the provider
    references applying assigns (ASSIGNED). known: (DN, attribute) pairs a render can't express yet, so reading it
    back drops them; their modifications are left out."""
    trips = round_trip(d, spec, installed, wanted, at)
    gaps = {(norm_dn(dn), attr) for dn, attr in known}
    after = record_after(d, _replayed(tuple(c for rt in trips for c in rt.changes), gaps))
    first, second = (assemble(*render_parts(x, spec, installed, wanted), installed=installed) for x in (d, after))
    return tuple(sorted(p for p in {*first, *second} if first.get(p) != second.get(p)))


def round_trip(d, spec, installed=ADAPTERS, wanted=None, at=None):
    """(RoundTrip, ...): environment spec rendered as `opsdir render` writes it (render targets wanted, all by default),
    then read back by each applicable adapter's ReadBacks against the record as the environment sees it (its overrides
    applied, as the render saw it)."""
    m, adapters, neutral, specific, targets = render_parts(d, spec, installed, wanted)
    rendered = assemble(m, adapters, neutral, specific, targets, installed=installed)
    return tuple(rt for a in adapters for rt in read_back(m.d, a, rendered, installed, at, spec))
