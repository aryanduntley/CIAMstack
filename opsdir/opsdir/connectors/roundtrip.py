"""Round trip (files >> db >> files): an environment's render read back by the adapters' own importers. Each adapter
declares which importer reads which of its rendered files (Adapter.reads_back); reading them back against the record
the render was made from must change nothing (drift: its changes but those to meta attributes, what an import records
about where and how it read, such as a manifest's path or the Secrets a pod reads by name). What an importer withholds
(secrets) or can't read is in its notices."""
from fnmatch import fnmatchcase
from typing import NamedTuple

from ..core.directory import portability
from .importing import import_plan
from .registry import ADAPTERS
from .render import assemble, render_parts

# One importer's read-back of a render: importer ('adapter/importer'), the paths it read (as given to it), the changes
# reading them back would make, its notices, and drift: those changes but modifications of meta attributes (() is the
# guarantee).
RoundTrip = NamedTuple("RoundTrip", [("importer", str), ("files", tuple), ("changes", tuple), ("notices", tuple),
                                     ("drift", tuple)])


def _drift(d, changes):
    kept = (c._replace(mods=tuple(m for m in c.mods if portability(d, m[1]) != "meta")) if c.changetype == "modify"
            else c for c in changes)
    return tuple(c for c in kept if c.changetype != "modify" or c.mods)


def _path(rb, path, environment):
    if "{environment}" in rb.place and not environment:
        raise ValueError(f"{rb.importer} reads its files from an environment's folder: name the environment")
    rest = path[len(rb.strip):] if rb.strip and path.startswith(rb.strip) else path
    return rb.place.replace("{environment}", environment or "") + rest


def _one(d, spec, rb, rendered, installed, at, environment):
    files = {_path(rb, p, environment): text for p, text in rendered.items() if fnmatchcase(p, rb.paths)}
    if not files:
        return RoundTrip(spec, (), (), (f"nothing rendered matches {rb.paths}",), ())
    plan = import_plan(d, spec, files, installed, at)
    return RoundTrip(spec, tuple(sorted(files)), plan.changes, plan.notices, _drift(d, plan.changes))


def read_back(d, adapter, rendered, installed=ADAPTERS, at=None, environment=None):
    """(RoundTrip, ...): the rendered files ({path: text}) read back by each of adapter's ReadBacks against record d
    (the record the render was made from); environment: the cloud/env rendered, for ReadBacks placing the files in its
    folder (ValueError without it)."""
    return tuple(_one(d, f"{adapter.name}/{rb.importer}", rb, rendered, installed, at, environment)
                 for rb in adapter.reads_back)


def round_trip(d, spec, installed=ADAPTERS, wanted=None, at=None):
    """(RoundTrip, ...): environment spec rendered as `opsdir render` writes it (render targets wanted, all by default),
    then read back by each applicable adapter's ReadBacks against the record as the environment sees it (its overrides
    applied, as the render saw it)."""
    m, adapters, neutral, specific, targets = render_parts(d, spec, installed, wanted)
    rendered = assemble(m, adapters, neutral, specific, targets)
    return tuple(rt for a in adapters for rt in read_back(m.d, a, rendered, installed, at, spec))
