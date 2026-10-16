"""What every part of the SiteMinder import shares: an object's settings with the sensitive ones withheld, where each
object is placed in the record, and an imported entry merged with what the record holds. Pure."""
from types import MappingProxyType
from typing import NamedTuple

from opsdir.core.directory import get, make_entry, merged_attrs, norm_dn, subtree
from opsdir.core.jsondata import canonical
from opsdir.core.secrets import scan
from .xps import FIELDS, NAME, kind, purpose, sensitive

# One XPSExport read: its objects by XID, each object's settings as the record may hold them (withheld ones out) and
# what was withheld, and the DN each object that becomes an entry is placed at (a response: the entries it becomes).
Export = NamedTuple("Export", [("objects", MappingProxyType), ("order", tuple), ("kept", MappingProxyType),
                               ("withheld", MappingProxyType), ("placed", MappingProxyType)])
SM_HELD = ("smXid", "smClass", "smConfig", "smWithheld")


def cleaned(o, patterns):
    """({property: values} of an object's settings the record may hold, ("<property>: <what it is>; re-provision in
    the target", ...) of those withheld)."""
    held = tuple(p for p, vs in o.props if sensitive(p, vs, patterns, scan))
    return ({p: vs for p, vs in o.props if p not in held},
            tuple(f"{p}: {purpose(p)}; re-provision in the target" for p in held))


def config(x, o):
    """smConfig: an object's settings the import doesn't map to an attribute of its own, as JSON (None: none)."""
    mapped = {*FIELDS.get(kind(o), {}).values(), NAME}
    rest = {p: list(vs) for p, vs in x.kept[o.xid].items() if p not in mapped}
    return canonical(rest) if rest else None


def sm_attrs(x, o):
    """The SiteMinder identity every imported entry carries (auxiliary class smObject)."""
    return {"smXid": (o.xid,), "smClass": (o.cls,), "smConfig": (config(x, o),), "smWithheld": x.withheld[o.xid]}


def facts(x, o):
    """An object's settings as source-object facts ("<property> <values>"), in property order."""
    return tuple(f"{p} {', '.join(vs)}" for p, vs in sorted(x.kept[o.xid].items()) if p != NAME)


def unique(base, name, taken):
    """name, or name-2, name-3, ... : the first not taken under base (taken: {(base, name lower-cased)})."""
    root = name or "unnamed"
    return next(n for n in (root, *(f"{root}-{i}" for i in range(2, 1000))) if (base, n.lower()) not in taken)


def entry(d, dn, classes, owned):
    """An imported entry: the attributes the import owns replaced, the rest the record holds kept (owners, what a
    change added), its classes those it has and the import's."""
    old = get(d, dn)
    names = tuple(owned)
    kept = tuple(c for c in (old.classes if old else ()) if c not in classes)
    return make_entry(dn, (*classes, *kept), merged_attrs(old, owned, names))


def with_rest(d, dn, entries):
    """(dn, entries): one group of the import, with the record's other entries below dn kept (the import replaces the
    subtree at dn with what the group holds)."""
    mine = {e.norm for e in entries}
    rest = tuple(e for e in subtree(d, dn) if e.norm not in mine and e.norm != norm_dn(dn))
    return dn, (*entries, *rest)
