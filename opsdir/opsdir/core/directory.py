"""The directory as immutable data: entries, the whole-directory snapshot, and lookups over it.

Technology-neutral. Every reader (renderers, planner, reports) is a pure function of a snapshot.
"""
import datetime as dt
import re
from types import MappingProxyType
from typing import Mapping, NamedTuple


def norm_dn(dn):
    return re.sub(r"\s*([=,])\s*", r"\1", dn.strip()).lower()


# ------------------------------------------------------------------ reads: immutable records
# An entry and the whole-directory snapshot are plain immutable records. Everything that reads
# them is a module-level function, so renderers and planners are pure functions of a snapshot.
Entry = NamedTuple("Entry", [("dn", str), ("norm", str), ("classes", tuple),
                             ("attrs", Mapping)])          # attrs: {name: (values…)}, read-only
Directory = NamedTuple("Directory", [("types", Mapping),     # {attr: {"value_type", "portability"}}
                                     ("lower_types", Mapping),   # {lowercase attr: canonical attr}
                                     ("supers", Mapping),        # {object class: superclass or None}
                                     ("entries", Mapping)])      # {normalized dn: Entry}


def _frozen(mapping):
    return MappingProxyType(dict(mapping))


def make_entry(dn, classes, attrs):
    return Entry(dn, norm_dn(dn), tuple(classes), _frozen((k, tuple(v)) for k, v in attrs.items()))


def one(e, name, default=None):
    v = e.attrs.get(name)
    return v[0] if v else default


def values(e, name):
    return e.attrs.get(name, ())


def is_a(e, oc):
    return oc in e.classes


def gtime_date(gt):
    """Date part of a GeneralizedTime value (e.g. 20261102000000Z)."""
    return dt.datetime.strptime(gt[:8], "%Y%m%d").date()


def rdn_value(e):
    return e.dn.split(",", 1)[0].split("=", 1)[1]


def make_directory(type_rows, class_rows, entry_rows):
    """Whole-directory snapshot for renderers and planners (built from rows; no I/O)."""
    types = {name: _frozen({"value_type": vt, "portability": p}) for name, vt, p in type_rows}
    entries = (make_entry(dn, classes, attrs) for dn, classes, attrs in entry_rows)
    return Directory(_frozen(types), _frozen((k.lower(), k) for k in types), _frozen(class_rows),
                     _frozen((e.norm, e) for e in entries))


# ------------------------------------------------------------------ reads: lookups
def value_type(d, name):
    t = d.types.get(name)
    return t["value_type"] if t else None


def get(d, dn):
    return d.entries.get(norm_dn(dn))


def follow(d, e, name):
    """The entry a single dn-valued attribute points at."""
    v = one(e, name)
    return get(d, v) if v else None


def follow_all(d, e, name):
    return tuple(get(d, v) for v in values(e, name))


def _lineage(supers, oc):
    return (oc, *_lineage(supers, supers.get(oc))) if oc else ()


def classes_with_supers(d, e):
    return frozenset(c for oc in e.classes for c in _lineage(d.supers, oc))


def _in_scope(n, b, scope):
    if scope == "base":
        return n == b
    if scope == "one":
        return n.endswith("," + b) and n.count(",") == b.count(",") + 1
    return n == b or n.endswith("," + b)


def in_scope(d, base, scope="sub"):
    b = norm_dn(base)
    return (e for n, e in d.entries.items() if _in_scope(n, b, scope))


def sorted_by_dn(entries):
    return tuple(sorted(entries, key=lambda e: e.dn))


def children(d, base, oc=None):
    return sorted_by_dn(e for e in in_scope(d, base, "one") if oc is None or is_a(e, oc))


def subtree(d, base, oc=None):
    return sorted_by_dn(e for e in in_scope(d, base, "sub") if oc is None or is_a(e, oc))


def referrers(d, target, attr=None):
    """(attribute, entry) pairs for every dn-valued attribute that points at target."""
    t = norm_dn(target) if isinstance(target, str) else target.norm
    return ((name, e) for e in d.entries.values() for name, vals in e.attrs.items()
            if (attr is None or name == attr) and value_type(d, name) == "dn"
            and any(norm_dn(v) == t for v in vals))
