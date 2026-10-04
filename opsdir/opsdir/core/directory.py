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


def rdn_of(dn):
    """The value of a DN's first RDN (ou=jobs,dc=x -> jobs)."""
    return dn.split(",", 1)[0].split("=", 1)[1]


def within(dn, base):
    """Whether dn is base or an entry below it."""
    n, b = norm_dn(dn), norm_dn(base)
    return n == b or n.endswith("," + b)


def ou_entry(dn):
    """An organizationalUnit entry at dn, its ou the RDN's value: the container an importer adds when missing."""
    return make_entry(dn, ("top", "organizationalUnit"), {"ou": (rdn_of(dn),)})


def one(e, name, default=None):
    v = e.attrs.get(name)
    return v[0] if v else default


def values(e, name):
    return e.attrs.get(name, ())


def is_a(e, oc):
    return oc in e.classes


def gtime(at):
    """GeneralizedTime text (UTC) of a datetime, as the record holds times (20261102000000Z); naive is taken as UTC."""
    utc = at if at.tzinfo else at.replace(tzinfo=dt.timezone.utc)
    return utc.astimezone(dt.timezone.utc).strftime("%Y%m%d%H%M%SZ")


def gtime_of_iso(text):
    """GeneralizedTime of an ISO 8601 time (Z allowed; no zone is UTC), or None when the text isn't one."""
    try:
        return gtime(dt.datetime.fromisoformat(str(text or "").replace("Z", "+00:00")))
    except ValueError:
        return None


def fingerprint(v):
    """A certificate fingerprint as the record writes it: uppercase hex pairs joined by colons."""
    h = re.sub(r"[^0-9A-Fa-f]", "", v or "").upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def gtime_date(gt):
    """Date part of a GeneralizedTime value (e.g. 20261102000000Z)."""
    return dt.datetime.strptime(gt[:8], "%Y%m%d").date()


def date_of(e, attr):
    """The date of an entry's time attribute, or None when it holds none."""
    v = one(e, attr)
    return gtime_date(v) if v else None


def rdn_value(e):
    return rdn_of(e.dn)


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


def is_subclass(d, oc, of):
    """Whether object class oc is `of` or one of its subclasses (as far as the directory's registry knows)."""
    return of in _lineage(d.supers, oc)


def is_kind(d, e, oc):
    """Whether an entry is of an object class or one of its subclasses (a ciamBackupTarget is a ciamObjectStore)."""
    return any(is_subclass(d, c, oc) for c in e.classes)


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


def merged_attrs(existing, owned, names):
    """An imported entry's attributes: those an importer owns (names) replaced by owned (None values dropped), and
    everything else the record holds on the entry (owners, a credential role, what operators add) kept."""
    return {**{k: v for k, v in (existing.attrs.items() if existing else ()) if k not in names},
            **{k: tuple(x for x in v if x is not None) for k, v in owned.items() if any(x is not None for x in v)}}
