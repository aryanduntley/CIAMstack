"""Change sets: the difference between two directory snapshots as LDIF change records.

Adds come first (parents before children), then modifies, then deletes (children before parents), so applying the
records in order to the first snapshot gives the second, and every DN reference resolves when the store commits.
A modify replaces each changed attribute (and the object classes when the set of them changes) and deletes removed
ones.
Technology-neutral and pure.
"""
from .interchange.ldif import LdifRecord


def _depth(e):
    return e.norm.count(",")


def _add(e):
    return LdifRecord(e.dn, "add", {"objectClass": tuple(e.classes), **dict(e.attrs)}, ())


def _delete(e):
    return LdifRecord(e.dn, "delete", {}, ())


def entry_mods(old, new):
    """The modify operations that turn one entry into the other (empty when they are equal)."""
    classes = (("replace", "objectClass", tuple(new.classes)),) if set(old.classes) != set(new.classes) else ()
    names = dict.fromkeys((*old.attrs, *new.attrs))
    return classes + tuple(("delete", n, ()) if n not in new.attrs else ("replace", n, tuple(new.attrs[n]))
                           for n in names if old.attrs.get(n) != new.attrs.get(n))


def diff(base, current):
    """LDIF change records that turn the `base` snapshot into `current`."""
    b, c = base.entries, current.entries
    adds = sorted((c[n] for n in c if n not in b), key=lambda e: (_depth(e), e.norm))
    modifies = tuple(LdifRecord(c[n].dn, "modify", {}, entry_mods(b[n], c[n]))
                     for n in sorted(c) if n in b and entry_mods(b[n], c[n]))
    deletes = sorted((b[n] for n in b if n not in c), key=lambda e: (-_depth(e), e.norm))
    return (*map(_add, adds), *modifies, *map(_delete, deletes))
