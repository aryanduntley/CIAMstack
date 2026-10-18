"""Browse and edit the record by its schema (milestone 7.8): area (the core, a domain or an adapter package: the schema
reference's parts) -> kind (an object class) -> entries -> one entry's fields, each with its value, type, portability,
whether it is required and what it holds, and the optional fields still empty. Generated from the store's registry
(custom fields and record types included), so a new adapter's kinds appear without code here. An edit is the modify
record of --set / --add / --remove values on one entry; the store checks it (operations.preview_edit) and it is applied
under an approved change or proposed for someone else to approve. Pure."""
from functools import reduce
from typing import NamedTuple

from ..core.directory import get
from ..core.interchange.ldif import LdifRecord

# The store's registry: {lower name: AttributeInfo} and {lower name: ClassInfo} (registry_rows rows)
AttributeInfo = NamedTuple("AttributeInfo", [("name", str), ("oid", str), ("value_type", str), ("portability", str),
                                             ("single_value", bool), ("description", str), ("rules", dict),
                                             ("origin", str)])
ClassInfo = NamedTuple("ClassInfo", [("name", str), ("oid", str), ("sup", str), ("kind", str), ("must", tuple),
                                     ("may", tuple), ("description", str), ("origin", str)])
Registry = NamedTuple("Registry", [("attributes", dict), ("classes", dict)])

STANDARD = "standard"          # the area of the standard LDAP classes (containers)
CUSTOM = "custom"              # the origin of the record's own definitions
RECORD_TYPES = "record-types"  # the area of the record's own record types (the custom domain's area holds their
                               # definitions)
AREA_HEADERS = ("area", "kind", "kinds", "entries")
KIND_HEADERS = ("kind", "type", "entries", "description")
ENTRY_HEADERS = ("entry",)
FIELD_HEADERS = ("field", "value", "type", "portability", "required", "description")
NOT_EDITABLE = ("objectclass",)


def registry_from_rows(attribute_rows, class_rows):
    """The Registry of store.postgres.registry_rows."""
    return Registry({r[0].lower(): AttributeInfo(r[0], r[1], r[2], r[3], bool(r[4]), r[5] or "", r[6] or {},
                                                 r[7] or "") for r in attribute_rows},
                    {r[0].lower(): ClassInfo(r[0], r[1], r[2], r[3], tuple(r[4] or ()), tuple(r[5] or ()),
                                             r[6] or "", r[7] or "") for r in class_rows})


def _areas(parts, registry):
    """((slug, title, kind, (class name, ...)), ...): each part's classes, then the record's custom classes, then the
    standard ones nothing defines."""
    defined = {c.name.lower() for p in parts for c in p.fragment.classes}
    custom = tuple(c.name for k, c in sorted(registry.classes.items())
                   if k not in defined and c.origin.lower().startswith(CUSTOM))
    standard = tuple(c.name for k, c in sorted(registry.classes.items())
                     if k not in defined and c.name not in custom and k != "top")
    return (*((p.slug, p.title, p.kind, tuple(sorted(c.name for c in p.fragment.classes))) for p in parts),
            *(((RECORD_TYPES, "Record types", "record", custom),) if custom else ()),
            (STANDARD, "Standard LDAP", "standard", standard))


def _count(d, cls):
    lower = cls.lower()
    return sum(1 for e in d.entries.values() if any(c.lower() == lower for c in e.classes))


def area_named(parts, registry, name):
    """(slug, title, kind, classes) of the area a name (slug or title, any case) names, or None."""
    return next((a for a in _areas(parts, registry) if name.lower() in (a[0].lower(), a[1].lower())), None)


def area_rows(d, parts, registry):
    """One row per area (AREA_HEADERS): its slug, what it is, how many kinds it defines and how many entries hold one
    of its structural kinds (areas holding no entry included, so what the installed parts can hold shows)."""
    def entries(classes):
        lower = {c.lower() for c in classes if registry.classes.get(c.lower(), ClassInfo(*(("",) * 8))).kind
                 == "STRUCTURAL"}
        return sum(1 for e in d.entries.values() if lower & {c.lower() for c in e.classes})
    return [(slug, kind, len(classes), entries(classes)) for slug, _, kind, classes in _areas(parts, registry)]


def kind_rows(d, registry, classes):
    """One row per kind (object class) of an area (KIND_HEADERS): its name, structural/auxiliary/abstract, how many
    entries hold it, what it is."""
    return [(c, registry.classes[c.lower()].kind.lower(), _count(d, c), registry.classes[c.lower()].description)
            for c in classes if c.lower() in registry.classes]


def entry_rows(d, cls):
    """One row per entry holding a kind (ENTRY_HEADERS: its DN), in tree order."""
    lower = cls.lower()
    held = (e for e in d.entries.values() if any(c.lower() == lower for c in e.classes))
    return [(e.dn,) for e in sorted(held, key=lambda e: tuple(reversed(e.norm.split(","))))]


def _closure(registry, classes):
    """The classes and every superclass they inherit from, each once (unknown names left out)."""
    def up(name, seen):
        info = registry.classes.get((name or "").lower())
        if info is None or info.name in seen:
            return seen
        return up(info.sup, (*seen, info.name))
    return reduce(lambda seen, c: up(c, seen), classes, ())


def entry_fields(registry, entry):
    """(required names, allowed names) of an entry: the MUST and MAY attributes of its classes and their superclasses,
    canonical names, each once, in the order the classes give them."""
    infos = [registry.classes[c.lower()] for c in _closure(registry, entry.classes)]
    must = tuple(dict.fromkeys(a for i in infos for a in i.must))
    return must, tuple(dict.fromkeys((*must, *(a for i in infos for a in i.may))))


def _value(vals):
    return " | ".join(vals)


def field_rows(registry, entry):
    """(rows of the fields an entry holds (FIELD_HEADERS), the optional fields it may hold that are empty): each field's
    values, value type, portability, whether its classes require it and what it holds; objectClass first."""
    must, allowed = entry_fields(registry, entry)
    held = {k.lower(): (k, v) for k, v in entry.attrs.items()}

    def row(name, vals):
        info = registry.attributes.get(name.lower())
        return (name, _value(vals), info.value_type if info else "", info.portability if info else "",
                "yes" if name.lower() in {m.lower() for m in must} else "", info.description if info else "")
    rows = [("objectClass", _value(entry.classes), "", "", "yes", "the entry's object classes"),
            *(row(k, v) for k, v in held.values())]
    empty = tuple(a for a in allowed if a.lower() not in held and a.lower() != "objectclass")
    return rows, empty


# ------------------------------------------------------------------ edits
def parsed_edits(pairs, what):
    """((attribute, value), ...) of ATTR=VALUE arguments, both stripped (ATTR alone: no value, for --remove);
    ValueError naming a --set or --add without '=' or with an empty value."""
    def one(text):
        name, eq, value = text.partition("=")
        if not name.strip() or (not eq and what != "remove") or (eq and not value.strip()):
            raise ValueError(f"--{what} {text}: give ATTRIBUTE=VALUE (to clear a field: --remove ATTRIBUTE)")
        return name.strip(), value.strip() if eq else None
    return tuple(one(p) for p in pairs)


def _canonical(registry, name):
    info = registry.attributes.get(name.lower())
    if info is None:
        raise ValueError(f"no attribute {name} in the schema (`opsdir browse` lists each kind's fields)")
    if name.lower() in NOT_EDITABLE:
        raise ValueError(f"{name} isn't edited here: an entry's object classes change by `opsdir modify`")
    return info.name


def _grouped(registry, pairs):
    """{canonical attribute: (value, ...)} of (attribute, value) pairs, values in order (None values left out)."""
    names = tuple(dict.fromkeys(_canonical(registry, n) for n, _ in pairs))
    return {n: tuple(v for a, v in pairs if _canonical(registry, a) == n and v is not None) for n in names}


def _once(values):
    return tuple(dict.fromkeys(values))


def _final(held, set_to, added, removed, whole):
    """An attribute's values after an edit: --set values (else what it holds), then --add values it lacks, then
    --remove values left out (all of them when the whole attribute is removed)."""
    if whole:
        return ()
    base = set_to if set_to is not None else held
    return tuple(v for v in _once((*base, *added)) if v not in removed)


def edit_record(d, registry, dn, sets=(), adds=(), removes=()):
    """The modify record of an edit to the entry at dn: each touched attribute's values as the edit leaves them
    (--set values replace what it holds, --add values it lacks are added, --remove values are taken out, a --remove
    with no value removes the whole attribute), written as a replace, or a delete when none are left. ValueError when
    there is no such entry, an attribute isn't in the schema or is objectClass, an attribute is both set and removed,
    or the edit changes nothing. The store's own checks (the classes' attributes, types, rules, vocabulary, single
    values, required attributes, secret material) run on the result (operations.preview_edit)."""
    entry = get(d, dn)
    if entry is None:
        raise ValueError(f"no entry {dn}")
    held = {k.lower(): (k, tuple(v)) for k, v in entry.attrs.items()}
    set_to, added, removed = (_grouped(registry, x) for x in (sets, adds, removes))
    both = sorted(set(set_to) & set(removed))
    if both:
        raise ValueError(f"{', '.join(both)}: set and removed in one edit; give one or the other")
    whole = {n for n, _ in removes if not any(v for a, v in removes if a.lower() == n.lower())}
    whole = {_canonical(registry, n) for n in whole}
    names = tuple(dict.fromkeys((*set_to, *added, *removed)))
    final = {n: _final(held.get(n.lower(), (n, ()))[1], set_to.get(n), added.get(n, ()), removed.get(n, ()),
                       n in whole) for n in names}
    mods = tuple(("replace", n, v) if v else ("delete", n, ()) for n, v in final.items()
                 if v != held.get(n.lower(), (n, ()))[1] and (v or n.lower() in held))
    if not mods:
        raise ValueError(f"the edit changes nothing in {entry.dn}")
    return LdifRecord(entry.dn, "modify", {}, mods)


def is_dn(text):
    """Whether a browse argument is a DN (it names an entry) rather than an area or kind."""
    return "=" in text
