"""Custom definitions composed into the schema: the fields and record types operators define as entries under
ou=custom-schema become attribute types and object classes under the custom arc, and each field joins the record
types it applies to. Pure: the input is the code-owned fragments and the definition entries; problems refuse the
composition (so a definition that can't be built is never accepted).
"""
import re

from ...core.directory import is_a, one, values
from ...core.standard import (CUSTOM_ARC, OVERRIDABLE, STANDARD_CLASSES, SYNTAX, AttributeDef, ClassDef,
                              check_fragments, fragment)
from .naming import PREFIX

FIELD, RECORD_TYPE = "ciamFieldDefinition", "ciamRecordTypeDefinition"
ORIGIN = "custom"
VALUE_TYPES = tuple(t for t in SYNTAX if t != "vocab")      # vocab values belong to installed domains and adapters
NUMERIC = ("int", "port")
_NAME = re.compile(rf"^{PREFIX}[A-Za-z0-9][A-Za-z0-9-]*$")
# definition attribute -> value rule the store enforces (X- extension)
RULES = (("ciamMinValue", "X-MIN"), ("ciamMaxValue", "X-MAX"), ("ciamPattern", "X-PATTERN"),
         ("ciamMaxLength", "X-MAX-LENGTH"))


def fields(entries):
    return tuple(e for e in entries if is_a(e, FIELD))


def record_types(entries):
    return tuple(e for e in entries if is_a(e, RECORD_TYPE))


def _name(e):
    return one(e, "cn")


def _description(e):
    return one(e, "description") or one(e, "ciamPurpose") or _name(e)


def rules(e):
    """The value rules a field definition states, as X- extensions (and X-OVERRIDABLE when an environment may
    override it)."""
    return (*((x, one(e, attr)) for attr, x in RULES if one(e, attr) is not None),
            *(OVERRIDABLE if one(e, "ciamOverridable") == "TRUE" else ()))


def field_def(e):
    return AttributeDef(int(one(e, "ciamDefinitionNumber")), _name(e), one(e, "ciamValueType"),
                        one(e, "ciamPortability"), one(e, "ciamMultiValued") != "TRUE", _description(e), rules(e))


def applied(entries):
    """{record type: fields that apply to it}, fields in definition order."""
    pairs = [(t, _name(f)) for f in fields(entries) for t in values(f, "ciamCarriedBy")]
    return {t: tuple(n for tt, n in pairs if tt == t) for t in dict.fromkeys(t for t, _ in pairs)}


def _kind(e):
    return (one(e, "ciamRecordKind") or "structural").upper()


def record_type_def(e, extra_may=()):
    parent = one(e, "ciamParentType") or ("top" if _kind(e) == "AUXILIARY" else "ciamObject")
    required = tuple(values(e, "ciamRequiredField"))
    must = ("cn", *required) if _kind(e) == "STRUCTURAL" else required
    may = tuple(dict.fromkeys(x for x in (*values(e, "ciamOptionalField"), *extra_may) if x not in must))
    return ClassDef(int(one(e, "ciamDefinitionNumber")), _name(e), parent, _kind(e), must, may, _description(e))


def custom_fragment(entries):
    """The definitions as a fragment under the custom arc (record types already carry the fields applied to them)."""
    extra = applied(entries)
    return fragment((field_def(f) for f in fields(entries)),
                    (record_type_def(t, extra.get(_name(t), ())) for t in record_types(entries)), CUSTOM_ARC, ORIGIN)


def _extended(f, extra):
    classes = tuple(c._replace(may=c.may + tuple(x for x in extra.get(c.name, ()) if x not in c.must + c.may))
                    for c in f.classes)
    return f._replace(classes=classes)


def compose(fragments, entries):
    """The code-owned fragments with custom fields added to the record types they apply to, then the custom fragment.
    Standard LDAP classes (top, organizationalUnit, domain) are the standard's and take no custom fields."""
    extra = applied(entries)
    return (*(_extended(f, extra) for f in fragments), custom_fragment(entries)) if entries else tuple(fragments)


def _value_type_ok(vt):
    return vt in VALUE_TYPES or (vt.startswith("enum:") and all(vt[5:].split("|")))


def _regex_ok(pattern):
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def _field_problems(e):
    name, vt = _name(e), one(e, "ciamValueType") or ""
    lo, hi = one(e, "ciamMinValue"), one(e, "ciamMaxValue")
    checks = (
        (not _value_type_ok(vt), f"value type {vt!r} is not one of {', '.join(VALUE_TYPES)} or enum:a|b"),
        ((lo is not None or hi is not None) and vt not in NUMERIC, f"min/max apply to int and port fields, not {vt}"),
        (lo is not None and hi is not None and int(lo) > int(hi), f"min {lo} is above max {hi}"),
        (one(e, "ciamPattern") is not None and not _regex_ok(one(e, "ciamPattern")),
         f"pattern {one(e, 'ciamPattern')!r} is not a regular expression"),
        ((one(e, "ciamPattern") is not None or one(e, "ciamMaxLength") is not None) and vt == "bool",
         "pattern and max length don't apply to bool fields"))
    return tuple(f"field {name}: {text}" for failed, text in checks if failed)


def _known_classes(fragments, entries):
    return ({c[0] for c in STANDARD_CLASSES} | {c.name for f in fragments for c in f.classes}
            | {_name(t) for t in record_types(entries)})


def problems(fragments, entries):
    """Why the definitions can't be composed with the code-owned fragments (empty when they can)."""
    names = [_name(e) for e in entries]
    code_classes = {c.name for f in fragments for c in f.classes}
    known = _known_classes(fragments, entries)
    own = (
        [f"{n}: custom names start with '{PREFIX}' and use letters, digits and hyphens" for n in names
         if not _NAME.match(n)]
        + [p for f in fields(entries) for p in _field_problems(f)]
        + [f"field {_name(f)} applies to unknown record type {t}" for f in fields(entries)
           for t in values(f, "ciamCarriedBy") if t not in known]
        + [f"field {_name(f)} can't apply to the standard class {t}" for f in fields(entries)
           for t in values(f, "ciamCarriedBy") if t in {c[0] for c in STANDARD_CLASSES} and t not in code_classes])
    return tuple(own) or check_fragments(compose(fragments, entries))
