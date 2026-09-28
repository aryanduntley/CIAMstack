"""Custom domain: the fields and record types operators define for the record itself, as governed entries with the
metadata that says what each is, what values it takes, which records carry it, where its value lives in real systems
and how it behaves in a migration. The store composes them into its schema (definitions.compose)."""
from ...core.contract import Domain, directory_report
from ...core.directory import children, is_a, one, rdn_value, values
from ...core.findings import owner_label
from .definitions import FIELD, fields, record_types
from .naming import CUSTOM_SCHEMA
from .schema import FRAGMENT

CUSTOM_HEADERS = ("kind", "name", "type", "applies to / extends", "status", "owner", "used by entries")


def definitions(d):
    """Every custom definition in the record (fields and record types), in DN order."""
    xs = children(d, CUSTOM_SCHEMA)
    return (*fields(xs), *record_types(xs))


def uses(d, e):
    """How many entries carry a custom field, or are of a custom record type."""
    name = rdn_value(e)
    if is_a(e, FIELD):
        return sum(1 for x in d.entries.values() if name in x.attrs)
    return sum(1 for x in d.entries.values() if name in x.classes)


def carriers(xs, field):
    """Record types that may carry a field: those it names (ciamCarriedBy), then custom record types that list it."""
    listing = (rdn_value(t) for t in record_types(xs)
               if rdn_value(field) in (*values(t, "ciamRequiredField"), *values(t, "ciamOptionalField")))
    return tuple(dict.fromkeys((*values(field, "ciamCarriedBy"), *listing)))


def _row(d, xs, e):
    if is_a(e, FIELD):
        kind, typ, where = "field", one(e, "ciamValueType"), ", ".join(carriers(xs, e)) or "-"
    else:
        kind, typ, where = "record type", (one(e, "ciamRecordKind") or "structural"), one(e, "ciamParentType") or "-"
    return (kind, rdn_value(e), typ, where, one(e, "ciamDefinitionStatus", "active"), owner_label(d, e), str(uses(d, e)))


def custom_rows(d, dn=None):
    """Report rows: every custom field and record type, fields first, with how many entries use it."""
    xs = definitions(d)
    return [_row(d, xs, e) for e in xs]


DOMAIN = Domain(name="custom", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"custom": directory_report(CUSTOM_HEADERS, custom_rows)}, checks=(), order=60,
                vocabulary={})
