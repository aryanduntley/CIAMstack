"""Findings: what a check reports. Every planner check returns one; a plan is their concatenation."""
from collections import namedtuple
from itertools import chain
from typing import NamedTuple

from .changeset import new_entry, set_values

from .directory import get, portability, rdn_value, value_type, values, within
from .naming import branch

# A change to the record that resolves a finding, offered for an operator (or an AI) to apply under an approved change
# or handle by hand: key: a stable name (area and what it changes); title: what it does, in words; records: the LDIF
# change records it applies (never secret values, observed facts or attestations); manual: the steps outside the
# record that go with it (a live change, a party's confirmation); risks: what applying it could hide.
# options: when the fix is a choice (which secret role, which claimant to keep), each Option's records instead of the
# fix's own; nothing is proposed or applied without one being chosen (connectors.fixes.chosen).
Fix = namedtuple("Fix", ("key", "area", "title", "records", "manual", "risks", "options"), defaults=((),))
# One choice a fix offers: key (what to pass to choose it), label (it in words), records, risks of its own.
Option = NamedTuple("Option", [("key", str), ("label", str), ("records", tuple), ("risks", tuple)])
# A value the operator gives (a provider reference, a DNS name, a bucket): it stands in a record's values (an add's
# attribute, a modify's values) where its values go once given (connectors.fixes.chosen); nothing with an Input left
# is proposed or applied. key: what to give it as; label: it in words; default: the values it takes when none are given
# (none: it must be given); example: what a value looks like (the source's own, for a binding); pattern: a regular
# expression each value must match. Never a secret: an input is a reference or a name, like every value in the record.
Input = namedtuple("Input", ("key", "label", "default", "example", "pattern"), defaults=((), (), None))


def choice_fix(key, area, title, entry, attr, choices, manual=(), risks=()):
    """A Fix setting an attribute of an entry to one of choices ((value, label, its own risks), ...): an option each,
    in the order given; None when there is nothing to choose from."""
    options = tuple(Option(value, label, (set_values(entry, attr, (value,)),), tuple(own))
                    for value, label, own in choices)
    return Fix(key, area, title, (), tuple(manual), tuple(risks), options) if options else None


# ------------------------------------------------------------------ inputs
def _record_values(r):
    return (v for vs in (*r.attrs.values(), *(m[2] for m in r.mods)) for v in vs)


def fix_inputs(records):
    """The Inputs change records hold, each once, in the order they first appear."""
    return tuple(dict.fromkeys(v for r in records for v in _record_values(r) if isinstance(v, Input)))


def _filled(vals, given):
    return tuple(x for v in vals for x in (given[v.key] if isinstance(v, Input) else (v,)))


def _filled_record(r, given):
    attrs = {k: f for k, f in ((k, _filled(v, given)) for k, v in r.attrs.items()) if f}
    mods = tuple((op, attr, f) for op, attr, v in r.mods for f in (_filled(v, given),) if f or not v)
    return r._replace(attrs=attrs, mods=mods)


def filled_records(records, given):
    """The change records with each Input replaced by its values ({key: values}). An input given no values leaves its
    attribute out of an add, and its modification out of a modify (a modify left with none is dropped)."""
    return tuple(f for f in (_filled_record(r, given) for r in records) if f.changetype != "modify" or f.mods)


def _template_value(d, attr, vals, home, prefix):
    """What a templated entry holds for an attribute: its values, an Input (its key the attribute's name after
    prefix), or None (left out)."""
    kind, is_dn = portability(d, attr), value_type(d, attr) in ("dn", "extdn")
    placed = is_dn and any(within(v, home) for v in vals)
    own = kind not in ("binding", "secret-ref", "contract") and (
        value_type(d, attr) == "time" or (is_dn and any(within(v, branch("changes")) for v in vals)))
    if kind == "observed" or own:
        return None
    if placed or (kind in ("binding", "secret-ref") and not is_dn):
        return (Input(prefix + attr, "this environment's own (the source's names its place)", (), tuple(vals)),)
    if kind in ("binding", "secret-ref", "contract"):
        return (Input(prefix + attr, "the source's, unless changed deliberately", tuple(vals), tuple(vals)),)
    return tuple(vals)


def bindings_container(d, dn):
    """The records adding the bindings container (ou=bindings) of the environment at dn: none when it has one."""
    container = f"ou=bindings,{dn}"
    return () if get(d, container) else (new_entry(container, ("top", "organizationalUnit"), {"ou": ("bindings",)}),)


def templated_entry(d, entry, dn, home, prefix=""):
    """The add record copying entry (of the environment at DN home) to dn, its Inputs in place of what is bound to a
    place: binding and secret-reference values, and DNs under home, are given for the new place (the entry's own as
    the example, never a default: copied, they would point at the source's resources); contract values, and binding
    DNs naming something outside home (a consumer), default to the entry's own; intent and meta values are copied,
    except dates and change references (when it was reviewed, tested or changed, and by which change, are the entry's
    own), and observed facts are left out. Each
    Input's key is the attribute's name after prefix (telling apart the entries one fix templates)."""
    attrs = {a: t for a, vals in entry.attrs.items() for t in (_template_value(d, a, vals, home, prefix),)
             if t is not None}
    return new_entry(dn, entry.classes, attrs)

# blockers: (area, text, owner); actions: (area, text, owner, do_by or None); ok: text;
# requests: (party entry, allowlist entry, new address, role, do_by); fixes: Fix
Findings = NamedTuple("Findings", [("blockers", tuple), ("actions", tuple), ("ok", tuple), ("requests", tuple),
                                   ("fixes", tuple)])


def findings(blockers=(), actions=(), ok=(), requests=(), fixes=()):
    return Findings(tuple(blockers), tuple(actions), tuple(ok), tuple(requests), tuple(fixes))


def merge_findings(parts):
    return Findings(*(tuple(chain.from_iterable(column)) for column in zip(*parts))) if parts else findings()


def responsible(d, *entries):
    """Owners of the first of these entries that has any (e.g. a service, then its environment),
    or **NO OWNER**. Findings name whoever owns the thing they are about, never a hardcoded team."""
    owned = next((e for e in entries if e is not None and values(e, "ciamOwner")), None)
    return owner_label(d, owned) if owned else "**NO OWNER**"


def owner_label(d, e):
    """Comma-joined names of an entry's owners, or **NO OWNER**."""
    return ", ".join(rdn_value(get(d, o)) for o in values(e, "ciamOwner")) or "**NO OWNER**"
