"""Findings: what a check reports. Every planner check returns one; a plan is their concatenation."""
from itertools import chain
from typing import NamedTuple

from .directory import get, rdn_value, values

# blockers: (area, text, owner); actions: (area, text, owner, do_by or None); ok: text;
# requests: (party entry, allowlist entry, new address, role, do_by)
Findings = NamedTuple("Findings", [("blockers", tuple), ("actions", tuple), ("ok", tuple), ("requests", tuple)])


def findings(blockers=(), actions=(), ok=(), requests=()):
    return Findings(tuple(blockers), tuple(actions), tuple(ok), tuple(requests))


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
