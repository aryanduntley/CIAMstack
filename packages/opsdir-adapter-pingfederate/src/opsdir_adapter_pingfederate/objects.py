"""PingFederate's objects in the record: how one names another, and how an import merges an object's entry with what the
record holds. Pure.

PingFederate names objects by id (a validator's data store, an adapter's validators, the adapters a policy runs). The
settings keep those ids as PingFederate writes them; the record links the objects by DN as well (pingfedUses), and the
planner checks that every object named is in the record: PingFederate refuses a configuration that names one it
doesn't have.
"""
from opsdir.core.directory import get
from opsdir.core.naming import rdn_safe
from .naming import BASES, named

LABELS = {"datastore": "data store", "validator": "password credential validator", "idp-adapter": "IdP adapter",
          "selector": "authentication selector", "contract": "policy contract", "fragment": "policy fragment"}


def ref_dn(kind, ref_id):
    """The DN an object of a kind with this id has in the record, or None when it can't have one."""
    return named(BASES[kind], ref_id) if kind in BASES and isinstance(ref_id, str) and rdn_safe(ref_id) else None


def describe(kind, ref_id):
    return f"{LABELS.get(kind, kind)} `{ref_id}`"


def links(d, refs, exported):
    """(DNs of the objects named that the export or the record has, (kind, id) of those neither has)."""
    found = [(k, i, ref_dn(k, i)) for k, i in refs]
    held = [(k, i, dn) for k, i, dn in found if dn and ((k, i) in exported or get(d, dn) is not None)]
    return tuple(dict.fromkeys(dn for _, _, dn in held)), tuple((k, i) for k, i, dn in found
                                                                 if (k, i, dn) not in held)


def missing(d, refs):
    """(kind, id) of the objects named that the record doesn't have."""
    return tuple((k, i) for k, i in refs if ref_dn(k, i) is None or get(d, ref_dn(k, i)) is None)


def merged_attrs(existing, owned, names):
    """An imported entry's attributes: what the import owns (names) replaced by owned (None values dropped), everything
    the record adds to the entry (owners, a credential role) kept."""
    return {**{k: v for k, v in (existing.attrs.items() if existing else ()) if k not in names},
            **{k: tuple(x for x in v if x is not None) for k, v in owned.items() if any(x is not None for x in v)}}
