"""PingFederate's objects in the record: how one names another, and how an import merges an object's entry with what the
record holds. Pure.

PingFederate names objects by id (a validator's data store, an adapter's validators, the adapters and IdP connections
a policy runs). The settings keep those ids as PingFederate writes them; the record links the objects by DN as well
(pingfedUses), and the planner checks that every object named is in the record: PingFederate refuses a configuration
that names one it doesn't have. PingFederate's own objects are named by their ids; an IdP connection is a partner
integration of the federation domain (named as the record names it), found by the id it carries
(pingfedConnectionId): that id, not the integration's name, is the durable link, and exactly one integration may
carry it (an id two integrations claim resolves to neither, and is named).
"""
from opsdir.core.directory import get, one
from opsdir.core.naming import rdn_safe
from opsdir.domains.federation.services import integrations
from .naming import BASES, named

CONNECTION = "idp-connection"     # the kind of reference an IdP connection is
# why a reference resolves to nothing: in a plan, and on import
NOT_RECORDED = "the record doesn't have: PingFederate refuses the configuration until it is recorded"
NOT_EXPORTED = "neither the export nor the record has"
LABELS = {"datastore": "data store", "validator": "password credential validator", "idp-adapter": "IdP adapter",
          "selector": "authentication selector", "contract": "policy contract", "fragment": "policy fragment",
          CONNECTION: "IdP connection"}


def ref_dn(kind, ref_id):
    """The DN an object of a kind with this id has in the record, or None when it can't have one."""
    return named(BASES[kind], ref_id) if kind in BASES and isinstance(ref_id, str) and rdn_safe(ref_id) else None


def describe(kind, ref_id):
    return f"{LABELS.get(kind, kind)} `{ref_id}`"


def claimants(d, connection_id):
    """DNs of the partner integrations that carry this PingFederate connection id (exactly one when the record is
    sound)."""
    return tuple(i.dn for i in integrations(d, "saml2-idp") if one(i, "pingfedConnectionId") == connection_id)


def record_dn(d, kind, ref_id):
    """The DN of the object of this kind and id the record has, or None (an IdP connection id that no integration, or
    more than one, carries)."""
    if kind == CONNECTION:
        held = claimants(d, ref_id)
        return held[0] if len(held) == 1 else None
    dn = ref_dn(kind, ref_id)
    return dn if dn and get(d, dn) is not None else None


def links(d, refs, exported):
    """(DNs of the objects named that the export ({(kind, id): DN}) or the record has, (kind, id) of those neither
    has)."""
    found = [(k, i, exported.get((k, i)) or record_dn(d, k, i)) for k, i in refs]
    return tuple(dict.fromkeys(dn for _, _, dn in found if dn)), tuple((k, i) for k, i, dn in found if not dn)


def missing(d, refs):
    """(kind, id) of the objects named that the record doesn't have (or has more than one of)."""
    return tuple((k, i) for k, i in refs if record_dn(d, k, i) is None)


def why_unresolved(d, kind, ref_id, absent):
    """A reference that resolves to nothing, in words: '<kind> `<id>`, which <absent>' ('the record doesn't have',
    'neither the export nor the record has'), or, for an IdP connection id several integrations claim, which ones."""
    held = claimants(d, ref_id) if kind == CONNECTION else ()
    if len(held) > 1:
        return (f"{describe(kind, ref_id)}, which {len(held)} integrations claim "
                f"({', '.join(dn.split(',', 1)[0].split('=', 1)[1] for dn in held)}): exactly one may carry its id, so "
                "the record must give it to one")
    return f"{describe(kind, ref_id)}, which {absent}"


def merged_attrs(existing, owned, names):
    """An imported entry's attributes: what the import owns (names) replaced by owned (None values dropped), everything
    the record adds to the entry (owners, a credential role) kept."""
    return {**{k: v for k, v in (existing.attrs.items() if existing else ()) if k not in names},
            **{k: tuple(x for x in v if x is not None) for k, v in owned.items() if any(x is not None for x in v)}}
