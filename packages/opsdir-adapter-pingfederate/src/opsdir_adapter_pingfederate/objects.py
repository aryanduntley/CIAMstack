"""PingFederate's objects in the record: how one names another, and how an import merges an object's entry with what the
record holds. Pure.

PingFederate names objects by id (a validator's data store, an adapter's validators, the adapters and IdP connections
a policy runs). The settings keep those ids as PingFederate writes them; the record links the objects by DN as well
(pingfedUses), and the planner checks that every object named is in the record: PingFederate refuses a configuration
that names one it doesn't have. PingFederate's own objects are named by their ids; an IdP connection is a partner
integration of the federation domain and a key pair is a certificate of the PKI domain (each named as the record
names it), found by the id it carries (pingfedConnectionId, pingfedKeyPairId): that id, not the entry's name, is the
durable link, and exactly one entry may carry it (an id two entries claim resolves to neither, and is named).
"""
from opsdir.core.directory import children, get, one
from opsdir.core.naming import rdn_safe
from opsdir.domains.federation.services import integrations
from opsdir.domains.pki.naming import CERTIFICATES
from .naming import BASES, named

CONNECTION = "idp-connection"     # the kind of reference an IdP connection is
KEY_PAIR = "key-pair"             # ... and one of PingFederate's key pairs (its certificate)
# what the record names otherwise carries PingFederate's id for it: (the entries that may, the attribute)
CARRIERS = {CONNECTION: (lambda d: integrations(d, "saml2-idp"), "pingfedConnectionId"),
            KEY_PAIR: (lambda d: children(d, CERTIFICATES, "ciamCertificate"), "pingfedKeyPairId")}
# why a reference resolves to nothing: in a plan, and on import
NOT_RECORDED = "the record doesn't have: PingFederate refuses the configuration until it is recorded"
NOT_EXPORTED = "neither the export nor the record has"
LABELS = {"datastore": "data store", "validator": "password credential validator", "idp-adapter": "IdP adapter",
          "selector": "authentication selector", "contract": "policy contract", "fragment": "policy fragment",
          "access-token-manager": "access token manager", "oidc-policy": "OIDC policy", CONNECTION: "IdP connection",
          KEY_PAIR: "key pair"}


def ref_dn(kind, ref_id):
    """The DN an object of a kind with this id has in the record, or None when it can't have one."""
    return named(BASES[kind], ref_id) if kind in BASES and isinstance(ref_id, str) and rdn_safe(ref_id) else None


def describe(kind, ref_id):
    return f"{LABELS.get(kind, kind)} `{ref_id}`"


def claimants(d, kind, ref_id):
    """DNs of the entries carrying PingFederate's id for an object the record names otherwise (an IdP connection's
    partner integration, a key pair's certificate): exactly one when the record is sound."""
    entries, attr = CARRIERS[kind]
    return tuple(e.dn for e in entries(d) if one(e, attr) == ref_id)


def record_dn(d, kind, ref_id):
    """The DN of the object of this kind and id the record has, or None (an IdP connection or key pair id that no
    entry, or more than one, carries)."""
    if kind in CARRIERS:
        held = claimants(d, kind, ref_id)
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
    'neither the export nor the record has'), or, for an IdP connection or key pair id several entries claim, which
    ones."""
    held = claimants(d, kind, ref_id) if kind in CARRIERS else ()
    if len(held) > 1:
        return (f"{describe(kind, ref_id)}, which {len(held)} entries claim "
                f"({', '.join(dn.split(',', 1)[0].split('=', 1)[1] for dn in held)}): exactly one may carry its id, so "
                "the record must give it to one")
    return f"{describe(kind, ref_id)}, which {absent}"


def merged_attrs(existing, owned, names):
    """An imported entry's attributes: what the import owns (names) replaced by owned (None values dropped), everything
    the record adds to the entry (owners, a credential role) kept."""
    return {**{k: v for k, v in (existing.attrs.items() if existing else ()) if k not in names},
            **{k: tuple(x for x in v if x is not None) for k, v in owned.items() if any(x is not None for x in v)}}
