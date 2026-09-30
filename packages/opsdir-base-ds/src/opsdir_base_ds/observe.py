"""A DS-lineage server's configuration, read from the file the server keeps it in (config/config.ldif: the cn=config
tree, ds-cfg-* attributes), as the record models it. Pure.

  database backends (JE, PDB)  -> ciamBackend (ciamBackendType je | pdb, ciamBaseDn); the server's internal backends
                                  (schema, tasks, monitor, root users, admin data, ...) are the product's, not
                                  configuration the record declares
  their indexes                -> ciamIndex, linked to the user-schema record of the indexed attribute; an attribute
                                  the record has no record for (objectClass, entryUUID, aci, ...) is named, not recorded
  password policies            -> ciamPasswordPolicy (default storage scheme, lockout, history, maximum age)
  connection handlers          -> ciamConnectionHandler, under the record's name for the handler
  log publishers               -> ciamLogPublisher
The replication topology's shape (how many replicas) can't be seen from one server, so it isn't read.

The entries are laid out as the declared configuration is (ou=backends, ou=password-policies, ...), under any base:
an observed snapshot, or the declared configuration itself.
"""
import re

from opsdir.core.directory import children, make_entry, one, rdn_value
from opsdir.core.interchange.ldif import parse
from opsdir.domains.directory.naming import USER_SCHEMA
from opsdir.domains.directory.schema import ATTRIBUTES
from .config import POLICY_PROPS

DATABASE_BACKENDS = (("ds-cfg-je-backend", "je"), ("ds-cfg-pdb-backend", "pdb"))
INDEX_TYPES = next(a.value_type for a in ATTRIBUTES if a.name == "ciamIndexType").split(":", 1)[1].split("|")
_DN_SPECIAL = re.compile(r'[,+"\\<>;=]')


# ------------------------------------------------------------------ reading config.ldif
def _records(text):
    """(dn, {lowercase attribute: values}) of every entry in the file."""
    return tuple((r.dn, {k.lower(): tuple(v) for k, v in r.attrs.items()}) for r in parse(text) if r.changetype == "add")


def _classes(attrs):
    return {c.lower() for c in attrs.get("objectclass", ())}


def _first(attrs, name):
    v = attrs.get(name)
    return v[0] if v else None


def _rdns(dn):
    """[(attribute, value), ...] of a DN, outermost last (config DNs hold no escaped commas)."""
    return [tuple(part.strip().split("=", 1)) for part in dn.split(",") if "=" in part]


def _component(dn, attr):
    return next((v for a, v in _rdns(dn) if a.lower() == attr), None)


def _bool(v):
    return (v or "false").upper()


def server_id(text):
    """The server ID the server's global configuration records (ds-cfg-server-id on cn=config), if any."""
    return next((_first(attrs, "ds-cfg-server-id") for dn, attrs in _records(text)
                 if dn.replace(" ", "").lower() == "cn=config"), None)


# ------------------------------------------------------------------ entries, as the record models them
def _ou(base, name):
    return make_entry(f"ou={name},{base}", ("top", "organizationalUnit"), {"ou": (name,)})


def _safe(name):
    return bool(name) and not _DN_SPECIAL.search(name)


def _backends(records):
    """(backend id, type, base DNs) of every database backend."""
    return tuple((_first(attrs, "ds-cfg-backend-id"), kind, attrs.get("ds-cfg-base-dn", ()))
                 for _, attrs in records for oc, kind in DATABASE_BACKENDS if oc in _classes(attrs))


def _backend_entries(records, user_attrs, base, label):
    found = _backends(records)
    backends = tuple(b for b in found if _safe(b[0]) and b[2])
    entries = tuple(make_entry(f"cn={bid},ou=backends,{base}", ("top", "ciamBackend"),
                               {"cn": (bid,), "ciamBackendType": (kind,), "ciamBaseDn": (bases[0],)})
                    for bid, kind, bases in backends)
    indexed = tuple(_indexes(records, user_attrs, base, bid, label) for bid, _, _ in backends)
    notices = (*(f"{label}: backend {bid} serves several base DNs; recorded with the first, {bases[0]} "
                 f"(also {', '.join(bases[1:])})" for bid, _, bases in backends if len(bases) > 1),
               *(f"{label}: backend {bid!r} not recorded (no base DN, or a name a record can't have)"
                 for bid, _, bases in found if (bid, _, bases) not in backends))
    return (*entries, *(e for es, _ in indexed for e in es)), (*notices, *(n for _, ns in indexed for n in ns))


def _indexes(records, user_attrs, base, backend, label):
    """(entries, notices) for one backend's indexes."""
    mine = tuple(attrs for dn, attrs in records if "ds-cfg-backend-index" in _classes(attrs)
                 and (_component(dn, "ds-cfg-backend-id") or "").lower() == backend.lower())
    placed = tuple((attrs, user_attrs.get((_first(attrs, "ds-cfg-attribute") or "").lower())) for attrs in mine)
    entries = tuple(make_entry(f"cn={rdn_value(record)},cn={backend},ou=backends,{base}", ("top", "ciamIndex"),
                               {"cn": (rdn_value(record),), "ciamIndexedAttribute": (record.dn,),
                                "ciamIndexType": tuple(t.lower() for t in attrs.get("ds-cfg-index-type", ())
                                                       if t.lower() in INDEX_TYPES)})
                    for attrs, record in placed if record is not None
                    and any(t.lower() in INDEX_TYPES for t in attrs.get("ds-cfg-index-type", ())))
    unrecorded = sorted(_first(attrs, "ds-cfg-attribute") or "?" for attrs, record in placed if record is None)
    other_types = sorted({f"{_first(attrs, 'ds-cfg-attribute')} ({t})" for attrs, record in placed if record
                          for t in attrs.get("ds-cfg-index-type", ()) if t.lower() not in INDEX_TYPES})
    notices = ((f"{label}: backend {backend}: indexes on attributes with no user-schema record, not recorded: "
                f"{', '.join(unrecorded)}",) if unrecorded else ()) + \
              ((f"{label}: backend {backend}: index types the record doesn't model, not recorded: "
                f"{', '.join(other_types)}",) if other_types else ())
    return entries, notices


def _scheme(attrs):
    v = _first(attrs, "ds-cfg-default-password-storage-scheme")
    return _component(v, "cn") if v and "=" in v else v


def _policy_entries(records, base, label):
    policies = tuple((_first(attrs, "cn"), attrs) for _, attrs in records
                     if "ds-cfg-password-policy" in _classes(attrs))
    kept = tuple((name, attrs) for name, attrs in policies if _safe(name) and _scheme(attrs))
    entries = tuple(make_entry(f"cn={name},ou=password-policies,{base}", ("top", "ciamPasswordPolicy"),
                               {"cn": (name,), "ciamStorageScheme": (_scheme(attrs),),
                                **{attr: (_first(attrs, "ds-cfg-" + prop),) for attr, prop in POLICY_PROPS
                                   if _first(attrs, "ds-cfg-" + prop) is not None}})
                    for name, attrs in kept)
    return entries, tuple(f"{label}: password policy {name!r} not recorded (no default storage scheme, or a name a "
                          f"record can't have)" for name, attrs in policies if (name, attrs) not in kept)


def _handler_entries(product, records, base, label):
    names = {v.lower(): k for k, v in product.handler_names.items()}
    handlers = tuple((names.get((_first(attrs, "cn") or "").lower(), _first(attrs, "cn")), attrs)
                     for _, attrs in records if "ds-cfg-connection-handler" in _classes(attrs))
    entries = tuple(make_entry(f"cn={name},ou=connection-handlers,{base}", ("top", "ciamConnectionHandler"),
                               {"cn": (name,), "ciamEnabled": (_bool(_first(attrs, "ds-cfg-enabled")),),
                                **({"ciamListenPort": (_first(attrs, "ds-cfg-listen-port"),)}
                                   if _first(attrs, "ds-cfg-listen-port") else {})})
                    for name, attrs in handlers if _safe(name))
    return entries, tuple(f"{label}: connection handler {name!r} not recorded (a name a record can't have)"
                          for name, _ in handlers if not _safe(name))


def _publisher_entries(records, base, label):
    publishers = tuple((_first(attrs, "cn"), attrs) for _, attrs in records
                       if "ds-cfg-log-publisher" in _classes(attrs))
    entries = tuple(make_entry(f"cn={name},ou=log-publishers,{base}", ("top", "ciamLogPublisher"),
                               {"cn": (name,), "ciamEnabled": (_bool(_first(attrs, "ds-cfg-enabled")),)})
                    for name, attrs in publishers if _safe(name))
    return entries, tuple(f"{label}: log publisher {name!r} not recorded (a name a record can't have)"
                          for name, _ in publishers if not _safe(name))


def user_attributes(d):
    """{lowercase LDAP name: user-schema record} of every attribute the record describes."""
    return {one(e, "ciamLdapName").lower(): e for e in children(d, USER_SCHEMA, "ciamUserAttribute")
            if one(e, "ciamLdapName")}


def config_entries(product, d, text, base, label):
    """(entries, notices): the configuration in a DS-lineage config.ldif as the record models it, laid out under base
    as the declared configuration is (each branch's container included when the branch has entries). label names
    the source in notices."""
    records = _records(text)
    parts = (("backends", _backend_entries(records, user_attributes(d), base, label)),
             ("password-policies", _policy_entries(records, base, label)),
             ("connection-handlers", _handler_entries(product, records, base, label)),
             ("log-publishers", _publisher_entries(records, base, label)))
    entries = tuple(e for name, (es, _) in parts for e in ((_ou(base, name), *es) if es else ()))
    return entries, tuple(n for _, (_, ns) in parts for n in ns)


# the attributes config_entries sets on each kind of entry: everything else on a record entry is the operator's
OWNED = {"organizationalUnit": ("ou",),
         "ciamBackend": ("cn", "ciamBackendType", "ciamBaseDn"),
         "ciamIndex": ("cn", "ciamIndexedAttribute", "ciamIndexType"),
         "ciamPasswordPolicy": ("cn", "ciamStorageScheme", *(attr for attr, _ in POLICY_PROPS)),
         "ciamConnectionHandler": ("cn", "ciamEnabled", "ciamListenPort"),
         "ciamLogPublisher": ("cn", "ciamEnabled")}
