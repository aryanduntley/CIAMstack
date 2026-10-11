"""The user directory's schema read back from a subschema LDIF (schema.py renders ldap/schema.ldif; a server's
subschema export has the same definitions): each RFC 4512 definition onto the user-schema record of its LDAP name.
Pure.

  attributeTypes   -> ciamUserAttribute: OID, DESC (its purpose), EQUALITY, SUBSTR, ORDERING, SYNTAX, SINGLE-VALUE
  objectClasses    -> ciamUserObjectClass: OID, DESC, SUP, kind, MUST and MAY (the attributes' records)
What only the record says (PII class, retention, export control, owners) is kept. Where the render writes a default
for a value the record leaves unset (SUP top; no SINGLE-VALUE), the record's absence (or FALSE) stays. A definition
the record has no record for is named, not recorded: an attribute record needs its PII class, which no schema gives.
"""
from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import children, make_entry, merged_attrs, one
from opsdir.core.interchange.ldif import parse
from opsdir.core.interchange.rfc4512 import attribute_type, object_class
from opsdir.domains.directory.naming import USER_SCHEMA
from opsdir.domains.directory.user_schema import attribute_records

ATTRIBUTE_OWNED = ("ciamLdapOid", "ciamPurpose", "ciamLdapEquality", "ciamLdapSubstring", "ciamLdapOrdering",
                   "ciamLdapSyntax", "ciamLdapSingleValue")
CLASS_OWNED = ("ciamLdapOid", "ciamPurpose", "ciamLdapSuperior", "ciamLdapClassKind", "ciamLdapMust", "ciamLdapMay")


def _values(text, name):
    """Every value of attribute name (any case) on any record of the LDIF, added or modified."""
    return tuple(v for r in parse(text)
                 for vals in ((v for k, v in r.attrs.items() if k.lower() == name.lower()),
                              (m[2] for m in r.mods if m[1].lower() == name.lower()))
                 for vs in vals for v in vs)


def _parsed(parse_one, defs, what):
    """((definition dict, None) | (None, notice), ...)."""
    def one_of(defn):
        try:
            return parse_one(defn), None
        except (ValueError, IndexError, KeyError):
            return None, f"an {what} definition that isn't RFC 4512: {defn[:60]}; not read"
    return tuple(one_of(x) for x in defs)


def _attribute(held, a):
    single = "TRUE" if a["single_value"] else ("FALSE" if one(held, "ciamLdapSingleValue") == "FALSE" else None)
    owned = {"ciamLdapOid": (a["oid"],), "ciamPurpose": (a["description"],), "ciamLdapEquality": (a["equality"],),
             "ciamLdapSubstring": (a["substr"],), "ciamLdapOrdering": (a["ordering"],),
             "ciamLdapSyntax": (a["syntax_oid"],), "ciamLdapSingleValue": (single,)}
    return make_entry(held.dn, held.classes, merged_attrs(held, owned, ATTRIBUTE_OWNED))


def _class(held, c, attrs):
    sup = None if c["sup"] in (None, "top") and not one(held, "ciamLdapSuperior") else c["sup"]
    owned = {"ciamLdapOid": (c["oid"],), "ciamPurpose": (c["description"],), "ciamLdapSuperior": (sup,),
             "ciamLdapClassKind": (c["kind"].lower(),),
             "ciamLdapMust": tuple(attrs[n.lower()].dn for n in c["must"] if n.lower() in attrs),
             "ciamLdapMay": tuple(attrs[n.lower()].dn for n in c["may"] if n.lower() in attrs)}
    return make_entry(held.dn, held.classes, merged_attrs(held, owned, CLASS_OWNED))


def read_schema(files, d, patterns, at=None):
    """Imported: the user-schema records the subschema LDIF's definitions describe."""
    texts = tuple(t for p, t in sorted(files.items()) if p.endswith(".ldif"))
    ats = _parsed(attribute_type, (v for t in texts for v in _values(t, "attributeTypes")), "attribute type")
    ocs = _parsed(object_class, (v for t in texts for v in _values(t, "objectClasses")), "object class")
    attrs = attribute_records(d)
    classes = {(one(c, "ciamLdapName") or "").lower(): c for c in children(d, USER_SCHEMA, "ciamUserObjectClass")}
    entries = (*(_attribute(attrs[a["name"].lower()], a) for a, _ in ats if a and a["name"].lower() in attrs),
               *(_class(classes[c["name"].lower()], c, attrs) for c, _ in ocs if c and c["name"].lower() in classes))
    return Imported(containers=(), groups=tuple((e.dn, (e,)) for e in entries), notices=(
        *(n for _, n in (*ats, *ocs) if n),
        *(f"attribute type {a['name']}: no user-schema record (one needs its PII class); not recorded"
          for a, _ in ats if a and a["name"].lower() not in attrs),
        *(f"object class {c['name']}: no user-schema record; not recorded"
          for c, _ in ocs if c and c["name"].lower() not in classes),
        *(f"object class {c['name']}: {n} has no user-schema record; not in its MUST/MAY"
          for c, _ in ocs if c and c["name"].lower() in classes for n in (*c["must"], *c["may"])
          if n.lower() not in attrs)))


SCHEMA_IMPORTER = Importer("schema", "a subschema LDIF (attributeTypes, objectClasses) as the user schema's "
                                     "definitions", read_schema)
