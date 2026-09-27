"""The opsdir standard as data: value types, the OID arc, schema fragments and how they compose into the
published RFC 4512 schema (schema/ciam-ops.schema.ldif).

Every domain (and later any adapter) owns a SchemaFragment. OIDs are pinned by number in each definition,
never derived from position, so moving a definition between fragments never renumbers anything.
"""
from typing import NamedTuple

from .interchange.ldif import fold
from .interchange.rfc4512 import attribute_type_definition, object_class_definition

ARC = "1.3.6.1.4.1.32473.1"   # RFC 5612 documentation PEN; replace with a registered arc (SPEC 1.0)
SYNTAX = {"string": ".15", "int": ".27", "bool": ".7", "time": ".24", "dn": ".12", "extdn": ".12",
          "cidr": ".15", "ip": ".15", "fqdn": ".26", "url": ".26", "port": ".27", "ref-uri": ".26", "json": ".15"}
EQUALITY = {"int": "integerMatch", "port": "integerMatch", "bool": "booleanMatch", "time": "generalizedTimeMatch",
            "dn": "distinguishedNameMatch", "extdn": "distinguishedNameMatch"}

# number: pinned OID suffix under ARC.1 (attributes) or ARC.2 (classes)
AttributeDef = NamedTuple("AttributeDef", [("number", int), ("name", str), ("value_type", str),
                                           ("portability", str), ("single_value", bool), ("description", str)])
ClassDef = NamedTuple("ClassDef", [("number", int), ("name", str), ("sup", str), ("kind", str),
                                   ("must", tuple), ("may", tuple), ("description", str)])
SchemaFragment = NamedTuple("SchemaFragment", [("attributes", tuple), ("classes", tuple)])

# Standard LDAP definitions (real OIDs), with the portability this standard assigns them.
STANDARD_ATTRIBUTES = (
    ("2.5.4.0", "objectClass", "string", "meta", False, "LDAP object classes"),
    ("2.5.4.3", "cn", "string", "meta", False, "Common name / RDN"),
    ("2.5.4.11", "ou", "string", "meta", False, "Organizational unit / RDN"),
    ("0.9.2342.19200300.100.1.25", "dc", "string", "meta", True, "Domain component / RDN"),
    ("2.5.4.13", "description", "string", "meta", False, "Free text"),
    ("0.9.2342.19200300.100.1.3", "mail", "string", "meta", False, "Contact email"),
)
STANDARD_CLASSES = (
    ("2.5.6.0", "top", None, "ABSTRACT", ("objectClass",), (), "Top of the class hierarchy"),
    ("2.5.6.5", "organizationalUnit", "top", "STRUCTURAL", ("ou",), ("description",), "Organizational unit"),
    ("0.9.2342.19200300.100.4.13", "domain", "top", "STRUCTURAL", ("dc",), ("description",), "Domain"),
)

HEADER = ("# Operations Directory schema (opsdir) — LDAP schema extended for platform configuration.",
          "# Standard RFC 4512 definitions. Extensions (legal per RFC 4512 §4.2):",
          "#   X-PORTABILITY  intent | contract | binding | secret-ref | observed | meta",
          "#   X-VALUE-TYPE   stricter value type enforced by the store (string, int, bool, time, dn, extdn,",
          "#                  cidr, ip, fqdn, url, port, ref-uri, json, enum:a|b|c)",
          "# OIDs use the RFC 5612 documentation arc 1.3.6.1.4.1.32473 as a placeholder.",
          "dn: cn=schema", "objectClass: top", "objectClass: ldapSubentry", "objectClass: subschema", "cn: schema")

# Base of every entry, plus vocabulary shared by several domains.
CORE_ATTRIBUTES = (
    AttributeDef(4, 'ciamOwner', 'dn', 'meta', False,
                 'Owning party (team, partner, vendor)'),
    AttributeDef(5, 'ciamLastChanged', 'time', 'meta', True,
                 'Last change before this directory tracked history'),
    AttributeDef(6, 'ciamChangeRef', 'dn', 'meta', False,
                 'Change record(s) that justify this entry'),
    AttributeDef(77, 'ciamCriticality', 'enum:critical|high|medium|low', 'meta', True,
                 'Business criticality'),
    AttributeDef(93, 'ciamPopulation', 'enum:customers|suppliers|partners|individuals', 'intent', False,
                 'Identity populations served'),
)
CORE_CLASSES = (
    ClassDef(1, 'ciamObject', 'top', 'ABSTRACT', (),
             ('description', 'ciamOwner', 'ciamLastChanged', 'ciamChangeRef'),
             'Base of every operations-directory entry'),
)
CORE = SchemaFragment(CORE_ATTRIBUTES, CORE_CLASSES)


def syntax(value_type):
    return "1.3.6.1.4.1.1466.115.121.1" + SYNTAX["string" if value_type.startswith("enum:") else value_type]


def equality(value_type):
    return EQUALITY.get(value_type, "caseIgnoreMatch")


def _attribute_line(oid, name, vt, portability, single, desc, origin):
    return "attributeTypes: " + attribute_type_definition(
        oid, name, desc, equality(vt), syntax(vt), single,
        (("X-PORTABILITY", portability), ("X-VALUE-TYPE", vt), ("X-ORIGIN", origin)))


def _class_line(oid, name, sup, kind, must, may, desc, origin):
    return "objectClasses: " + object_class_definition(oid, name, desc, sup, kind, must, may, (("X-ORIGIN", origin),))


def _duplicates(values):
    return sorted({v for v in values if values.count(v) > 1})


def check_fragments(fragments):
    """Problems that make a set of fragments unpublishable: reused numbers or names, classes using
    attributes or superclasses nobody defines. Empty when the fragments compose cleanly."""
    attrs = [a for f in fragments for a in f.attributes]
    classes = [c for f in fragments for c in f.classes]
    known_attrs = {a[1] for a in STANDARD_ATTRIBUTES} | {a.name for a in attrs}
    known_classes = {c[1] for c in STANDARD_CLASSES} | {c.name for c in classes}
    return tuple(
        [f"attribute number reused: {n}" for n in _duplicates([a.number for a in attrs])]
        + [f"attribute name reused: {n}" for n in _duplicates([a.name for a in attrs])]
        + [f"class number reused: {n}" for n in _duplicates([c.number for c in classes])]
        + [f"class name reused: {n}" for n in _duplicates([c.name for c in classes])]
        + [f"class {c.name} uses undefined attribute {x}" for c in classes for x in c.must + c.may
           if x not in known_attrs]
        + [f"class {c.name} has undefined superclass {c.sup}" for c in classes if c.sup not in known_classes])


def schema_ldif(fragments):
    """The published schema: standard definitions, then every fragment's definitions in OID order."""
    problems = check_fragments(fragments)
    if problems:
        raise SystemExit("schema fragments do not compose: " + "; ".join(problems))
    attrs = sorted((a for f in fragments for a in f.attributes), key=lambda a: a.number)
    classes = sorted((c for f in fragments for c in f.classes), key=lambda c: c.number)
    definitions = (
             *(_attribute_line(oid, n, vt, p, sv, d, "RFC 4519") for oid, n, vt, p, sv, d in STANDARD_ATTRIBUTES),
             *(_attribute_line(f"{ARC}.1.{a.number}", a.name, a.value_type, a.portability, a.single_value,
                               a.description, "opsdir") for a in attrs),
             *(_class_line(oid, n, sup, kind, must, may, d, "RFC 4519")
               for oid, n, sup, kind, must, may, d in STANDARD_CLASSES),
             *(_class_line(f"{ARC}.2.{c.number}", c.name, c.sup, c.kind, c.must, c.may, c.description, "opsdir")
               for c in classes))
    return "\n".join((*HEADER, *("\n".join(fold(line, 76)) for line in definitions))) + "\n"


def fragment_counts(fragments):
    return sum(len(f.attributes) for f in fragments), sum(len(f.classes) for f in fragments)
