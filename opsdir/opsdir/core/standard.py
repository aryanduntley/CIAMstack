"""The opsdir standard as data: value types, the OID arc, schema fragments and how they compose into the
published RFC 4512 schema (schema/ciam-ops.schema.ldif).

Every domain and any adapter package owns a SchemaFragment, numbered under the fragment's OID arc (<arc>.1.n attribute
types, <arc>.2.n object classes). The core and its domains share ARC; each package that adds definitions uses an arc
of its own, so independently written packages never collide. Numbers are pinned in each definition, never derived
from position, so moving a definition between fragments of one arc never renumbers anything.
"""
from collections import namedtuple
from typing import NamedTuple

from .interchange.ldif import fold
from .interchange.rfc4512 import attribute_type_definition, object_class_definition
from .ldap_schema import standard_attribute, standard_class

ARC = "1.3.6.1.4.1.32473.1"   # RFC 5612 documentation PEN; replace with a registered arc (SPEC 1.0)
# Sub-arcs of the documentation PEN used in this repository: .1 the core and its domains (ARC), .2 the showcase's
# user-directory schema, .3.<n> packages in this repository, .4 fields and record types operators define in the record.
CUSTOM_ARC = "1.3.6.1.4.1.32473.4"
SYNTAX = {"string": ".15", "int": ".27", "bool": ".7", "time": ".24", "dn": ".12", "extdn": ".12",
          "cidr": ".15", "ip": ".15", "fqdn": ".26", "url": ".26", "port": ".27", "ref-uri": ".26", "json": ".15",
          "vocab": ".15"}
EQUALITY = {"int": "integerMatch", "port": "integerMatch", "bool": "booleanMatch", "time": "generalizedTimeMatch",
            "dn": "distinguishedNameMatch", "extdn": "distinguishedNameMatch"}

# number: pinned OID suffix under <arc>.1 (attributes) or <arc>.2 (classes) of the fragment that holds it
# rules: ((X-extension, value), ...) the store enforces on every value, beyond the value type: X-MIN, X-MAX (int and
# port values), X-PATTERN (a regular expression the whole value matches), X-MAX-LENGTH (characters). Usually none.
AttributeDef = namedtuple("AttributeDef", ("number", "name", "value_type", "portability", "single_value",
                                           "description", "rules"), defaults=((),))
ClassDef = NamedTuple("ClassDef", [("number", int), ("name", str), ("sup", str), ("kind", str),
                                   ("must", tuple), ("may", tuple), ("description", str)])
SchemaFragment = NamedTuple("SchemaFragment", [("attributes", tuple), ("classes", tuple), ("arc", str),
                                               ("origin", str)])     # X-ORIGIN of its definitions


def fragment(attributes, classes, arc=ARC, origin="opsdir"):
    """A schema fragment: definitions numbered under an OID arc (the core's by default) and marked with an origin."""
    return SchemaFragment(tuple(attributes), tuple(classes), arc, origin)


def attribute_oid(f, a):
    return f"{f.arc}.1.{a.number}"


def class_oid(f, c):
    return f"{f.arc}.2.{c.number}"

# The standard LDAP definitions opsdir's own entries use, with what this standard adds to them: (name, value type,
# portability, description). OID, single-value, superclass, kind, MUST and origin come from the standard catalogue
# (ldap_schema); a class allows the standard MAY attributes that are listed here.
STANDARD_ATTRIBUTES = (
    ("objectClass", "string", "meta", "LDAP object classes"),
    ("cn", "string", "meta", "Common name / RDN"),
    ("ou", "string", "meta", "Organizational unit / RDN"),
    ("dc", "string", "meta", "Domain component / RDN"),
    ("description", "string", "meta", "Free text"),
    ("mail", "string", "meta", "Contact email"),
)
STANDARD_CLASSES = (
    ("top", "Top of the class hierarchy"),
    ("organizationalUnit", "Organizational unit"),
    ("domain", "Domain"),
)

HEADER = ("# Operations Directory schema (opsdir) — LDAP schema extended for platform configuration.",
          "# Standard RFC 4512 definitions. Extensions (legal per RFC 4512 §4.2):",
          "#   X-PORTABILITY  intent | contract | binding | secret-ref | observed | meta",
          "#   X-VALUE-TYPE   stricter value type enforced by the store (string, int, bool, time, dn, extdn,",
          "#                  cidr, ip, fqdn, url, port, ref-uri, json, enum:a|b|c, vocab = values the",
          "#                  installed domains and adapters register)",
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
    AttributeDef(172, 'ciamFormat', 'vocab', 'meta', True,
                 'File format or language of something recorded (one of the registered formats)'),
)
CORE_CLASSES = (
    ClassDef(1, 'ciamObject', 'top', 'ABSTRACT', (),
             ('description', 'ciamOwner', 'ciamLastChanged', 'ciamChangeRef'),
             'Base of every operations-directory entry'),
)
CORE = fragment(CORE_ATTRIBUTES, CORE_CLASSES)


def syntax(value_type):
    return "1.3.6.1.4.1.1466.115.121.1" + SYNTAX["string" if value_type.startswith("enum:") else value_type]


def equality(value_type):
    return EQUALITY.get(value_type, "caseIgnoreMatch")


def _attribute_line(oid, name, vt, portability, single, desc, origin, rules=()):
    return "attributeTypes: " + attribute_type_definition(
        oid, name, desc, equality(vt), syntax(vt), single,
        (("X-PORTABILITY", portability), ("X-VALUE-TYPE", vt), *rules, ("X-ORIGIN", origin)))


def _class_line(oid, name, sup, kind, must, may, desc, origin):
    return "objectClasses: " + object_class_definition(oid, name, desc, sup, kind, must, may, (("X-ORIGIN", origin),))


def _standard_attribute_line(name, vt, portability, desc):
    a = standard_attribute(name)
    return _attribute_line(a.oid, a.name, vt, portability, a.single_value, desc, a.standard)


def _standard_class_line(name, desc):
    c = standard_class(name)
    used = {n for n, *_ in STANDARD_ATTRIBUTES}
    return _class_line(c.oid, c.name, c.sup, c.kind, c.must, tuple(x for x in c.may if x in used), desc, c.standard)


def _duplicates(values):
    return sorted({v for v in values if values.count(v) > 1})


def check_fragments(fragments):
    """Problems that make a set of fragments unpublishable: a reused OID (in any arc, by attribute or class) or name,
    classes using attributes or superclasses nobody defines. Empty when the fragments compose cleanly."""
    attrs = [a for f in fragments for a in f.attributes]
    classes = [c for f in fragments for c in f.classes]
    oids = ([attribute_oid(f, a) for f in fragments for a in f.attributes]
            + [class_oid(f, c) for f in fragments for c in f.classes])
    known_attrs = {a[0] for a in STANDARD_ATTRIBUTES} | {a.name for a in attrs}
    known_classes = {c[0] for c in STANDARD_CLASSES} | {c.name for c in classes}
    return tuple(
        [f"OID reused: {o}" for o in _duplicates(oids)]
        + [f"attribute name reused: {n}" for n in _duplicates([a.name for a in attrs])]
        + [f"class name reused: {n}" for n in _duplicates([c.name for c in classes])]
        + [f"class {c.name} uses undefined attribute {x}" for c in classes for x in c.must + c.may
           if x not in known_attrs]
        + [f"class {c.name} has undefined superclass {c.sup}" for c in classes if c.sup not in known_classes])


def _oid_order(item):
    return tuple(int(x) for x in item[0].split("."))


def schema_ldif(fragments):
    """The published schema: standard definitions, then every fragment's definitions in OID order."""
    problems = check_fragments(fragments)
    if problems:
        raise SystemExit("schema fragments do not compose: " + "; ".join(problems))
    attrs = sorted(((attribute_oid(f, a), a, f.origin) for f in fragments for a in f.attributes), key=_oid_order)
    classes = sorted(((class_oid(f, c), c, f.origin) for f in fragments for c in f.classes), key=_oid_order)
    definitions = (
             *(_standard_attribute_line(*a) for a in STANDARD_ATTRIBUTES),
             *(_attribute_line(oid, a.name, a.value_type, a.portability, a.single_value, a.description, origin,
                               a.rules) for oid, a, origin in attrs),
             *(_standard_class_line(*c) for c in STANDARD_CLASSES),
             *(_class_line(oid, c.name, c.sup, c.kind, c.must, c.may, c.description, origin)
               for oid, c, origin in classes))
    return "\n".join((*HEADER, *("\n".join(fold(line, 76)) for line in definitions))) + "\n"


def fragment_counts(fragments):
    return sum(len(f.attributes) for f in fragments), sum(len(f.classes) for f in fragments)
