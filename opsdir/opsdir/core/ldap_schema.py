"""The standard LDAP schema as data: the attribute types and object classes directories get from the standards
(RFC 4512 top and objectClass, RFC 4519 core, RFC 4524 COSINE, RFC 2798 inetOrgPerson, RFC 4523 certificates,
RFC 2079 labeledURI, RFC 2247 dcObject). The one source of these facts for both LDAP layers: opsdir's own schema
(core.standard takes the standard definitions it uses from here) and the user directories opsdir manages (the
directory domain; every compliant server already knows these, so the record defines only what is not here).
"""
from typing import NamedTuple

SYNTAX_PREFIX = "1.3.6.1.4.1.1466.115.121.1"
# RFC 4517 syntaxes by name → OID suffix under SYNTAX_PREFIX
SYNTAXES = {"audio": ".4", "binary": ".5", "bit-string": ".6", "boolean": ".7", "certificate": ".8",
            "country-string": ".11", "dn": ".12", "delivery-method": ".14", "directory-string": ".15",
            "fax": ".23", "generalized-time": ".24", "guide": ".25", "ia5-string": ".26", "integer": ".27",
            "jpeg": ".28", "name-and-optional-uid": ".34", "numeric-string": ".36", "oid": ".38",
            "octet-string": ".40", "postal-address": ".41", "printable-string": ".44", "telephone-number": ".50",
            "teletex-terminal-identifier": ".51", "telex-number": ".52"}

StandardAttribute = NamedTuple("StandardAttribute", [("oid", str), ("name", str), ("syntax", str),
                                                     ("single_value", bool), ("standard", str)])
StandardClass = NamedTuple("StandardClass", [("oid", str), ("name", str), ("sup", str), ("kind", str),
                                             ("must", tuple), ("may", tuple), ("standard", str)])


def syntax_oid(name):
    """Full OID of a named RFC 4517 syntax."""
    return SYNTAX_PREFIX + SYNTAXES[name]


def _a(oid, name, syntax, standard, single_value=False):
    return StandardAttribute(oid, name, syntax_oid(syntax), single_value, standard)


_UCB = "0.9.2342.19200300.100.1"       # COSINE / RFC 1274 attribute arc
_NS = "2.16.840.1.113730.3.1"          # inetOrgPerson attribute arc

ATTRIBUTES = (
    _a("2.5.4.0", "objectClass", "oid", "RFC 4512"),
    _a("2.5.4.3", "cn", "directory-string", "RFC 4519"),
    _a("2.5.4.4", "sn", "directory-string", "RFC 4519"),
    _a("2.5.4.5", "serialNumber", "printable-string", "RFC 4519"),
    _a("2.5.4.6", "c", "country-string", "RFC 4519", True),
    _a("2.5.4.7", "l", "directory-string", "RFC 4519"),
    _a("2.5.4.8", "st", "directory-string", "RFC 4519"),
    _a("2.5.4.9", "street", "directory-string", "RFC 4519"),
    _a("2.5.4.10", "o", "directory-string", "RFC 4519"),
    _a("2.5.4.11", "ou", "directory-string", "RFC 4519"),
    _a("2.5.4.12", "title", "directory-string", "RFC 4519"),
    _a("2.5.4.13", "description", "directory-string", "RFC 4519"),
    _a("2.5.4.14", "searchGuide", "guide", "RFC 4519"),
    _a("2.5.4.15", "businessCategory", "directory-string", "RFC 4519"),
    _a("2.5.4.16", "postalAddress", "postal-address", "RFC 4519"),
    _a("2.5.4.17", "postalCode", "directory-string", "RFC 4519"),
    _a("2.5.4.18", "postOfficeBox", "directory-string", "RFC 4519"),
    _a("2.5.4.19", "physicalDeliveryOfficeName", "directory-string", "RFC 4519"),
    _a("2.5.4.20", "telephoneNumber", "telephone-number", "RFC 4519"),
    _a("2.5.4.21", "telexNumber", "telex-number", "RFC 4519"),
    _a("2.5.4.22", "teletexTerminalIdentifier", "teletex-terminal-identifier", "RFC 4519"),
    _a("2.5.4.23", "facsimileTelephoneNumber", "fax", "RFC 4519"),
    _a("2.5.4.24", "x121Address", "numeric-string", "RFC 4519"),
    _a("2.5.4.25", "internationalISDNNumber", "numeric-string", "RFC 4519"),
    _a("2.5.4.26", "registeredAddress", "postal-address", "RFC 4519"),
    _a("2.5.4.27", "destinationIndicator", "printable-string", "RFC 4519"),
    _a("2.5.4.28", "preferredDeliveryMethod", "delivery-method", "RFC 4519", True),
    _a("2.5.4.31", "member", "dn", "RFC 4519"),
    _a("2.5.4.32", "owner", "dn", "RFC 4519"),
    _a("2.5.4.33", "roleOccupant", "dn", "RFC 4519"),
    _a("2.5.4.34", "seeAlso", "dn", "RFC 4519"),
    _a("2.5.4.35", "userPassword", "octet-string", "RFC 4519"),
    _a("2.5.4.36", "userCertificate", "certificate", "RFC 4523"),
    _a("2.5.4.41", "name", "directory-string", "RFC 4519"),
    _a("2.5.4.42", "givenName", "directory-string", "RFC 4519"),
    _a("2.5.4.43", "initials", "directory-string", "RFC 4519"),
    _a("2.5.4.44", "generationQualifier", "directory-string", "RFC 4519"),
    _a("2.5.4.45", "x500UniqueIdentifier", "bit-string", "RFC 4519"),
    _a("2.5.4.46", "dnQualifier", "printable-string", "RFC 4519"),
    _a("2.5.4.49", "distinguishedName", "dn", "RFC 4519"),
    _a("2.5.4.50", "uniqueMember", "name-and-optional-uid", "RFC 4519"),
    _a("2.5.4.51", "houseIdentifier", "directory-string", "RFC 4519"),
    _a(f"{_UCB}.1", "uid", "directory-string", "RFC 4519"),
    _a(f"{_UCB}.3", "mail", "ia5-string", "RFC 4524"),
    _a(f"{_UCB}.6", "roomNumber", "directory-string", "RFC 4524"),
    _a(f"{_UCB}.7", "photo", "fax", "RFC 2798"),
    _a(f"{_UCB}.9", "host", "directory-string", "RFC 4524"),
    _a(f"{_UCB}.10", "manager", "dn", "RFC 4524"),
    _a(f"{_UCB}.20", "homePhone", "telephone-number", "RFC 4524"),
    _a(f"{_UCB}.21", "secretary", "dn", "RFC 4524"),
    _a(f"{_UCB}.25", "dc", "ia5-string", "RFC 4519", True),
    _a(f"{_UCB}.38", "associatedName", "dn", "RFC 4524"),
    _a(f"{_UCB}.39", "homePostalAddress", "postal-address", "RFC 4524"),
    _a(f"{_UCB}.41", "mobile", "telephone-number", "RFC 4524"),
    _a(f"{_UCB}.42", "pager", "telephone-number", "RFC 4524"),
    _a(f"{_UCB}.55", "audio", "audio", "RFC 2798"),
    _a(f"{_UCB}.60", "jpegPhoto", "jpeg", "RFC 2798"),
    _a(f"{_NS}.1", "carLicense", "directory-string", "RFC 2798"),
    _a(f"{_NS}.2", "departmentNumber", "directory-string", "RFC 2798"),
    _a(f"{_NS}.3", "employeeNumber", "directory-string", "RFC 2798", True),
    _a(f"{_NS}.4", "employeeType", "directory-string", "RFC 2798"),
    _a(f"{_NS}.39", "preferredLanguage", "directory-string", "RFC 2798", True),
    _a(f"{_NS}.40", "userSMIMECertificate", "binary", "RFC 2798"),
    _a(f"{_NS}.216", "userPKCS12", "binary", "RFC 2798"),
    _a(f"{_NS}.241", "displayName", "directory-string", "RFC 2798", True),
    _a("1.3.6.1.4.1.250.1.57", "labeledURI", "directory-string", "RFC 2079"),
)

# Attributes a postal/telecom-addressable entry may carry (RFC 4519 organizationalUnit, organization, ...)
_ADDRESSABLE = ("businessCategory", "description", "destinationIndicator", "facsimileTelephoneNumber",
                "internationalISDNNumber", "l", "physicalDeliveryOfficeName", "postalAddress", "postalCode",
                "postOfficeBox", "preferredDeliveryMethod", "registeredAddress", "searchGuide", "seeAlso", "st",
                "street", "telephoneNumber", "teletexTerminalIdentifier", "telexNumber", "userPassword",
                "x121Address")
_GROUP = ("businessCategory", "seeAlso", "owner", "ou", "o", "description")

CLASSES = (
    StandardClass("2.5.6.0", "top", None, "ABSTRACT", ("objectClass",), (), "RFC 4512"),
    StandardClass("2.5.6.4", "organization", "top", "STRUCTURAL", ("o",), _ADDRESSABLE, "RFC 4519"),
    StandardClass("2.5.6.5", "organizationalUnit", "top", "STRUCTURAL", ("ou",), _ADDRESSABLE, "RFC 4519"),
    StandardClass("2.5.6.6", "person", "top", "STRUCTURAL", ("sn", "cn"),
                  ("userPassword", "telephoneNumber", "seeAlso", "description"), "RFC 4519"),
    StandardClass("2.5.6.7", "organizationalPerson", "person", "STRUCTURAL", (),
                  ("title", "x121Address", "registeredAddress", "destinationIndicator", "preferredDeliveryMethod",
                   "telexNumber", "teletexTerminalIdentifier", "telephoneNumber", "internationalISDNNumber",
                   "facsimileTelephoneNumber", "street", "postOfficeBox", "postalCode", "postalAddress",
                   "physicalDeliveryOfficeName", "ou", "st", "l"), "RFC 4519"),
    StandardClass("2.5.6.8", "organizationalRole", "top", "STRUCTURAL", ("cn",),
                  ("x121Address", "registeredAddress", "destinationIndicator", "preferredDeliveryMethod",
                   "telexNumber", "teletexTerminalIdentifier", "telephoneNumber", "internationalISDNNumber",
                   "facsimileTelephoneNumber", "seeAlso", "roleOccupant", "street", "postOfficeBox", "postalCode",
                   "postalAddress", "physicalDeliveryOfficeName", "ou", "st", "l", "description"), "RFC 4519"),
    StandardClass("2.5.6.9", "groupOfNames", "top", "STRUCTURAL", ("member", "cn"), _GROUP, "RFC 4519"),
    StandardClass("2.5.6.17", "groupOfUniqueNames", "top", "STRUCTURAL", ("uniqueMember", "cn"), _GROUP, "RFC 4519"),
    StandardClass("0.9.2342.19200300.100.4.5", "account", "top", "STRUCTURAL", ("uid",),
                  ("description", "seeAlso", "l", "o", "ou", "host"), "RFC 4524"),
    StandardClass("0.9.2342.19200300.100.4.13", "domain", "top", "STRUCTURAL", ("dc",),
                  (*_ADDRESSABLE, "o", "associatedName"), "RFC 4524"),
    StandardClass("1.3.6.1.4.1.1466.344", "dcObject", "top", "AUXILIARY", ("dc",), (), "RFC 2247"),
    StandardClass("1.3.6.1.1.3.1", "uidObject", "top", "AUXILIARY", ("uid",), (), "RFC 4519"),
    StandardClass("2.16.840.1.113730.3.2.2", "inetOrgPerson", "organizationalPerson", "STRUCTURAL", (),
                  ("audio", "businessCategory", "carLicense", "departmentNumber", "displayName", "employeeNumber",
                   "employeeType", "givenName", "homePhone", "homePostalAddress", "initials", "jpegPhoto",
                   "labeledURI", "mail", "manager", "mobile", "o", "pager", "photo", "roomNumber", "secretary", "uid",
                   "userCertificate", "x500UniqueIdentifier", "preferredLanguage", "userSMIMECertificate",
                   "userPKCS12"), "RFC 2798"),
)

_ATTRIBUTES_BY_NAME = {a.name.lower(): a for a in ATTRIBUTES}
_CLASSES_BY_NAME = {c.name.lower(): c for c in CLASSES}


def standard_attribute(name):
    """The standard attribute type of that name (case-insensitive), or None."""
    return _ATTRIBUTES_BY_NAME.get(name.lower())


def standard_class(name):
    """The standard object class of that name (case-insensitive), or None."""
    return _CLASSES_BY_NAME.get(name.lower())
