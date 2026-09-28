"""The standard LDAP user schema catalogue, and the user directory's schema as the record describes it."""
from types import SimpleNamespace

from opsdir.core.directory import make_directory
from opsdir.domains.directory.naming import USER_SCHEMA
from opsdir.core.ldap_schema import ATTRIBUTES, CLASSES, standard_attribute, standard_class
from opsdir.domains.directory.user_schema import (DEFINED, check_user_schema, defined_attributes, defined_classes,
                                                  described, user_schema_rows)


def _attr(name, **defn):
    return (f"cn={name},{USER_SCHEMA}", ("top", "ciamUserAttribute"),
            {"cn": [name], "ciamLdapName": [name], "ciamPiiClass": ["low"], **{k: [v] for k, v in defn.items()}})


def _class(name, kind="auxiliary", **defn):
    return (f"cn={name},{USER_SCHEMA}", ("top", "ciamUserObjectClass"),
            {"cn": [name], "ciamLdapName": [name], "ciamLdapClassKind": [kind], **{k: [v] for k, v in defn.items()}})


def _d(*entries):
    return make_directory((), {}, entries)


def one_name(e):
    return e.attrs["ciamLdapName"][0]


def test_the_catalogue_is_consistent():
    names = [a.name for a in ATTRIBUTES] + [c.name for c in CLASSES]
    oids = [a.oid for a in ATTRIBUTES] + [c.oid for c in CLASSES]
    assert len(set(names)) == len(names) and len(set(oids)) == len(oids)
    assert all(standard_attribute(x) for c in CLASSES for x in c.must + c.may)
    assert all(c.sup is None or standard_class(c.sup) for c in CLASSES)


def test_lookups_ignore_case():
    assert standard_attribute("GIVENNAME").oid == "2.5.4.42" and standard_class("inetorgperson").sup == "organizationalPerson"
    assert standard_attribute("companyId") is None


def test_each_record_is_standard_defined_or_a_problem():
    d = _d(_attr("mail"), _attr("companyId", ciamLdapOid="1.2.3.1", ciamLdapSyntax="1.3.6.1.4.1.1466.115.121.1.15"),
           _attr("badge"), _attr("uid", ciamLdapOid="9.9"), _class("inetOrgPerson", "structural"),
           _class("acmePerson", ciamLdapOid="1.2.3.2", ciamLdapSuperior="top"), _class("orphan", ciamLdapOid="1.2.3.3",
                                                                                     ciamLdapSuperior="nosuch"))
    assert user_schema_rows(d) == [
        ("attribute", "badge", "undefined", "", "not standard; needs ciamLdapOid, ciamLdapSyntax"),
        ("attribute", "companyId", DEFINED, "1.2.3.1", ""),
        ("attribute", "mail", "RFC 4524", "0.9.2342.19200300.100.1.3", ""),
        ("attribute", "uid", "RFC 4519", "9.9", "redefines standard uid (0.9.2342.19200300.100.1.1)"),
        ("class", "acmePerson", DEFINED, "1.2.3.2", ""),
        ("class", "inetOrgPerson", "RFC 2798", "2.16.840.1.113730.3.2.2", ""),
        ("class", "orphan", DEFINED, "1.2.3.3", "superclass nosuch is neither standard nor recorded")]
    assert [one_name(e) for e in defined_attributes(d)] == ["companyId"]
    assert [one_name(e) for e in defined_classes(d)] == ["acmePerson"]


def test_a_superclass_may_be_another_recorded_class():
    d = _d(_class("base", ciamLdapOid="1.2.3.1"), _class("derived", ciamLdapOid="1.2.3.2", ciamLdapSuperior="base"))
    assert all(x.problem is None for x in described(d))


def test_the_check_blocks_what_cannot_be_built_and_reports_the_rest():
    blocked = check_user_schema(SimpleNamespace(d=_d(_attr("badge"))))
    assert blocked.blockers == (("Schema", "User-directory attribute `badge`: not standard; needs ciamLdapOid, "
                                 "ciamLdapSyntax. The target directory can't be built from the record.", "**NO OWNER**"),)
    fine = check_user_schema(SimpleNamespace(d=_d(_attr("mail"), _class("x", ciamLdapOid="1.2.3"))))
    assert fine.ok == ("Every user-directory attribute and object class is standard (1) or defined in the record (1).",)
