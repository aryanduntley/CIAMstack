"""The user schema read back from a subschema LDIF (`ldap/schema`): the rendered schema.ldif reads back unchanged (the
defaults it writes for unset values keep the record's absence), an edited definition says what changed, what only
the record says is kept, and definitions with no record are named."""
from opsdir.connectors.importing import import_changes
from opsdir.core.directory import make_directory
from opsdir.domains.directory.naming import USER_SCHEMA
from opsdir_adapter_ldap.schema import schema_ldif
from opsdir_adapter_ldap.schema_import import read_schema

TYPES = (("ciamLdapMust", "dn", "intent"), ("ciamLdapMay", "dn", "intent"))


def _attr(name, **defn):
    return (f"cn={name},{USER_SCHEMA}", ("top", "ciamUserAttribute"),
            {"cn": [name], "ciamLdapName": [name], "ciamPiiClass": ["low"], **{k: [v] for k, v in defn.items()}})


def _class(name, **defn):
    return (f"cn={name},{USER_SCHEMA}", ("top", "ciamUserObjectClass"),
            {"cn": [name], "ciamLdapName": [name], "ciamLdapClassKind": ["auxiliary"],
             **{k: list(v) if isinstance(v, tuple) else [v] for k, v in defn.items()}})


def directory():
    return make_directory(TYPES, {}, (
        _attr("badge", ciamLdapOid="1.2.3.1.1", ciamLdapSyntax="1.3.6.1.4.1.1466.115.121.1.15",
              ciamLdapEquality="caseIgnoreMatch", ciamLdapSingleValue="TRUE", ciamPurpose="Door badge number",
              ciamRetentionRule="while employed"),
        _attr("seen", ciamLdapOid="1.2.3.1.2", ciamLdapSyntax="1.3.6.1.4.1.1466.115.121.1.24",
              ciamLdapEquality="generalizedTimeMatch", ciamLdapOrdering="generalizedTimeOrderingMatch",
              ciamLdapSingleValue="FALSE", ciamPurpose="Last seen at a door"),
        _attr("nick", ciamLdapOid="1.2.3.1.3", ciamLdapSyntax="1.3.6.1.4.1.1466.115.121.1.15",
              ciamLdapEquality="caseIgnoreMatch", ciamLdapSubstring="caseIgnoreSubstringsMatch",
              ciamPurpose="Nickname, it's what friends use"),
        _class("acmePerson", ciamLdapOid="1.2.3.2.1",
               ciamLdapMay=(f"cn=badge,{USER_SCHEMA}", f"cn=seen,{USER_SCHEMA}", f"cn=nick,{USER_SCHEMA}")),
        _class("acmeEmployee", ciamLdapOid="1.2.3.2.2", ciamLdapSuperior="acmePerson",
               ciamLdapMust=f"cn=badge,{USER_SCHEMA}")))


def test_the_rendered_schema_reads_back_unchanged():
    d = directory()
    imported = read_schema({"schema.ldif": schema_ldif(d)}, d, ())
    assert len(imported.groups) == 5 and imported.notices == ()
    assert import_changes(d, imported) == ()


def test_an_edited_definition_says_what_changed_and_keeps_what_only_the_record_says():
    d = directory()
    text = schema_ldif(d).replace("SINGLE-VALUE ", "").replace("Door badge number", "Badge number")
    changes = import_changes(d, read_schema({"schema.ldif": text}, d, ()))
    assert [(c.dn, sorted(m[1] for m in c.mods)) for c in changes] == \
        [(f"cn=badge,{USER_SCHEMA}", ["ciamLdapSingleValue", "ciamPurpose"])]
    (entry,) = read_schema({"schema.ldif": text}, d, ()).groups[0][1]
    assert entry.attrs["ciamRetentionRule"] == ("while employed",) and entry.attrs["ciamPiiClass"] == ("low",)


def test_definitions_with_no_record_are_named():
    text = ("dn: cn=schema\nchangetype: modify\nadd: attributeTypes\n"
            "attributeTypes: ( 1.2.3.1.9 NAME 'pager2' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n"
            "attributeTypes: ( not a definition\n-\nadd: objectClasses\n"
            "objectClasses: ( 1.2.3.2.1 NAME 'acmePerson' SUP top AUXILIARY MAY ( badge $ pager2 ) )\n-\n")
    imported = read_schema({"server-schema.ldif": text}, directory(), ())
    assert imported.notices == (
        "an attribute type definition that isn't RFC 4512: ( not a definition; not read",
        "attribute type pager2: no user-schema record (one needs its PII class); not recorded",
        "object class acmePerson: pager2 has no user-schema record; not in its MUST/MAY")
