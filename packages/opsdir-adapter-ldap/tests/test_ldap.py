"""The standard LDAPv3 base: the user directory's schema and tree as standard LDIF, and the generic adapter that
renders them for any compliant server an environment's stack names."""
from types import SimpleNamespace

from opsdir.connectors.registry import ADAPTERS
from opsdir.connectors.stack import declared_adapters
from opsdir.core.directory import make_directory
from opsdir.core.environment import StackComponent
from opsdir.core.interchange.ldif import parse
from opsdir.domains.directory.naming import DECLARED, USER_SCHEMA
from opsdir_adapter_ldap.adapter import ADAPTER, render_standard
from opsdir_adapter_ldap.dit import tree
from opsdir_adapter_ldap.schema import schema_record

BASE = "dc=users,dc=example,dc=test"
TYPES = (("ciamBaseDn", "extdn", "intent"), ("ciamBindDn", "extdn", "intent"), ("ciamAciTargetDn", "extdn", "intent"),
         ("ciamLdapMay", "dn", "intent"))


def _attr(name, **defn):
    return (f"cn={name},{USER_SCHEMA}", ("top", "ciamUserAttribute"),
            {"cn": [name], "ciamLdapName": [name], "ciamPiiClass": ["low"], **{k: [v] for k, v in defn.items()}})


def _class(name, sup, **defn):
    return (f"cn={name},{USER_SCHEMA}", ("top", "ciamUserObjectClass"),
            {"cn": [name], "ciamLdapName": [name], "ciamLdapClassKind": ["auxiliary"], "ciamLdapSuperior": [sup],
             **{k: [v] for k, v in defn.items()}})


def directory():
    return make_directory(TYPES, {}, (
        (f"cn=userData,ou=backends,{DECLARED}", ("top", "ciamBackend"), {"cn": ["userData"], "ciamBaseDn": [BASE]}),
        ("cn=app,ou=consumers,dc=ciam-ops", ("top", "ciamConsumer"),
         {"cn": ["app"], "ciamBindDn": [f"uid=app,ou=apps,ou=accounts,{BASE}"]}),
        ("cn=a1,ou=acis,dc=ciam-ops", ("top", "ciamAci"), {"cn": ["a1"], "ciamAciTargetDn": [f"ou=people,{BASE}"]}),
        ("cn=elsewhere,ou=consumers,dc=ciam-ops", ("top", "ciamConsumer"),
         {"cn": ["elsewhere"], "ciamBindDn": ["uid=x,ou=other,dc=not-ours"]}),
        ("cn=odd,ou=acis,dc=ciam-ops", ("top", "ciamAci"),
         {"cn": ["odd"], "ciamAciTargetDn": [f"ou=x,cn=group,{BASE}"]}),
        _attr("mail"),
        _attr("badge", ciamLdapOid="1.2.3.1.1", ciamLdapSyntax="1.3.6.1.4.1.1466.115.121.1.15",
              ciamLdapEquality="caseIgnoreMatch", ciamLdapSingleValue="TRUE", ciamPurpose="Door badge number"),
        _attr("undefinedOne"),
        _class("acmeEmployee", "acmePerson", ciamLdapOid="1.2.3.2.2", ciamLdapMay=f"cn=badge,{USER_SCHEMA}"),
        _class("acmePerson", "top", ciamLdapOid="1.2.3.2.1")))


def test_registered_and_declaration_only():
    assert ADAPTER in ADAPTERS and ADAPTER.applies is None and ADAPTER.render_env is None


def test_rendered_only_where_a_stack_names_it():
    m = SimpleNamespace(stack=(StackComponent("directory", "ldap", None, None),))
    assert declared_adapters(m, (ADAPTER,)) == (ADAPTER,)
    assert declared_adapters(SimpleNamespace(stack=()), (ADAPTER,)) == ()


def test_the_schema_adds_only_what_the_record_defines_superclasses_first():
    r = schema_record(directory())
    assert (r.dn, r.changetype) == ("cn=schema", "modify")
    assert r.mods == (
        ("add", "attributeTypes", ("( 1.2.3.1.1 NAME 'badge' DESC 'Door badge number' EQUALITY caseIgnoreMatch "
                                   "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE X-ORIGIN 'opsdir' )",)),
        ("add", "objectClasses", ("( 1.2.3.2.1 NAME 'acmePerson' SUP top AUXILIARY X-ORIGIN 'opsdir' )",
                                  "( 1.2.3.2.2 NAME 'acmeEmployee' SUP acmePerson AUXILIARY MAY badge "
                                  "X-ORIGIN 'opsdir' )")))


def test_the_schema_file_parses_back_as_one_modify():
    records = parse(render_standard(directory())["ldap/schema.ldif"])
    assert [(r.dn, [op for op, _, _ in r.mods]) for r in records] == [("cn=schema", ["add", "add"])]


def test_nothing_to_add_without_definitions():
    empty = make_directory((), {}, ())
    assert schema_record(empty) is None and render_standard(empty)["ldap/schema.ldif"].endswith("control.\n")


def test_the_tree_is_the_naming_context_and_the_containers_the_record_refers_to():
    assert tree(directory()) == (BASE, f"ou=accounts,{BASE}", f"ou=people,{BASE}", f"ou=apps,ou=accounts,{BASE}")


def test_the_tree_file_is_standard_entries():
    records = parse(render_standard(directory())["ldap/dit.ldif"])
    assert [(r.dn, r.attrs["objectClass"]) for r in records][:2] == [
        (BASE, ("top", "domain")), (f"ou=accounts,{BASE}", ("top", "organizationalUnit"))]
