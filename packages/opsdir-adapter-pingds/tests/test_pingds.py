"""The PingDS adapter as the core sees it: registered, chosen from the servers' products, rendering its
environment-neutral files. Full renders are exercised by the showcase golden outputs."""
from types import SimpleNamespace

from opsdir.connectors.registry import ADAPTERS
from opsdir.core.directory import make_directory, make_entry
from opsdir_adapter_pingds.adapter import ADAPTER


def _servers(*products):
    return SimpleNamespace(servers=tuple(make_entry(f"cn=s{i},dc=x", ["ciamServer"], {"ciamProductVersion": [p]})
                                         for i, p in enumerate(products)), d=make_directory((), {}, ()))


def test_registered_through_its_entry_point():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "product"


def test_applies_when_a_server_runs_it():
    assert ADAPTER.applies(_servers("Other 1.0", "PingDS 7.5.1")) and not ADAPTER.applies(_servers("Other 1.0"))


def test_requires_the_roles_a_directory_deployment_binds():
    assert {"subnet-ds", "ds-ldaps-service", "ds-deployment-id"} <= set(ADAPTER.required_roles)


def test_renders_its_environment_neutral_files_from_any_directory():
    assert sorted(ADAPTER.render_neutral(make_directory((), (), ()))) == [
        "ds/acis.ldif", "ds/dsconfig.batch", "ldap/dit.ldif", "ldap/schema.ldif"]


def test_it_reads_its_servers_configuration_as_snapshots_or_as_the_declared_configuration():
    assert [i.name for i in ADAPTER.importers] == ["config", "declared", "access-log", "rendered", "schema"]


def test_an_upgrade_names_the_changes_between_the_two_releases():
    from opsdir.connectors.upgrades import crossing
    listed, between = crossing(None, None, ADAPTER, ("ds",), "7.5.1", "8.1.2")
    assert between == 4 and [c.has for c, names in listed] == [">=8.0", ">=8.1", ">=8.1", ">=8.1"]
    assert all(names is None and c.effect == "info" for c, names in listed)
    assert crossing(None, None, ADAPTER, ("ds",), "7.2.5", "7.5.4")[1] == 1        # 7.3's log move


def test_its_profile_is_its_standard_ldap_files_and_its_notes_name_what_it_ships():
    from opsdir.core.profiles import profile_tree
    from opsdir.domains.directory.naming import USER_SCHEMA
    files = ADAPTER.render_neutral(make_directory((), (), ()))
    assert sorted(profile_tree(ADAPTER.profile, files)) == ["ldap/dit.ldif", "ldap/schema.ldif"]
    fr = (f"cn=fr-idm-uuid,{USER_SCHEMA}", ("top", "ciamUserAttribute"),
          {"cn": ["fr-idm-uuid"], "ciamLdapName": ["fr-idm-uuid"], "ciamPiiClass": ["low"],
           "ciamLdapOid": ["1.3.6.1.4.1.36733.2.3.1.27"], "ciamLdapSyntax": ["1.3.6.1.4.1.1466.115.121.1.15"]})
    d = make_directory((), {}, (fr,))
    assert "fr-idm-uuid" not in ADAPTER.render_neutral(d)["ldap/schema.ldif"].split("# NOTE")[0]
    assert [n.subject for n in ADAPTER.notes(SimpleNamespace(d=d), None)] == ["schema fr-idm-uuid"]
