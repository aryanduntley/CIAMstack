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
