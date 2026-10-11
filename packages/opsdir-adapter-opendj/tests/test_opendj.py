"""The OpenDJ adapter as the core sees it: registered, chosen from the servers' products, rendering the DS-lineage
neutral files with OpenDJ's handler names. Full renders are exercised by the showcase (test_directory_products)."""
from types import SimpleNamespace

from opsdir.connectors.registry import ADAPTERS
from opsdir.core.directory import make_directory, make_entry
from opsdir.core.versions import in_range
from opsdir_adapter_opendj.adapter import ADAPTER
from opsdir_adapter_opendj.render import OPENDJ
from opsdir_base_ds.observe import config_entries


def _servers(*products):
    return SimpleNamespace(servers=tuple(make_entry(f"cn=s{i},dc=x", ["ciamServer"], {"ciamProductVersion": [p]})
                                         for i, p in enumerate(products)), d=make_directory((), {}, ()))


def test_registered_through_its_entry_point():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "product"


def test_applies_when_a_server_runs_it():
    assert ADAPTER.applies(_servers("OpenDJ 4.6.4")) and not ADAPTER.applies(_servers("PingDS 7.5.1"))


def test_supports_opendj_4_and_5():
    assert ADAPTER.applies(_servers("OpenDJ 5.1.2"))
    (product, versions), = ADAPTER.products
    assert product == "OpenDJ" and all(in_range(v, versions) for v in ("4.6.4", "5.0.1", "5.1.2"))
    assert not in_range("6.0.0", versions) and not in_range("3.5.3", versions)


def test_requires_a_replication_administrator_and_no_deployment_id():
    assert "ds-replication-admin-password" in ADAPTER.required_roles
    assert not any(r.startswith("ds-deployment") for r in ADAPTER.required_roles)


def test_renders_the_lineage_files_as_opendj():
    files = ADAPTER.render_neutral(make_directory((), (), ()))
    assert sorted(files) == ["ds/acis.ldif", "ds/dsconfig.batch", "ldap/dit.ldif", "ldap/schema.ldif"]
    assert OPENDJ.root_dn in files["ds/dsconfig.batch"]


def test_its_servers_configuration_is_read_back_under_the_records_handler_names():
    assert [i.name for i in ADAPTER.importers] == ["config", "declared", "access-log"]
    config = ("dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config\nobjectClass: top\n"
              "objectClass: ds-cfg-connection-handler\ncn: LDAPS Connection Handler\nds-cfg-enabled: true\n"
              "ds-cfg-listen-port: 1636\n")
    entries, _ = config_entries(OPENDJ, make_directory((), {}, ()), config, "ou=declared,ou=config,dc=ciam-ops", "x")
    assert [e.dn for e in entries] == ["ou=connection-handlers,ou=declared,ou=config,dc=ciam-ops",
                                       "cn=LDAPS,ou=connection-handlers,ou=declared,ou=config,dc=ciam-ops"]


def test_5_1_2_changes_the_storage_formats():
    from opsdir.connectors.upgrades import crossing
    (change,), _ = crossing(None, None, ADAPTER, ("ds",), "4.4.11", "5.1.2")
    assert change[0].effect == "action" and "indexes must be rebuilt" in change[0].change
    assert crossing(None, None, ADAPTER, ("ds",), "5.1.2", "5.1.3") == ((), 0)
    assert crossing(None, None, ADAPTER, ("ds",), "4.4.11", "5.0.1") == ((), 0)
