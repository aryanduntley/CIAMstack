"""The OpenDJ adapter as the core sees it: registered, chosen from the servers' products, rendering the DS-lineage
neutral files with OpenDJ's handler names. Full renders are exercised by the showcase (test_directory_products)."""
from types import SimpleNamespace

from opsdir.connectors.registry import ADAPTERS
from opsdir.core.directory import make_directory, make_entry
from opsdir_adapter_opendj.adapter import ADAPTER
from opsdir_adapter_opendj.render import OPENDJ


def _servers(*products):
    return SimpleNamespace(servers=tuple(make_entry(f"cn=s{i},dc=x", ["ciamServer"], {"ciamProductVersion": [p]})
                                         for i, p in enumerate(products)))


def test_registered_through_its_entry_point():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "product"


def test_applies_when_a_server_runs_it():
    assert ADAPTER.applies(_servers("OpenDJ 4.6.4")) and not ADAPTER.applies(_servers("PingDS 7.5.1"))


def test_requires_a_replication_administrator_and_no_deployment_id():
    assert "ds-replication-admin-password" in ADAPTER.required_roles
    assert not any(r.startswith("ds-deployment") for r in ADAPTER.required_roles)


def test_renders_the_lineage_files_as_opendj():
    files = ADAPTER.render_neutral(make_directory((), (), ()))
    assert sorted(files) == ["ds/acis.ldif", "ds/dsconfig.batch", "ldap/dit.ldif", "ldap/schema.ldif"]
    assert OPENDJ.root_dn in files["ds/dsconfig.batch"]
