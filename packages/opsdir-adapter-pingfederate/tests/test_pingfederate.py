"""The PingFederate adapter as the core sees it: registered, chosen from the servers' products, owning its server
roles, rendering its environment-neutral files. Full renders are exercised by the showcase golden outputs."""
from types import SimpleNamespace

from opsdir.connectors.registry import ADAPTERS
from opsdir.core.directory import make_directory, make_entry
from opsdir_adapter_pingfederate.adapter import ADAPTER


def _servers(*products):
    return SimpleNamespace(servers=tuple(make_entry(f"cn=s{i},dc=x", ["ciamServer"], {"ciamProductVersion": [p]})
                                         for i, p in enumerate(products)))


def test_registered_through_its_entry_point():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "product"


def test_applies_when_a_server_runs_it():
    assert ADAPTER.applies(_servers("PingFederate 12.1.4")) and not ADAPTER.applies(_servers("PingDS 7.5.1"))


def test_owns_its_server_roles():
    assert ADAPTER.vocabulary == {"ciamServerRole": ("pf-engine", "pf-admin"), "ciamTargetRole": ("pf-engine", "pf-admin")}


def test_renders_empty_configuration_for_an_empty_directory():
    assert ADAPTER.render_neutral(make_directory((), (), ())) == {
        "pingfederate/sp-connections.json": "[]\n", "pingfederate/oidc-clients.json": "[]\n",
        "pingfederate/idp-connections.json": "[]\n"}
