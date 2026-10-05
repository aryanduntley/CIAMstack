"""PingFederate's settings for an explicit egress proxy: run.properties' forward proxy keys on every node role, the
revocation checking proxy once on the admin node, and that the adapter declares them."""
from types import SimpleNamespace

from opsdir.core.contract import ProxySetting
from opsdir.core.directory import make_entry
from opsdir.domains.network.proxies import ProxySettings
from opsdir_adapter_pingfederate.adapter import ADAPTER

PROXY = ProxySettings("proxy.corp.example", 3128, ("localhost", "10.20.*"), None)


def _env(*roles):
    return SimpleNamespace(servers=tuple(make_entry(f"cn=s{i}", ("ciamServer",), {"ciamServerRole": (r,)})
                                         for i, r in enumerate(roles)))


def test_run_properties_on_each_node_role_and_revocation_on_the_admin_node():
    found = ADAPTER.proxy_settings(_env("pf-engine", "pf-admin"), PROXY)
    run = [(s.server_role, s.locator, s.value) for s in found if s.file == "bin/run.properties"]
    assert [s.link for s in found if s.server_role == "pf-admin" and s.file] == [
        "proxy:host", "proxy:port", "proxy:host", "proxy:port", "proxy:bypass"]
    assert run == [(r, k, v) for r in ("pf-engine", "pf-admin") for k, v in (
        ("http.proxyHost", "proxy.corp.example"), ("http.proxyPort", "3128"), ("https.proxyHost", "proxy.corp.example"),
        ("https.proxyPort", "3128"), ("http.nonProxyHosts", "localhost|10.20.*"))]
    assert [s for s in found if s.file is None] == [ProxySetting(
        "pf-admin", "certificate revocation checking's proxy settings (CRL and OCSP)", None, "proxy",
        "proxy.corp.example:3128", "proxy:address")]


def test_engines_alone_set_revocation_on_the_engine_and_no_nodes_need_nothing():
    assert [s.server_role for s in ADAPTER.proxy_settings(_env("pf-engine"), PROXY) if s.file is None] == ["pf-engine"]
    assert ADAPTER.proxy_settings(_env("ds"), PROXY) == ()
