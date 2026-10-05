"""PingGateway's settings for an explicit egress proxy: the default ProxyOptions heap object as SystemProxyOptions and
the JVM's proxy in the options it starts with (so routes' own backends stay off the proxy)."""
from types import SimpleNamespace

from opsdir.core.directory import make_entry
from opsdir.domains.network.proxies import ProxySettings
from opsdir_adapter_pinggateway.adapter import ADAPTER

PROXY = ProxySettings("proxy.corp.example", 3128, ("localhost", "*.int.example"), None)


def test_system_proxy_options_and_jvm_options():
    m = SimpleNamespace(servers=(make_entry("cn=ig-1", ("ciamServer",), {"ciamServerRole": ("ig",)}),))
    heap, jvm = ADAPTER.proxy_settings(m, PROXY)
    assert (heap.place, heap.locator, heap.value) == ("config.json's heap object named ProxyOptions", "type",
                                                      "SystemProxyOptions")
    assert jvm.value.endswith("-Dhttp.nonProxyHosts=localhost|*.int.example")
