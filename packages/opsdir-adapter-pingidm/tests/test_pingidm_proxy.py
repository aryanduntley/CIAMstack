"""PingIDM's settings for an explicit egress proxy: its HTTP client on the JVM's proxy (resolver/boot.properties),
the JVM's proxy in the options it starts with."""
from types import SimpleNamespace

from opsdir.core.directory import make_entry
from opsdir.domains.network.proxies import ProxySettings
from opsdir_adapter_pingidm.adapter import ADAPTER

PROXY = ProxySettings("proxy.corp.example", 3128, ("localhost",), None)


def test_boot_properties_use_the_jvm_proxy():
    m = SimpleNamespace(servers=(make_entry("cn=idm-1", ("ciamServer",), {"ciamServerRole": ("idm",)}),))
    boot, jvm = ADAPTER.proxy_settings(m, PROXY)
    assert (boot.file, boot.locator, boot.value) == ("resolver/boot.properties", "openidm.http.client.proxy.useSystem",
                                                     "true")
    assert jvm.file is None and "-Dhttp.nonProxyHosts=localhost" in jvm.value
