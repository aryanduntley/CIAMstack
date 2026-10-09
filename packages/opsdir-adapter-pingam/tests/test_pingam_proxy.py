"""PingAM's settings for an explicit egress proxy: its HTTP client's advanced server properties (proxy URI, hosts
reached directly comma-separated) and the JVM options of its container."""
from types import SimpleNamespace

from opsdir.core.directory import make_directory, make_entry
from opsdir.domains.network.proxies import ProxySettings
from opsdir_adapter_pingam.adapter import ADAPTER

PROXY = ProxySettings("proxy.corp.example", 3128, ("localhost", "10.20.*"), None)


def test_advanced_server_properties_and_jvm_options():
    m = SimpleNamespace(servers=(make_entry("cn=am-1", ("ciamServer",), {"ciamServerRole": ("am",)}),),
                        d=make_directory((), {}, ()))
    assert [(s.place, s.locator, s.value) for s in ADAPTER.proxy_settings(m, PROXY)] == [
        ("advanced server properties (server defaults)", "org.forgerock.openam.httpclienthandler.system.proxy.uri",
         "http://proxy.corp.example:3128"),
        ("advanced server properties (server defaults)", "org.forgerock.openam.httpclienthandler.system.nonProxyHosts",
         "localhost,10.20.*"),
        ("the JVM options of its container (JAVA_OPTS)", "JVM options",
         "-Dhttp.proxyHost=proxy.corp.example -Dhttp.proxyPort=3128 -Dhttps.proxyHost=proxy.corp.example "
         "-Dhttps.proxyPort=3128 -Dhttp.nonProxyHosts=localhost|10.20.*")]
    assert ADAPTER.proxy_settings(SimpleNamespace(servers=(), d=make_directory((), {}, ())), PROXY) == ()
