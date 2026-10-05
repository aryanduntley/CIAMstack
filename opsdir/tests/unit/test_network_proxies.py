"""The explicit proxy the products are told about: only one with an address (a firewall with domain rules is
transparent), its host and port, what bypasses it (the host, the private ranges as host patterns, private zones,
the service names), and the standard Java properties that say so."""
from opsdir.domains.network.proxies import (ProxySettings, bypass_hosts, explicit_proxy, java_options, proxy_settings,
                                            range_pattern)
from network_fixtures import ALPHA, entry, model

SQUID = entry(ALPHA, "squid", "ciamProxy", ciamBindingRole="squid", ciamProxyKind="forward-proxy",
              ciamProxyAddress="proxy.corp.example:3128")
FIREWALL = entry(ALPHA, "fw", "ciamProxy", ciamBindingRole="fw", ciamProxyKind="firewall",
                 ciamProxyAddress="10.1.9.4:3128")
ZONES = (entry(ALPHA, "zone-int", "ciamDnsZoneBinding", ciamBindingRole="zone-int", ciamDnsZone="int.example.test",
               ciamZoneVisibility="private"),
         entry(ALPHA, "zone-pub", "ciamDnsZoneBinding", ciamBindingRole="zone-pub", ciamDnsZone="example.test",
               ciamZoneVisibility="public"))


def test_only_a_proxy_with_an_address_that_isn_t_a_firewall_is_explicit():
    assert explicit_proxy(model(alpha=(FIREWALL,))[1]) is None
    assert proxy_settings(model(alpha=(FIREWALL,))[1]) is None and java_options(None) == ()
    assert explicit_proxy(model(alpha=(FIREWALL, SQUID))[1]).dn.startswith("cn=squid,")


def test_ranges_become_host_patterns_cut_at_their_octet():
    assert [range_pattern(c) for c in ("10.0.0.0/8", "10.20.0.0/16", "172.16.0.0/12", "10.1.2.0/24",
                                       "10.1.2.3/32", "fd00::/8")] == [
        "10.*", "10.20.*", "172.*", "10.1.2.*", "10.1.2.3", None]


def test_what_bypasses_the_proxy():
    m = model(alpha=(SQUID, *ZONES))[1]
    assert bypass_hosts(m) == ("localhost", "127.*", "10.1.*", "*.int.example.test", "sso.example.test")


def test_settings_and_java_options():
    m = model(alpha=(SQUID,))[1]
    s = proxy_settings(m)
    assert (s.host, s.port, s.binding.dn) == ("proxy.corp.example", 3128, explicit_proxy(m).dn)
    assert java_options(ProxySettings("p.example", 8080, ("localhost", "10.*"), None)) == (
        "-Dhttp.proxyHost=p.example", "-Dhttp.proxyPort=8080", "-Dhttps.proxyHost=p.example",
        "-Dhttps.proxyPort=8080", "-Dhttp.nonProxyHosts=localhost|10.*")
