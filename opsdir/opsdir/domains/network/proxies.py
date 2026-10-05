"""The explicit proxy an environment's servers send outside traffic through, read neutrally for the product adapters:
a forward proxy, web proxy or proxy service with an address (ciamProxyAddress) has to be configured in each product
that fetches from outside sites (partner metadata, signing keys, certificate status, vendors), while a firewall with
domain rules is transparent and needs nothing. What doesn't go through it: the host itself, the networks the stack
reaches privately, the private DNS zones it publishes in and its own service names. Pure."""
import ipaddress
from typing import NamedTuple, Optional

from ...core.directory import one
from ...core.environment import EnvModel, of_class
from .stack import private_ranges

LOCAL = ("localhost", "127.*")

# host, port: where clients send the traffic; bypass: hosts reached directly, as wildcard patterns (*.zone, 10.20.*);
# binding: the proxy's
ProxySettings = NamedTuple("ProxySettings", [("host", str), ("port", int), ("bypass", tuple),
                                             ("binding", Optional[object])])


def explicit_proxy(m: EnvModel):
    """Environment m's proxy that clients must be told about (an address recorded, not a transparent firewall), or
    None."""
    return next((p for p in of_class(m, "ciamProxy")
                 if one(p, "ciamProxyAddress") and one(p, "ciamProxyKind") != "firewall"), None)


def range_pattern(cidr):
    """A host pattern covering an IPv4 range, cut at the octet its prefix falls in (10.20.0.0/16 -> 10.20.*,
    172.16.0.0/12 -> 172.*), or None for IPv6 (host patterns can't say it)."""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4:
        return None
    octets = net.prefixlen // 8
    return ".".join(str(net.network_address).split(".")[:octets] + ["*"]) if octets < 4 else str(net.network_address)


def bypass_hosts(m):
    """The hosts environment m's servers reach without the proxy: the host itself, its private ranges as patterns,
    its private DNS zones (*.zone) and its service names, unique, in that order."""
    zones = (f"*.{one(z, 'ciamDnsZone').rstrip('.')}" for z in of_class(m, "ciamDnsZoneBinding")
             if one(z, "ciamZoneVisibility") == "private" and one(z, "ciamDnsZone"))
    names = (one(s, "ciamFqdn") for s in of_class(m, "ciamServiceName") if one(s, "ciamFqdn"))
    ranges = (range_pattern(c) for c in private_ranges(m))
    return tuple(dict.fromkeys(h for h in (*LOCAL, *ranges, *zones, *names) if h))


def settings_of(m, proxy):
    """ProxySettings of a proxy binding of environment m (its address, the hosts m reaches directly)."""
    host, _, port = one(proxy, "ciamProxyAddress").rpartition(":")
    return ProxySettings(host, int(port), bypass_hosts(m), proxy)


def proxy_settings(m: EnvModel):
    """ProxySettings for environment m's explicit proxy, or None when its egress needs no client settings."""
    p = explicit_proxy(m)
    return settings_of(m, p) if p is not None else None


def java_options(settings):
    """The standard Java networking properties for proxy settings (both schemes through the one proxy; the bypass
    list pipe-separated, as java.net reads http.nonProxyHosts for HTTPS too), as -D options; () for None."""
    if settings is None:
        return ()
    return (f"-Dhttp.proxyHost={settings.host}", f"-Dhttp.proxyPort={settings.port}",
            f"-Dhttps.proxyHost={settings.host}", f"-Dhttps.proxyPort={settings.port}",
            f"-Dhttp.nonProxyHosts={'|'.join(settings.bypass)}")


# Values a captured file's setting can take from an environment's proxy binding (ciamValueFrom
# '<proxy role>#proxy:<name>'): computed from the record wherever the file is rendered, never stored copies, so each
# environment's file names its own proxy and the hosts it reaches directly.
DERIVATIONS = {
    "proxy:host": lambda s: s.host,
    "proxy:port": lambda s: str(s.port),
    "proxy:address": lambda s: f"{s.host}:{s.port}",
    "proxy:uri": lambda s: f"http://{s.host}:{s.port}",
    "proxy:bypass": lambda s: "|".join(s.bypass),               # java.net's http.nonProxyHosts
    "proxy:bypass-list": lambda s: ",".join(s.bypass),
    "proxy:java-options": lambda s: " ".join(java_options(s)),
}


def derived(m, binding, name):
    """The value derivation name gives for a proxy binding of environment m; ValueError when the name is unknown or
    the binding records no proxy address."""
    if name not in DERIVATIONS:
        raise ValueError(f"no derived value {name} (known: {', '.join(DERIVATIONS)})")
    if not one(binding, "ciamProxyAddress"):
        raise ValueError(f"{one(binding, 'ciamBindingRole')} records no proxy address (ciamProxyAddress)")
    return DERIVATIONS[name](settings_of(m, binding))
