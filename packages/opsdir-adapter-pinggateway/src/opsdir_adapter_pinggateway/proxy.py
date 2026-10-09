"""PingGateway's settings for an explicit egress proxy (opsdir.domains.network.proxies): config.json's heap object
named ProxyOptions, the default of every ClientHandler and ReverseProxyHandler, as SystemProxyOptions, and the
standard Java proxy properties in the JVM options it starts with. The JVM's proxy is used rather than a
CustomProxyOptions URI because only the JVM's honours the hosts reached directly: the routes' own backends (the
applications behind service names) stay off the proxy. Pure."""
from opsdir.core.contract import ProxySetting
from opsdir.domains.compute.workloads import runs_here
from opsdir.domains.network.proxies import DERIVATIONS
from .naming import SERVER_ROLES

HEAP = "config.json's heap object named ProxyOptions"


def proxy_settings(m, proxy):
    """The ProxySettings environment m's gateways need for an explicit proxy (on servers or Kubernetes)."""
    return tuple(s for r in SERVER_ROLES if runs_here(m, r) for s in (
        ProxySetting(r, HEAP, None, "type", "SystemProxyOptions"),
        ProxySetting(r, "the JVM options it starts with", None, "JVM options",
                     DERIVATIONS["proxy:java-options"](proxy), "proxy:java-options")))
