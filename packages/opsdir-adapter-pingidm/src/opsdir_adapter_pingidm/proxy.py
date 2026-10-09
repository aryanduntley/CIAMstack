"""PingIDM's settings for an explicit egress proxy (opsdir.domains.network.proxies): its HTTP client (external REST,
the identity provider service) told to use the JVM's proxy in resolver/boot.properties, and the standard Java proxy
properties in the JVM options it starts with (OPENIDM_OPTS). The JVM's proxy is used rather than IDM's own proxy URI
because only the JVM's honours the hosts reached directly, so connectors to the platform's own services stay off the
proxy. Pure."""
from opsdir.core.contract import ProxySetting
from opsdir.domains.compute.workloads import runs_here
from opsdir.domains.network.proxies import DERIVATIONS
from .naming import SERVER_ROLES

BOOT_PROPERTIES = "resolver/boot.properties"


def proxy_settings(m, proxy):
    """The ProxySettings environment m's IDM nodes need for an explicit proxy (on servers or Kubernetes)."""
    return tuple(s for r in SERVER_ROLES if runs_here(m, r) for s in (
        ProxySetting(r, BOOT_PROPERTIES, BOOT_PROPERTIES, "openidm.http.client.proxy.useSystem", "true"),
        ProxySetting(r, "the JVM options it starts with (OPENIDM_OPTS)", None, "JVM options",
                     DERIVATIONS["proxy:java-options"](proxy), "proxy:java-options")))
