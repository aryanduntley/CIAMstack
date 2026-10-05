"""PingAM's settings for an explicit egress proxy (opsdir.domains.network.proxies): its HTTP client's advanced server
properties (the proxy as a URI, the hosts reached directly comma-separated; the URI takes precedence over the JVM's
proxy), which the scripting engine, social providers and the other users of AM's HTTP client honour, and the standard
Java proxy properties in the JVM options of its container (JAVA_OPTS, setenv.sh) for the rest. Pure."""
from opsdir.core.contract import ProxySetting
from opsdir.core.environment import servers_with_role
from opsdir.domains.network.proxies import DERIVATIONS
from .realms import SERVER_ROLES

PROPERTIES = "advanced server properties (server defaults)"
CLIENT = "org.forgerock.openam.httpclienthandler.system"


def proxy_settings(m, proxy):
    """The ProxySettings environment m's AM servers need for an explicit proxy."""
    return tuple(s for r in SERVER_ROLES if servers_with_role(m, r) for s in (
        ProxySetting(r, PROPERTIES, None, f"{CLIENT}.proxy.uri", DERIVATIONS["proxy:uri"](proxy), "proxy:uri"),
        ProxySetting(r, PROPERTIES, None, f"{CLIENT}.nonProxyHosts", DERIVATIONS["proxy:bypass-list"](proxy),
                     "proxy:bypass-list"),
        ProxySetting(r, "the JVM options of its container (JAVA_OPTS)", None, "JVM options",
                     DERIVATIONS["proxy:java-options"](proxy), "proxy:java-options")))
