"""PingFederate's settings for an explicit egress proxy (opsdir.domains.network.proxies): the forward proxy keys of
each node's bin/run.properties, which HTTP and HTTPS traffic originating from PingFederate uses (partner metadata,
signing keys, notifications; the AWS SDK plugins, such as the SNS notification publisher, read only the http.* keys,
so both are set), and the proxy of its certificate revocation checking (CRL and OCSP), a cluster setting of its own
(Security > Certificate Revocation Checking, or /certificates/revocation/settings) set once on the admin node. Pure."""
from opsdir.core.contract import ProxySetting
from opsdir.core.environment import servers_with_role
from opsdir.domains.network.proxies import DERIVATIONS
from .naming import SERVER_ROLES
from .nodes import RUN_PROPERTIES

REVOCATION = "certificate revocation checking's proxy settings (CRL and OCSP)"


def proxy_settings(m, proxy):
    """The ProxySettings environment m's PingFederate nodes need for an explicit proxy."""
    roles = tuple(r for r in SERVER_ROLES if servers_with_role(m, r))
    run = (("http.proxyHost", "proxy:host"), ("http.proxyPort", "proxy:port"), ("https.proxyHost", "proxy:host"),
           ("https.proxyPort", "proxy:port"), ("http.nonProxyHosts", "proxy:bypass"))
    admin = ("pf-admin",) if "pf-admin" in roles else roles[:1]      # the cluster's setting, set once
    return (*(ProxySetting(r, RUN_PROPERTIES, RUN_PROPERTIES, k, DERIVATIONS[link](proxy), link)
              for r in roles for k, link in run),
            *(ProxySetting(r, REVOCATION, None, "proxy", DERIVATIONS["proxy:address"](proxy), "proxy:address")
              for r in admin))
