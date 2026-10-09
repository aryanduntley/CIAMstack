"""The routes PingFederate serves through a cluster gateway with the ping-devops chart. Pure.

The chart's admin console and engines each have a Service serving TLS on their own port (release.SERVICE_PORTS); behind
the cluster's in-cluster gateway (edge.gateways) their service names' whole host goes to it, re-encrypted, and the
chart's own Ingress is off.
"""
from opsdir.core.contract import Route
from opsdir.domains.edge.gateways import role_gateway
from .products import placements
from .release import PRODUCTS, SERVICE_PORTS, product_of, service_of


def routes(m):
    """Adapter routes: for each product a placement runs, its role's whole host to the product's Service (TLS)."""
    roles, ports = {x.name: x.role for x in PRODUCTS}, dict(SERVICE_PORTS)
    return tuple(dict.fromkeys(Route(roles[name], "/", "prefix", service_of(name), ports[name], None, True)
                               for p in placements(m) for name, _ in p.placed))


def gateway_fronted(m, role):
    """Whether a cluster gateway in environment m fronts a server role the chart runs: its Ingress is then off."""
    return product_of(role) is not None and role_gateway(m, role) is not None
