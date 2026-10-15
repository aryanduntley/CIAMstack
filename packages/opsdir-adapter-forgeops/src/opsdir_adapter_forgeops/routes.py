"""The routes ForgeOps serves through a cluster gateway, and whether its own Ingresses stay on. Pure.

The release's Ingresses (ingress-nginx's class and annotations by default, a controller the Kubernetes project has
retired) give way to the cluster's in-cluster gateway when the record has one in front of the roles they serve
(edge.gateways): their paths are declared here as contract Routes (release.ROUTES) and opsdir-adapter-kubernetes renders
them as HTTPRoutes.
"""
from opsdir.core.contract import Route
from opsdir.core.environment import roles_for
from opsdir.domains.edge.gateways import role_gateway
from .components import placements
from .release import CHART_PRODUCTS, ROUTES, TAKEN_ROUTES


def routes(m):
    """Adapter routes: the Routes of the components on in each of environment m's placements, one per role whose
    service names carry each path; a path another component on takes over is its (TAKEN_ROUTES)."""
    on = {c for p in placements(m) for c in p.on}
    taken = {(was, path) for was, path, by in TAKEN_ROUTES if by in on}
    return tuple(Route(role, path, match, service, port, rewrite)
                 for component, roles, path, match, service, port, rewrite in ROUTES
                 if component in on and (component, path) not in taken for role in roles)


def gateway_fronted(m, chart):
    """Whether a cluster gateway in environment m fronts a role a chart's Ingresses serve: its Ingresses are then
    off."""
    return any(role_gateway(m, role) is not None for c, products in CHART_PRODUCTS if c == chart
               for product in products for role in roles_for(m, product, "server"))
