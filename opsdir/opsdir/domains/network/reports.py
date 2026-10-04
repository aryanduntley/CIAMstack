"""Network reports: routes, private endpoints, endpoint services and outside sites across every environment. Pure
functions of the directory snapshot."""
from ...core.directory import get, one, rdn_value, subtree, values
from ...core.environment import environment_of
from ...core.naming import branch, env_label
from .routing import allows, parse_route, required_sites

ROUTE_HEADERS = ("environment", "table", "subnets", "destination", "target kind", "target", "for")
PRIVATE_ENDPOINT_HEADERS = ("environment", "endpoint", "service", "kind", "reaches", "subnets", "private dns")
ENDPOINT_SERVICE_HEADERS = ("environment", "binding", "service", "name", "allowed", "consumers", "acceptance",
                            "visible to")
SITE_HEADERS = ("site", "kind", "needed by", "allowed by")


def _bound(d, oc):
    return subtree(d, branch("environments"), oc)


def _joined(e, attr):
    return ", ".join(values(e, attr))


def route_rows(d, dn=None):
    """One row per route of every route table."""
    return sorted(((env_label(environment_of(t)), rdn_value(t),
                    _joined(t, "ciamSubnetRole") or ("main" if one(t, "ciamMainTable") == "TRUE" else ""),
                    r.destination, r.kind, r.target, ", ".join(r.roles))
                   for t in _bound(d, "ciamRouteTable") for r in map(parse_route, values(t, "ciamRoute")) if r),
                  key=lambda row: row[:4])


def private_endpoint_rows(d, dn=None):
    """One row per private endpoint."""
    return sorted((env_label(environment_of(p)), rdn_value(p), one(p, "ciamPrivateService"),
                   one(p, "ciamPrivateEndpointKind") or "", _joined(p, "ciamReachesRole"), _joined(p, "ciamSubnetRole"),
                   {"TRUE": "yes", "FALSE": "no"}.get(one(p, "ciamPrivateDns"), ""))
                  for p in _bound(d, "ciamPrivateEndpoint"))


def endpoint_service_rows(d, dn=None):
    """One row per endpoint service: what it exposes, under which name, to whom."""
    def consumers(e):
        return ", ".join(rdn_value(c) for c in (get(d, x) for x in values(e, "ciamAllowsConsumer")) if c is not None)
    return sorted((env_label(environment_of(e)), rdn_value(e), _joined(e, "ciamServiceRole"),
                   one(e, "ciamServiceAlias") or "", _joined(e, "ciamAllowedPrincipal"), consumers(e),
                   "required" if one(e, "ciamAcceptanceRequired") == "TRUE" else "automatic",
                   _joined(e, "ciamVisibleTo") or "anyone with the name")
                  for e in _bound(d, "ciamEndpointService"))


def site_rows(d, dn=None):
    """One row per outside site the platform must reach, with the proxies and firewalls that allow it (environment:
    binding)."""
    proxies = _bound(d, "ciamProxy")
    return [(s.host, s.kind, ", ".join(s.needed_by),
             ", ".join(f"{env_label(environment_of(p))}: {rdn_value(p)}" for p in proxies if allows(p, s)))
            for s in sorted(required_sites(d), key=lambda s: (s.kind, s.host))]
