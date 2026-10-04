"""Routes and outside sites as data: an environment's route tables read into routes, where its default route goes, and
the outside sites the platform must reach (recorded ones, and the vendors the messaging domain records). Pure."""
import re
from typing import NamedTuple

from ...core.directory import children, one, values
from ...core.environment import of_class
from ..messaging.services import covered, external_services
from .naming import DEFAULT_ROUTE, EGRESS_DESTINATIONS, ROUTE

Route = NamedTuple("Route", [("destination", str), ("kind", str), ("target", str), ("roles", tuple)])
Site = NamedTuple("Site", [("host", str), ("kind", str), ("needed_by", tuple), ("source", str)])


def parse_route(text):
    """A ciamRoute value as a Route (target '' when none is named, roles () when it applies to every server), or None
    when it isn't one."""
    found = re.match(ROUTE, text)
    if not found:
        return None
    dest, kind, target, scope = found.group(1), found.group(2), (found.group(3) or "").strip(), found.group(4) or ""
    return Route(dest, kind, target, tuple(scope.removeprefix(" for ").split(",")) if scope else ())


def routes(m):
    """((route table, Route), ...) of environment m, in table order."""
    return tuple((t, r) for t in of_class(m, "ciamRouteTable") for r in map(parse_route, values(t, "ciamRoute")) if r)


def default_routes(m):
    """Environment m's routes for everything (0.0.0.0/0, ::/0): where its egress to the internet goes."""
    return tuple((t, r) for t, r in routes(m) if r.destination in DEFAULT_ROUTE)


def required_sites(d):
    """The outside sites the platform must reach: the recorded ones, then the external services the messaging domain
    records with an endpoint host (an MFA vendor, a mail or SMS API)."""
    recorded = (Site(one(e, "ciamDestination"), one(e, "ciamSiteKind"), values(e, "ciamNeededByRole"), e.dn)
                for e in children(d, EGRESS_DESTINATIONS, "ciamEgressDestination"))
    vendors = (Site(one(s, "ciamEndpointHost"), "mfa" if one(s, "ciamServiceKind") == "mfa" else "messaging",
                    values(s, "ciamReachedFrom"), s.dn)
               for s in external_services(d) if one(s, "ciamEndpointHost"))
    return tuple(dict((s.host.lower(), s) for s in (*vendors, *recorded)).values())


def site_host(site):
    """A site's host name without its port."""
    return site.host.rsplit(":", 1)[0] if re.search(r":[0-9]+$", site.host) else site.host


def allows(proxy, site):
    """Whether a proxy or firewall lets egress out to a site: an allowed host, or a domain it is under (a site that is
    a whole domain, *.example, needs that domain or one above it)."""
    allowed = tuple(re.sub(r":[0-9]+$", "", a) for a in values(proxy, "ciamAllowedDestination"))
    return covered(site_host(site).removeprefix("*."), allowed)
