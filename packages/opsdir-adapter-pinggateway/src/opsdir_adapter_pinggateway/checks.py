"""PingGateway planner checks: every route can work in the target (its backend role is bound there, the client it
signs users in as and the OpenID provider it trusts are in the record); a route to a fixed backend is an action."""

from opsdir.core.directory import children, one, rdn_value
from opsdir.core.environment import bound_nowhere
from opsdir.core.findings import findings, merge_findings, responsible
from opsdir.core.jsondata import held_json
from opsdir.domains.federation.services import identity_services, integrations
from opsdir.domains.infrastructure.external import external_host_fix
from .naming import ROUTES
from .routes import backend, client_ids, issuers


def route_problems(d, route):
    """Why a route can't sign users in anywhere: clients or OpenID providers the record doesn't have."""
    config = held_json(route, "pinggwConfig")
    known_clients = {one(i, "ciamClientId") for i in integrations(d, "oidc-client")}
    known_issuers = {one(s, "ciamOidcIssuer") for s in identity_services(d) if one(s, "ciamOidcIssuer")}
    trusted = (*issuers(config), *((one(route, "pinggwIssuer"),) if one(route, "pinggwIssuer") else ()))
    return (*(f"it signs users in as client {c}, which no integration in the record is" for c in client_ids(config)
              if c not in known_clients),
            *(f"it trusts {u}, which is no identity service's issuer in the record" for u in dict.fromkeys(trusted)
              if u not in known_issuers))


def _route(ctx, r):
    name, role = rdn_value(r), one(r, "pinggwBackendRole")
    owner = responsible(ctx.d, r, ctx.dst.env)
    why = route_problems(ctx.d, r)
    config = held_json(r, "pinggwConfig")
    fixed = "baseURI" in config
    found = backend(config) if fixed and not role else None
    fix = external_host_fix(ctx.src, found[1], f"route `{name}`", f"external-host:route/{name}", "pinggateway/config",
                            found[2]) if found and found[1] else None
    return findings(
        blockers=[*((("Gateway", f"Route `{name}` can't sign users in: {'; '.join(why)}.", owner),) if why else ()),
                  *((("Gateway", f"Route `{name}` protects role `{role}`, which {ctx.dst.label} doesn't bind.", owner),)
                    if bound_nowhere((role,), ctx.dst) else ())],
        actions=[("Gateway", f"Route `{name}` sends requests to a fixed backend from every environment (no backend "
                  f"role): confirm {ctx.dst.label} can reach it, or record the application's service name.", owner,
                  None)] if fixed and not role else [],
        fixes=[fix] if fix else [])


def check_routes(ctx):
    """Routes the target can't serve are blockers; a route to a fixed backend is an action."""
    routes = children(ctx.d, ROUTES, "pinggwRoute")
    found = merge_findings([_route(ctx, r) for r in routes])
    counted = "The gateway route signs" if len(routes) == 1 else f"All {len(routes)} gateway routes sign"
    return found if found.blockers or not routes else found._replace(
        ok=(*found.ok, f"{counted} users in with clients and OpenID providers the record has."))
