"""PingGateway adapter: render the gateway's routes for each environment.

  pinggateway/routes/<name>.json     each route, its backend address from the binding of its backend role in the
                                     environment (UNBOUND:<role> when the environment binds none)

The gateway's own settings (config.json, admin.json) are captured config files, rendered with the rest of the
environment's captured files. The routes follow the gateway's JSON but are not validated against a live gateway.
"""
import json

from opsdir.core.directory import children, one, rdn_value, values
from opsdir.core.environment import one_role
from .naming import ROUTES

FORMATS = (("pinggateway/routes/*.json", "json"),)
DEFAULT_PORTS = {"https": "443", "http": "80"}


def backend_uri(m, route):
    """scheme://<the backend role's service name>[:port] in environment m, or UNBOUND:<role>."""
    role = one(route, "pinggwBackendRole")
    b = one_role(m, role)
    if b is None or not one(b, "ciamFqdn"):
        return f"UNBOUND:{role}"
    scheme = one(route, "pinggwBackendScheme", "https")
    port = next((p for p in values(b, "ciamPort") if p != DEFAULT_PORTS.get(scheme)), None)
    return f"{scheme}://{one(b, 'ciamFqdn')}" + (f":{port}" if port else "")


def route_file(m, route):
    config = json.loads(one(route, "pinggwConfig") or "{}")
    return {"name": rdn_value(route),
            **({"condition": one(route, "pinggwCondition")} if one(route, "pinggwCondition") else {}),
            **({"baseURI": backend_uri(m, route)} if one(route, "pinggwBackendRole") else {}), **config}


def render_env(m, services):
    """Every route, for this environment."""
    return {f"pinggateway/routes/{rdn_value(r)}.json": json.dumps(route_file(m, r), indent=2) + "\n"
            for r in children(m.d, ROUTES, "pinggwRoute")}
