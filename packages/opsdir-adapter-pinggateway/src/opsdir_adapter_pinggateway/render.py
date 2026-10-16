"""PingGateway adapter: render the gateway's routes for each environment.

  pinggateway/routes/<name>.json     each route, its backend address from the binding of its backend role in the
                                     environment (UNBOUND:<role> when the environment binds none); and a route for each
                                     protected application the environment has its gateways take over (takeover.py)

The gateway's own settings (config.json, admin.json) are captured config files, rendered with the rest of the
environment's captured files. The routes follow the gateway's JSON but are not validated against a live gateway.
"""
import json
from types import MappingProxyType

from opsdir.core.directory import children, one, rdn_value, values
from opsdir.core.environment import one_role
from opsdir.core.jsondata import held_json
from opsdir.core.profiles import ProductProfile
from .naming import ROUTES
from .takeover import handed_over, takeover_routes

FORMATS = (("pinggateway/routes/*.json", "json"),)
# The gateway's configuration as it reads it under its instance directory (config/config.json, admin.json,
# config/routes/): the product profile a deployment kit consumes (core.profiles)
PROFILE = ProductProfile("PingGateway", (("pinggateway/routes/", "config/routes/"),
                                         ("files/pinggateway/", "")))
DEFAULT_PORTS = MappingProxyType({"https": "443", "http": "80"})


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
    config = held_json(route, "pinggwConfig")
    return {"name": rdn_value(route),
            **({"condition": one(route, "pinggwCondition")} if one(route, "pinggwCondition") else {}),
            **({"baseURI": backend_uri(m, route)} if one(route, "pinggwBackendRole") else {}), **config}


def render_env(m, services):
    """Every route, for this environment: the record's routes (but those whose protected application another role
    enforces here), and one for each protected application the environment has its gateways take over
    (takeover.py)."""
    gone = handed_over(m.d)
    own = {f"pinggateway/routes/{rdn_value(r)}.json": route_file(m, r) for r in children(m.d, ROUTES, "pinggwRoute")
           if r.dn.lower() not in gone}
    return {path: json.dumps(body, indent=2) + "\n" for path, body in {**takeover_routes(m), **own}.items()}
