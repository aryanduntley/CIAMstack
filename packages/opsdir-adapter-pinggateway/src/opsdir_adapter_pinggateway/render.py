"""PingGateway adapter: render the gateway's routes for each environment.

  pinggateway/routes/<name>.json     each route, its backend address from the binding of its backend role in the
                                     environment (UNBOUND:<role> when the environment binds none); and a route for each
                                     protected application the environment has its gateways take over (takeover.py);
                                     each handler wrapped in a guard where an edge forwards client certificates
  pinggateway/admin-tls/, secrets/   the client certificate check of trust policies the gateway enforces itself
                                     (client_certificates.py)

The gateway's own settings (config.json, admin.json) are captured config files, rendered with the rest of the
environment's captured files. The routes follow the gateway's JSON but are not validated against a live gateway.
"""
import json
from types import MappingProxyType

from opsdir.core.directory import children, one, rdn_value, values
from opsdir.core.environment import one_role
from opsdir.core.jsondata import held_json
from opsdir.core.profiles import ProductProfile
from .client_certificates import PEM_DIR, TLS_DIR, client_certificate_notes, client_tls_files, guard_routes, unguarded
from .naming import ROUTES
from .takeover import handed_over, own_routes, takeover_notes, takeover_routes

FORMATS = (("pinggateway/routes/*.json", "json"), (f"{TLS_DIR}/*.json", "json"), (f"{PEM_DIR}/*.pem", "pem"))
# The gateway's configuration as it reads it under its instance directory (config/config.json, admin.json,
# config/routes/, and secrets/ for the client CA bundles): the product profile a deployment kit consumes (core.profiles)
PROFILE = ProductProfile("PingGateway", (("pinggateway/routes/", "config/routes/"),
                                         ("pinggateway/secrets/", "secrets/"),
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
    (takeover.py), guarded where an edge forwards client certificates; and the client certificate check of the trust
    policies the gateway enforces itself (client_certificates.py)."""
    gone = handed_over(m.d)
    own = {f"pinggateway/routes/{rdn_value(r)}.json": route_file(m, r) for r in children(m.d, ROUTES, "pinggwRoute")
           if r.dn.lower() not in gone}
    routes = guard_routes(m, services, {**takeover_routes(m), **own})
    return {**{path: json.dumps(body, indent=2) + "\n" for path, body in routes.items()}, **client_tls_files(m)}


def gateway_notes(m, services=None):
    """Render notes (Adapter.notes): the taken-over applications', and the client certificate checks'."""
    return (*takeover_notes(m, services), *(client_certificate_notes(m, services) if services is not None else ()))


def routes_read_back(files, d, environment):
    """The rendered gateway files as its own configuration (Adapter.reads_back's prepare): taken-over routes left out
    (takeover.own_routes), the client certificate guard and files too (client_certificates.unguarded)."""
    return unguarded(own_routes(files, d, environment))
