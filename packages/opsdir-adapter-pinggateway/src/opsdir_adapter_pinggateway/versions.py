"""What changes between PingGateway (ForgeRock Identity Gateway) releases (contract.VersionChange; milestone 86), from
the vendor's release notes (research 2403): what the record's routes hold that each change touches, so the planner
names it when a move upgrades the gateway. Pure."""
import json

from opsdir.core.contract import VersionChange
from opsdir.core.directory import children, one
from .naming import ROUTES, SERVER_ROLES
from .routes import objects

HTTP_HANDLERS = ("ClientHandler", "ReverseProxyHandler")


def _routes(d):
    """(name, the route's settings as JSON objects) for every route the record holds."""
    return tuple((one(r, "cn"), objects(json.loads(one(r, "pinggwConfig") or "{}"))) for r in children(d, ROUTES,
                                                                                                      "pinggwRoute"))


def routes_using(types):
    """A VersionChange.touches: the routes holding an object of one of these types (a filter, handler or heap
    object)."""
    def touches(d, m, role):
        return tuple(name for name, found in _routes(d) if any(o.get("type") in types for o in found)) \
            if role in SERVER_ROLES else ()
    return touches


def _default_protocol(o):
    """Whether an object is an HTTP handler that leaves its protocol version to the default, or a route's handler
    naming the default one (the heap's ClientHandler or ReverseProxyHandler)."""
    return (o.get("type") in HTTP_HANDLERS and not (o.get("config") or {}).get("protocolVersion")) \
        or o.get("handler") in HTTP_HANDLERS


def default_protocol_routes(d, m, role):
    """The routes whose backend handlers take the default HTTP protocol version (HTTP/2 from 2026.9)."""
    return tuple(name for name, found in _routes(d) if any(_default_protocol(o) for o in found)) \
        if role in SERVER_ROLES else ()


VERSION_CHANGES = (
    VersionChange(">=7.2", "OAuth2ClientFilter is renamed AuthorizationCodeOAuth2ClientFilter", "routes' OAuth 2.0 "
                  "client filters", "action", "Rename the filter type in the routes (the record keeps reading both).",
                  routes_using(("OAuth2ClientFilter",))),
    VersionChange(">=2023.6", "scripts load only from absolute paths or the base script directory", "routes' "
                  "scriptable filters and handlers", "action", "Move each script under the base script directory "
                  "(or give its absolute path) and record its bundle.",
                  routes_using(("ScriptableFilter", "ScriptableHandler", "ScriptableThrottlingPolicy"))),
    VersionChange(">=2024.3", "inline heap objects can no longer be referenced by name, and objects that use secrets "
                  "need a secretsProvider", "routes", "info", "Render and run the target's routes in a test gateway "
                  "before the cutover."),
    VersionChange(">=2025.3", "the admin endpoints move to the admin port 8085 without the /openig prefix (/ping; "
                  "/health/startup from 2025.6)", "health checks and admin access", "info", "The render, listeners "
                  "and the edge's health checks follow the target's version; open 8085 to the monitors."),
    VersionChange(">=2025.3", "issuer repositories default to the new behaviour (useDeprecatedIssuerRepository "
                  "false)", "routes trusting an OpenID provider", "info", "Test the routes' sign-in against the target "
                  "gateway.", routes_using(("Issuer", "IssuerRepository"))),
    VersionChange(">=2026.3", "the Docker image's directories move (/opt/ig to /opt/gateway, /var/ig to /var/gateway), "
                  "the admin session cookie is IG_ADMIN_SESSIONID, and invalid configuration or routes fail startup",
                  "images, mounts and routes", "info", "Point mounts and scripts at the new directories."),
    VersionChange(">=2026.9", "ClientHandler and ReverseProxyHandler use HTTP/2 when protocolVersion is unset",
                  "routes' backend handlers", "action", "Set protocolVersion \"HTTP/1.1\" on the handlers of "
                  "backends that speak only HTTP/1.1.", default_protocol_routes),
    VersionChange(">=2026.9", "UmaService resource actions require scopes", "routes with an UmaService", "action",
                  "Give every UmaService resource action its scopes.", routes_using(("UmaService",))),
)
