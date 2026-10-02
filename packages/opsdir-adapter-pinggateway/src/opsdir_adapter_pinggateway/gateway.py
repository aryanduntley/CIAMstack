"""Gateway configuration import: a PingGateway configuration directory (config/ and routes/) read into the record.
Pure.

  routes/*.json      -> routes (pinggwRoute): a backend host that is a service name in the record becomes that
                        binding's role (rendered per environment); the OAuth 2.0 client a route signs users in as is
                        linked to the integration with that client id, and the OpenID provider it trusts is recorded
  config/*.json      -> captured config files (config.json, admin.json: the gateway's own settings)
  anything else      -> named in a notice

The importer owns what it reads; what the record adds to a route (owners) is kept.
"""

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import get, make_entry, one, ou_entry
from opsdir.core.environment import UNBOUND, published_role
from opsdir.core.formats import JSON
from opsdir.core.jsondata import canonical, rendered_in_place, without_secrets
from opsdir.core.naming import rdn_safe
from opsdir.core.sources import json_document
from opsdir.domains.configuration.naming import CONFIG_FILES
from opsdir.domains.configuration.record import captured_file
from opsdir.domains.federation.services import integrations
from .naming import PINGGATEWAY, ROUTES, SERVER_ROLES, route_dn
from .routes import backend, client_ids, issuers

OWNED = ("cn", "pinggwCondition", "pinggwBackendRole", "pinggwBackendScheme", "pinggwIntegration", "pinggwIssuer",
         "pinggwConfig", "pinggwWithheld")


def _backend_role(d, route):
    """(role, scheme) when the route's backend is a service name in the record (or a rendered UNBOUND:<role>)."""
    base = route.get("baseURI")
    if isinstance(base, str) and base.startswith(UNBOUND):
        return base[len(UNBOUND):], None
    found = backend(route)
    role = published_role(d, found[1]) if found else None
    return (role, found[0]) if role else (None, None)


def _route(d, name, route, patterns):
    role, scheme = _backend_role(d, route)
    kept = {k: v for k, v in route.items() if k not in ("name", "condition") and not (role and k == "baseURI")}
    config, held = without_secrets(kept, patterns, sealed=rendered_in_place)
    ids = client_ids(route)
    clients = {one(i, "ciamClientId"): i for i in integrations(d, "oidc-client")}
    integration = next((clients[c] for c in ids if c in clients), None)
    trusted = issuers(route)
    dn = route_dn(name)
    existing = get(d, dn)
    owned = {"cn": (name,), "pinggwCondition": (route.get("condition"),), "pinggwBackendRole": (role,),
             "pinggwBackendScheme": (scheme,), "pinggwIntegration": (integration.dn if integration else None,),
             "pinggwIssuer": (trusted[0] if trusted else None,), "pinggwConfig": (canonical(config),),
             "pinggwWithheld": held}
    attrs = {**{k: v for k, v in (existing.attrs.items() if existing else ()) if k not in OWNED},
             **{k: tuple(x for x in v if x is not None) for k, v in owned.items() if any(x is not None for x in v)}}
    entry = make_entry(dn, ("top", "ciamObject", "pinggwRoute"), attrs)
    notices = (*(f"route {name}: client {c} is no integration's client id in the record" for c in ids
                 if c not in clients),
               *((f"route {name}: it trusts more than one OpenID provider; recorded {trusted[0]}",)
                 if len(trusted) > 1 else ()),
               *((f"route {name}: its backend is no service name in the record, so it goes to the same place from "
                  "every environment",) if not role and route.get("baseURI") else ()))
    return dn, entry, notices


def _captured(path, text, patterns):
    dn, entries, notices = captured_file(JSON, "ig", "pinggateway", path, text, patterns, SERVER_ROLES[0])
    return (dn, entries), notices


def read_config(files, d, patterns, at=None):
    """Imported from a gateway configuration directory."""
    routes = tuple((p, json_document(t, dict)) for p, t in sorted(files.items())
                   if p.startswith("routes/") and p.endswith(".json"))
    named = tuple((r.get("name") or p[len("routes/"):-5], r) for p, r in routes if r is not None)
    parts = tuple(_route(d, name, r, patterns) for name, r in named if rdn_safe(name))
    captured = tuple(_captured(p, t, patterns) for p, t in sorted(files.items())
                     if p.startswith("config/") and p.endswith(".json"))
    other = sorted(p for p in files if not ((p.startswith("routes/") or p.startswith("config/")) and p.endswith(".json")))
    return Imported(
        containers=tuple(ou_entry(dn) for dn in (PINGGATEWAY, ROUTES, CONFIG_FILES)),
        groups=(*((dn, (entry,)) for dn, entry, _ in parts), *(g for g, _ in captured)),
        notices=(*(n for _, _, ns in parts for n in ns), *(n for _, ns in captured for n in ns),
                 *(f"not a JSON route: {p}" for p, r in routes if r is None),
                 *(f"{name!r} can't be a record name (it holds a DN special character); not imported"
                   for name, _ in named if not rdn_safe(name)),
                 *(f"not gateway configuration, not imported: {p}" for p in other)))


GATEWAY_CONFIG = Importer("config", "a PingGateway configuration directory (config/ and routes/)", read_config)
