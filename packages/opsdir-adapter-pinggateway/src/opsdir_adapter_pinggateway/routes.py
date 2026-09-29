"""What a route says, read from the gateway's own JSON: its backend, the OAuth 2.0 client it signs users in as and
the OpenID provider it trusts (wherever in its handler chain the filter sits). Pure."""
from urllib.parse import urlsplit

CLIENT_FILTERS = ("OAuth2ClientFilter", "AuthorizationCodeOAuth2ClientFilter")
WELL_KNOWN = "/.well-known/openid-configuration"


def objects(value):
    """Every JSON object in a value, depth first (the route itself, its handler, filters, heap objects)."""
    if isinstance(value, dict):
        return (value, *(o for v in value.values() for o in objects(v)))
    if isinstance(value, list):
        return tuple(o for v in value for o in objects(v))
    return ()


def client_filters(route):
    return tuple(o for o in objects(route) if o.get("type") in CLIENT_FILTERS)


def _registration(f):
    config = f.get("config") or {}
    regs = config.get("registrations") or config.get("registration") or ()
    return (regs if isinstance(regs, list) else [regs])


def client_ids(route):
    """The OAuth 2.0 client ids the route's client filters sign users in as."""
    return tuple(dict.fromkeys(r.get("config", r).get("clientId") for f in client_filters(route)
                               for r in _registration(f) if isinstance(r, dict) and r.get("config", r).get("clientId")))


def issuers(route):
    """The OpenID providers the route trusts: issuer or well-known URLs anywhere in it, well-known suffix removed."""
    found = (o.get(k) for o in objects(route) for k in ("wellKnownEndpoint", "issuer") if isinstance(o.get(k), str))
    return tuple(dict.fromkeys(u[:-len(WELL_KNOWN)] if u.endswith(WELL_KNOWN) else u for u in found))


def backend(route):
    """(scheme, host, port or None) of the route's baseURI, or None."""
    base = route.get("baseURI")
    if not isinstance(base, str) or "://" not in base:
        return None
    parts = urlsplit(base)
    return parts.scheme, parts.hostname, parts.port
