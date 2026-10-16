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


# ------------------------------------------------------------------ the neutral protected-application layer
# What the projection (neutral.py) reads and the takeover render (takeover.py) writes, from PingGateway's 2026
# reference (research note 3133): the route's condition (a Boolean expression; find() over request.uri.path or .host),
# AllowOnlyFilter (rules ORed, a rule's destination paths Java regular expressions and methods ANDed; the reference
# marks `from` required while its own example omits it, and its prose calls a path a prefix while its example is a
# regex: unverified), ConditionEnforcementFilter (a condition; refuses with 403), ConditionalFilter (a condition and
# the delegate it runs when true), HeaderFilter (REQUEST; add, replace, remove), the session managers (one timeout:
# no separate idle and maximum), and the sign-in's claims in contexts.oauth2Info.userInfo (a map in Ping's examples,
# an array of maps in the context's reference: unverified).
ALLOW_ONLY, ENFORCE, CONDITIONAL, HEADERS = "AllowOnlyFilter", "ConditionEnforcementFilter", "ConditionalFilter", \
    "HeaderFilter"
SESSION_TIMEOUTS = (("JwtSessionManager", "sessionTimeout"), ("InMemorySessionManager", "timeout"),
                    ("JwtSession", "sessionTimeout"))
USERINFO = "contexts.oauth2Info.userInfo"
PATH_TEST = r"(?:find|matchesWithRegex)\(\s*request\.uri\.path\s*,\s*'([^']*)'\s*\)"
HOST_TEST = r"(?:find|matchesWithRegex)\(\s*request\.uri\.host\s*,\s*'([^']*)'\s*\)"
# a claim test: userInfo.<claim> == 'v', userInfo['<claim>'] == 'v', or contains(userInfo['<claim>'], 'v')
CLAIM_TEST = (r"^\$\{\s*(not\s*\(?)?\s*(?:contains\(\s*)?" + USERINFO.replace(".", r"\.")
              + r"(?:\.(\w+)|\['([^']+)'\])\s*(?:==\s*|,\s*)'([^']*)'\s*\)?\s*\)?\s*\}$")
DURATION = r"^\s*(\d+)\s*(second|minute|hour|day)s?\s*$"
DURATION_SECONDS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}


def filters(route, kind):
    """Every filter (or heap object) of a kind anywhere in a route, in document order."""
    return tuple(o for o in objects(route) if o.get("type") == kind)
