"""Bearer tokens: an access token's claims, accepted only when signed by a key the identity provider publishes (JWKS,
matched by kid) with an allowed asymmetric algorithm, issued by the exact issuer for this API's audience, within its
validity (leeway allowed), naming a subject (claims_of, pure). The provider's keys are fetched over HTTPS (fetch_jwks,
from discovery when no JWKS URL is configured) and kept for a while at the edge (key_source)."""
import base64
import json
import time
from typing import NamedTuple, Optional

import httpx
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

MAX_TOKEN = 16384                 # characters; a token longer than this isn't parsed
SIGNING_KEY_TYPES = frozenset({"RSA", "EC", "OKP"})
UNKNOWN_KEY = "the token names a key the identity provider doesn't publish"
KEYS_TTL, KEYS_MIN_INTERVAL = 300.0, 30.0   # seconds a JWKS is kept; the least between refetches for an unknown kid
HTTP_TIMEOUT = 5.0

Checked = NamedTuple("Checked", [("claims", Optional[dict]), ("refusal", Optional[str])])
KeyCache = NamedTuple("KeyCache", [("jwks", Optional[dict]), ("fetched_at", float)])


def _b64json(part):
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def header_of(token):
    """The unverified JOSE header of a compact JWS (three dot-separated parts), or None when it isn't one."""
    parts = token.split(".")
    if len(parts) != 3 or len(token) > MAX_TOKEN:
        return None
    try:
        header = _b64json(parts[0])
    except (ValueError, UnicodeDecodeError):
        return None
    return header if isinstance(header, dict) else None


def key_for(jwks, kid):
    """(the signing key the JWKS publishes under kid, refusal): RSA, EC or OKP keys only (never a shared secret)."""
    try:
        keys = KeySet.import_key_set({"keys": [k for k in jwks.get("keys", ()) if k.get("kty") in SIGNING_KEY_TYPES]})
    except (JoseError, ValueError, TypeError, AttributeError, KeyError):
        return None, "the identity provider publishes no usable signing key"
    found = next((k for k in keys if k.kid == kid), None)
    return (found, None) if found is not None else (None, UNKNOWN_KEY)


def _audiences(claims):
    aud = claims.get("aud")
    return (aud,) if isinstance(aud, str) else tuple(a for a in aud if isinstance(a, str)) \
        if isinstance(aud, list) else ()


def _number(claims, name):
    value = claims.get(name)
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def claim_refusal(claims, config, now):
    """Why verified claims aren't accepted (issuer, audience, times with the leeway, subject), or None."""
    exp, nbf, iat, leeway = _number(claims, "exp"), _number(claims, "nbf"), _number(claims, "iat"), config.leeway
    checks = (
        (claims.get("iss") != config.issuer, f"issuer {claims.get('iss')!r} isn't {config.issuer}"),
        (config.audience not in _audiences(claims), f"the token isn't for audience {config.audience}"),
        (exp is None, "the token has no expiry (exp)"),
        (exp is not None and now >= exp + leeway, "the token expired"),
        ("nbf" in claims and (nbf is None or now < nbf - leeway), "the token isn't valid yet (nbf)"),
        ("iat" in claims and (iat is None or iat > now + leeway), "the token is issued in the future (iat)"),
        (not isinstance(claims.get("sub"), str) or not claims["sub"].strip(), "the token names no subject (sub)"))
    return next((why for failed, why in checks if failed), None)


MAX_GROUPS, MAX_CLIENT = 1000, 256
OVERAGE = ("the token's group list is incomplete (more groups than the identity provider puts in a token); "
           "membership can't be decided, so nothing is allowed: emit only the groups assigned to this application, "
           "or fewer groups")
Membership = NamedTuple("Membership", [("groups", tuple), ("client", Optional[str]), ("refusal", Optional[str])])


def membership_of(claims, claim):
    """Membership(groups, client, refusal) of accepted claims: the identity provider groups the token lists in its
    `claim` (none named: none), each as '<issuer> <group id>' so groups of different providers never match; the API
    client it was issued to (azp, else client_id; None when neither is a short plain string). Refused (fail closed)
    when the group list is incomplete (Entra ID's overage: _claim_names names the claim, or hasgroups is set) or isn't
    strings. Pure."""
    names = claims.get("_claim_names")
    if claim and ((isinstance(names, dict) and claim in names) or claims.get("hasgroups") is True):
        return Membership((), None, OVERAGE)
    listed = claims.get(claim) if claim else None
    listed = [listed] if isinstance(listed, str) else [] if listed is None else listed
    if not isinstance(listed, list) or len(listed) > MAX_GROUPS or not all(
            isinstance(g, str) and g and " " not in g for g in listed):
        return Membership((), None, f"the token's {claim} claim isn't a list of group IDs")
    client = next((c for c in (claims.get("azp"), claims.get("client_id"))
                   if isinstance(c, str) and 0 < len(c) <= MAX_CLIENT and c.isprintable()), None)
    return Membership(tuple(dict.fromkeys(f"{claims['iss']} {g}" for g in listed)), client, None)


def claims_of(token, jwks, config, now):
    """Checked(claims, None) of an accepted token, else Checked(None, why): its algorithm one of config.algorithms
    (never 'none' or HMAC), its signature by the JWKS key its kid names, then claim_refusal at `now` (seconds since the
    epoch). Pure."""
    header = header_of(token)
    if header is None:
        return Checked(None, "the bearer token isn't a signed JWT")
    alg, kid = header.get("alg"), header.get("kid")
    if alg not in config.algorithms:
        return Checked(None, f"algorithm {alg} isn't accepted ({', '.join(config.algorithms)})")
    if not isinstance(kid, str) or not kid:
        return Checked(None, "the token names no key (kid)")
    key, why = key_for(jwks, kid)
    if key is None:
        return Checked(None, why)
    try:
        claims = jwt.decode(token, key, algorithms=[alg]).claims
    except (JoseError, ValueError, TypeError):
        return Checked(None, "the token's signature isn't valid")
    if not isinstance(claims, dict):
        return Checked(None, "the token's claims aren't an object")
    why = claim_refusal(claims, config, now)
    return Checked(None, why) if why else Checked(claims, None)


# ------------------------------------------------------------------ the provider's keys (effects)
def _get_json(get, url):
    response = get(url, timeout=HTTP_TIMEOUT, follow_redirects=False)
    response.raise_for_status()
    return response.json()


def jwks_url(config, get=httpx.get):
    """Effect (HTTP when not configured): the JWKS URL: OPSDIR_API_JWKS_URL, else the jwks_uri of the issuer's
    discovery document, whose issuer must be the configured one exactly; ValueError otherwise."""
    if config.jwks_url:
        return config.jwks_url
    found = _get_json(get, config.issuer.rstrip("/") + "/.well-known/openid-configuration")
    if found.get("issuer") != config.issuer:
        raise ValueError(f"discovery names issuer {found.get('issuer')!r}, not {config.issuer}")
    uri = found.get("jwks_uri")
    if not isinstance(uri, str) or not uri.startswith("https://"):
        raise ValueError("discovery names no https jwks_uri")
    return uri


def fetch_jwks(config, get=httpx.get):
    """Effect (HTTP): the identity provider's published keys (a JWKS document); ValueError saying why when they can't
    be fetched."""
    try:
        found = _get_json(get, jwks_url(config, get))
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        raise ValueError(f"the identity provider's keys can't be fetched: {e}") from None
    if not isinstance(found, dict) or not isinstance(found.get("keys"), list):
        raise ValueError("the identity provider's JWKS has no keys")
    return found


def needs_fetch(cache, now, refresh, ttl=KEYS_TTL, min_interval=KEYS_MIN_INTERVAL):
    """Whether keys are fetched again: none yet, kept longer than ttl, or a refresh asked (an unknown kid: the provider
    may have rotated) at least min_interval after the last fetch."""
    age = now - cache.fetched_at
    return cache.jwks is None or age >= ttl or (refresh and age >= min_interval)


def key_source(config, fetch=fetch_jwks, clock=time.time):
    """Effect (the edge's one-slot cache): keys(refresh=False) -> the JWKS, fetched when needs_fetch says so."""
    slot = [KeyCache(None, 0.0)]

    def keys(refresh=False):
        now = clock()
        if needs_fetch(slot[0], now, refresh):
            slot[0] = KeyCache(fetch(config), now)
        return slot[0].jwks
    return keys
