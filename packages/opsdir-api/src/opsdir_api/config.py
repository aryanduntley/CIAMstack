"""The API's configuration from the environment: the API login's database, the identity provider whose tokens it
accepts (exact issuer, audience, keys, signing algorithms, clock leeway) and where it listens. Pure."""
from typing import NamedTuple, Optional
from urllib.parse import urlsplit

# Asymmetric JWS algorithms only: 'none' and the HMAC family (HS*) are never accepted, since an HMAC "verified" with a
# published key proves nothing (RFC 8725, 3.1 and 3.2).
ASYMMETRIC = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"})
DEFAULT_ALGORITHMS = "RS256,PS256,ES256"
DEFAULT_LEEWAY = 60
MAX_LEEWAY = 300
DEFAULT_HOST, DEFAULT_PORT = "127.0.0.1", 8080
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

Config = NamedTuple("Config", [("dsn", str), ("issuer", str), ("audience", str), ("jwks_url", Optional[str]),
                               ("algorithms", tuple), ("leeway", int)])
Listen = NamedTuple("Listen", [("host", str), ("port", int)])


def url_problem(name, url):
    """Why an identity provider URL isn't acceptable (https, or http only to this host for a local test IdP), or
    None."""
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return None
    if parts.scheme == "http" and parts.hostname in LOCAL_HOSTS:
        return None
    return f"{name} {url}: give an https URL (http only to localhost)"


def algorithms_of(text):
    """(algorithms, problems) of a comma-separated algorithm list: only the asymmetric JWS algorithms."""
    names = tuple(dict.fromkeys(n.strip() for n in text.split(",") if n.strip()))
    refused = tuple(n for n in names if n.lower() == "none" or n.upper().startswith("HS"))
    unknown = tuple(n for n in names if n not in ASYMMETRIC and n not in refused)
    problems = (*((f"OPSDIR_API_ALGORITHMS: {', '.join(refused)} never accepted (only asymmetric signatures: "
                   f"{', '.join(sorted(ASYMMETRIC))})",) if refused else ()),
                *((f"OPSDIR_API_ALGORITHMS: unknown {', '.join(unknown)}",) if unknown else ()),
                *(("OPSDIR_API_ALGORITHMS: name at least one algorithm",) if not names else ()))
    return tuple(n for n in names if n in ASYMMETRIC), problems


def leeway_of(text):
    """(seconds, problems) of the clock leeway: a whole number from 0 to MAX_LEEWAY."""
    try:
        seconds = int(text)
    except ValueError:
        return DEFAULT_LEEWAY, (f"OPSDIR_API_LEEWAY {text}: give whole seconds",)
    if not 0 <= seconds <= MAX_LEEWAY:
        return DEFAULT_LEEWAY, (f"OPSDIR_API_LEEWAY {text}: give 0 to {MAX_LEEWAY} seconds",)
    return seconds, ()


def config_from(env):
    """(Config, problems) of an environment mapping; the Config is None while there are problems."""
    dsn, issuer, audience = (env.get(k, "").strip() for k in ("OPSDIR_DSN", "OPSDIR_API_ISSUER", "OPSDIR_API_AUDIENCE"))
    jwks_url = env.get("OPSDIR_API_JWKS_URL", "").strip() or None
    algorithms, bad_algorithms = algorithms_of(env.get("OPSDIR_API_ALGORITHMS", DEFAULT_ALGORITHMS))
    leeway, bad_leeway = leeway_of(env.get("OPSDIR_API_LEEWAY", str(DEFAULT_LEEWAY)).strip())
    problems = (*(f"{k} is not set{why}" for k, v, why in (
                    ("OPSDIR_DSN", dsn, " (the API login's connection string)"),
                    ("OPSDIR_API_ISSUER", issuer, " (the identity provider's exact issuer, iss)"),
                    ("OPSDIR_API_AUDIENCE", audience, " (the audience its tokens carry for this API, aud)")) if not v),
                *((url_problem("OPSDIR_API_ISSUER", issuer),) if issuer and url_problem("OPSDIR_API_ISSUER", issuer)
                  else ()),
                *((url_problem("OPSDIR_API_JWKS_URL", jwks_url),)
                  if jwks_url and url_problem("OPSDIR_API_JWKS_URL", jwks_url) else ()),
                *bad_algorithms, *bad_leeway)
    return (None if problems else Config(dsn, issuer, audience, jwks_url, algorithms, leeway)), problems


def listen_from(env):
    """(Listen, problems) of OPSDIR_API_HOST and OPSDIR_API_PORT (default 127.0.0.1:8080)."""
    host = env.get("OPSDIR_API_HOST", "").strip() or DEFAULT_HOST
    text = env.get("OPSDIR_API_PORT", "").strip() or str(DEFAULT_PORT)
    port = int(text) if text.isdigit() else 0
    return Listen(host, port or DEFAULT_PORT), (() if 0 < port < 65536 else (f"OPSDIR_API_PORT {text}: give 1-65535",))
