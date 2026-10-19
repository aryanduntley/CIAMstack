"""Bearer tokens and configuration: claims_of accepts only a token signed by the JWKS key its kid names with an allowed
asymmetric algorithm, for the exact issuer and the audience, within its times (leeway) and naming a subject; 'none',
HS256 keyed with the public key, unknown kids, other keys' signatures, wrong issuers and audiences and expired tokens
are refused. The configuration refuses missing values, 'none' and HMAC algorithms and plain-HTTP providers; the key
cache refetches when stale or on a rotation; discovery insists on the exact issuer."""
import base64
import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest
from joserfc import jwt
from joserfc.jwk import RSAKey

from opsdir_api.config import Config, config_from, listen_from
from opsdir_api.tokens import UNKNOWN_KEY, KeyCache, claims_of, jwks_url, key_source, membership_of, needs_fetch

ISSUER, AUDIENCE, NOW = "https://idp.example.com/realms/ops", "opsdir-api", 1_800_000_000
KEY = RSAKey.generate_key(2048, parameters={"kid": "k1"})
OTHER = RSAKey.generate_key(2048, parameters={"kid": "k1"})
JWKS = {"keys": [KEY.as_dict(private=False)]}
CONFIG = Config("postgresql://api@db/opsdir", ISSUER, AUDIENCE, None, ("RS256", "PS256", "ES256"), 60)
CLAIMS = {"iss": ISSUER, "aud": [AUDIENCE, "account"], "sub": "f81d4fae-7dec", "iat": NOW - 10, "nbf": NOW - 10,
          "exp": NOW + 300}


def signed(claims=None, header=None, key=KEY):
    header = header or {"alg": "RS256", "kid": "k1"}
    return jwt.encode(header, CLAIMS if claims is None else claims, key, algorithms=[header["alg"]])


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def crafted(header, claims, sign=lambda signing_input: b""):
    head = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}"
    return f"{head}.{b64(sign(head.encode()))}"


def test_a_good_token_gives_its_claims():
    checked = claims_of(signed(), JWKS, CONFIG, NOW)
    assert checked.refusal is None and checked.claims["sub"] == "f81d4fae-7dec"
    assert claims_of(signed({**CLAIMS, "aud": AUDIENCE}), JWKS, CONFIG, NOW).claims is not None
    assert claims_of(signed(header={"alg": "PS256", "kid": "k1"}), JWKS, CONFIG, NOW).claims is not None


@pytest.mark.parametrize("claims, why", [
    ({**CLAIMS, "iss": "https://idp.example.com/realms/other"}, "issuer"),
    ({**CLAIMS, "iss": ISSUER + "/"}, "issuer"),
    ({**CLAIMS, "aud": ["account"]}, "audience"),
    ({**CLAIMS, "exp": NOW - 61}, "expired"),
    ({k: v for k, v in CLAIMS.items() if k != "exp"}, "no expiry"),
    ({**CLAIMS, "nbf": NOW + 120}, "isn't valid yet"),
    ({**CLAIMS, "iat": NOW + 120}, "future"),
    ({k: v for k, v in CLAIMS.items() if k != "sub"}, "no subject"),
    ({**CLAIMS, "sub": " "}, "no subject")])
def test_claims_refused(claims, why):
    checked = claims_of(signed(claims), JWKS, CONFIG, NOW)
    assert checked.claims is None and why in checked.refusal


def test_leeway_allows_a_little_clock_skew():
    assert claims_of(signed({**CLAIMS, "exp": NOW - 30}), JWKS, CONFIG, NOW).claims is not None
    assert claims_of(signed({**CLAIMS, "nbf": NOW + 30}), JWKS, CONFIG, NOW).claims is not None
    assert claims_of(signed({**CLAIMS, "exp": NOW - 30}), JWKS, CONFIG._replace(leeway=0), NOW).claims is None


def test_alg_none_is_refused():
    checked = claims_of(crafted({"alg": "none", "kid": "k1"}, CLAIMS), JWKS, CONFIG, NOW)
    assert checked.claims is None and "algorithm none" in checked.refusal


def test_hs256_keyed_with_the_public_key_is_refused():
    secret = KEY.as_pem(private=False)
    token = crafted({"alg": "HS256", "kid": "k1"}, CLAIMS, lambda m: hmac.new(secret, m, hashlib.sha256).digest())
    checked = claims_of(token, JWKS, CONFIG, NOW)
    assert checked.claims is None and "algorithm HS256" in checked.refusal
    # even were HS256 configured, the JWKS's oct keys are never used: a shared secret published proves nothing
    oct_jwks = {"keys": [{"kty": "oct", "kid": "k1", "k": b64(secret)}]}
    assert claims_of(token, oct_jwks, CONFIG._replace(algorithms=("HS256",)), NOW).claims is None


def test_keys_must_match_the_kid_and_sign_it():
    assert claims_of(signed(header={"alg": "RS256", "kid": "k2"}), JWKS, CONFIG, NOW).refusal == UNKNOWN_KEY
    assert "no key (kid)" in claims_of(signed(header={"alg": "RS256"}), JWKS, CONFIG, NOW).refusal
    assert "signature" in claims_of(signed(key=OTHER), JWKS, CONFIG, NOW).refusal
    assert "usable signing key" in claims_of(signed(), {"keys": []}, CONFIG, NOW).refusal


def test_not_a_jwt():
    assert "isn't a signed JWT" in claims_of("abc", JWKS, CONFIG, NOW).refusal
    assert "isn't a signed JWT" in claims_of("a.b.c.d.e", JWKS, CONFIG, NOW).refusal
    tampered = signed().rsplit(".", 2)
    swapped = ".".join((tampered[0], b64(json.dumps({**CLAIMS, "sub": "admin"}).encode()), tampered[2]))
    assert "signature" in claims_of(swapped, JWKS, CONFIG, NOW).refusal


# ------------------------------------------------------------------ configuration
ENV = {"OPSDIR_DSN": "postgresql://api@db/opsdir", "OPSDIR_API_ISSUER": ISSUER, "OPSDIR_API_AUDIENCE": AUDIENCE}


def test_config_from_the_environment():
    config, problems = config_from(ENV)
    assert problems == () and config == CONFIG
    config, _ = config_from({**ENV, "OPSDIR_API_JWKS_URL": "https://idp.example.com/certs",
                             "OPSDIR_API_ALGORITHMS": "ES256, EdDSA", "OPSDIR_API_LEEWAY": "5"})
    assert config.jwks_url == "https://idp.example.com/certs" and config.algorithms == ("ES256", "EdDSA")
    assert config.leeway == 5
    assert config_from({**ENV, "OPSDIR_API_ISSUER": "http://localhost:8443/realms/x"})[1] == ()


@pytest.mark.parametrize("change, problem", [
    ({"OPSDIR_DSN": ""}, "OPSDIR_DSN is not set"),
    ({"OPSDIR_API_AUDIENCE": ""}, "OPSDIR_API_AUDIENCE is not set"),
    ({"OPSDIR_API_ISSUER": "http://idp.example.com"}, "https URL"),
    ({"OPSDIR_API_JWKS_URL": "ftp://idp.example.com/certs"}, "https URL"),
    ({"OPSDIR_API_ALGORITHMS": "RS256,none"}, "none never accepted"),
    ({"OPSDIR_API_ALGORITHMS": "HS256"}, "HS256 never accepted"),
    ({"OPSDIR_API_ALGORITHMS": "RS999"}, "unknown RS999"),
    ({"OPSDIR_API_LEEWAY": "ten"}, "whole seconds"),
    ({"OPSDIR_API_LEEWAY": "3600"}, "0 to 300")])
def test_config_problems(change, problem):
    config, problems = config_from({**ENV, **change})
    assert config is None and any(problem in p for p in problems)


def test_listen_from():
    assert listen_from({}) == (("127.0.0.1", 8080), ())
    assert listen_from({"OPSDIR_API_HOST": "0.0.0.0", "OPSDIR_API_PORT": "9000"}) == (("0.0.0.0", 9000), ())
    assert listen_from({"OPSDIR_API_PORT": "http"})[1]


# ------------------------------------------------------------------ the provider's keys
def test_needs_fetch():
    assert needs_fetch(KeyCache(None, 0.0), NOW, False)
    assert not needs_fetch(KeyCache(JWKS, NOW - 10), NOW, False)
    assert needs_fetch(KeyCache(JWKS, NOW - 301), NOW, False)
    assert not needs_fetch(KeyCache(JWKS, NOW - 10), NOW, True)        # a refresh at most every 30 seconds
    assert needs_fetch(KeyCache(JWKS, NOW - 31), NOW, True)


def test_key_source_keeps_the_keys():
    fetched, clock = [], [float(NOW)]
    keys = key_source(CONFIG, lambda config: fetched.append(config) or JWKS, lambda: clock[0])
    assert keys() == JWKS and keys() == JWKS and len(fetched) == 1
    clock[0] += 31
    assert keys(True) == JWKS and len(fetched) == 2


def test_discovery_needs_the_exact_issuer():
    def get(document):
        return lambda url, **options: SimpleNamespace(raise_for_status=lambda: None, json=lambda: document)
    assert jwks_url(CONFIG, get({"issuer": ISSUER, "jwks_uri": "https://idp.example.com/certs"})) == \
        "https://idp.example.com/certs"
    with pytest.raises(ValueError, match="names issuer"):
        jwks_url(CONFIG, get({"issuer": "https://evil.example.com", "jwks_uri": "https://evil.example.com/certs"}))
    with pytest.raises(ValueError, match="https jwks_uri"):
        jwks_url(CONFIG, get({"issuer": ISSUER, "jwks_uri": "http://idp.example.com/certs"}))
    assert jwks_url(CONFIG._replace(jwks_url="https://idp.example.com/k"), None) == "https://idp.example.com/k"


def test_the_tokens_groups_and_client():
    claims = {"iss": ISSUER, "sub": "s", "groups": ["7f3c", "9a10", "7f3c"], "azp": "opsdir-console"}
    assert membership_of(claims, "groups") == ((f"{ISSUER} 7f3c", f"{ISSUER} 9a10"), "opsdir-console", None)
    assert membership_of({**claims, "groups": "7f3c"}, "groups").groups == (f"{ISSUER} 7f3c",)    # one, as a string
    assert membership_of({"iss": ISSUER, "client_id": "cli"}, "groups") == ((), "cli", None)       # none listed
    assert membership_of({**claims, "roles": ["ops"]}, "roles").groups == (f"{ISSUER} ops",)      # another claim
    assert membership_of(claims, "").groups == ()                                                 # groups not used
    assert membership_of({**claims, "azp": "x" * 300, "client_id": "short"}, "groups").client == "short"


@pytest.mark.parametrize("extra", [{"_claim_names": {"groups": "src1"}, "groups": None}, {"hasgroups": True}])
def test_an_incomplete_group_list_is_refused(extra):
    m = membership_of({"iss": ISSUER, "sub": "s", **extra}, "groups")
    assert m.groups == () and "group list is incomplete" in m.refusal


@pytest.mark.parametrize("groups", [[1], ["a b"], [""], {"a": 1}, ["g"] * 1001])
def test_a_group_list_that_isnt_ids_is_refused(groups):
    assert "isn't a list of group IDs" in membership_of({"iss": ISSUER, "groups": groups}, "groups").refusal


def test_the_groups_claim_is_configured():
    env = {"OPSDIR_DSN": "x", "OPSDIR_API_ISSUER": ISSUER, "OPSDIR_API_AUDIENCE": AUDIENCE}
    assert config_from(env)[0].groups_claim == "groups"
    assert config_from({**env, "OPSDIR_API_GROUPS_CLAIM": " roles "})[0].groups_claim == "roles"
    assert CONFIG.groups_claim == "groups"


def test_the_upload_limits_are_configured():
    env = {"OPSDIR_DSN": "x", "OPSDIR_API_ISSUER": ISSUER, "OPSDIR_API_AUDIENCE": AUDIENCE}
    config = config_from(env)[0]
    assert (config.max_upload, config.max_files) == (100 * 1024 * 1024, 10000)
    config = config_from({**env, "OPSDIR_API_MAX_UPLOAD_MB": "500", "OPSDIR_API_MAX_FILES": "50000"})[0]
    assert (config.max_upload, config.max_files) == (500 * 1024 * 1024, 50000)
    assert config_from({**env, "OPSDIR_API_MAX_UPLOAD_MB": "0"})[1] == ("OPSDIR_API_MAX_UPLOAD_MB 0: give 1 to 4096",)
    assert config_from({**env, "OPSDIR_API_MAX_FILES": "lots"})[1] == ("OPSDIR_API_MAX_FILES lots: give 1 to 1000000",)
