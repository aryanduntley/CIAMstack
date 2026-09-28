"""OpenID Provider metadata (OpenID Connect Discovery 1.0 section 3) of one of the platform's identity services: its
issuer and endpoints (the service's base URL and a product's paths), and what it supports, derived from the record
(the service's own scopes and algorithms, and what the recorded clients use)."""
from typing import NamedTuple

from opsdir.core.directory import one, values
from opsdir.domains.federation.schema import GRANT_TYPES, SIGNING_ALGS, TOKEN_AUTH_METHODS
from opsdir.domains.federation.services import claims, endpoint, in_order, union
from .registration import response_types

# A product's OpenID provider endpoints, as paths under the service's base URL (None: the product has none)
OidcEndpoints = NamedTuple("OidcEndpoints", [("authorization", str), ("token", str), ("userinfo", str),
                                             ("jwks", str), ("end_session", str)])
REQUIRED_ALG = "RS256"        # Discovery 1.0: RS256 MUST be among the ID token signing algorithms


def _supported(d, service, clients):
    grants = in_order(GRANT_TYPES, union(clients, "ciamGrantType"))
    return (("scopes_supported", list(dict.fromkeys((*values(service, "ciamScope"), *union(clients, "ciamScope"))))),
            ("response_types_supported", response_types(grants)),
            ("grant_types_supported", list(grants)),
            ("subject_types_supported", ["public"]),
            ("id_token_signing_alg_values_supported",
             list(in_order(SIGNING_ALGS, (*values(service, "ciamSigningAlg"), REQUIRED_ALG)))),
            ("token_endpoint_auth_methods_supported", list(in_order(TOKEN_AUTH_METHODS,
                                                                    union(clients, "ciamTokenAuthMethod")))),
            ("claims_supported", sorted({name for c in clients for name, _, _ in claims(d, c)})),
            ("code_challenge_methods_supported",
             ["S256"] if any(one(c, "ciamPkceRequired") == "TRUE" for c in clients) else []))


def discovery_document(d, service, endpoints, clients):
    """The provider metadata of a service with an issuer, for the recorded clients; empty optional lists left out."""
    urls = tuple((name, endpoint(service, path)) for name, path in (
        ("authorization_endpoint", endpoints.authorization), ("token_endpoint", endpoints.token),
        ("userinfo_endpoint", endpoints.userinfo), ("jwks_uri", endpoints.jwks),
        ("end_session_endpoint", endpoints.end_session)) if path)
    required = {"response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported"}
    return {"issuer": one(service, "ciamOidcIssuer"), **dict(urls),
            **{k: v for k, v in _supported(d, service, clients) if v or k in required}}
