"""The OIDC base: client registration metadata and the discovery document, from the record."""
import json

from opsdir.core.directory import make_directory
from opsdir.domains.federation.naming import IDENTITY_SERVICES, INTEGRATIONS
from opsdir_base_oidc.discovery import OidcEndpoints, discovery_document
from opsdir_base_oidc.registration import client_metadata
from opsdir_base_oidc.render import oidc_files

ENDPOINTS = OidcEndpoints(authorization="/authorize", token="/token", userinfo=None, jwks="/jwks", end_session=None)


def _client(cn, **attrs):
    return (f"cn={cn},{INTEGRATIONS}", ("top", "ciamIntegration"),
            {"cn": [cn], "ciamProtocolType": ["oidc-client"], **{k: v if isinstance(v, list) else [v]
                                                                 for k, v in attrs.items()}})


def _directory():
    return make_directory((), {}, (
        _client("web", ciamClientId="web-app", ciamRedirectUri="https://web.test/cb", ciamPkceRequired="TRUE",
                ciamGrantType=["refresh_token", "authorization_code"], ciamTokenAuthMethod="none",
                ciamScope=["openid", "email"]),
        _client("batch", ciamClientId="batch", ciamGrantType="client_credentials",
                ciamTokenAuthMethod="private_key_jwt"),
        (f"cn=op,{IDENTITY_SERVICES}", ("top", "ciamIdentityService"),
         {"cn": ["op"], "ciamBaseUrl": ["https://op.test"], "ciamOidcIssuer": ["https://op.test"],
          "ciamScope": ["openid", "profile"], "ciamSigningAlg": ["PS256"]}),
        (f"cn=saml-only,{IDENTITY_SERVICES}", ("top", "ciamIdentityService"),
         {"cn": ["saml-only"], "ciamBaseUrl": ["https://saml.test"]})))


def _get(d, dn):
    return d.entries[dn.lower()]


def test_client_metadata_is_rfc_7591_in_the_standards_order():
    d = _directory()
    assert client_metadata(_get(d, f"cn=web,{INTEGRATIONS}")) == {
        "client_id": "web-app", "client_name": "web", "redirect_uris": ["https://web.test/cb"],
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "token_endpoint_auth_method": "none", "scope": "openid email"}
    batch = client_metadata(_get(d, f"cn=batch,{INTEGRATIONS}"))
    assert batch["response_types"] == [] and "redirect_uris" not in batch


def test_discovery_derives_what_the_provider_supports_from_the_record():
    d = _directory()
    clients = tuple(e for e in d.entries.values() if "ciamIntegration" in e.classes)
    doc = discovery_document(d, _get(d, f"cn=op,{IDENTITY_SERVICES}"), ENDPOINTS, clients)
    assert (doc["issuer"], doc["token_endpoint"], doc["jwks_uri"]) == ("https://op.test", "https://op.test/token",
                                                                       "https://op.test/jwks")
    assert "userinfo_endpoint" not in doc and "claims_supported" not in doc
    assert doc["scopes_supported"] == ["openid", "profile", "email"]
    assert doc["id_token_signing_alg_values_supported"] == ["RS256", "PS256"]          # RS256 is required
    assert doc["token_endpoint_auth_methods_supported"] == ["none", "private_key_jwt"]
    assert doc["grant_types_supported"] == ["authorization_code", "client_credentials", "refresh_token"]
    assert doc["code_challenge_methods_supported"] == ["S256"] and doc["subject_types_supported"] == ["public"]


def test_only_services_with_an_issuer_get_a_discovery_document():
    d = _directory()
    services = (_get(d, f"cn=op,{IDENTITY_SERVICES}"), _get(d, f"cn=saml-only,{IDENTITY_SERVICES}"))
    files = oidc_files(d, services, ENDPOINTS)
    assert sorted(files) == ["oidc/clients/batch.json", "oidc/clients/web.json", "oidc/discovery/op.json"]
    assert json.loads(files["oidc/clients/batch.json"])["token_endpoint_auth_method"] == "private_key_jwt"
