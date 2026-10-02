"""PingFederate adapter: render the federation domain as PingFederate integration definitions and, on the SAML and
OIDC bases, the standard documents at PingFederate's endpoint paths (all environment-neutral).

  pingfederate/*.json       SP connections, OIDC clients, IdP connections
  saml/, oidc/              standard metadata, client registrations and discovery (opsdir-base-saml, -oidc)
  pingfederate/authentication-policy-contracts.json, authentication-policies.json,
    authentication-policy-fragments.json      authentication policies (environment-neutral)
  pingfederate/data-stores.json   data stores, per environment: hosts from the bindings of their target roles,
                                  withheld credentials as the references of their credential roles
  pingfederate/password-credential-validators.json, idp-adapters.json, authentication-selectors.json,
    access-token-managers.json    plugin instances, per environment: withheld secrets from their credential roles
  pingfederate/cluster/jgroups.properties
                                  per environment: the nodes' discovery lines from its pf-cluster-discovery binding
  pingfederate/other-resources.json
                                  per environment: the resources held as is, in the bulk export's shape

The PingFederate JSON follows the shape of Admin API resources (SP connections, OIDC clients, IdP connections) but is
an illustrative subset. It hasn't been validated against a live /pf-admin-api/v1. In production this renderer would
target the Admin API or the PingFederate Terraform provider. Endpoint paths are PingFederate's defaults.
"""
import json
from types import MappingProxyType

from opsdir.core.directory import children, get, one, rdn_value, values
from opsdir.domains.federation.services import claims, identity_services, integrations_served
from opsdir_base_oidc.discovery import OidcEndpoints
from opsdir_base_oidc.render import oidc_files
from opsdir_base_saml.render import SamlEndpoints, saml_files
from .datastores import data_stores_file
from .naming import DATA_STORES, SERVER_ROLES
from .generic import resources_file
from .discovery import discovery_file
from .oauth import client_view, oauth_files
from .plugins import plugin_files
from .policies import policy_files

USER_DIRECTORY = MappingProxyType({"type": "LDAP_DATA_STORE", "id": "ciam-user-directory"})
SAML_ENDPOINTS = SamlEndpoints(sso=(("HTTP-Redirect", "/idp/SSO.saml2"), ("HTTP-POST", "/idp/SSO.saml2")),
                               slo=(("HTTP-Redirect", "/idp/SLO.saml2"), ("HTTP-POST", "/idp/SLO.saml2")))
OIDC_ENDPOINTS = OidcEndpoints(authorization="/as/authorization.oauth2", token="/as/token.oauth2",
                               userinfo="/idp/userinfo.openid", jwks="/pf/JWKS", end_session="/idp/startSLO.ping")
# standard value → PingFederate Admin API name (verify extension grants against the target version)
GRANT_TYPES = MappingProxyType({"authorization_code": "AUTHORIZATION_CODE", "client_credentials": "CLIENT_CREDENTIALS",
                                "refresh_token": "REFRESH_TOKEN",
                                "urn:ietf:params:oauth:grant-type:device_code": "DEVICE_CODE",
                                "urn:ietf:params:oauth:grant-type:token-exchange": "TOKEN_EXCHANGE",
                                "urn:ietf:params:oauth:grant-type:jwt-bearer": "EXTENSION",
                                "urn:ietf:params:oauth:grant-type:saml2-bearer": "EXTENSION"})
CLIENT_AUTH = MappingProxyType({"none": "NONE", "client_secret_basic": "SECRET", "client_secret_post": "SECRET",
                                "client_secret_jwt": "SECRET", "private_key_jwt": "PRIVATE_KEY_JWT",
                                "tls_client_auth": "CLIENT_CERT", "self_signed_tls_client_auth": "CLIENT_CERT"})
BINDINGS = MappingProxyType({"HTTP-POST": "POST", "HTTP-Redirect": "REDIRECT", "HTTP-Artifact": "ARTIFACT",
                             "SOAP": "SOAP"})


def _fulfillment_entry(attr, transform):
    base = {"source": dict(USER_DIRECTORY), "value": attr}
    return {**base, "x-opsdir-transform": transform} if transform else base


def _fulfillment(claims):
    return {name: _fulfillment_entry(attr, transform) for name, attr, transform in claims}


def _sp_connection(i, claims, owners, certs, refs):
    return {
        "id": rdn_value(i), "name": rdn_value(i), "entityId": one(i, "ciamEntityId"), "active": True,
        "contactInfo": {"company": ", ".join(owners)},
        "spBrowserSso": {
            "protocol": "SAML20", "enabledProfiles": ["SP_INITIATED_SSO"],
            "ssoServiceEndpoints": [{"binding": BINDINGS[one(i, "ciamSamlBinding", "HTTP-POST")],
                                     "url": one(i, "ciamAcsUrl"), "isDefault": True}],
            "attributeContract": {
                "coreAttributes": [{"name": "SAML_SUBJECT"}],
                "extendedAttributes": [{"name": n} for n, _, _ in claims]},
            "adapterMappings": [{"attributeContractFulfillment": {
                "SAML_SUBJECT": {"source": dict(USER_DIRECTORY), "value": "uid"}, **_fulfillment(claims)}}]},
        "x-opsdir": {"mfaRequired": one(i, "ciamMfaRequired") == "TRUE",
                     "populations": list(values(i, "ciamPopulation")), "certificateFingerprints": list(certs)}}


def _client_options(i):
    """Client authentication and scope restriction, when the record holds them."""
    auth = one(i, "ciamTokenAuthMethod")
    scopes = list(values(i, "ciamScope"))
    return {**({"clientAuth": {"type": CLIENT_AUTH[auth]}} if auth else {}),
            **({"restrictScopes": True, "restrictedScopes": scopes} if scopes else {})}


def _oidc_client(i, claims, owners, certs, refs):
    return {
        "clientId": one(i, "ciamClientId"), "name": rdn_value(i), "enabled": True,
        "redirectUris": list(values(i, "ciamRedirectUri")),
        "grantTypes": [GRANT_TYPES[g] for g in values(i, "ciamGrantType")],
        "requireProofKeyForCodeExchange": one(i, "ciamPkceRequired") == "TRUE", **_client_options(i), **refs,
        "x-opsdir": {"claims": _fulfillment(claims), "mfaRequired": one(i, "ciamMfaRequired") == "TRUE",
                     "owners": list(owners)}}


def _idp_connection(i, claims, owners, certs, refs):
    return {
        "id": one(i, "pingfedConnectionId") or rdn_value(i), "name": rdn_value(i), "entityId": one(i, "ciamEntityId"),
        "active": True,
        "credentials": {"certs": [{"certView": {"sha256Fingerprint": f}} for f in certs]},
        "idpBrowserSso": {"protocol": "SAML20", "jitProvisioning": {
            "userRepository": {"type": "LDAP", "baseDn": one(i, "ciamJitBaseDn")}}},
        "x-opsdir": {"owners": list(owners)}}


# protocol type → (output file, resource builder)
RESOURCES = MappingProxyType({"saml2-sp": ("pingfederate/sp-connections.json", _sp_connection),
                              "oidc-client": ("pingfederate/oidc-clients.json", _oidc_client),
                              "saml2-idp": ("pingfederate/idp-connections.json", _idp_connection)})


def _resource(d, i):
    owners = tuple(rdn_value(get(d, o)) for o in values(i, "ciamOwner"))
    certs = tuple(one(get(d, c), "ciamFingerprint") for c in values(i, "ciamUsesCertificate"))
    return RESOURCES[one(i, "ciamProtocolType")][1](i, claims(d, i), owners, certs, client_view(d, i))


def pingfederate_files(d, served):
    """The integrations the services PingFederate serves are registered with (or that name none)."""
    return {path: json.dumps([_resource(d, i) for i in integrations_served(d, served, ptype)], indent=2) + "\n"
            for ptype, (path, _) in RESOURCES.items()}


def render_neutral(d):
    """PingFederate's own resources, then the standard SAML and OIDC documents for the services it serves."""
    served = identity_services(d, SERVER_ROLES)
    return {**pingfederate_files(d, served), **policy_files(d), **oauth_files(d),
            **saml_files(d, served, SAML_ENDPOINTS), **oidc_files(d, served, OIDC_ENDPOINTS)}


def render_env(m, services):
    """PingFederate's configuration for environment m: its data stores and plugin instances (validators, adapters,
    selectors, token managers), with that environment's hosts and secret references, and its cluster's discovery."""
    return {**data_stores_file(m, children(m.d, DATA_STORES, "pingfedDataStore")), **plugin_files(m),
            **discovery_file(m), **resources_file(m)}
