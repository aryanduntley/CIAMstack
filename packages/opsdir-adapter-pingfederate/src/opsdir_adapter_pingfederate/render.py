"""PingFederate adapter: render the federation domain as PingFederate integration definitions (environment-neutral).

The JSON follows the shape of PingFederate Admin API resources (SP connections, OIDC clients,
IdP connections) but is an illustrative subset. It hasn't been validated against a live
/pf-admin-api/v1. In production this renderer would target the Admin API or the PingFederate
Terraform provider.
"""
import json

from ...core.directory import children, follow, get, one, rdn_value, values
from ...domains.federation.domain import INTEGRATIONS

USER_DIRECTORY = {"type": "LDAP_DATA_STORE", "id": "ciam-user-directory"}


def _claims(d, integ):
    return tuple((one(c, "ciamClaimName"), one(follow(d, c, "ciamSourceAttribute"), "ciamLdapName"),
                  one(c, "ciamTransform"))
                 for c in children(d, f"ou=claims,{integ.dn}", "ciamClaimMap"))


def _fulfillment_entry(attr, transform):
    base = {"source": USER_DIRECTORY, "value": attr}
    return {**base, "x-opsdir-transform": transform} if transform else base


def _fulfillment(claims):
    return {name: _fulfillment_entry(attr, transform) for name, attr, transform in claims}


def _sp_connection(i, claims, owners, certs):
    return {
        "id": rdn_value(i), "name": rdn_value(i), "entityId": one(i, "ciamEntityId"), "active": True,
        "contactInfo": {"company": ", ".join(owners)},
        "spBrowserSso": {
            "protocol": "SAML20", "enabledProfiles": ["SP_INITIATED_SSO"],
            "ssoServiceEndpoints": [{"binding": "POST", "url": one(i, "ciamAcsUrl"), "isDefault": True}],
            "attributeContract": {
                "coreAttributes": [{"name": "SAML_SUBJECT"}],
                "extendedAttributes": [{"name": n} for n, _, _ in claims]},
            "adapterMappings": [{"attributeContractFulfillment": {
                "SAML_SUBJECT": {"source": USER_DIRECTORY, "value": "uid"}, **_fulfillment(claims)}}]},
        "x-opsdir": {"mfaRequired": one(i, "ciamMfaRequired") == "TRUE",
                     "populations": list(values(i, "ciamPopulation")), "certificateFingerprints": list(certs)}}


def _oidc_client(i, claims, owners, certs):
    return {
        "clientId": one(i, "ciamClientId"), "name": rdn_value(i), "enabled": True,
        "redirectUris": list(values(i, "ciamRedirectUri")),
        "grantTypes": [g.upper() for g in values(i, "ciamGrantType")],
        "requireProofKeyForCodeExchange": one(i, "ciamPkceRequired") == "TRUE",
        "x-opsdir": {"claims": _fulfillment(claims), "mfaRequired": one(i, "ciamMfaRequired") == "TRUE",
                     "owners": list(owners)}}


def _idp_connection(i, claims, owners, certs):
    return {
        "id": rdn_value(i), "name": rdn_value(i), "entityId": one(i, "ciamEntityId"), "active": True,
        "credentials": {"certs": [{"certView": {"sha256Fingerprint": f}} for f in certs]},
        "idpBrowserSso": {"protocol": "SAML20", "jitProvisioning": {
            "userRepository": {"type": "LDAP", "baseDn": one(i, "ciamJitBaseDn")}}},
        "x-opsdir": {"owners": list(owners)}}


# protocol type → (output file, resource builder)
RESOURCES = {"saml2-sp": ("pingfederate/sp-connections.json", _sp_connection),
             "oidc-client": ("pingfederate/oidc-clients.json", _oidc_client),
             "saml2-idp": ("pingfederate/idp-connections.json", _idp_connection)}


def _resource(d, i):
    owners = tuple(rdn_value(get(d, o)) for o in values(i, "ciamOwner"))
    certs = tuple(one(get(d, c), "ciamFingerprint") for c in values(i, "ciamUsesCertificate"))
    return RESOURCES[one(i, "ciamProtocolType")][1](i, _claims(d, i), owners, certs)


def render_neutral(d):
    integrations = children(d, INTEGRATIONS, "ciamIntegration")
    return {path: json.dumps([_resource(d, i) for i in integrations if one(i, "ciamProtocolType") == ptype],
                             indent=2) + "\n"
            for ptype, (path, _) in RESOURCES.items()}
