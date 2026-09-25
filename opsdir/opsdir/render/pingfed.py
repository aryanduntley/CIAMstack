"""Render PingFederate integration definitions (environment-neutral).

The JSON follows the shape of PingFederate Admin API resources (SP connections, OIDC clients,
IdP connections) but is an illustrative subset. It hasn't been validated against a live
/pf-admin-api/v1. In production this renderer would target the Admin API or the PingFederate
Terraform provider.
"""
import json


def _claims(d, integ):
    return [(c.one("ciamClaimName"), d.ref(c, "ciamSourceAttribute").one("ciamLdapName"), c.one("ciamTransform"))
            for c in d.children(f"ou=claims,{integ.dn}", "ciamClaimMap")]


def _fulfillment(claims):
    out = {}
    for name, attr, transform in claims:
        f = {"source": {"type": "LDAP_DATA_STORE", "id": "ciam-user-directory"}, "value": attr}
        if transform:
            f["x-opsdir-transform"] = transform
        out[name] = f
    return out


def render_neutral(d):
    sp, oidc, idp = [], [], []
    for i in d.children("ou=integrations,dc=ciam-ops", "ciamIntegration"):
        t = i.one("ciamProtocolType")
        claims = _claims(d, i)
        owners = [d.get(o).name for o in i.all("ciamOwner")]
        certs = [d.get(c).one("ciamFingerprint") for c in i.all("ciamUsesCertificate")]
        if t == "saml2-sp":
            sp.append({
                "id": i.name, "name": i.name, "entityId": i.one("ciamEntityId"), "active": True,
                "contactInfo": {"company": ", ".join(owners)},
                "spBrowserSso": {
                    "protocol": "SAML20", "enabledProfiles": ["SP_INITIATED_SSO"],
                    "ssoServiceEndpoints": [{"binding": "POST", "url": i.one("ciamAcsUrl"), "isDefault": True}],
                    "attributeContract": {
                        "coreAttributes": [{"name": "SAML_SUBJECT"}],
                        "extendedAttributes": [{"name": n} for n, _, _ in claims]},
                    "adapterMappings": [{"attributeContractFulfillment": {
                        "SAML_SUBJECT": {"source": {"type": "LDAP_DATA_STORE", "id": "ciam-user-directory"},
                                         "value": "uid"}, **_fulfillment(claims)}}]},
                "x-opsdir": {"mfaRequired": i.one("ciamMfaRequired") == "TRUE",
                             "populations": i.all("ciamPopulation"), "certificateFingerprints": certs}})
        elif t == "oidc-client":
            oidc.append({
                "clientId": i.one("ciamClientId"), "name": i.name, "enabled": True,
                "redirectUris": i.all("ciamRedirectUri"),
                "grantTypes": [g.upper() for g in i.all("ciamGrantType")],
                "requireProofKeyForCodeExchange": i.one("ciamPkceRequired") == "TRUE",
                "x-opsdir": {"claims": _fulfillment(claims), "mfaRequired": i.one("ciamMfaRequired") == "TRUE",
                             "owners": owners}})
        elif t == "saml2-idp":
            idp.append({
                "id": i.name, "name": i.name, "entityId": i.one("ciamEntityId"), "active": True,
                "credentials": {"certs": [{"certView": {"sha256Fingerprint": f}} for f in certs]},
                "idpBrowserSso": {"protocol": "SAML20", "jitProvisioning": {
                    "userRepository": {"type": "LDAP", "baseDn": i.one("ciamJitBaseDn")}}},
                "x-opsdir": {"owners": owners}})
    dump = lambda x: json.dumps(x, indent=2) + "\n"  # noqa: E731
    return {"pingfederate/sp-connections.json": dump(sp), "pingfederate/oidc-clients.json": dump(oidc),
            "pingfederate/idp-connections.json": dump(idp)}
