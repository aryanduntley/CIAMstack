"""PingFederate as an OAuth authorization server: a JWT access token manager linked to the certificate of the key pair
it signs with (the certificate carries PingFederate's key pair id), its symmetric key withheld; OIDC policies linked to
their token manager; the authorization server's settings and scopes; an OAuth client linked to its token manager and
OIDC policy and rendered back with them; renders that import back unchanged, and the planner's findings."""
import datetime as dt
import json

import pytest

from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import core_fragments
from opsdir.core.contract import PlanContext
from opsdir.core.directory import get, one, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir.domains.federation.naming import INTEGRATIONS
from opsdir.domains.pki.naming import CERTIFICATES
from opsdir_adapter_pingfederate.adapter import ADAPTER
from opsdir_adapter_pingfederate.checks import check_references
from opsdir_adapter_pingfederate.naming import AUTH_SERVER, OIDC_POLICIES, TOKEN_MANAGERS, named
from opsdir_adapter_pingfederate.admin_api import OUTPUT as REQUESTS, rendered_bodies
from opsdir_adapter_pingfederate.render import render_env
from opsdir_adapter_pingfederate.schema import FRAGMENT
import mini_estate
from support import build_directory

REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
FP = "18:50:45:3C:96:D7:6C:B8:F5:90:6A:4B:06:37:F9:99:AE:16:65:5C:A3:29:EC:90:34:04:37:FA:10:28:B6:99"
KEY_PAIR = {"id": "signing-2025", "sha256Fingerprint": FP.replace(":", ""), "subjectDN": "CN=sso.example.test",
            "issuerDN": "CN=sso.example.test", "validFrom": "2025-07-01T00:00:00Z", "expires": "2027-06-30T00:00:00Z"}


def _row(**fields):
    return {"fields": [{"name": k, "value": v} if not isinstance(v, dict) else {"name": k, **v}
                       for k, v in fields.items()]}


JWT = {"id": "jwt", "name": "JWT", "pluginDescriptorRef": {
    "id": "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"},
       "configuration": {"tables": [
           {"name": "Symmetric Keys", "rows": [_row(**{"Key ID": "s1", "Key": {"encryptedValue": "eyJ..not-a-key"}})]},
           {"name": "Certificates", "rows": [_row(**{"Key ID": "k1", "Certificate": "signing-2025"})]}],
           "fields": [{"name": "Token Lifetime", "value": "120"}, {"name": "JWS Algorithm", "value": "RS256"},
                      {"name": "Active Signing Certificate Key ID", "value": "k1"}]},
       "attributeContract": {"extendedAttributes": [{"name": "sub"}]}}
OIDC = {"id": "default-oidc", "name": "Default", "accessTokenManagerRef": {"id": "jwt"}, "idTokenLifetime": 5,
        "attributeContract": {"coreAttributes": [{"name": "sub"}]}}
ORPHAN = {"id": "orphan", "name": "Orphan", "accessTokenManagerRef": {"id": "gone"}}
SERVER = {"scopes": [{"name": "email", "description": "Email address"}],
          "exclusiveScopes": [{"name": "admin", "description": "Administration"}],
          "authorizationCodeTimeout": 60, "persistentGrantLifetime": -1}
PORTAL = {"clientId": "portal", "name": "Portal", "enabled": True, "redirectUris": ["https://portal.example.test/cb"],
          "grantTypes": ["AUTHORIZATION_CODE"], "clientAuth": {"type": "NONE"},
          "defaultAccessTokenManagerRef": {"id": "jwt"}, "oidcPolicy": {"policyGroup": {"id": "default-oidc"}}}
PORTAL_DN = f"cn=portal,{INTEGRATIONS}"
JWT_DN, OIDC_DN = named(TOKEN_MANAGERS, "jwt"), named(OIDC_POLICIES, "default-oidc")
CERT_DN = f"cn=pf-signing-2025,{CERTIFICATES}"


def export(policies=(OIDC, ORPHAN)):
    ops = (("/keyPairs/signing", [KEY_PAIR]), ("/oauth/accessTokenManagers", [JWT]),
           ("/oauth/openIdConnect/policies", list(policies)), ("/oauth/authServerSettings", [SERVER]),
           ("/oauth/clients", [PORTAL]))
    return {"data.json": json.dumps({"operations": [{"operationType": "SAVE", "resourceType": r, "items": items}
                                                     for r, items in ops]})}


def records():
    return tuple(parse(mini_estate.LDIF))


def imported(changes=(), files=None):
    """(the record after importing (then the changes), the import's change records, notices)."""
    base = build_directory(REGISTRY, records())
    import_changes, notices = preview_import(base, "pingfederate/bulk", files or export(), (ADAPTER,))
    return build_directory(REGISTRY, records(), (*import_changes, *changes)), import_changes, notices


@pytest.fixture(scope="module")
def after():
    d, _, notices = imported()
    return d, notices


def _config(e):
    return json.loads(one(e, "pingfedConfig"))


def test_a_token_manager_links_the_certificate_of_the_key_pair_it_signs_with(after):
    d, notices = after
    cert, jwt = get(d, CERT_DN), get(d, JWT_DN)
    assert ("pingfedKeyPair" in cert.classes, one(cert, "pingfedKeyPairId"), one(cert, "ciamFingerprint")) == \
        (True, "signing-2025", FP)
    assert (one(jwt, "pingfedPluginKind"), values(jwt, "pingfedUses")) == ("access-token-manager", (CERT_DN,))
    assert values(jwt, "pingfedWithheld") == ("/configuration/tables/0/rows/0/fields/1/value",)
    assert "access token manager JWT: its secrets are withheld; set pingfedCredentialRole to the secret role that " \
           "holds them" in notices
    assert "not-a-key" not in json.dumps([dict(e.attrs) for e in d.entries.values()])


def test_oidc_policies_link_their_token_manager(after):
    d, notices = after
    oidc = get(d, OIDC_DN)
    assert (values(oidc, "pingfedUses"), _config(oidc)["idTokenLifetime"]) == ((JWT_DN,), 5)
    assert not values(get(d, named(OIDC_POLICIES, "orphan")), "pingfedUses")
    assert ("OIDC policy Orphan: names access token manager `gone`, which neither the export nor the record has"
            in notices)


def test_the_authorization_servers_settings_list_its_scopes(after):
    d, _ = after
    server = get(d, AUTH_SERVER)
    assert (values(server, "pingfedScope"), _config(server)["authorizationCodeTimeout"]) == (("email", "admin"), 60)


def test_a_client_links_its_token_manager_and_oidc_policy(after):
    d, _ = after
    portal = get(d, PORTAL_DN)
    assert ("pingfedClient" in portal.classes, values(portal, "pingfedUses")) == (True, (JWT_DN, OIDC_DN))
    client = next(c for c in rendered_bodies(render_env(env_model(d, "alpha/prod"), None)[REQUESTS])["/oauth/clients"]
                  if c["clientId"] == one(portal, "ciamClientId"))
    assert (client["defaultAccessTokenManagerRef"], client["oidcPolicy"]) == \
        ({"id": "jwt"}, {"policyGroup": {"id": "default-oidc"}})


def test_renders():
    d, _, _ = imported()
    alpha = rendered_bodies(render_env(env_model(d, "alpha/prod"), None)[REQUESTS])
    assert [p["id"] for p in alpha["/oauth/openIdConnect/policies"]] == ["default-oidc", "orphan"]
    assert alpha["/oauth/authServerSettings"] == [SERVER]
    jwt = alpha["/oauth/accessTokenManagers"][0]
    assert (jwt["configuration"]["tables"][0]["rows"][0]["fields"][1]["value"],
            jwt["configuration"]["tables"][1]["rows"][0]["fields"][1]["value"]) == ("${withheld}", "signing-2025")


@pytest.mark.parametrize("env", ["alpha/prod", "beta/prod"])
def test_what_it_renders_imports_back_unchanged(env):
    d, _, _ = imported()
    rendered = {p: t for p, t in render_env(env_model(d, env), None).items() if p.endswith(".json")}
    again, _ = preview_import(d, "pingfederate/bulk", rendered, (ADAPTER,))
    assert again == ()


def plan(d):
    return check_references(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None,
                                        dt.date(2026, 10, 1), {}, {}, ()))


def test_the_planner_names_what_is_missing():
    d, _, _ = imported()
    assert [t for _, t, _ in plan(d).blockers] == [
        "Access token manager `jwt` has withheld credentials but no credential role: nothing says which secret "
        "beta/prod gives it. Set pingfedCredentialRole.",
        "OIDC policy `orphan` names access token manager `gone`, which the record doesn't have: PingFederate refuses "
        "the configuration until it is recorded."]


def test_a_key_pair_the_record_lacks_is_blocked():
    d, _, _ = imported(files={"data.json": json.dumps({"operations": [
        {"operationType": "SAVE", "resourceType": "/oauth/accessTokenManagers", "items": [JWT]}]})})
    assert "Access token manager `jwt` names key pair `signing-2025`, which the record doesn't have: PingFederate " \
           "refuses the configuration until it is recorded." in [t for _, t, _ in plan(d).blockers]
