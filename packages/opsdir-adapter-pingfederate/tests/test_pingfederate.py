"""The PingFederate adapter as the core sees it: registered, chosen from the servers' products, owning its server
roles, rendering its environment-neutral files. Full renders are exercised by the showcase golden outputs."""
import json
from types import SimpleNamespace

from opsdir.connectors.registry import ADAPTERS
from opsdir.core.directory import make_directory, make_entry
from opsdir.domains.federation.naming import IDENTITY_SERVICES, INTEGRATIONS
from opsdir_adapter_pingfederate.adapter import ADAPTER


def _servers(*products):
    return SimpleNamespace(servers=tuple(make_entry(f"cn=s{i},dc=x", ["ciamServer"], {"ciamProductVersion": [p]})
                                         for i, p in enumerate(products)))


def test_registered_through_its_entry_point():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "product"


def test_applies_when_a_server_runs_it():
    assert ADAPTER.applies(_servers("PingFederate 12.1.4")) and not ADAPTER.applies(_servers("PingDS 7.5.1"))


def test_owns_its_server_roles():
    assert ADAPTER.vocabulary == {"ciamServerRole": ("pf-engine", "pf-admin"),
                                  "ciamTargetRole": ("pf-engine", "pf-admin"),
                                  "pingfedDiscoveryProtocol": ("TCPPING", "NATIVE_S3_PING", "DNS_PING")}


def test_renders_empty_configuration_for_an_empty_directory():
    assert ADAPTER.render_neutral(make_directory((), (), ())) == {
        "pingfederate/sp-connections.json": "[]\n", "pingfederate/oidc-clients.json": "[]\n",
        "pingfederate/idp-connections.json": "[]\n"}


def _federation():
    return make_directory((), {}, (
        (f"cn=app,{INTEGRATIONS}", ("top", "ciamIntegration"),
         {"cn": ["app"], "ciamProtocolType": ["oidc-client"], "ciamClientId": ["app"],
          "ciamGrantType": ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"],
          "ciamTokenAuthMethod": ["private_key_jwt"], "ciamScope": ["openid"]}),
        (f"cn=sso,{IDENTITY_SERVICES}", ("top", "ciamIdentityService"),
         {"cn": ["sso"], "ciamBaseUrl": ["https://sso.test"], "ciamEntityId": ["https://sso.test/idp"],
          "ciamOidcIssuer": ["https://sso.test"], "ciamTargetRole": ["pf-engine"]}),
        (f"cn=other,{IDENTITY_SERVICES}", ("top", "ciamIdentityService"),
         {"cn": ["other"], "ciamBaseUrl": ["https://other.test"], "ciamOidcIssuer": ["https://other.test"],
          "ciamTargetRole": ["some-other-product"]})))


def test_renders_the_standard_documents_for_the_services_it_serves_at_its_paths():
    files = ADAPTER.render_neutral(_federation())
    assert {"saml/idp/sso.xml", "oidc/discovery/sso.json", "oidc/clients/app.json"} <= set(files)
    assert "oidc/discovery/other.json" not in files
    assert '"token_endpoint": "https://sso.test/as/token.oauth2"' in files["oidc/discovery/sso.json"]


def test_maps_standard_values_to_its_api_names():
    client = json.loads(ADAPTER.render_neutral(_federation())["pingfederate/oidc-clients.json"])[0]
    assert client["grantTypes"] == ["AUTHORIZATION_CODE", "TOKEN_EXCHANGE"]
    assert (client["clientAuth"], client["restrictedScopes"]) == ({"type": "PRIVATE_KEY_JWT"}, ["openid"])
