"""The PingAM adapter: registered and chosen from data; an Amster export imported into the record (clients as
standard integrations, journeys and policy sets in the package's schema, everything else captured, secrets withheld,
realms the record doesn't have named); the record rendered back as Amster entities and standard documents at AM's
paths, which import again with no change; and journeys that can't run blocked."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import ADAPTERS, core_fragments
from opsdir.core.directory import children, get, make_directory, one, values
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir_adapter_pingam.adapter import ADAPTER
from opsdir_adapter_pingam.checks import journey_problems
from opsdir_adapter_pingam.naming import journey_dn, policy_set_dn
from opsdir_adapter_pingam.realms import oauth2_path, meta_alias
from opsdir_adapter_pingam.render import render_neutral
from opsdir_adapter_pingam.schema import FRAGMENT
from support import build_directory

EXPORT = Path(__file__).resolve().parent / "amster-export"
REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
REALM = "cn=customers,ou=identity-services,dc=ciam-ops"
LOGIN = journey_dn("customers", "Login")
OTP = "a1b2c3d4-0000-4000-8000-000000000005"
BASE = f"""dn: dc=ciam-ops
objectClass: top
objectClass: domain
dc: ciam-ops

dn: ou=identity-services,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: identity-services

dn: {REALM}
objectClass: top
objectClass: ciamIdentityService
objectClass: pingamRealm
cn: customers
ciamBaseUrl: https://login.example.test
ciamOidcIssuer: https://login.example.test/am/oauth2/realms/root/realms/customers
ciamEntityId: https://login.example.test/am/customers
ciamTargetRole: am
pingamRealmPath: /customers
"""


def files_of(root):
    return {p.relative_to(root).as_posix(): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


def directory(changes=()):
    return build_directory(REGISTRY, parse(BASE), changes)


def imported(files=None, d=None):
    """(the record after importing the export, notices)."""
    base = d or directory()
    changes, notices = preview_import(base, "pingam", files or files_of(EXPORT), (ADAPTER,))
    return build_directory(REGISTRY, parse(BASE), changes) if d is None else base, changes, notices


@pytest.fixture(scope="module")
def after():
    d, _, notices = imported()
    return d, notices


NO_RECORDS = make_directory((), {}, ())        # an environment's directory with nothing in it


def test_registered_and_chosen_from_the_products_on_the_servers():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "product" and ADAPTER.schema.arc == "1.3.6.1.4.1.32473.3.1"
    server = lambda v: SimpleNamespace(attrs={"ciamProductVersion": (v,)})   # noqa: E731
    assert ADAPTER.applies(SimpleNamespace(servers=(server("PingAM 8.0.1"),), d=NO_RECORDS))
    assert ADAPTER.applies(SimpleNamespace(servers=(server("ForgeRock AM 7.5.0"),), d=NO_RECORDS))
    assert not ADAPTER.applies(SimpleNamespace(servers=(server("PingFederate 12.1.4"),), d=NO_RECORDS))


def test_clients_become_standard_integrations_registered_with_their_realm(after):
    d, notices = after
    i = get(d, "cn=portal-web,ou=integrations,dc=ciam-ops")
    assert (one(i, "ciamProtocolType"), one(i, "ciamServedBy"), one(i, "ciamTokenAuthMethod")) == \
        ("oidc-client", REALM, "client_secret_basic")
    assert values(i, "ciamGrantType") == ("authorization_code", "refresh_token")
    assert values(i, "ciamScope") == ("openid", "profile")
    assert "client portal-web: its secret is not imported; each environment binds it" in notices
    assert "client portal-web: grant types not in the standard vocabulary, not imported: implicit" in notices


def test_journeys_hold_every_node_with_its_outcomes_and_secrets_withheld(after):
    d, notices = after
    j = get(d, LOGIN)
    assert (one(j, "pingamRealm"), one(j, "pingamEnabled")) == (REALM, "TRUE")
    assert json.loads(one(j, "pingamTreeConfig")) == {"description": "Customer sign-in",
                                                      "staticNodes": {"startNode": {"x": 50, "y": 25}}}
    nodes = {one(n, "cn"): n for n in children(d, LOGIN, "pingamNode")}
    assert sorted(one(n, "pingamNodeType") for n in nodes.values()) == [
        "DataStoreDecisionNode", "OneTimePasswordSmtpSenderNode", "PageNode", "PasswordCollectorNode",
        "UsernameCollectorNode"]
    otp = nodes[OTP]
    assert values(otp, "pingamWithheld") == ("/password",)
    assert json.loads(one(otp, "pingamNodeConfig"))["password"] is None
    assert values(otp, "pingamOutcome") == ("outcome=70e691a5-1e33-4ac3-a356-e7b6d60d92e0",)
    assert journey_problems(d, j) == ()


def test_policy_sets_hold_their_policies_without_bookkeeping(after):
    d, _ = after
    s = get(d, policy_set_dn("customers", "portal-policies"))
    assert one(s, "pingamApplicationType") == "iPlanetAMWebAgentService"
    assert "creationDate" not in json.loads(one(s, "pingamSetConfig"))
    (p,) = children(d, s.dn, "pingamPolicy")
    assert json.loads(one(p, "pingamPolicyConfig"))["resources"] == ["https://portal.example.test/*"]


def test_other_entities_are_captured_and_unknown_realms_named(after):
    d, notices = after
    f = get(d, "cn=am.realms.root-customers.OAuth2Provider.OAuth2Provider.json,ou=config-files,dc=ciam-ops")
    assert (one(f, "ciamCaptureLevel"), one(f, "ciamTargetRole")) == ("settings", "am")
    assert ("realm /partners: no identity service in the record is this realm (record one with pingamRealmPath "
            "/partners); its entities are not imported") in notices


def test_importing_again_changes_nothing(after):
    d, _ = after
    _, changes, _ = imported(d=d)
    assert changes == ()


def test_rendered_as_amster_entities_and_standard_documents_at_ams_paths(after):
    d, _ = after
    files = render_neutral(d)
    tree = json.loads(files["am/realms/root-customers/AuthTree/Login.json"])
    assert set(tree["data"]["nodes"]) == {"a1b2c3d4-0000-4000-8000-000000000001",
                                          "a1b2c3d4-0000-4000-8000-000000000004", OTP}   # page children are not
    client = json.loads(files["am/realms/root-customers/OAuth2Clients/portal-web.json"])
    assert client["metadata"] == {"realm": "/customers", "entityType": "OAuth2Clients", "entityId": "portal-web",
                                  "pathParams": {}}
    assert "userpassword" not in client["data"]["coreOAuth2ClientConfig"]
    assert json.loads(files["am/global/Realms/customers.json"])["data"]["aliases"] == ["login.example.test"]
    discovery = json.loads(files["oidc/discovery/customers.json"])
    assert discovery["token_endpoint"] == "https://login.example.test" + oauth2_path("/customers") + "/access_token"
    assert oauth2_path("/customers") == "/am/oauth2/realms/root/realms/customers"
    assert meta_alias("/customers", "SSORedirect") in files["saml/idp/customers.xml"]


def test_what_it_renders_imports_back_unchanged(after):
    d, _ = after
    rendered = {p[len("am/"):]: t for p, t in render_neutral(d).items() if p.startswith("am/")}
    _, changes, _ = imported(rendered, d)
    assert changes == ()


def test_a_journey_leading_to_a_node_it_doesnt_have_cant_run(after):
    d, _ = after
    broken = parse(f"dn: {LOGIN}\nchangetype: modify\nreplace: pingamEntryNode\npingamEntryNode: nowhere\n-\n")
    d2 = build_directory(REGISTRY, parse(BASE), (*imported()[1], *broken))
    assert journey_problems(d2, get(d2, LOGIN)) == ("it starts at node nowhere, which it doesn't have",)
