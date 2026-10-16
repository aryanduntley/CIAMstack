"""Microsoft Entra External ID's Graph configuration read into the record (azure/external-id): the collector's calls
(the tenant checked first, every page, each flow's applications, an allowlist kept before anything else sees an
output), and the importer (applications as the identity service's integrations, user flows and custom authentication
extensions beneath the binding, never a credential); a render read back changes nothing."""
import json

from opsdir.connectors.collecting import collect
from opsdir.connectors.importing import import_changes
from opsdir.core.contract import SecretPattern
from opsdir.core.directory import get, one, subtree, values
from opsdir_format_terraform.hcl import written
from opsdir_adapter_azure.adapter import ADAPTER
from opsdir_adapter_azure.external_id import SERVICE
from opsdir_adapter_azure.external_id_graph import (GRAPH_COLLECTOR, GRAPH_IMPORTER, graph_problems, graph_steps,
                                                    project_output, read_graph, tenant_check)
from opsdir_adapter_azure.terraform import render_files
from network_fixtures import ALPHA, entry, model

INTEGRATIONS = "ou=integrations,dc=ciam-ops"
TREE = ("dn: ou=integrations,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: integrations\n",
        entry(INTEGRATIONS, "portal", "ciamIntegration", ciamProtocolType="oidc-client", ciamClientId="portal",
              ciamGrantType=("authorization_code", "client_credentials"), ciamTokenAuthMethod="client_secret_post",
              ciamRedirectUri="https://portal.example.test/cb"),
        entry(INTEGRATIONS, "crm", "ciamIntegration", ciamProtocolType="saml2-sp",
              ciamEntityId="https://crm.example.test", ciamAcsUrl="https://crm.example.test/acs"))
TENANT = dict(ciamBindingRole="sso-tenant", ciamManagedService=SERVICE, ciamRealizes="sso")
TENANT_ID = "8d3e1f02-6a5b-4c7d-9e8f-0a1b2c3d4e5f"
BINDING = f"cn=sso-tenant,ou=bindings,{ALPHA}"
TARGET = entry(ALPHA, "sso-tenant", "ciamManagedIdentity", ciamProviderRef=TENANT_ID, **TENANT)
BASE = "alpha/prod/external-id"
PORTAL_APP, CRM_APP, ORDERS_APP = ("0f1e2d3c-0000-4000-8000-00000000000a", "0f1e2d3c-0000-4000-8000-00000000000b",
                                   "0f1e2d3c-0000-4000-8000-00000000000c")
EXTENSION = "6b7c8d9e-0000-4000-8000-0000000000e1"
FLOW = "5a4b3c2d-0000-4000-8000-0000000000f1"


def _page(*items, next_link=None):
    return json.dumps({"value": list(items), **({"@odata.nextLink": next_link} if next_link else {})})


def _graph():
    """A tenant's Graph outputs as the collector saves them, credentials included where Graph would send them (the
    importer must not keep them)."""
    return {
        f"{BASE}/organization.json": _page({"id": TENANT_ID, "displayName": "SSO customers"}),
        f"{BASE}/applications.json": _page(
            {"id": "o1", "appId": PORTAL_APP, "displayName": "portal",
             "web": {"redirectUris": ["https://portal.example.test/cb"]}, "spa": {"redirectUris": []},
             "publicClient": {"redirectUris": []}, "identifierUris": [],
             "passwordCredentials": [{"hint": "abc", "keyId": "k1"}]},
            {"id": "o0", "appId": "b2c0", "displayName": "b2c-extensions-app. Do not modify. Used by AADB2C for "
                                                         "storing user data."},
            next_link="https://graph.microsoft.com/v1.0/applications?$skiptoken=X"),
        f"{BASE}/applications-2.json": _page(
            {"id": "o2", "appId": CRM_APP, "displayName": "CRM (SAML)", "identifierUris": ["https://crm.example.test"],
             "web": {"redirectUris": ["https://crm.example.test/acs"]}},
            {"id": "o3", "appId": ORDERS_APP, "displayName": "Orders", "web": {"redirectUris": []},
             "spa": {"redirectUris": ["https://orders.example.test/"]}, "identifierUris": []}),
        f"{BASE}/service-principals.json": _page(
            {"appId": PORTAL_APP, "displayName": "portal", "servicePrincipalType": "Application"},
            {"appId": CRM_APP, "displayName": "CRM (SAML)", "preferredSingleSignOnMode": "saml"}),
        f"{BASE}/identity-providers.json": _page({"id": "Google-OAUTH", "displayName": "Google"}),
        f"{BASE}/sign-in-flows.json": _page({
            "@odata.type": "#microsoft.graph.externalUsersSelfServiceSignUpEventsFlow", "id": FLOW,
            "displayName": "Customers sign up and sign in", "description": None,
            "onInteractiveAuthFlowStart": {"isSignUpAllowed": True},
            "onAuthenticationMethodLoadStart": {"identityProviders": [
                {"id": "EmailPassword-OAUTH", "displayName": "Email with password"},
                {"id": "Google-OAUTH", "displayName": "Google", "clientId": "g-client", "clientSecret": "******"}]},
            "onAttributeCollection": {"attributes": [{"id": "email", "displayName": "Email Address"},
                                                     {"id": "displayName", "displayName": "Display Name"}]},
            "onAttributeCollectionSubmit": {"handler": {"customExtension": {"id": EXTENSION}}}}),
        f"{BASE}/flow-{FLOW}-applications.json": _page({"appId": PORTAL_APP}, {"appId": ORDERS_APP}),
        f"{BASE}/extensions.json": _page(
            {"@odata.type": "#microsoft.graph.onAttributeCollectionSubmitCustomExtension", "id": EXTENSION,
             "displayName": "Check loyalty number", "description": "Validates the loyalty number at sign-up",
             "endpointConfiguration": {"targetUrl": "https://ext.example.test/api/check?code=SECRET"},
             "authenticationConfiguration": {"resourceId": "api://ext.example.test/0f1e"}},
            {"@odata.type": "#microsoft.graph.onTokenIssuanceStartCustomExtension", "id": "e2",
             "displayName": "Loyalty claims", "authenticationConfiguration": {"resourceId": "api://claims.example.test"},
             "claimsForTokenConfiguration": [{"claimIdInApiResponse": "loyaltyTier"}]},
            {"@odata.type": "#microsoft.graph.someFutureCustomExtension", "id": "e3", "displayName": "Future"}),
    }


# ------------------------------------------------------------------ the collector
def test_the_collector_reads_the_tenant_its_target_records_with_the_allowlist_kept_first():
    assert GRAPH_COLLECTOR in ADAPTER.collectors and GRAPH_IMPORTER in ADAPTER.importers
    d, m, _ = model(alpha=(TARGET,), tree=TREE)
    call, check = tenant_check(d, m)
    assert call.argv == ("az", "account", "show", "-o", "json")
    assert check(json.dumps({"tenantId": TENANT_ID, "environmentName": "AzureCloud"})) is None
    assert "az login --tenant" in check(json.dumps({"tenantId": "other", "environmentName": "AzureCloud"}))
    assert "AzureCloud only" in check(json.dumps({"tenantId": TENANT_ID, "environmentName": "AzureUSGovernment"}))
    first = dict(graph_steps(d, m, {}, {}))
    assert sorted(first) == sorted(f"{BASE}/{n}.json" for n in ("organization", "applications", "service-principals",
                                                                "identity-providers", "sign-in-flows", "extensions"))
    apps = first[f"{BASE}/applications.json"]
    assert apps.argv[:4] == ("az", "rest", "--method", "get") and apps.argv[5] == (
        "https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,identifierUris,web,spa,"
        "publicClient")
    assert first[f"{BASE}/identity-providers.json"].argv[5].endswith("?$select=id,displayName")
    assert "$select" not in first[f"{BASE}/sign-in-flows.json"].argv[5]      # none documented: projected instead
    # what comes back is kept to the allowlist before anything else sees it: no credential survives
    kept = apps.keep(_graph()[f"{BASE}/applications.json"])
    assert "passwordCredentials" not in kept and "@odata.nextLink" in kept
    flows = first[f"{BASE}/sign-in-flows.json"].keep(_graph()[f"{BASE}/sign-in-flows.json"])
    assert "clientSecret" not in flows and "g-client" not in flows and "EmailPassword-OAUTH" in flows
    extensions = project_output("extensions", _graph()[f"{BASE}/extensions.json"])
    assert "targetUrl" not in extensions and "SECRET" not in extensions and "api://ext.example.test/0f1e" in extensions
    assert project_output("applications", "not json") == '{\n "value": []\n}'
    # then the next page each output names, and each flow's applications; nothing read twice
    done = {p: t for p, t in _graph().items() if p.count("/") == 3 and "flow-" not in p and "-2" not in p}
    later = dict(graph_steps(d, m, done, {}))
    assert sorted(later) == [f"{BASE}/applications-2.json", f"{BASE}/flow-{FLOW}-applications.json"]
    assert later[f"{BASE}/applications-2.json"].argv[5].endswith("$skiptoken=X")
    assert later[f"{BASE}/flow-{FLOW}-applications.json"].argv[5].endswith(
        f"/identity/authenticationEventsFlows/{FLOW}/conditions/applications/includeApplications")


def test_without_one_recorded_tenant_there_is_nothing_to_collect():
    d, m, _ = model(alpha=(entry(ALPHA, "sso-tenant", "ciamManagedIdentity", **TENANT),), tree=TREE)
    assert "no Entra External ID target recording its tenant ID" in graph_problems(d, m, {})[0]
    assert graph_steps(d, m, {}, {}) == ()
    d, m, _ = model(alpha=(TARGET, entry(ALPHA, "b2b-tenant", "ciamManagedIdentity", ciamBindingRole="b2b",
                                         ciamManagedService=SERVICE, ciamRealizes="sso", ciamProviderRef="t2")),
                    tree=TREE)
    assert "one login reads one tenant" in graph_problems(d, m, {})[0]
    d, m, _ = model(alpha=(TARGET,), tree=TREE)
    assert graph_problems(d, m, {}) is None


# ------------------------------------------------------------------ the importer
def test_applications_become_the_services_integrations_and_flows_and_extensions_entries_beneath_the_binding():
    old = entry(BINDING, "retired-flow", "ciamSignInFlow")
    d, _, _ = model(alpha=(TARGET,), tree=(*TREE, old))
    imported = read_graph(_graph(), d)
    groups = dict(imported.groups)
    portal = groups[f"cn=portal,{INTEGRATIONS}"][0]
    # matched by name: Entra's client ID differs from the record's, which is kept (the application switches later)
    assert one(portal, "ciamClientId") == "portal" and values(portal, "ciamRedirectUri") == (
        "https://portal.example.test/cb",)
    assert any(f"portal is registered in the tenant as client {PORTAL_APP}; the record's client ID is portal" in n
               for n in imported.notices)
    crm = groups[f"cn=crm,{INTEGRATIONS}"][0]                         # matched by entity ID
    assert one(crm, "ciamAcsUrl") == "https://crm.example.test/acs" and one(crm, "ciamProtocolType") == "saml2-sp"
    orders = groups[f"cn=orders,{INTEGRATIONS}"][0]                   # new: registered with the service
    assert (one(orders, "ciamClientId"), one(orders, "ciamProtocolType")) == (ORDERS_APP, "oidc-client")
    assert values(orders, "ciamRedirectUri") == ("https://orders.example.test/",)
    assert one(orders, "ciamServedBy") == "cn=sso,ou=identity-services,dc=ciam-ops"
    assert not any("b2c" in dn for dn in groups)                       # Microsoft's own
    binding, *beneath = groups[BINDING]
    assert binding == get(d, BINDING)                                  # the binding itself unchanged
    by_cn = {one(e, "cn"): e for e in beneath}
    assert set(by_cn) == {"check-loyalty-number", "loyalty-claims", "customers-sign-up-and-sign-in"}
    flow = by_cn["customers-sign-up-and-sign-in"]
    assert values(flow, "ciamSignInMethod") == ("email-password", "federated", "sign-up")
    assert values(flow, "ciamUpstreamProvider") == ("Google",) and values(flow, "ciamCollectedAttribute") == (
        "email", "displayName")
    assert values(flow, "ciamFlowApplications") == (f"cn=portal,{INTEGRATIONS}", f"cn=orders,{INTEGRATIONS}")
    assert values(flow, "ciamFlowExtension") == (f"cn=check-loyalty-number,{BINDING}",)
    check, claims = by_cn["check-loyalty-number"], by_cn["loyalty-claims"]
    assert (one(check, "ciamExtensionEvent"), one(check, "ciamExtensionResource")) == (
        "attribute-collection-submit", "api://ext.example.test/0f1e")
    assert values(claims, "ciamExtensionClaim") == ("loyaltyTier",) and "targetUrl" not in str(check.attrs)
    assert any("Future" in n and "answers no event" in n for n in imported.notices)
    assert any("upstream identity providers in the tenant" in n and "Google" in n for n in imported.notices)
    # the binding's flows are exactly the tenant's: the retired one goes
    changes = import_changes(d, imported)
    assert any(r.changetype == "delete" and r.dn.startswith("cn=retired-flow,") for r in changes)
    assert not any(r.changetype == "delete" and "ou=integrations" in r.dn for r in changes)


def test_another_tenant_or_a_secret_looking_value_is_not_imported():
    d, _, _ = model(alpha=(TARGET,), tree=TREE)
    files = {**_graph(), f"{BASE}/organization.json": _page({"id": "another-tenant"})}
    imported = read_graph(files, d)
    assert imported.groups == () and "no External ID target records tenant another-tenant" in imported.notices[0]
    leaky = {**_graph(), f"{BASE}/extensions.json": _page({
        "@odata.type": "#microsoft.graph.onTokenIssuanceStartCustomExtension", "id": "e9", "displayName": "Leaky",
        "authenticationConfiguration": {"resourceId": "AKIAABCDEFGHIJKLMNOP"}})}
    pattern = SecretPattern("aws-access-key", "AKIA[0-9A-Z]{16}", "an AWS access key ID")
    imported = read_graph(leaky, d, (pattern,))
    leak, = (e for _, es in imported.groups for e in es if one(e, "cn") == "leaky")
    assert one(leak, "ciamExtensionResource") is None
    assert any("ciamExtensionResource withheld" in n for n in imported.notices)
    assert read_graph({}, d).notices == ("no Graph outputs found (<cloud>/<env>/external-id/*.json)",)


def test_a_render_read_back_from_the_tenant_changes_nothing():
    """What the render registers, as Graph reports it once applied (Entra assigns the client IDs): the record's
    integrations stay as they are, beneath the binding only what the tenant adds."""
    d, m, _ = model(alpha=(TARGET,), tree=TREE)
    main = written(render_files(m, None))["terraform/main.tf"]
    assert 'display_name     = "portal"' in main and 'display_name    = "crm"' in main
    applied = {f"{BASE}/organization.json": _page({"id": TENANT_ID}),
               f"{BASE}/applications.json": _page(
                   {"appId": PORTAL_APP, "displayName": "portal",
                    "web": {"redirectUris": ["https://portal.example.test/cb"]}},
                   {"appId": CRM_APP, "displayName": "crm", "identifierUris": ["https://crm.example.test"],
                    "web": {"redirectUris": ["https://crm.example.test/acs"]}}),
               f"{BASE}/service-principals.json": _page({"appId": PORTAL_APP},
                                                        {"appId": CRM_APP, "preferredSingleSignOnMode": "saml"})}
    changes = import_changes(d, read_graph(applied, d))
    assert changes == () and not subtree(d, BINDING)[1:]


def test_a_collection_keeps_no_credential_and_reads_back_as_the_files_saved_by_hand():
    raw = _graph()
    answers = {"skiptoken=X": "applications-2", "/organization": "organization", "/applications?": "applications",
               "/servicePrincipals": "service-principals", "/identity/identityProviders": "identity-providers",
               "/identity/authenticationEventsFlows?": None, "/includeApplications": f"flow-{FLOW}-applications",
               "/identity/customAuthenticationExtensions": "extensions"}

    def run(call):
        url = call.argv[5]
        name = next((n for k, n in answers.items() if k in url), None) or (
            "sign-in-flows" if url.endswith("/identity/authenticationEventsFlows") else None)
        return raw[f"{BASE}/{name}.json"], None
    d, m, _ = model(alpha=(TARGET,), tree=TREE)
    c = collect("azure/external-id", GRAPH_COLLECTOR, d, m, run)
    assert c.problems == () and set(c.files) == set(raw)
    saved = "".join(c.files.values())
    assert not any(s in saved for s in ("passwordCredentials", "clientSecret", "g-client", "targetUrl", "SECRET"))
    by_hand = read_graph(raw, d)
    assert read_graph(c.files, d).groups == by_hand.groups != ()
