"""Microsoft Entra External ID as a managed identity service: the descriptor the planner reads (Microsoft's documented
capabilities; external tenants in public clouds only), its render (the tenant through azapi where the add-on is
allowed, its app registrations through the tenant-aliased azuread provider once its tenant ID is recorded, the rest
actions; a neighbour a note), External ID in the FedRAMP boundary by its name."""
import json

from opsdir.connectors.managed_identity import managed_identity_check
from opsdir.core.contract import PlanContext
from opsdir.core.interchange.ldif import parse
from opsdir_format_terraform.hcl import written
from opsdir_adapter_azure.adapter import ADAPTER
from opsdir_adapter_azure.boundary import azure_services
from opsdir.domains.federation.managed import realized_service
from opsdir_adapter_azure.external_id import (EXTERNAL_ID, GRAPH_SCOPES, SAML_TEMPLATE, SERVICE, TENANT_TYPE,
                                              custom_scopes, external_id_bindings, external_id_notes, hostless,
                                              partition, scope_id)
from opsdir_adapter_azure.terraform import render, render_files
from network_fixtures import ALPHA, BETA, entry, model

INTEGRATIONS = "ou=integrations,dc=ciam-ops"
TREE = ("dn: ou=integrations,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: integrations\n",
        entry(INTEGRATIONS, "portal", "ciamIntegration", ciamProtocolType="oidc-client", ciamClientId="portal",
              ciamGrantType=("authorization_code", "client_credentials"), ciamTokenAuthMethod="client_secret_post",
              ciamRedirectUri="https://portal.example.test/cb"),
        entry(INTEGRATIONS, "crm", "ciamIntegration", ciamProtocolType="saml2-sp",
              ciamEntityId="https://crm.example.test", ciamAcsUrl="https://crm.example.test/acs"))
TENANT = dict(ciamBindingRole="sso-tenant", ciamManagedService=SERVICE, ciamRealizes="sso")
TENANT_ID = "8d3e1f02-6a5b-4c7d-9e8f-0a1b2c3d4e5f"
ADD_ON = tuple(parse("dn: cloud=alpha,ou=environments,dc=ciam-ops\nchangetype: modify\nadd: ciamProviderAddOn\n"
                     "ciamProviderAddOn: azapi\n"))
GOVERNMENT = tuple(parse("dn: cloud=beta,ou=environments,dc=ciam-ops\nchangetype: modify\nreplace: ciamRegion\n"
                         "ciamRegion: usgovvirginia\n"))


def _block(text, head):
    """The text of the block starting at head, to its closing brace."""
    start = text.index(head)
    return text[start:text.index("\n}\n", start) + 2]


def test_the_adapter_declares_external_id_for_public_clouds_only():
    assert ADAPTER.managed_identity == (EXTERNAL_ID,) and ADAPTER.vocabulary["ciamManagedService"] == (SERVICE,)
    assert set(EXTERNAL_ID.available) == {"public"} and set(EXTERNAL_ID.absent) == {"usgovernment"}
    assert {"issue:oidc", "issue:saml", "grant:refresh_token", "token-auth:client_secret_basic", "signing-alg:RS256",
            "custom-domain", "mfa-per-client", "claim-transform"} <= set(EXTERNAL_ID.supported)
    assert set(EXTERNAL_ID.unsupported) == {"grant:password"}           # ROPC: documented as not taken
    # what no documentation establishes stays out of both: confirmed through the unknowns register
    assert not {"dpop-bound", "pkce-required", "custom-issuer", "token-auth:tls_client_auth", "signing-alg:ES256",
                "grant:urn:ietf:params:oauth:grant-type:token-exchange"} & {*EXTERNAL_ID.supported,
                                                                           *EXTERNAL_ID.unsupported}
    assert "M2M Premium add-on" in EXTERNAL_ID.conditions["grant:client_credentials"]
    assert "custom authentication extension" in EXTERNAL_ID.conditions["claim-transform"]
    _, _, beta = model(tree=TREE, changes=GOVERNMENT)
    assert partition(beta) == "usgovernment"


def _render(alpha, changes=()):
    _, m, _ = model(alpha=alpha, tree=TREE, changes=changes)
    return m, written(render_files(m, None))


def test_without_a_tenant_id_nothing_renders_the_tenant_and_registrations_are_actions_a_neighbour_a_note():
    m, files = _render((entry(ALPHA, "sso-tenant", "ciamManagedIdentity", **TENANT),
                        entry(ALPHA, "partner-tenant", "ciamManagedIdentity", ciamBindingRole="partner-tenant",
                              ciamManagedService=SERVICE, ciamPartnerOf=f"cn=portal,{INTEGRATIONS}")))
    neighbour, tenant, registrations, flows = external_id_notes(m)          # bindings in DN order
    assert (tenant.severity, tenant.subject) == ("action", "external tenant sso-tenant")
    assert "doesn't allow the azapi add-on): create it by hand and record its tenant ID" in tenant.text
    assert (registrations.subject, registrations.severity) == ("external tenant sso-tenant applications", "action")
    assert ("crm (saml2-sp: https://crm.example.test/acs), portal (oidc-client: https://portal.example.test/cb)"
            in registrations.text)
    assert "a SAML application needs one: crm" in flows.how[0]
    assert (neighbour.severity, neighbour.subject) == ("note", "external tenant partner-tenant")
    main = files["terraform/main.tf"]
    assert "NOTE: external tenant sso-tenant: the external tenant isn't rendered" in main
    assert "azuread_application" not in main and "azapi_resource" not in main
    assert "azuread" not in files["terraform/providers.tf"]


def test_with_its_tenant_id_a_target_s_applications_render_through_the_tenant_aliased_provider():
    m, files = _render((entry(ALPHA, "sso-tenant", "ciamManagedIdentity", ciamProviderRef=TENANT_ID, **TENANT),))
    main, providers = files["terraform/main.tf"], files["terraform/providers.tf"]
    assert f'provider "azuread" {{\n  alias     = "sso_tenant"\n  tenant_id = "{TENANT_ID}"' in providers
    assert '"hashicorp/azuread"' in providers and "azapi" not in providers
    portal = _block(main, 'resource "azuread_application" "sso_tenant_portal"')
    assert "provider         = azuread.sso_tenant" in portal and 'redirect_uris = ["https://portal.example.test/cb"]' \
        in portal and "id_token_issuance_enabled     = false" in portal
    assert f'id   = "{GRAPH_SCOPES["openid"]}"' in portal and GRAPH_SCOPES["offline_access"] not in portal
    assert 'client_id = azuread_application.sso_tenant_portal.client_id' in _block(
        main, 'resource "azuread_service_principal" "sso_tenant_portal"')
    crm = _block(main, 'resource "azuread_application" "sso_tenant_crm"')
    assert f'template_id     = "{SAML_TEMPLATE}"' in crm and 'identifier_uris = ["https://crm.example.test"]' in crm
    assert 'preferred_single_sign_on_mode = "saml"' in _block(main, 'resource "azuread_service_principal" '
                                                                   '"sso_tenant_crm"')
    assert 'resource "azuread_service_principal_token_signing_certificate" "sso_tenant_crm"' in main
    assert "azuread_application_password" not in main
    tenant, *rest = (n for n in external_id_notes(m) if n.subject.endswith("credentials"))
    assert "portal: create its client secret" in tenant.how[0] and not rest
    assert not any(n.subject == "external tenant sso-tenant" for n in external_id_notes(m))   # nothing to create


def test_the_tenant_renders_through_azapi_where_the_add_on_is_allowed_and_is_adopted_once_recorded():
    m, files = _render((entry(ALPHA, "sso-tenant", "ciamManagedIdentity", ciamDataGeography="europe",
                              ciamFqdn="ssoexample.ciamlogin.com", **TENANT),), ADD_ON)
    main = files["terraform/main.tf"]
    tenant = _block(main, 'resource "azapi_resource" "sso_tenant"')
    assert f'type      = "{TENANT_TYPE}"' in tenant and 'name      = "ssoexample"' in tenant
    assert 'location  = "Europe"' in tenant and "displayName = var.sso_tenant_display_name" in tenant
    assert 'parent_id = data.azurerm_resource_group.main.id' in tenant and "lifecycle" not in tenant
    assert 'variable "sso_tenant_country_code"' in main and "import {" not in main
    assert '"Azure/azapi"' in files["terraform/providers.tf"]
    note, = (n for n in external_id_notes(m) if n.subject == "external tenant sso-tenant")
    assert "preview API" in note.text and "Tenant Creator" in note.how[0]
    m, files = _render((entry(ALPHA, "sso-tenant", "ciamManagedIdentity", ciamProviderRef=TENANT_ID, **TENANT),),
                       ADD_ON)
    main = files["terraform/main.tf"]
    assert "UNBOUND: the binding records no data geography (ciamDataGeography)" in main
    assert 'name      = "ssotenant"' in main                    # its name's letters and digits
    assert ("/providers/Microsoft.AzureActiveDirectory/ciamDirectories/ssotenant" in
            _block(main, "import {"))


def test_api_scopes_get_an_api_application_and_hostless_redirect_uris_a_comment():
    mobile = entry(INTEGRATIONS, "mobile", "ciamIntegration", ciamProtocolType="oidc-client", ciamClientId="mobile",
                   ciamTokenAuthMethod="none", ciamGrantType=("authorization_code", "refresh_token"),
                   ciamScope=("openid", "orders.read"),
                   ciamRedirectUri=("com.example.mobile:/cb", "https://mobile.example.test/cb"))
    _, m, _ = model(alpha=(entry(ALPHA, "sso-tenant", "ciamManagedIdentity", ciamProviderRef=TENANT_ID, **TENANT),),
                    tree=(*TREE, mobile))
    main = written(render_files(m, None))["terraform/main.tf"]
    api = _block(main, 'resource "azuread_application" "sso_tenant_api"')
    service = realized_service(m.d, external_id_bindings(m)[0])
    assert custom_scopes(m, external_id_bindings(m)[0]) == ("orders.read",)
    assert f'id                         = "{scope_id(service, "orders.read")}"' in api
    assert scope_id(service, "orders.read") == scope_id(service, "orders.read") != scope_id(service, "x")
    client = _block(main, 'resource "azuread_application" "sso_tenant_mobile"')
    assert "public_client {" in client and "web {" not in client
    assert "# redirect URI com.example.mobile:/cb has no host, which azuread refuses" in client
    assert GRAPH_SCOPES["offline_access"] in client and "azuread_application.sso_tenant_api.client_id" in client
    assert hostless("com.example.mobile:/cb") and not hostless("https://mobile.example.test/cb")


def test_external_id_is_in_the_fedramp_boundary_by_its_name():
    _, m, _ = model(alpha=(entry(ALPHA, "sso-tenant", "ciamManagedIdentity", **TENANT),), tree=TREE)
    assert ("Microsoft Entra External ID", "sso-tenant") in azure_services(m)


def test_an_azure_government_target_is_blocked_and_a_public_one_needs_the_add_on():
    check = managed_identity_check((ADAPTER,))
    d, alpha, beta = model(beta=(entry(BETA, "sso-tenant", "ciamManagedIdentity", **TENANT),), tree=TREE,
                           changes=GOVERNMENT)
    blockers = [b[1] for b in check(PlanContext(d, alpha, beta, None, None, {}, {}, ())).blockers]
    assert any("`sso-tenant` in beta/prod (usgovernment) is Microsoft Entra External ID, which doesn't exist there "
               "(external tenants support public clouds only" in t for t in blockers)
    d, alpha, beta = model(beta=(entry(BETA, "sso-tenant", "ciamManagedIdentity", **TENANT),), tree=TREE)
    found = check(PlanContext(d, alpha, beta, None, None, {}, {}, ()))
    assert not any("doesn't exist there" in b[1] for b in found.blockers)
    assert any("on a condition: the External ID M2M Premium add-on" in a[1] for a in found.actions)
    # the issuer is the tenant's: no documentation establishes a custom one, so it waits on a question
    assert any("issue tokens under a custom issuer, and no vendor documentation establishes that it can" in b[1]
               for b in found.blockers)


def test_a_bicep_render_keeps_the_app_registrations_in_its_terraform_root():
    _, m, _ = model(alpha=(entry(ALPHA, "sso-tenant", "ciamManagedIdentity", ciamProviderRef=TENANT_ID, **TENANT),),
                    tree=TREE)
    placements = json.loads(render(m, None, ("bicep",))["bicep/placements.json"])
    assert placements["azuread_application.sso_tenant_portal"] == {"in": "terraform/main.tf", "why": "no ARM type"}
    assert placements["azuread_service_principal_token_signing_certificate.sso_tenant_crm"]["why"] == "no ARM type"
