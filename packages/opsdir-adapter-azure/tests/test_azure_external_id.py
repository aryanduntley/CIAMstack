"""Microsoft Entra External ID as a managed identity service: the descriptor the planner reads (Microsoft's documented
capabilities; external tenants in public clouds only), nothing rendered (a target is an action naming what to create
by hand, a neighbour a note), External ID in the FedRAMP boundary by its name."""
from opsdir.connectors.managed_identity import managed_identity_check
from opsdir.core.contract import PlanContext
from opsdir.core.interchange.ldif import parse
from opsdir_format_terraform.hcl import written
from opsdir_adapter_azure.adapter import ADAPTER
from opsdir_adapter_azure.boundary import azure_services
from opsdir_adapter_azure.external_id import EXTERNAL_ID, SERVICE, external_id_notes, partition
from opsdir_adapter_azure.terraform import render_files
from network_fixtures import ALPHA, BETA, entry, model

INTEGRATIONS = "ou=integrations,dc=ciam-ops"
TREE = ("dn: ou=integrations,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: integrations\n",
        entry(INTEGRATIONS, "portal", "ciamIntegration", ciamProtocolType="oidc-client", ciamClientId="portal",
              ciamGrantType=("authorization_code", "client_credentials"), ciamTokenAuthMethod="client_secret_post",
              ciamRedirectUri="https://portal.example.test/cb"),
        entry(INTEGRATIONS, "crm", "ciamIntegration", ciamProtocolType="saml2-sp",
              ciamEntityId="https://crm.example.test", ciamAcsUrl="https://crm.example.test/acs"))
TENANT = dict(ciamBindingRole="sso-tenant", ciamManagedService=SERVICE, ciamRealizes="sso")
GOVERNMENT = tuple(parse("dn: cloud=beta,ou=environments,dc=ciam-ops\nchangetype: modify\nreplace: ciamRegion\n"
                         "ciamRegion: usgovvirginia\n"))


def test_the_adapter_declares_external_id_for_public_clouds_only():
    assert ADAPTER.managed_identity == (EXTERNAL_ID,) and ADAPTER.vocabulary["ciamManagedService"] == (SERVICE,)
    assert set(EXTERNAL_ID.available) == {"public"} and set(EXTERNAL_ID.absent) == {"usgovernment"}
    assert {"issue:oidc", "issue:saml"} <= set(EXTERNAL_ID.supported) and not EXTERNAL_ID.unsupported
    assert "M2M Premium add-on" in EXTERNAL_ID.conditions["grant:client_credentials"]
    _, _, beta = model(tree=TREE, changes=GOVERNMENT)
    assert partition(beta) == "usgovernment"


def test_nothing_is_rendered_a_target_is_what_to_create_by_hand_and_a_neighbour_a_note():
    _, m, _ = model(alpha=(entry(ALPHA, "sso-tenant", "ciamManagedIdentity", **TENANT),
                           entry(ALPHA, "partner-tenant", "ciamManagedIdentity", ciamBindingRole="partner-tenant",
                                 ciamManagedService=SERVICE, ciamPartnerOf=f"cn=portal,{INTEGRATIONS}")), tree=TREE)
    neighbour, target = external_id_notes(m)          # bindings in DN order
    assert (target.severity, target.subject) == ("action", "external tenant sso-tenant")
    assert "the external tenant running `sso` and its app registrations are created by hand" in target.text
    assert "portal (oidc-client: https://portal.example.test/cb)" in target.text
    assert "Register crm (saml2-sp: https://crm.example.test/acs) in it" in target.how
    assert (neighbour.severity, neighbour.subject) == ("note", "external tenant partner-tenant")
    main = written(render_files(m, None))["terraform/main.tf"]
    assert "NOTE: external tenant sso-tenant: Entra External ID isn't rendered" in main
    assert "azuread_application" not in main


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
