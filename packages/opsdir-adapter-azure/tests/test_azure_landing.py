"""The Azure landing zone rendered for whoever keeps it: a deployer's managed identity with a federated credential for
its pipeline's tokens and its role assignments, an operator group's role assignments (eligible through PIM when the
principal's condition says jit), the owner in the header; nothing when the environment needs nothing from one."""
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir_adapter_azure.landing import render_landing
from support import REGISTRY, build_directory

ENV = "env=prod,cloud=az,ou=environments,dc=ciam-ops"
GITHUB = "https://token.actions.githubusercontent.com"


def _entry(dn, oc, **attrs):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: {oc}\n" + "".join(
        f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,)))


def _record(operator_conditions=()):
    return build_directory(REGISTRY, tuple(parse(_records_text(operator_conditions))))


def _records_text(operator_conditions=()):
    conditions = {"ciamCondition": tuple(operator_conditions)} if operator_conditions else {}
    return "\n".join((
        "dn: dc=ciam-ops\nobjectClass: top\nobjectClass: domain\ndc: ciam-ops\n",
        "dn: ou=environments,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: environments\n",
        _entry("cloud=az,ou=environments,dc=ciam-ops", "ciamCloud", cloud="az", ciamCloudProvider="azure",
               ciamRegion="eastus2"),
        _entry(ENV, "ciamEnvironment", env="prod"),
        _entry(f"ou=bindings,{ENV}", "organizationalUnit", ou="bindings"),
        _entry(f"cn=vnet,ou=bindings,{ENV}", "ciamNetwork", cn="vnet", ciamBindingRole="network",
               ciamCidr="10.60.0.0/16", ciamProviderRef="vnet-ciam-prod", ciamResourceGroup="rg-ciam-prod"),
        _entry(f"cn=secret,ou=bindings,{ENV}", "ciamSecretRef", cn="secret", ciamBindingRole="pf-admin-password",
               ciamRefUri="azkv://kv-ciam-prod/pf-admin-password"),
        "dn: ou=permission-sets,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: permission-sets\n",
        _entry("cn=release,ou=permission-sets,dc=ciam-ops", "ciamPermissionSet", cn="release",
               ciamPermits="read-secret pf-admin-password"),
        "dn: ou=principals,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: principals\n",
        _entry("cn=ci-deploy,ou=principals,dc=ciam-ops", "ciamPrincipal", cn="ci-deploy", ciamPrincipalKind="deployer",
               ciamIdentityRole="identity-ci", ciamHoldsSet="cn=release,ou=permission-sets,dc=ciam-ops"),
        _entry("cn=ops-admins,ou=principals,dc=ciam-ops", "ciamPrincipal", cn="ops-admins",
               ciamPrincipalKind="operator", ciamIdentityRole="admin-group",
               ciamHoldsSet="cn=release,ou=permission-sets,dc=ciam-ops", **conditions),
        _entry(f"cn=identity-ci,ou=bindings,{ENV}", "ciamIdentityBinding", cn="identity-ci",
               ciamBindingRole="identity-ci", ciamProviderRef="id-ciam-prod-deploy", ciamIdentityKind="federated",
               ciamTrustedBy=f"{GITHUB} repo:example-aero/ciam-ops:environment:prod"),
        _entry(f"cn=admin-group,ou=bindings,{ENV}", "ciamIdentityBinding", cn="admin-group",
               ciamBindingRole="admin-group", ciamProviderRef="5b2c0000-0000-4000-8000-0000000000aa",
               ciamIdentityKind="group")))


def test_a_deployers_federated_identity_and_an_operator_groups_assignments():
    out = render_landing(env_model(_record(), "az/prod"))["terraform/landing-zone/main.tf"]
    assert 'resource "azurerm_federated_identity_credential" "identity_ci"' in out
    assert f'issuer              = "{GITHUB}"' in out and 'audience            = ["api://AzureADTokenExchange"]' in out
    assert 'subject             = "repo:example-aero/ciam-ops:environment:prod"' in out
    assert 'principal_id         = azurerm_user_assigned_identity.identity_ci.principal_id' in out
    assert 'principal_id         = "5b2c0000-0000-4000-8000-0000000000aa"' in out
    assert 'scope                = "${data.azurerm_key_vault.kv_ciam_prod.id}/secrets/pf-admin-password"' in out
    assert 'data "azurerm_key_vault" "kv_ciam_prod"' in out and "azurerm_pim_eligible_role_assignment" not in out


def test_a_jit_operator_is_eligible_through_pim():
    out = render_landing(env_model(_record(("jit",)), "az/prod"))["terraform/landing-zone/main.tf"]
    assert 'resource "azurerm_pim_eligible_role_assignment" "admin_group_read_secret_pf_admin_password"' in out
    assert 'name  = "Key Vault Secrets User"' in out and "duration_days = 365" in out
    assert 'data "azurerm_subscription" "current"' in out


def test_guardrails_as_built_in_policy_assignments():
    guardrail = ("dn: cn=baseline,ou=bindings," + ENV + "\nobjectClass: top\nobjectClass: ciamGuardrail\ncn: baseline\n"
                 "ciamBindingRole: guardrails\nciamGuardrailKind: policy-assignment\nciamDenies: region-escape\n"
                 "ciamDenies: audit-log-disable\nciamDenies: root-use\n")
    d = build_directory(REGISTRY, tuple(parse(_records_text() + "\n" + guardrail)))
    out = render_landing(env_model(d, "az/prod"))["terraform/landing-zone/main.tf"]
    assert ('policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/'
            'e56962a6-4747-49cd-b67b-bf8b01975c4c"') in out and '"eastus2"' in out
    assert "blocks deleting diagnostic settings, not changing them" in out
    assert "# NOTE: guardrail baseline: root-use: Azure has no root user" in out
    assert 'data "azurerm_subscription" "current"' in out
