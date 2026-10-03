"""Azure access control read from Terraform state into the record's identities, guardrails and access paths: a managed
identity's federated trust and role assignments (conditions, custom roles with NotActions); groups and PIM eligibility;
Key Vault access policies; policy assignments by what they prevent; and what the record then says of a permission."""
import json
from types import SimpleNamespace

from opsdir.core.directory import make_directory, one
from opsdir.domains.access.grants import ALLOWED, UNKNOWN, effective
from opsdir_adapter_azure.access import ACCESS
from opsdir_adapter_azure.iam import iam_resources
from opsdir_adapter_azure.inventory import read_terraform_state

SUB = "/subscriptions/0000-1111"
RG = f"{SUB}/resourceGroups/rg-ciam-prod"
VAULT = f"{RG}/providers/Microsoft.KeyVault/vaults/ciam-prod-kv"
IDENTITY = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-ciam-prod-pf"
PID, GROUP, DEPLOYER = "1111-pf", "2222-admins", "3333-ci"
DEFS = "/providers/Microsoft.Authorization/roleDefinitions"
ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"


def _pairs(*extra):
    return [
        ("azurerm_user_assigned_identity", {"id": IDENTITY, "name": "id-ciam-prod-pf", "principal_id": PID,
                                            "tags": {"Role": "identity-pf"}}),
        ("azurerm_federated_identity_credential", {"parent_id": IDENTITY.replace("resourceGroups", "resourcegroups"),
                                                   "issuer": "https://token.actions.githubusercontent.com",
                                                   "subject": "repo:example/ciam:environment:prod"}),
        ("azurerm_role_assignment", {"scope": VAULT, "role_definition_name": "Key Vault Secrets User",
                                     "principal_id": PID, "principal_type": "ServicePrincipal"}),
        ("azurerm_role_assignment", {"scope": f"{RG}/providers/Microsoft.Storage/storageAccounts/ciambackups",
                                     "role_definition_name": "Storage Blob Data Contributor", "principal_id": PID,
                                     "condition": "@Resource[Microsoft.Storage/storageAccounts/blobServices/"
                                                  "containers:name] StringEquals 'ds'"}),
        ("azurerm_role_definition", {"role_definition_resource_id": f"{SUB}{DEFS}/c0ffee", "name": "ciam-operator",
                                     "permissions": [{"actions": ["Microsoft.Compute/*"],
                                                      "not_actions": ["Microsoft.Compute/*/delete"],
                                                      "data_actions": [], "not_data_actions": []}]}),
        ("azurerm_role_assignment", {"scope": RG, "role_definition_id": f"{SUB}{DEFS}/c0ffee",
                                     "role_definition_name": "ciam-operator", "principal_id": GROUP,
                                     "principal_type": "Group"}),
        ("azurerm_role_definition", {"id": f"{SUB}{DEFS}/b86a8fe4", "role_definition_id": "b86a8fe4",
                                     "name": "Key Vault Secrets Officer", "type": "BuiltInRole",
                                     "permissions": [{"actions": [],
                                                      "data_actions": ["Microsoft.KeyVault/vaults/secrets/*"]}]}),
        ("azurerm_pim_eligible_role_assignment", {"scope": VAULT, "role_definition_id": f"{SUB}{DEFS}/b86a8fe4",
                                                  "principal_id": GROUP}),
        ("azurerm_key_vault_access_policy", {"key_vault_id": VAULT, "object_id": DEPLOYER,
                                             "secret_permissions": ["Get", "List"], "key_permissions": ["UnwrapKey"]}),
        ("azurerm_subscription_policy_assignment", {
            "id": f"{SUB}/providers/Microsoft.Authorization/policyAssignments/ciam-prod-region-escape",
            "subscription_id": SUB, "name": "ciam-prod-region-escape",
            "policy_definition_id": "/providers/Microsoft.Authorization/policyDefinitions/"
                                    "e56962a6-4747-49cd-b67b-bf8b01975c4c"}),
        ("azurerm_subscription_policy_assignment", {
            "subscription_id": SUB, "name": "ciam-prod-public-storage",
            "policy_definition_id": "/providers/Microsoft.Authorization/policyDefinitions/"
                                    "4fa4b6c0-31ca-4c0d-b10d-24b96f62a751"}),
        ("azurerm_bastion_host", {"id": f"{RG}/providers/Microsoft.Network/bastionHosts/bas-ciam", "name": "bas-ciam"}),
        *extra]


def _one(resources, kind, ref):
    return next(r for r in resources if r.kind == kind and r.ref == ref)


def test_identities_and_what_their_assignments_grant():
    resources, notices = iam_resources(_pairs())
    pf = _one(resources, "identity", IDENTITY)
    assert pf.role == "identity-pf" and pf.attrs["ciamIdentityKind"] == ("federated",)
    assert pf.attrs["ciamTrustedBy"] == (
        "https://token.actions.githubusercontent.com repo:example/ciam:environment:prod",)
    assert set(pf.attrs["ciamGrant"]) == {
        f"Key Vault Secrets User on {VAULT}",
        f"Storage Blob Data Contributor on {RG}/providers/Microsoft.Storage/storageAccounts/ciambackups (if "
        "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'ds')"}
    admins = _one(resources, "identity", GROUP)
    assert admins.attrs["ciamIdentityKind"] == ("group",) and admins.role is None     # a role map names it
    assert set(admins.attrs["ciamGrant"]) == {
        f"Microsoft.Compute/*!Microsoft.Compute/*/delete on {RG}",                   # the custom role, expanded
        f"Key Vault Secrets Officer on {VAULT} (eligible)"}                          # its name from the data source
    ci = _one(resources, "identity", DEPLOYER)
    assert "ciamIdentityKind" not in ci.attrs                                         # not known: the record's kept
    assert set(ci.attrs["ciamGrant"]) == {
        f"Microsoft.KeyVault/vaults/secrets/getSecret/action on {VAULT} (resource policy)",
        f"Microsoft.KeyVault/vaults/secrets/readMetadata/action on {VAULT} (resource policy)",
        f"Microsoft.KeyVault/vaults/keys/unwrap/action on {VAULT} (resource policy)"}
    fence = _one(resources, "guardrail", f"{SUB}/providers/Microsoft.Authorization/policyAssignments")
    assert fence.attrs["ciamDenies"] == ("public-storage", "region-escape")
    assert fence.role == "guardrail-policy-0000-1111"
    assert _one(resources, "access", f"{RG}/providers/Microsoft.Network/bastionHosts/bas-ciam").role == "access-bastion"
    assert not notices


def test_a_pim_role_known_only_by_its_id_is_named():
    pairs = [p for p in _pairs() if not (p[0] == "azurerm_role_definition" and p[1].get("type") == "BuiltInRole")]
    resources, notices = iam_resources(pairs)
    assert f"{SUB}{DEFS}/b86a8fe4 on {VAULT} (eligible)" in _one(resources, "identity", GROUP).attrs["ciamGrant"]
    assert notices == (f"role definition {SUB}{DEFS}/b86a8fe4: its name isn't in the state (add a data "
                       "azurerm_role_definition); recorded by its ID",)


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _imported():
    d = make_directory((), {}, (
        _row("cloud=main,ou=environments,dc=ciam-ops", ("ciamCloud",), cloud="main", ciamCloudProvider="azure",
             ciamRegion="eastus2"),
        _row(ENV, ("ciamEnvironment",), env="prod"),
        _row(B, ("organizationalUnit",), ou="bindings"),
        _row(f"cn=pf-admin,{B}", ("ciamSecretRef",), cn="pf-admin", ciamBindingRole="pf-admin-password",
             ciamRefUri="azkv://ciam-prod-kv/pf-admin-password"),
        _row(f"cn=admins,{B}", ("ciamIdentityBinding",), cn="admins", ciamBindingRole="admin-group",
             ciamProviderRef=GROUP, ciamIdentityKind="group"),
        _row(f"cn=ci,{B}", ("ciamIdentityBinding",), cn="ci", ciamBindingRole="identity-ci",
             ciamProviderRef=DEPLOYER, ciamIdentityKind="federated")))
    state = json.dumps({"version": 4, "resources": [
        {"mode": "managed", "type": t, "name": "x", "instances": [{"attributes": a}]} for t, a in _pairs()]})
    imported = read_terraform_state({"main/prod/terraform.tfstate": state}, d, ())
    entries = {**{e.norm: e for e in d.entries.values() if e.dn.lower().endswith(B.lower()) and e.dn != B},
               **{e.norm: e for _, es in imported.groups for e in es}}               # the record, then the import
    env = SimpleNamespace(bindings=tuple(entries.values()))
    return env, {one(e, "ciamBindingRole"): e for e in env.bindings}


def test_the_record_learns_what_each_principal_may_do():
    env, by_role = _imported()
    assert one(by_role["identity-ci"], "ciamIdentityKind") == "federated"       # kept: the state doesn't say
    assert effective(ACCESS, env, "read-secret pf-admin-password", by_role["identity-pf"]).state == ALLOWED
    assert effective(ACCESS, env, "read-secret pf-admin-password", by_role["identity-ci"]).state == ALLOWED
    verdict = effective(ACCESS, env, "write-secret pf-admin-password", by_role["admin-group"])
    assert verdict.state == UNKNOWN and "eligible, not active" in verdict.why
