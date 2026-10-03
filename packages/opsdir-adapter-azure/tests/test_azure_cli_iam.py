"""Azure access control read from the Azure CLI's and `az rest`'s outputs, as from Terraform state: identities and
federated credentials, role assignments (conditions; custom roles expanded, built-in definitions naming roles), PIM
eligibility with the role's name, deny assignments as denials, vault access policies, policy assignments, bastions."""
import json

from opsdir_adapter_azure.cli import cli_resources

SUB = "/subscriptions/0000-1111"
RG = f"{SUB}/resourceGroups/rg-ciam-prod"
VAULT = f"{RG}/providers/Microsoft.KeyVault/vaults/ciam-prod-kv"
IDENTITY = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-ciam-prod-pf"
PID, GROUP = "1111-pf", "2222-admins"
AUTH = "/providers/Microsoft.Authorization"


def _outputs():
    return {
        "identities.json": json.dumps([{"id": IDENTITY, "name": "id-ciam-prod-pf", "principalId": PID,
                                        "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                                        "tags": {"Role": "identity-pf"}}]),
        "federated.json": json.dumps([{"id": f"{IDENTITY}/federatedIdentityCredentials/gh", "issuer":
                                       "https://token.actions.githubusercontent.com", "subject": "repo:x/y:env:prod",
                                       "type": "Microsoft.ManagedIdentity/userAssignedIdentities/"
                                               "federatedIdentityCredentials"}]),
        "assignments.json": json.dumps([
            {"type": "Microsoft.Authorization/roleAssignments", "scope": VAULT, "principalId": PID,
             "principalType": "ServicePrincipal", "roleDefinitionName": "Key Vault Secrets User",
             "roleDefinitionId": f"{SUB}{AUTH}/roleDefinitions/4633458b"},
            {"type": "Microsoft.Authorization/roleAssignments", "scope": RG, "principalId": GROUP,
             "principalType": "Group", "roleDefinitionName": "ciam-operator",
             "roleDefinitionId": f"{SUB}{AUTH}/roleDefinitions/c0ffee",
             "condition": "@Resource[Microsoft.Compute/virtualMachines:tags.env] StringEquals 'prod'"}]),
        "definitions.json": json.dumps([
            {"type": "Microsoft.Authorization/roleDefinitions", "id": f"{SUB}{AUTH}/roleDefinitions/c0ffee",
             "name": "c0ffee", "roleName": "ciam-operator", "roleType": "CustomRole",
             "permissions": [{"actions": ["Microsoft.Compute/virtualMachines/*"],
                              "notActions": ["Microsoft.Compute/virtualMachines/delete"]}]},
            {"type": "Microsoft.Authorization/roleDefinitions", "id": f"{AUTH}/roleDefinitions/b86a8fe4",
             "name": "b86a8fe4", "roleName": "Key Vault Secrets Officer", "roleType": "BuiltInRole",
             "permissions": [{"dataActions": ["Microsoft.KeyVault/vaults/secrets/*"]}]}]),
        "pim.json": json.dumps({"value": [{
            "type": "Microsoft.Authorization/roleEligibilityScheduleInstances", "properties": {
                "scope": VAULT, "principalId": GROUP, "principalType": "Group",
                "roleDefinitionId": f"{SUB}{AUTH}/roleDefinitions/b86a8fe4",
                "expandedProperties": {"roleDefinition": {"displayName": "Key Vault Secrets Officer"}}}}]}),
        "deny.json": json.dumps({"value": [{
            "id": f"{RG}{AUTH}/denyAssignments/d-1", "type": "Microsoft.Authorization/denyAssignments",
            "properties": {"denyAssignmentName": "stack-protect", "scope": RG,
                           "permissions": [{"actions": ["*/delete"], "notActions": [],
                                            "dataActions": [], "notDataActions": []}],
                           "principals": [{"id": "00000000-0000-0000-0000-000000000000",
                                           "type": "SystemDefined"}],
                           "excludePrincipals": [{"id": GROUP, "type": "Group"}]}}]}),
        "vault.json": json.dumps({"id": VAULT, "name": "ciam-prod-kv", "type": "Microsoft.KeyVault/vaults",
                                  "properties": {"accessPolicies": [{"objectId": "3333-ci", "permissions": {
                                      "secrets": ["get"], "keys": [], "certificates": []}}]}}),
        "policy.json": json.dumps([{"type": "Microsoft.Authorization/policyAssignments", "scope": SUB,
                                    "id": f"{SUB}{AUTH}/policyAssignments/ciam-prod-key-deletion",
                                    "name": "ciam-prod-key-deletion",
                                    "policyDefinitionId": f"{AUTH}/policyDefinitions/"
                                                          "0b60c0b2-2dc2-4e1c-b5c9-abbed971de53"}]),
        "bastion.json": json.dumps([{"type": "Microsoft.Network/bastionHosts", "name": "bas-ciam",
                                     "id": f"{RG}/providers/Microsoft.Network/bastionHosts/bas-ciam"}])}


def _one(resources, kind, ref):
    return next(r for r in resources if r.kind == kind and r.ref == ref)


def test_access_control_from_the_cli_reads_as_from_state():
    resources, notices = cli_resources(_outputs())
    pf = _one(resources, "identity", IDENTITY)
    assert pf.attrs["ciamIdentityKind"] == ("federated",) and pf.role == "identity-pf"
    assert pf.attrs["ciamTrustedBy"] == ("https://token.actions.githubusercontent.com repo:x/y:env:prod",)
    assert pf.attrs["ciamGrant"] == (f"Key Vault Secrets User on {VAULT}",)
    assert pf.attrs["ciamDenial"] == (f"*/delete on {RG}",)                             # everyone's deny
    admins = _one(resources, "identity", GROUP)
    assert set(admins.attrs["ciamGrant"]) == {
        f"Microsoft.Compute/virtualMachines/*!Microsoft.Compute/virtualMachines/delete on {RG} (if "
        "@Resource[Microsoft.Compute/virtualMachines:tags.env] StringEquals 'prod')",
        f"Key Vault Secrets Officer on {VAULT} (eligible)"}                             # named by PIM itself
    assert "ciamDenial" not in admins.attrs                                             # excluded from the deny
    ci = _one(resources, "identity", "3333-ci")
    assert ci.attrs["ciamGrant"] == (f"Microsoft.KeyVault/vaults/secrets/getSecret/action on {VAULT} "
                                     "(resource policy)",)
    fence = _one(resources, "guardrail", f"{SUB}/providers/Microsoft.Authorization/policyAssignments")
    assert fence.attrs["ciamDenies"] == ("key-deletion",)
    assert _one(resources, "access", f"{RG}/providers/Microsoft.Network/bastionHosts/bas-ciam").role == "access-bastion"
    assert not [n for n in notices if "aren't Azure CLI output" in n]
