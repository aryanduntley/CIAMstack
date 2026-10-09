"""What the Azure CLI (and the REST API through `az rest`) reports about access control, normalized to the attribute
names of the matching hashicorp/azurerm resources so the same mapping (opsdir_adapter_azure.iam) reads them as reads
Terraform state. Pure. Items are recognized by their ARM type (opsdir_adapter_azure.cli), properties flattened or not:

  az identity list                              Microsoft.ManagedIdentity/userAssignedIdentities
  az identity federated-credential list         …/userAssignedIdentities/federatedIdentityCredentials
  az role assignment list --all                 Microsoft.Authorization/roleAssignments (conditions; with
    --include-inherited --include-groups          --include-inherited, those at the subscription and above)
  az role definition list                       Microsoft.Authorization/roleDefinitions (custom roles expanded; the
                                                built-in ones name the roles PIM assignments use by ID)
  az rest …/roleEligibilityScheduleInstances    Microsoft.Authorization/roleEligibilityScheduleInstances (PIM
                                                eligible, not active; the role's name from expandedProperties)
  az rest …/denyAssignments                     Microsoft.Authorization/denyAssignments: denials on the principals they
                                                name (everyone, 00000000-…, less the excluded ones)
  az keyvault show                              Microsoft.KeyVault/vaults: the vault's access policies
  az policy assignment list                     Microsoft.Authorization/policyAssignments
  az network bastion list                       Microsoft.Network/bastionHosts
`az rest` prints {"value": [...]}: the items are read from it.
"""
import re

FEDERATED = "microsoft.managedidentity/userassignedidentities/federatedidentitycredentials"
_CREDENTIAL = re.compile(r"/federatedidentitycredentials/[^/]+$", re.IGNORECASE)


def _props(item):
    """An item's fields, its properties flattened into them (as the CLI prints most resources)."""
    return {**item, **(item.get("properties") or {})} if isinstance(item.get("properties"), dict) else item


def _of(items, kind):
    return [_props(i) for k, i in items if k == kind]


def _permissions(blocks):
    return [{"actions": b.get("actions") or [], "not_actions": b.get("notActions") or [],
             "data_actions": b.get("dataActions") or [], "not_data_actions": b.get("notDataActions") or []}
            for b in blocks or ()]


def _role_definitions(items):
    """Custom roles as managed definitions (their actions read), built-in ones as the data source naming them."""
    def one(d):
        custom = d.get("roleType") == "CustomRole"
        return ("azurerm_role_definition", {
            **({"role_definition_resource_id": d.get("id")} if custom else {"id": d.get("id")}),
            "role_definition_id": d.get("name"), "name": d.get("roleName"), "type": d.get("roleType"),
            "permissions": _permissions(d.get("permissions"))})
    return [one(d) for d in _of(items, "microsoft.authorization/roledefinitions")]


def _vault_policies(items):
    return [("azurerm_key_vault", {"id": v.get("id"), "name": v.get("name"), "access_policy": [
                {"object_id": p.get("objectId"), "secret_permissions": (p.get("permissions") or {}).get("secrets"),
                 "key_permissions": (p.get("permissions") or {}).get("keys"),
                 "certificate_permissions": (p.get("permissions") or {}).get("certificates")}
                for p in v.get("accessPolicies") or ()]})
            for v in _of(items, "microsoft.keyvault/vaults") if v.get("accessPolicies")]


def iam_items(items):
    """Pairs of the access-control items among an environment's recognized Azure CLI items ((kind, item), ...)."""
    def role(p):
        return ((p.get("expandedProperties") or {}).get("roleDefinition") or {}).get("displayName")
    return [
        *(("azurerm_user_assigned_identity", {"id": i.get("id"), "name": i.get("name"),
                                              "principal_id": i.get("principalId"), "client_id": i.get("clientId"),
                                              "tags": i.get("tags") or {}})
          for i in _of(items, "microsoft.managedidentity/userassignedidentities")),
        *(("azurerm_federated_identity_credential", {"parent_id": _CREDENTIAL.sub("", c.get("id") or ""),
                                                     "issuer": c.get("issuer"), "subject": c.get("subject")})
          for c in _of(items, FEDERATED)),
        *(("azurerm_role_assignment", {"scope": a.get("scope"), "role_definition_name": a.get("roleDefinitionName"),
                                       "role_definition_id": a.get("roleDefinitionId"),
                                       "principal_id": a.get("principalId"), "principal_type": a.get("principalType"),
                                       "condition": a.get("condition")})
          for a in _of(items, "microsoft.authorization/roleassignments")),
        *_role_definitions(items),
        *(("azurerm_pim_eligible_role_assignment", {"scope": p.get("scope"), "role_definition_name": role(p),
                                                    "role_definition_id": p.get("roleDefinitionId"),
                                                    "principal_id": p.get("principalId"),
                                                    "principal_type": p.get("principalType"),
                                                    "condition": p.get("condition")})
          for p in _of(items, "microsoft.authorization/roleeligibilityscheduleinstances")),
        *(("azure_deny_assignment", {"id": d.get("id"), "name": d.get("denyAssignmentName") or d.get("name"),
                                     "scope": d.get("scope"), "permissions": _permissions(d.get("permissions")),
                                     "principals": [p.get("id") for p in d.get("principals") or ()],
                                     "exclude_principals": [p.get("id") for p in d.get("excludePrincipals") or ()]})
          for d in _of(items, "microsoft.authorization/denyassignments")),
        *_vault_policies(items),
        *(("azurerm_policy_assignment", {"id": a.get("id"), "name": a.get("name"),
                                         "policy_definition_id": a.get("policyDefinitionId"), "scope": a.get("scope")})
          for a in _of(items, "microsoft.authorization/policyassignments")),
        *(("azurerm_bastion_host", {"id": b.get("id"), "name": b.get("name"), "tags": b.get("tags") or {}})
          for b in _of(items, "microsoft.network/bastionhosts"))]
