"""Microsoft Entra ID Protection as the CLI reports it, normalized to the attribute names of the azuread / azurerm
resources (identity_protection.identity_read reads both alike). Pure.

  az rest --method GET --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies
                                        Conditional Access policies ({"value": [...]}; Azure Government L4:
                                        graph.microsoft.us, DoD: dod-graph.microsoft.us), recognized by their conditions
                                        and grant controls: risk levels, users and groups, grant, state
  az monitor diagnostic-settings list --resource /providers/Microsoft.AADIAM
                                        Microsoft Entra ID's diagnostic settings: the risk logs' export
Graph lists the tenant's policies: every risk-based one is read onto the environment's threat detection.
"""
from .audit import DIAGNOSTIC
from .identity_protection import CA_POLICY, RISK_EXPORT

CA_KIND = "graph-ca-policy"
AADIAM = "/providers/microsoft.aadiam/"


def is_policy(item):
    """Whether a CLI item is a Conditional Access policy as Graph returns it."""
    return isinstance(item, dict) and "conditions" in item and "grantControls" in item


def _policy(p):
    c, g = p.get("conditions") or {}, p.get("grantControls") or {}
    users, apps = c.get("users") or {}, c.get("applications") or {}
    strength = (g.get("authenticationStrength") or {}).get("id")
    return (CA_POLICY, {
        "id": p.get("id"), "display_name": p.get("displayName"), "state": p.get("state"),
        "conditions": [{"sign_in_risk_levels": c.get("signInRiskLevels") or [],
                        "user_risk_levels": c.get("userRiskLevels") or [],
                        "client_app_types": c.get("clientAppTypes") or [],
                        "applications": [{"included_applications": apps.get("includeApplications") or []}],
                        "users": [{"included_users": users.get("includeUsers") or [],
                                   "included_groups": users.get("includeGroups") or [],
                                   "excluded_users": users.get("excludeUsers") or [],
                                   "excluded_groups": users.get("excludeGroups") or []}]}],
        "grant_controls": [{"operator": g.get("operator"), "built_in_controls": g.get("builtInControls") or [],
                            "authentication_strength_policy_id":
                                f"/policies/authenticationStrengthPolicies/{strength}" if strength else None}]})


def _export(i):
    return (RISK_EXPORT, {"id": i.get("id"), "name": i.get("name"),
                          "log_analytics_workspace_id": i.get("workspaceId"),
                          "storage_account_id": i.get("storageAccountId"),
                          "enabled_log": [{"category": x.get("category")} for x in i.get("logs") or ()
                                          if x.get("enabled")]})


def identity_items(items):
    """(azuread/azurerm type, attributes) pairs of the Conditional Access policies and Entra diagnostic settings among
    (kind, item) pairs."""
    return [*(_policy(i) for k, i in items if k == CA_KIND),
            *(_export(i) for k, i in items if k == DIAGNOSTIC and (i.get("id") or "").lower().startswith(AADIAM))]
