"""What Azure reports about consumption budgets (az rest on Microsoft.Consumption/budgets at the subscription and the
resource group: `az consumption` is in preview; and an ARM template's, read the same way), normalized to the
hashicorp/azurerm attribute names opsdir_adapter_azure.budgets reads. Properties nested or flattened, fields in any
case. Pure.

  GET <scope>/providers/Microsoft.Consumption/budgets   {"value": [...]} -> azurerm_consumption_budget_resource_group
                                                         (an ID under a resource group) or _subscription: amount, time
                                                         grain, notifications (enabled, operator, threshold, type,
                                                         action groups; contact e-mails aren't read)
"""
from .arm_ids import arm_field, with_properties

BUDGETS = "microsoft.consumption/budgets"
READ = (BUDGETS,)


def _notification(n):
    return {"enabled": arm_field(n, "enabled"), "operator": arm_field(n, "operator"),
            "threshold": arm_field(n, "threshold"), "threshold_type": arm_field(n, "thresholdType"),
            "contact_groups": list(arm_field(n, "contactGroups") or ())}


def budget_items(items):
    """(azurerm type, attributes) pairs of the consumption budgets among (kind, item) pairs."""
    budgets = [with_properties(i) for k, i in items if k == BUDGETS]
    return [("azurerm_consumption_budget_resource_group" if "/resourcegroups/" in (b.get("id") or "").lower()
             else "azurerm_consumption_budget_subscription", {
                 "id": b.get("id"), "name": b.get("name"), "amount": arm_field(b, "amount"),
                 "time_grain": arm_field(b, "timeGrain"),
                 "notification": [_notification(n) for n in (arm_field(b, "notifications") or {}).values()
                                  if isinstance(n, dict)]})
            for b in budgets]
