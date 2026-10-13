"""Budgets on Azure (core estate: ciamBudget) as Cost Management consumption budgets. Pure.

Rendered in the environment's root for each budget the platform team keeps (one someone else keeps is named in a
comment): azurerm_consumption_budget_resource_group on the environment's resource group (data.azurerm_resource_group
.main), its amount per time grain (Monthly, Quarterly, Annually) from the input budget_start_date (the first of a month:
Azure starts a budget there, and changing it replaces the budget), and a notification per threshold
(ciamActualThreshold Actual, ciamForecastThreshold Forecasted, GreaterThan, percent) to the action group of the channel
its ciamAlertRole names (contact_groups: its ciamProviderRef). Azure needs a notification with a contact on every
budget: without thresholds the budget alerts at 100% spent, without an action group its subscription's Owners (both
said in a comment), and it takes at most five (the rest named). Azure budgets count in the billing account's currency:
a budget recording another currency says so. In Azure Government, Cost Management budgets serve Enterprise Agreement and
pay-as-you-go subscriptions, not CSP ones (Microsoft's Cost Management data page): a comment.

Read back from Terraform state: azurerm_consumption_budget_resource_group and _subscription -> budgets (kind budget):
amount, period from the time grain, GreaterThan thresholds, the first action group its notifications go to as the
channel its alerts go to."""
from decimal import Decimal, InvalidOperation

from opsdir.core.directory import get, one, rdn_value
from opsdir.core.inventory import of_types, resource
from opsdir.domains.estate.budgets import budget_channel, budgets, currency, thresholds
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name

BUDGET = "azurerm_consumption_budget_resource_group"
SUBSCRIPTION_BUDGET = "azurerm_consumption_budget_subscription"
START = "budget_start_date"
GRAINS = {"monthly": "Monthly", "quarterly": "Quarterly", "annually": "Annually"}
PERIOD_OF = {"Monthly": "monthly", "BillingMonth": "monthly", "Quarterly": "quarterly", "BillingQuarter": "quarterly",
             "Annually": "annually", "BillingAnnual": "annually"}
NOTIFIED = (("ciamActualThreshold", "Actual"), ("ciamForecastThreshold", "Forecasted"))
MAX_NOTIFICATIONS = 5
GOV_NOTE = (comment("Azure Government: Cost Management budgets serve Enterprise Agreement and pay-as-you-go "
                    "subscriptions, not CSP ones"))


def _action_group(m, b):
    channel = budget_channel(m, b)
    arn = one(channel, "ciamProviderRef") if channel is not None else None
    return arn if arn and "/actiongroups/" in arn.lower() else None


def _notifications(m, b):
    """(the notification blocks, comments)."""
    wanted = [(p, kind) for attr, kind in NOTIFIED for p in thresholds(b, attr)] or [(100, "Actual")]
    group = _action_group(m, b)
    contact = ("contact_groups", [group]) if group else ("contact_roles", ["Owner"])
    notes = (*(() if thresholds(b, "ciamActualThreshold") or thresholds(b, "ciamForecastThreshold") else
               (comment(f"budget {rdn_value(b)}: no thresholds recorded: Azure needs a notification, so it alerts at "
                        "100% spent"),)),
             *(() if group else (comment(f"budget {rdn_value(b)}: {one(b, 'ciamAlertRole') or 'no alert role'} names "
                                         "no action group: its alerts go to the subscription's Owners"),)),
             *((comment(f"budget {rdn_value(b)}: Azure takes five notifications: "
                        f"{', '.join(f'{p}% {k}' for p, k in wanted[MAX_NOTIFICATIONS:])} left out"),)
               if len(wanted) > MAX_NOTIFICATIONS else ()))
    return tuple(("notification", Block((("operator", "GreaterThan"), ("threshold", p), ("threshold_type", kind),
                                         contact))) for p, kind in wanted[:MAX_NOTIFICATIONS]), notes


def _budget(m, b):
    cn = rdn_value(b)
    notifications, notes = _notifications(m, b)
    gov = one(m.cloud, "ciamCloudEnvironment") == "usgovernment"
    return (*notes, *((GOV_NOTE,) if gov else ()),
            *((comment(f"budget {cn}: Azure counts it in the billing account's currency, not {currency(b)}"),)
              if one(b, "ciamCurrency") and currency(b) != "USD" else ()),
            tf_block("resource", [BUDGET, tf_name(cn)], [
                ("name", f"{rdn_value(m.cloud)}-{rdn_value(m.env)}-{cn}"),
                ("resource_group_id", ref("data.azurerm_resource_group.main.id")),
                ("amount", float(one(b, "ciamBudgetAmount")) if "." in one(b, "ciamBudgetAmount")
                 else int(one(b, "ciamBudgetAmount"))),
                ("time_grain", GRAINS[one(b, "ciamBudgetPeriod") or "monthly"]),
                ("time_period", Block((("start_date", ref(f"var.{START}")),))), *notifications]))


def render_budgets(m):
    """HCL (and comments) for environment m's budgets (whoever keeps each), each stamped with its entry (the render
    places it by its keeper)."""
    return tuple(x for b in budgets(m) for x in from_entry(b.dn, _budget(m, b)))


def budget_inputs(m):
    """The input the environment's budgets start from, when it has budgets (in each root rendering one)."""
    return (tf_block("variable", [START], [
        ("description", "The first day of the month the budgets start from (YYYY-MM-01T00:00:00Z; changing it "
                        "replaces them)"), ("type", ref("string"))]),) if budgets(m) else ()


def _amount(v):
    try:
        return format(Decimal(str(v)).normalize(), "f")
    except InvalidOperation:
        return None


def _percents(a, kind):
    return tuple(sorted({int(n["threshold"]) for n in a.get("notification") or ()
                         if (n.get("threshold_type") or "Actual") == kind and n.get("operator") == "GreaterThan"
                         and n.get("threshold") is not None and n.get("enabled", True) is not False}))


def _group(a):
    return next((g for n in a.get("notification") or () for g in n.get("contact_groups") or ()), None)


def budget_resources(pairs):
    """Budgets of (Terraform resource type, attributes) pairs: resource group and subscription consumption budgets."""
    return tuple(resource("budget", a.get("id"), {
        "ciamBudgetAmount": _amount(a.get("amount")),
        "ciamBudgetPeriod": PERIOD_OF.get(a.get("time_grain") or "Monthly"),
        "ciamActualThreshold": _percents(a, "Actual"), "ciamForecastThreshold": _percents(a, "Forecasted")},
        links={"ciamAlertRole": _group(a)}, name=a.get("name"))
        for a in of_types(pairs, BUDGET, SUBSCRIPTION_BUDGET) if a.get("id"))
