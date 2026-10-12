"""What gcloud reports about Cloud Billing budgets, normalized to the hashicorp/google attribute names
opsdir_adapter_gcp.budgets reads. Pure.

  gcloud billing budgets list --billing-account=A   billingAccounts/<A>/budgets/<id> -> google_billing_budget: display
                                                     name, amount, the budget filter's period and projects, threshold
                                                     rules, where its updates go (notificationsRule: monitoring
                                                     channels, a Pub/Sub topic)
"""
import re

BUDGET = re.compile(r"^billingAccounts/[^/]+/budgets/[^/]+$")


def is_budget(item):
    """Whether an item is a billing budget (by its resource name)."""
    return bool(BUDGET.match(item.get("name") or ""))


def _amount(d):
    given = (d.get("amount") or {}).get("specifiedAmount")
    return [{"specified_amount": [{"currency_code": given.get("currencyCode"), "units": given.get("units"),
                                   "nanos": given.get("nanos")}]}] if isinstance(given, dict) else []


def budget_pairs(of):
    """The (google type, attributes) pairs of the billing budgets listed."""
    def budget(d):
        found, rule = d.get("budgetFilter") or {}, d.get("notificationsRule") or {}
        return ("google_billing_budget", {
            "name": d.get("name"), "display_name": d.get("displayName"), "amount": _amount(d),
            "budget_filter": [{"calendar_period": found.get("calendarPeriod"),
                               "projects": found.get("projects") or []}],
            "threshold_rules": [{"threshold_percent": r.get("thresholdPercent"), "spend_basis": r.get("spendBasis")}
                                for r in d.get("thresholdRules") or () if isinstance(r, dict)],
            "all_updates_rule": [{"monitoring_notification_channels": rule.get("monitoringNotificationChannels") or [],
                                  "pubsub_topic": rule.get("pubsubTopic")}] if rule else []})
    return [budget(d) for d, _ in of("budget")]
