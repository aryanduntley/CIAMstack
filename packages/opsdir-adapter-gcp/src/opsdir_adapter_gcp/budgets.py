"""Budgets on Google Cloud (core estate: ciamBudget) as Cloud Billing budgets. Pure.

A budget lives on the billing account (the cloud's ciamBillingAccountRef), where only its administrators or costs
managers may create one, so each budget the platform team keeps is rendered in the landing-zone root, applied by
whoever keeps the landing zone (one someone else keeps is named in a comment; without a billing account it is a
`# NOTE`): google_billing_budget, its amount (specified_amount: currency and units, nanos for cents) per calendar
period (MONTH, QUARTER, YEAR), filtered to the environment's project (by number: data.google_project) and, when the tag
policy has an environment tag, to the resources labelled with it; a threshold rule per threshold (ciamActualThreshold
CURRENT_SPEND, ciamForecastThreshold FORECASTED_SPEND; 1.0 is 100%); and its updates to the channel its ciamAlertRole
names: a Cloud Monitoring notification channel (monitoring_notification_channels) or a Pub/Sub topic (pubsub_topic),
by the channel's ciamProviderRef; otherwise the billing account's administrators get Google's default emails (a
comment). Calling the Budget API with user credentials needs a quota project: the landing zone's provider bills its
calls to the environment's project (billing_project, user_project_override).

Read back from Terraform state: google_billing_budget -> budgets (kind budget): amount and currency, period, threshold
rules, the notification channel or topic its updates go to as the channel its alerts go to."""
from decimal import Decimal

from opsdir.core.directory import get, one, rdn_value
from opsdir.core.inventory import of_types, resource
from opsdir.domains.estate.budgets import budget_channel, budgets, currency, thresholds
from opsdir.domains.estate.tags import tag_rules
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .account import label_key
from .names import label, resource_id

BUDGET = "google_billing_budget"
PERIODS = {"monthly": "MONTH", "quarterly": "QUARTER", "annually": "YEAR"}
PERIOD_OF = {v: k for k, v in PERIODS.items()}
BASES = (("ciamActualThreshold", "CURRENT_SPEND"), ("ciamForecastThreshold", "FORECASTED_SPEND"))
DISPLAY = 60                                   # display_name's limit


def billing_account(m):
    """The billing account environment m's cloud's budgets live on (ciamBillingAccountRef), or None."""
    return one(m.cloud, "ciamBillingAccountRef")


def landing_budgets(m):
    """Environment m's budgets the landing zone renders: those the platform team keeps."""
    return tuple(b for b in budgets(m) if not one(b, "ciamManagedBy"))


def _updates(m, b):
    """(the all_updates_rule settings, comments)."""
    channel = budget_channel(m, b)
    target = one(channel, "ciamProviderRef") if channel is not None else None
    if target and "/notificationChannels/" in target:
        return (("all_updates_rule", Block((("monitoring_notification_channels", [target]),))),), ()
    if target and "/topics/" in target:
        return (("all_updates_rule", Block((("pubsub_topic", target), ("schema_version", "1.0")))),), ()
    return (), (f"# budget {rdn_value(b)}: {one(b, 'ciamAlertRole') or 'no alert role'} names no notification "
                "channel or Pub/Sub topic: the billing account's administrators get Google's default emails",)


def _filter(m):
    key = next((one(r, "ciamTagKey") for r in tag_rules(m.d) if one(r, "ciamTagSource") == "environment"), None)
    return Block((("projects", ["projects/${data.google_project.budgets.number}"]),
                  *((("labels", {label_key(key): label(m.label)}),) if key else ())))


def _amount(b):
    value = Decimal(one(b, "ciamBudgetAmount"))
    nanos = int((value - int(value)) * 1_000_000_000)
    return Block((("specified_amount", Block((("currency_code", currency(b)), ("units", str(int(value))),
                                              *((("nanos", nanos),) if nanos else ())))),))


def _budget(m, b):
    cn, keeper = rdn_value(b), one(b, "ciamManagedBy")
    if keeper:
        holder = get(m.d, keeper)
        return (f"# Budget {cn}: kept by {rdn_value(holder) if holder is not None else keeper}, not rendered here",)
    if not billing_account(m):
        return (f"# NOTE: budget {cn}: not rendered: a Google Cloud budget lives on the billing account and the cloud "
                "names none (ciamBillingAccountRef)",)
    updates, notes = _updates(m, b)
    period = PERIODS[one(b, "ciamBudgetPeriod") or "monthly"]
    return (*notes, block("resource", [BUDGET, tf_name(cn)], [
        ("billing_account", billing_account(m)),
        ("display_name", f"{rdn_value(m.cloud)}-{rdn_value(m.env)}-{cn}"[:DISPLAY]),
        ("budget_filter", Block((*_filter(m).body, ("calendar_period", period)))), ("amount", _amount(b)),
        *(("threshold_rules", Block((("threshold_percent", p / 100), ("spend_basis", basis))))
          for attr, basis in BASES for p in thresholds(b, attr)),
        *updates]))


def render_budgets(m):
    """HCL (and comments) for environment m's budgets, for the landing-zone root (budget_notes: the platform root's,
    without a billing account): the project lookup when any is rendered."""
    out = tuple(x for b in budgets(m) for x in _budget(m, b))
    lookup = (block("data", ["google_project", "budgets"], [("project_id", ref("var.project_id"))]),) \
        if any(x.startswith("resource ") for x in out) else ()
    return (*lookup, *out)


def budget_notes(m):
    """The platform root's notes on environment m's budgets the landing zone can't render: those the platform keeps
    when its cloud names no billing account."""
    return () if billing_account(m) else tuple(x for b in landing_budgets(m) for x in _budget(m, b))


def budget_provider_settings(m):
    """The landing zone provider's settings for the Budget API under user credentials: a quota project."""
    return (("billing_project", ref("var.project_id")), ("user_project_override", True)) \
        if billing_account(m) and landing_budgets(m) else ()


def _first(v):
    return v[0] if isinstance(v, list) and v else v if isinstance(v, dict) else {}


def _value(a):
    amount = _first(_first(a.get("amount")).get("specified_amount"))
    units = amount.get("units")
    if units is None:
        return None, None
    value = Decimal(str(units)) + Decimal(amount.get("nanos") or 0) / 1_000_000_000
    return format(value.normalize(), "f"), amount.get("currency_code")


def _percents(a, basis):
    return tuple(sorted({int(round(float(r["threshold_percent"]) * 100)) for r in a.get("threshold_rules") or ()
                         if (r.get("spend_basis") or "CURRENT_SPEND") == basis and r.get("threshold_percent")}))


def _target(a):
    rule = _first(a.get("all_updates_rule"))
    channels = rule.get("monitoring_notification_channels") or ()
    return resource_id(channels[0]) if channels else rule.get("pubsub_topic") or None


def budget_resources(pairs):
    """Budgets of (Terraform resource type, attributes) pairs: billing budgets of a calendar period."""
    return tuple(resource("budget", a.get("name") or a.get("id"), {
        "ciamBudgetAmount": value, "ciamCurrency": code,
        "ciamBudgetPeriod": PERIOD_OF.get(_first(a.get("budget_filter")).get("calendar_period") or "MONTH"),
        "ciamActualThreshold": _percents(a, "CURRENT_SPEND"),
        "ciamForecastThreshold": _percents(a, "FORECASTED_SPEND")},
        links={"ciamAlertRole": _target(a)}, name=a.get("display_name"))
        for a in of_types(pairs, BUDGET) if a.get("name") or a.get("id")
        for value, code in (_value(a),) if value is not None)
