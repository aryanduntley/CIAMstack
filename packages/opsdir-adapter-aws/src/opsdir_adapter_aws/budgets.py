"""Budgets on AWS (core estate: ciamBudget) as AWS Budgets. Pure.

Rendered in the environment's root for each budget the platform team keeps (one someone else keeps is named in a
comment): aws_budgets_budget, a COST budget of ciamBudgetAmount in ciamCurrency per period (MONTHLY, QUARTERLY,
ANNUALLY), filtered to the environment by the tag policy's environment tag (TagKeyValue user:<key>$<cloud/env>: AWS
filters by a tag only once it is activated as a cost allocation tag, said in a comment) or, without one, the whole
account (LinkedAccount when the cloud names it); a notification per threshold (ciamActualThreshold ACTUAL,
ciamForecastThreshold FORECASTED, percent, GREATER_THAN) to the SNS topic of the channel its ciamAlertRole names. AWS
Budgets publishes only to a topic in the budget's own account whose policy lets budgets.amazonaws.com publish: a
channel elsewhere (another account or partition) or without an ARN is named in a comment and the notifications left
out.

GovCloud (a us-gov- region): its billing is managed only in the associated standard account, where AWS Budgets runs
(us-east-1), so the budget goes through the provider aliased `billing` to that account (the cloud's
ciamBillingAccountRef; without it the budget is a comment). Whether a tag or LinkedAccount filter in the standard
account isolates one GovCloud account's spend isn't documented: a comment says to check the budget's spend.

Read back from Terraform state: aws_budgets_budget of type COST and period MONTHLY, QUARTERLY or ANNUALLY -> budgets
(kind budget), percentage thresholds above the budget as alert thresholds, the first SNS topic its notifications go to
as the channel its alerts go to."""
from decimal import Decimal, InvalidOperation

from opsdir.core.directory import get, one, rdn_value
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.estate.budgets import budget_channel, budgets, currency, thresholds
from opsdir.domains.estate.tags import tag_rules
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .account import account_id, govcloud
from .tags import state_tags

BUDGET = "aws_budgets_budget"
BILLING = "billing"                      # the provider alias of a GovCloud cloud's standard (billing) account
BILLING_REGION = "us-east-1"
PERIODS = {"monthly": "MONTHLY", "quarterly": "QUARTERLY", "annually": "ANNUALLY"}
PERIOD_OF = {v: k for k, v in PERIODS.items()}
NOTIFIED = (("ciamActualThreshold", "ACTUAL"), ("ciamForecastThreshold", "FORECASTED"))


def billing_account(m):
    """The standard account a GovCloud cloud's budgets live in (ciamBillingAccountRef), or None."""
    return one(m.cloud, "ciamBillingAccountRef")


def _arn_account(arn):
    parts = (arn or "").split(":")
    return (parts[1], parts[4]) if len(parts) > 5 else (None, None)


def _subscriber(m, b):
    """(SNS topic ARN the budget's alerts go to, or None; comments when they can't)."""
    channel = budget_channel(m, b)
    if channel is None:
        return None, ()
    arn = one(channel, "ciamProviderRef") or ""
    partition, account = _arn_account(arn)
    owner, wanted = (billing_account(m), "aws") if govcloud(m) else (account_id(m), partition)
    if ":sns:" not in arn:
        why = f"{rdn_value(channel)} names no SNS topic ARN (ciamProviderRef)"
    elif partition != wanted or (owner and account != owner):
        why = (f"AWS Budgets publishes only to a topic in the budget's account ({owner or 'its account'}) and "
               f"{arn} is elsewhere")
    else:
        return arn, ()
    return None, (f"# NOTE: budget {rdn_value(b)}'s alerts to {one(b, 'ciamAlertRole')}: not rendered: {why}",)


def _filter(m):
    """The cost filter keeping the budget to environment m: the tag policy's environment tag, else its account."""
    key = next((one(r, "ciamTagKey") for r in tag_rules(m.d) if one(r, "ciamTagSource") == "environment"), None)
    if key:
        return (("#", f"filters by tag {key}: activate it as a cost allocation tag in the billing account"),
                ("cost_filter", Block((("name", "TagKeyValue"), ("values", [f"user:{key}${m.label}"])))))
    return (("cost_filter", Block((("name", "LinkedAccount"), ("values", [account_id(m)])))),) if account_id(m) \
        else (("#", "the tag policy has no environment tag: the budget covers the whole account"),)


def _budget(m, b):
    cn, keeper = rdn_value(b), one(b, "ciamManagedBy")
    if keeper:
        holder = get(m.d, keeper)
        return (f"# Budget {cn}: kept by {rdn_value(holder) if holder is not None else keeper}, not rendered here",)
    if govcloud(m) and not billing_account(m):
        return (f"# NOTE: budget {cn}: not rendered: GovCloud's billing is managed in its associated standard account "
                "and the cloud names none (ciamBillingAccountRef)",)
    topic, notes = _subscriber(m, b)
    return (*notes, block("resource", [BUDGET, tf_name(cn)], [
        *((("provider", ref(f"aws.{BILLING}")),
           ("#", "GovCloud spend is billed to this standard account: check the budget's spend once it runs (how a "
                 "filter isolates one GovCloud account isn't documented)")) if govcloud(m) else ()),
        ("name", f"{rdn_value(m.cloud)}-{rdn_value(m.env)}-{cn}"), ("budget_type", "COST"),
        ("limit_amount", one(b, "ciamBudgetAmount")), ("limit_unit", currency(b)),
        ("time_unit", PERIODS[one(b, "ciamBudgetPeriod") or "monthly"]), *_filter(m),
        *(("notification", Block((("comparison_operator", "GREATER_THAN"), ("threshold", p),
                                  ("threshold_type", "PERCENTAGE"), ("notification_type", kind),
                                  ("subscriber_sns_topic_arns", [topic]))))
          for attr, kind in NOTIFIED for p in thresholds(b, attr) if topic)]))


def needs_billing_provider(m):
    """Whether environment m's root needs the provider aliased to its standard (billing) account: a GovCloud cloud
    naming one, with a budget the platform keeps."""
    return govcloud(m) and bool(billing_account(m)) and any(not one(b, "ciamManagedBy") for b in budgets(m))


def render_budgets(m):
    """HCL (and comments) for environment m's budgets."""
    return tuple(x for b in budgets(m) for x in _budget(m, b))


def _amount(v):
    try:
        return format(Decimal(str(v)).normalize(), "f")
    except InvalidOperation:
        return None


def budget_topics(pairs):
    """ARNs of the SNS topics budgets' notifications go to (alert channels)."""
    return frozenset(arn for a in of_types(pairs, BUDGET) for n in a.get("notification") or ()
                     for arn in n.get("subscriber_sns_topic_arns") or ())


def _percents(a, kind):
    return tuple(sorted({int(n["threshold"]) for n in a.get("notification") or ()
                         if n.get("notification_type") == kind and n.get("threshold_type") == "PERCENTAGE"
                         and n.get("comparison_operator") == "GREATER_THAN" and n.get("threshold") is not None}))


def budget_resources(pairs):
    """Budgets of (Terraform resource type, attributes) pairs: COST budgets of a period the record has."""
    return tuple(resource("budget", a.get("arn") or a.get("id"), {
        "ciamBudgetAmount": _amount(a.get("limit_amount")), "ciamCurrency": a.get("limit_unit"),
        "ciamBudgetPeriod": PERIOD_OF[a.get("time_unit")],
        "ciamActualThreshold": _percents(a, "ACTUAL"), "ciamForecastThreshold": _percents(a, "FORECASTED")},
        links={"ciamAlertRole": next(iter(sorted(budget_topics([(BUDGET, a)]))), None)}, name=a.get("name"),
        role=tagged_role(state_tags(a)), tags=state_tags(a))
        for a in of_types(pairs, BUDGET)
        if a.get("budget_type", "COST") == "COST" and a.get("time_unit") in PERIOD_OF and (a.get("arn") or a.get("id")))
