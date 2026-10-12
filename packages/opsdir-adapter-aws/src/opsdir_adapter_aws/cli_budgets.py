"""The AWS Budgets outputs of the AWS CLI, normalized to the attribute names of the matching Terraform resource
(opsdir_adapter_aws.budgets reads both). Pure.

None of these outputs names the account or the budget it describes, so they are saved under budgets/ by account:

  budgets describe-budgets --account-id A                   budgets/<A>.json -> aws_budgets_budget (its ARN
                                                             arn:<partition>:budgets::<A>:budget/<name>)
  budgets describe-notifications-for-budget --budget-name N budgets/<A>/<N>/notifications.json (N percent-encoded)
  budgets describe-subscribers-for-notification             budgets/<A>/<N>/subscribers-<i>.json: the subscribers of
                                                             the i-th notification (from 0, in notifications.json's
                                                             order); SNS topics are read, e-mail addresses aren't
  budgets list-tags-for-resource --resource-arn <its ARN>   budgets/<A>/<N>/tags.json
A GovCloud account's budgets are its associated standard account's (AWS bills GovCloud there): their ARNs are in the
standard partition.
"""
from .cli_outputs import file_name, home_of, named, stem, tags_of

FOLDER = "budgets"


def budget_output(path):
    """The key a budget output is recognized under by its path, else None."""
    parts = path.split("/")
    if parts[0] != FOLDER or not path.endswith(".json"):
        return None
    if len(parts) == 2:
        return "budgets"
    leaf = stem(path)
    return f"budget-{leaf.split('-', 1)[0]}" if len(parts) == 4 and leaf.split("-", 1)[0] in (
        "notifications", "subscribers", "tags") else None


def budget_folder(account, name):
    """Where a budget's notifications, subscribers and tags are saved."""
    return f"{FOLDER}/{account}/{file_name(name)}"


def _budget_of(path):
    """(account, budget name) of a per-budget output's path (budgets/<account>/<budget>/<file>)."""
    _, account, budget, _ = path.split("/")
    return account, named(f"{budget}.json")


def _of(outs, key):
    """{(account, budget name): [(path, document), ...]} of one kind of per-budget output."""
    found = [(_budget_of(p), (p, doc)) for p, k, doc in outs if k == key]
    return {b: [x for at, x in found if at == b] for b in dict.fromkeys(b for b, _ in found)}


def _subscribers(found):
    """{index: SNS topic ARNs} of one budget's subscriber outputs."""
    return {int(stem(p).split("-", 1)[1]): [s.get("Address") for s in doc.get("Subscribers") or ()
                                             if isinstance(s, dict) and s.get("SubscriptionType") == "SNS"]
            for p, doc in found if stem(p).split("-", 1)[1].isdigit()}


def budget_pairs(outs):
    """The (Terraform type, attributes) pairs of the budgets each account's outputs describe."""
    home = home_of(outs)
    partition = "aws" if not home or home[0] == "aws-us-gov" else home[0]
    notes, subs, tags = _of(outs, "budget-notifications"), _of(outs, "budget-subscribers"), _of(outs, "budget-tags")

    def notifications(key):
        listed = [n for _, doc in notes.get(key, ()) for n in doc.get("Notifications") or () if isinstance(n, dict)]
        topics = _subscribers(subs.get(key, ()))
        return [{"notification_type": n.get("NotificationType"), "comparison_operator": n.get("ComparisonOperator"),
                 "threshold": n.get("Threshold"), "threshold_type": n.get("ThresholdType"),
                 "subscriber_sns_topic_arns": topics.get(i, [])} for i, n in enumerate(listed)]
    return [("aws_budgets_budget", {
                "arn": f"arn:{partition}:budgets::{account}:budget/{b.get('BudgetName')}",
                "id": f"{account}:{b.get('BudgetName')}", "name": b.get("BudgetName"),
                "budget_type": b.get("BudgetType"), "time_unit": b.get("TimeUnit"),
                "limit_amount": (b.get("BudgetLimit") or {}).get("Amount"),
                "limit_unit": (b.get("BudgetLimit") or {}).get("Unit"),
                "notification": notifications((account, b.get("BudgetName"))),
                "tags": {k: v for _, doc in tags.get((account, b.get("BudgetName")), ())
                         for k, v in tags_of(doc.get("ResourceTags")).items()}})
            for p, k, doc in outs if k == "budgets" for account in (stem(p),)
            for b in doc.get("Budgets") or () if isinstance(b, dict) and b.get("BudgetName")]
