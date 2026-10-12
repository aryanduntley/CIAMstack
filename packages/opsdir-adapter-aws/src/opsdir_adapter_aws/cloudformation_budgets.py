"""What CloudFormation stacks declare of budgets, normalized to the Terraform attribute names the shared mapping reads
(opsdir_adapter_aws.budgets.budget_resources). Pure.

  AWS::Budgets::Budget   -> aws_budgets_budget: its Budget (name, type, time unit, limit), its notifications with
                            their SNS subscribers (e-mail ones aren't read), ResourceTags; its Ref is its name, its ARN
                            arn:<partition>:budgets::<account>:budget/<name> from the stack's partition and account
GovCloud's resource specification has no AWS::Budgets::Budget: a GovCloud render keeps budgets in Terraform.
"""
from .cloudformation_values import number, tag_map

BUDGET_TYPES = ("AWS::Budgets::Budget",)


def _notification(n):
    note = n.get("Notification") or {}
    return {"notification_type": note.get("NotificationType"), "comparison_operator": note.get("ComparisonOperator"),
            "threshold": number(note.get("Threshold")), "threshold_type": note.get("ThresholdType"),
            "subscriber_sns_topic_arns": [s.get("Address") for s in n.get("Subscribers") or ()
                                          if isinstance(s, dict) and s.get("SubscriptionType") == "SNS"]}


def budget_stack_pairs(declared, names):
    """(Terraform resource type, attributes) pairs of the budgets among a stack's declared resources."""
    partition, account = names.get("AWS::Partition"), names.get("AWS::AccountId")

    def budget(p, pid):
        b = p.get("Budget") or {}
        name = b.get("BudgetName") or pid
        return ("aws_budgets_budget", {
            "arn": f"arn:{partition}:budgets::{account}:budget/{name}" if partition and account else None,
            "id": f"{account}:{name}" if account else name, "name": name, "budget_type": b.get("BudgetType"),
            "time_unit": b.get("TimeUnit"), "limit_amount": (b.get("BudgetLimit") or {}).get("Amount"),
            "limit_unit": (b.get("BudgetLimit") or {}).get("Unit"),
            "notification": [_notification(n) for n in p.get("NotificationsWithSubscribers") or ()
                             if isinstance(n, dict)],
            "tags": tag_map(p.get("ResourceTags"))})
    return [budget(p, pid) for _, t, p, _, pid in declared if t == "AWS::Budgets::Budget"]
