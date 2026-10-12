"""What CloudFormation stacks declare of findings' handling, normalized to the Terraform attribute names the shared
mapping reads (opsdir_adapter_aws.suppressions.suppression_resources). CloudFormation's properties follow the AWS API
(the CLI reader's terraform_shape gives a rule's criteria and actions as Terraform blocks). Pure.

  AWS::SecurityHub::AutomationRule   -> aws_securityhub_automation_rule (its criteria, its actions)
  AWS::GuardDuty::Filter             -> aws_guardduty_filter (its criteria per field, its action)
"""
from .cli_edge import terraform_shape

SECURITY_TYPES = ("AWS::SecurityHub::AutomationRule", "AWS::GuardDuty::Filter")


def _of(declared, type_):
    return [(lid, p, pid) for lid, t, p, _, pid in declared if t == type_]


def _criteria(criterion):
    """A GuardDuty filter's Criterion ({field: {Equals: [...], ...}}) as Terraform's criterion blocks."""
    return [{"field": field, **{k[0].lower() + k[1:]: v for k, v in (ops or {}).items()}}
            for field, ops in (criterion or {}).items()]


def security_stack_pairs(declared, names):
    """(Terraform resource type, attributes) pairs of findings' handling among a stack's declared resources."""
    return [*(("aws_securityhub_automation_rule", {
                "arn": names.get(f"{lid}.RuleArn") or pid, "rule_name": p.get("RuleName"),
                "rule_status": p.get("RuleStatus"), "description": p.get("Description"),
                "criteria": terraform_shape(p.get("Criteria") or {}),
                "actions": [terraform_shape(a)[0] for a in p.get("Actions") or () if isinstance(a, dict)]})
              for lid, p, pid in _of(declared, "AWS::SecurityHub::AutomationRule")),
            *(("aws_guardduty_filter", {
                "id": pid, "name": p.get("Name"), "action": p.get("Action"), "rank": p.get("Rank"),
                "finding_criteria": [{"criterion": _criteria((p.get("FindingCriteria") or {}).get("Criterion"))}]})
              for _, p, pid in _of(declared, "AWS::GuardDuty::Filter"))]
