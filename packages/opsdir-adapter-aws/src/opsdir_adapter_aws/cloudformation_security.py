"""What CloudFormation stacks declare of security services and findings' handling, normalized to the Terraform
attribute names the shared mapping reads (opsdir_adapter_aws.security.security_resources,
opsdir_adapter_aws.suppressions.suppression_resources). CloudFormation's properties follow the AWS API (the CLI
reader's terraform_shape gives a rule's criteria and actions as Terraform blocks). Pure.

  AWS::GuardDuty::Detector            -> aws_guardduty_detector (+ an aws_guardduty_detector_feature per feature); its
                                         Ref is its id, its ARN from the stack's partition, region and account
  AWS::Config::ConfigurationRecorder  -> aws_config_configuration_recorder
  AWS::Config::DeliveryChannel        -> aws_config_delivery_channel (its bucket)
  AWS::SecurityHub::Hub               -> aws_securityhub_account (its Ref is its ARN)
  AWS::SecurityHub::Standard          -> aws_securityhub_standards_subscription
  AWS::SecurityHub::AutomationRule    -> aws_securityhub_automation_rule (its criteria, its actions)
  AWS::GuardDuty::Filter              -> aws_guardduty_filter (its criteria per field, its action)
Inspector's enabler, Config's retention and the services' organization configurations have no CloudFormation type: an
opsdir render keeps them in the Terraform root beside the stacks, read with them.
"""
from .cli_edge import terraform_shape
from .cloudformation_values import tag_map, truth

SECURITY_TYPES = ("AWS::GuardDuty::Detector", "AWS::Config::ConfigurationRecorder", "AWS::Config::DeliveryChannel",
                  "AWS::SecurityHub::Hub", "AWS::SecurityHub::Standard", "AWS::SecurityHub::AutomationRule",
                  "AWS::GuardDuty::Filter")


def _of(declared, type_):
    return [(lid, p, pid) for lid, t, p, _, pid in declared if t == type_]


def _criteria(criterion):
    """A GuardDuty filter's Criterion ({field: {Equals: [...], ...}}) as Terraform's criterion blocks."""
    return [{"field": field, **{k[0].lower() + k[1:]: v for k, v in (ops or {}).items()}}
            for field, ops in (criterion or {}).items()]


def _where(names):
    where = (names.get("AWS::Partition"), names.get("AWS::Region"), names.get("AWS::AccountId"))
    return where if all(where) else None


def _services(declared, names):
    """GuardDuty detectors with their features, Config recorders and delivery channels, Security Hub and its
    standards."""
    where = _where(names)

    def hub_arn(lid, pid):
        return names.get(f"{lid}.ARN") or (pid if str(pid).startswith("arn:") else
                                           f"arn:{where[0]}:securityhub:{where[1]}:{where[2]}:hub/default"
                                           if where else None)
    detectors = _of(declared, "AWS::GuardDuty::Detector")
    return [*(("aws_guardduty_detector", {
                "id": pid, "enable": truth(p.get("Enable")) is not False,
                "arn": f"arn:{where[0]}:guardduty:{where[1]}:{where[2]}:detector/{pid}" if where else None,
                "tags": tag_map(p.get("Tags"))}) for _, p, pid in detectors),
            *(("aws_guardduty_detector_feature", {
                "detector_id": pid, "name": f.get("Name"), "status": f.get("Status"),
                "additional_configuration": [{"name": c.get("Name"), "status": c.get("Status")}
                                             for c in f.get("AdditionalConfiguration") or () if isinstance(c, dict)]})
              for _, p, pid in detectors for f in p.get("Features") or () if isinstance(f, dict)),
            *(("aws_config_configuration_recorder", {"name": p.get("Name") or pid, "role_arn": p.get("RoleARN")})
              for _, p, pid in _of(declared, "AWS::Config::ConfigurationRecorder")),
            *(("aws_config_delivery_channel", {"name": p.get("Name") or pid, "s3_bucket_name": p.get("S3BucketName")})
              for _, p, pid in _of(declared, "AWS::Config::DeliveryChannel")),
            *(("aws_securityhub_account", {"arn": hub_arn(lid, pid), "id": where[2] if where else None,
                                           "auto_enable_controls": p.get("AutoEnableControls"),
                                           "control_finding_generator": p.get("ControlFindingGenerator")})
              for lid, p, pid in _of(declared, "AWS::SecurityHub::Hub")),
            *(("aws_securityhub_standards_subscription", {"standards_arn": p.get("StandardsArn"), "id": pid})
              for _, p, pid in _of(declared, "AWS::SecurityHub::Standard"))]


def security_stack_pairs(declared, names):
    """(Terraform resource type, attributes) pairs of security services and findings' handling among a stack's declared
    resources."""
    return [*_services(declared, names),
            *(("aws_securityhub_automation_rule", {
                "arn": names.get(f"{lid}.RuleArn") or pid, "rule_name": p.get("RuleName"),
                "rule_status": p.get("RuleStatus"), "description": p.get("Description"),
                "criteria": terraform_shape(p.get("Criteria") or {}),
                "actions": [terraform_shape(a)[0] for a in p.get("Actions") or () if isinstance(a, dict)]})
              for lid, p, pid in _of(declared, "AWS::SecurityHub::AutomationRule")),
            *(("aws_guardduty_filter", {
                "id": pid, "name": p.get("Name"), "action": p.get("Action"), "rank": p.get("Rank"),
                "finding_criteria": [{"criterion": _criteria((p.get("FindingCriteria") or {}).get("Criterion"))}]})
              for _, p, pid in _of(declared, "AWS::GuardDuty::Filter"))]
