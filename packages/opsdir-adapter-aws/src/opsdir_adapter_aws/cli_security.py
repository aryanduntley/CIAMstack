"""The security service outputs of the AWS CLI, normalized to the attribute names of the matching Terraform resources
(opsdir_adapter_aws.security reads both). Pure.

  guardduty get-detector --detector-id ID      a detector: its Status, Features (with their additional
                                               configuration) and Tags; the output doesn't name the detector: save it
                                               as guardduty/<detector id>.json -> aws_guardduty_detector (+ an
                                               aws_guardduty_detector_feature per feature); its ARN from the export's
                                               partition, region and account (cli_outputs.home_of)
  inspector2 batch-get-account-status          accounts            -> aws_inspector2_enabler: the resource types whose
                                                                      scanning is ENABLED
  configservice describe-configuration-recorders   ConfigurationRecorders   -> aws_config_configuration_recorder
                                                                      (service-linked ones, which another AWS service
                                                                      owns, named, not read)
  configservice describe-delivery-channels     DeliveryChannels    -> aws_config_delivery_channel (its bucket)
  configservice describe-retention-configurations  RetentionConfigurations  -> aws_config_retention_configuration
  securityhub describe-hub                     HubArn              -> aws_securityhub_account
  securityhub get-enabled-standards            StandardsSubscriptions  -> aws_securityhub_standards_subscription
                                                                      (those not failing or being deleted)
  guardduty, inspector2, securityhub describe-organization-configuration: answered only in the service's delegated
  administrator account; saved as organization-configuration/guardduty-<detector id>.json, inspector2.json,
  securityhub.json, each reads its service as organization-wide (as the Terraform resource does)
EventBridge rules routing findings are the CLI reader's (cli.py: list-rules with their EventPattern,
list-targets-by-rule).
"""
from .cli_outputs import documents, home_of, items, stem

KEYS = ("HubArn", "StandardsSubscriptions", "ConfigurationRecorders", "DeliveryChannels", "RetentionConfigurations",
        "accounts")
DETECTORS = "guardduty"                   # the folder detectors are saved under, by id
ORGANIZATION = "organization-configuration"
ORGANIZATION_TYPES = {"guardduty": "aws_guardduty_organization_configuration",
                      "inspector2": "aws_inspector2_organization_configuration",
                      "securityhub": "aws_securityhub_organization_configuration"}
SCANNED = (("ec2", "EC2"), ("ecr", "ECR"), ("lambda", "LAMBDA"), ("lambdaCode", "LAMBDA_CODE"))
_GONE = ("FAILED", "DELETING")


def _folder(path):
    parts = path.split("/")
    return parts[-2] if len(parts) > 1 else None


def security_output(path):
    """The key a security output saved by path is recognized under (a detector, an organization configuration), else
    None: their top-level keys don't say what they are."""
    folder = _folder(path)
    return folder if folder in (DETECTORS, ORGANIZATION) and path.endswith(".json") else None


def _detectors(outs, home):
    def arn(i):
        return f"arn:{home[0]}:guardduty:{home[1]}:{home[2]}:detector/{i}" if home else None
    detectors = [(stem(p), doc) for p, doc in documents(outs, DETECTORS)]
    return ([*(("aws_guardduty_detector", {"id": i, "arn": arn(i), "enable": d.get("Status") == "ENABLED",
                                           "tags": d.get("Tags") or {}}) for i, d in detectors),
             *(("aws_guardduty_detector_feature", {
                 "detector_id": i, "name": f.get("Name"), "status": f.get("Status"),
                 "additional_configuration": [{"name": c.get("Name"), "status": c.get("Status")}
                                              for c in f.get("AdditionalConfiguration") or ()]})
               for i, d in detectors for f in d.get("Features") or () if isinstance(f, dict))],
            (f"guardduty: no output names the account and region (describe-subnets, describe-hub, ...): "
             f"{len(detectors)} detector(s) read by ID",) if detectors and not home else ())


def _scanners(outs):
    return [("aws_inspector2_enabler", {
                "id": f"{a.get('accountId')}-{':'.join(types)}", "account_ids": [a.get("accountId")],
                "resource_types": list(types)})
            for a in items(outs, "accounts") if isinstance(a, dict)
            for types in (sorted(t for k, t in SCANNED
                                 if ((a.get("resourceState") or {}).get(k) or {}).get("status") == "ENABLED"),)
            if types]


def _recorders(outs):
    recorders = items(outs, "ConfigurationRecorders")
    linked = [r.get("name") for r in recorders if r.get("servicePrincipal")]
    return ([*(("aws_config_configuration_recorder", {"name": r.get("name"), "role_arn": r.get("roleARN")})
               for r in recorders if r.get("name") and not r.get("servicePrincipal")),
             *(("aws_config_delivery_channel", {"name": c.get("name"), "s3_bucket_name": c.get("s3BucketName")})
               for c in items(outs, "DeliveryChannels")),
             *(("aws_config_retention_configuration", {"name": r.get("Name"),
                                                       "retention_period_in_days": r.get("RetentionPeriodInDays")})
               for r in items(outs, "RetentionConfigurations"))],
            (f"config: service-linked recorder(s) {', '.join(linked)} (kept by another AWS service) not read",)
            if linked else ())


def _hubs(outs):
    return [*(("aws_securityhub_account", {"arn": doc.get("HubArn"), "id": (doc.get("HubArn") or "").split(":")[4]
                                           or None, "auto_enable_controls": doc.get("AutoEnableControls"),
                                           "control_finding_generator": doc.get("ControlFindingGenerator")})
              for _, doc in documents(outs, "HubArn") if doc.get("HubArn")),
            *(("aws_securityhub_standards_subscription", {"standards_arn": s.get("StandardsArn"),
                                                          "id": s.get("StandardsSubscriptionArn")})
              for s in items(outs, "StandardsSubscriptions") if s.get("StandardsStatus") not in _GONE)]


def _organizations(outs):
    """The organization configurations saved from the delegated administrator's account, by service."""
    return [(ORGANIZATION_TYPES[service], {"detector_id": detector or None})
            for p, _ in documents(outs, ORGANIZATION)
            for service, _, detector in (stem(p).partition("-"),) if service in ORGANIZATION_TYPES]


def _account_wide(pairs):
    """Notices for the services read without their organization configuration (read as account-wide)."""
    held = {t for t, _ in pairs}
    return tuple(f"{service}: no describe-organization-configuration saved (only the delegated administrator's "
                 f"account answers it): read as the account's own" for service, (read, org) in (
                     ("guardduty", ("aws_guardduty_detector", ORGANIZATION_TYPES["guardduty"])),
                     ("inspector2", ("aws_inspector2_enabler", ORGANIZATION_TYPES["inspector2"])),
                     ("securityhub", ("aws_securityhub_account", ORGANIZATION_TYPES["securityhub"])))
                 if read in held and org not in held)


def security_pairs(outs):
    """(pairs, notices): GuardDuty detectors with their features, Inspector's enabled scans, Config recorders with their
    delivery channels and retention, Security Hub with its standards, and the organization configurations saved."""
    detectors, detector_notices = _detectors(outs, home_of(outs))
    recorders, recorder_notices = _recorders(outs)
    pairs = [*detectors, *_scanners(outs), *recorders, *_hubs(outs), *_organizations(outs)]
    return pairs, (*detector_notices, *recorder_notices, *_account_wide(pairs))
