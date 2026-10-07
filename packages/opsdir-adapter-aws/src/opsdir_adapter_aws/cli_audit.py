"""CloudTrail trails as the AWS CLI and CloudFormation describe them, normalized to the attribute names of Terraform's
aws_cloudtrail (opsdir_adapter_aws.audit reads both). Pure.

  cloudtrail describe-trails            trailList                 -> aws_cloudtrail: bucket, CloudWatch log group, all
                                                                     regions, global services' events, log file
                                                                     validation, organization trail (a multi-region
                                                                     trail listed again from another region is read
                                                                     once)
  cloudtrail get-event-selectors        EventSelectors or         -> its event selectors (the trail named by TrailARN):
    --trail-name T                      AdvancedEventSelectors       basic or advanced
  cloudtrail list-tags                  ResourceTagList           -> its tags (the trail named by ResourceId)
    --resource-id-list ARN …
A CloudFormation AWS::CloudTrail::Trail has the same properties (opsdir_adapter_aws.cloudformation).
"""
from .cli_outputs import documents, items, tags_of

KEYS = ("trailList", "EventSelectors", "AdvancedEventSelectors", "ResourceTagList")


def _basic(s):
    given = {"read_write_type": s.get("ReadWriteType"), "include_management_events": s.get("IncludeManagementEvents")}
    return {**{k: v for k, v in given.items() if v is not None},
            "data_resource": [{"type": r.get("Type"), "values": r.get("Values") or []}
                              for r in s.get("DataResources") or ()]}


def _advanced(s):
    return {"name": s.get("Name"), "field_selector": [
        {"field": f.get("Field"), "equals": f.get("Equals") or []} for f in s.get("FieldSelectors") or ()]}


def trail_attributes(arn, t, selectors=None, tags=None):
    """aws_cloudtrail attributes of a trail described in CloudTrail's own names (describe-trails, or a CloudFormation
    resource's properties), with event selectors ({EventSelectors | AdvancedEventSelectors}; else t's own) and tags."""
    chosen = selectors if selectors is not None else t
    return {"arn": arn, "name": t.get("Name") or t.get("TrailName"), "s3_bucket_name": t.get("S3BucketName"),
            "cloud_watch_logs_group_arn": t.get("CloudWatchLogsLogGroupArn"),
            "is_multi_region_trail": t.get("IsMultiRegionTrail"),
            "include_global_service_events": t.get("IncludeGlobalServiceEvents"),
            "enable_log_file_validation": t.get("LogFileValidationEnabled", t.get("EnableLogFileValidation")),
            "is_organization_trail": t.get("IsOrganizationTrail"),
            "event_selector": [_basic(s) for s in chosen.get("EventSelectors") or ()],
            "advanced_event_selector": [_advanced(s) for s in chosen.get("AdvancedEventSelectors") or ()],
            "tags_all": tags or {}}


def audit_pairs(outs):
    """aws_cloudtrail pairs of the CloudTrail outputs among the recognized CLI outputs ((path, key, document), ...)."""
    selectors = {doc.get("TrailARN"): doc for key in ("EventSelectors", "AdvancedEventSelectors")
                 for _, doc in documents(outs, key) if doc.get("TrailARN")}
    tags = {r.get("ResourceId"): tags_of(r.get("TagsList")) for r in items(outs, "ResourceTagList")}
    trails = {t["TrailARN"]: t for t in items(outs, "trailList") if t.get("TrailARN")}
    return [("aws_cloudtrail", trail_attributes(arn, t, selectors.get(arn), tags.get(arn)))
            for arn, t in trails.items()]
