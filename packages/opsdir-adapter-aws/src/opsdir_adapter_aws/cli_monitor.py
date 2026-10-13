"""The monitoring outputs of the AWS CLI, normalized to the attribute names of the matching Terraform resources
(opsdir_adapter_aws.inventory reads both: alert channels, log destinations, alarms, canaries). Pure.

  cloudwatch describe-alarms              MetricAlarms  -> aws_cloudwatch_metric_alarm (what it evaluates, its actions)
  cloudwatch list-tags-for-resource       Tags          -> an alarm's tags; the output doesn't name the alarm: save it
                                                           as alarm-tags/<alarm name>.json
  logs describe-log-groups                logGroups     -> aws_cloudwatch_log_group (its retention, key)
  logs list-tags-for-resource             tags          -> a log group's tags; save it as log-group-tags/<log group
                                                           name, percent-encoded (/ as %2F)>.json
  synthetics describe-canaries            Canaries      -> aws_synthetics_canary (its schedule, artifact location; its
                                                           ARN from its name and its engine's partition, region and
                                                           account: the output holds no canary ARN)
  sns list-topics                         Topics        -> aws_sns_topic (its name from its ARN)
  sns list-tags-for-resource              Tags          -> a topic's tags; save it as topic-tags/<topic name>.json
"""
import re

from .cli_outputs import file_name, folder_tags, items, under

KEYS = ("MetricAlarms", "logGroups", "Canaries", "Topics")
TAG_KEYS = ("tags",)                      # a log group's tags; alarms' and topics' are Tags, recognized last
TAGS = ("alarm-tags", "log-group-tags", "topic-tags")
_ENGINE = re.compile(r"^arn:([^:]+):lambda:([^:]+):(\d+):")


def is_tags_of(path):
    """Whether a file is a monitoring resource's tags (saved under alarm-tags/, log-group-tags/ or topic-tags/)."""
    return any(under(path, t) for t in TAGS)


def _alarms(outs):
    tags = folder_tags(outs, "alarm-tags")
    return [("aws_cloudwatch_metric_alarm", {
                "arn": a.get("AlarmArn"), "alarm_name": a.get("AlarmName"),
                "alarm_description": a.get("AlarmDescription"), "namespace": a.get("Namespace"),
                "metric_name": a.get("MetricName"), "statistic": a.get("Statistic"), "period": a.get("Period"),
                "evaluation_periods": a.get("EvaluationPeriods"), "threshold": a.get("Threshold"),
                "comparison_operator": a.get("ComparisonOperator"), "treat_missing_data": a.get("TreatMissingData"),
                "alarm_actions": a.get("AlarmActions") or [], "ok_actions": a.get("OKActions") or [],
                "insufficient_data_actions": a.get("InsufficientDataActions") or [],
                "dimensions": {d.get("Name"): d.get("Value") for d in a.get("Dimensions") or ()},
                "metric_query": [{"id": q.get("Id")} for q in a.get("Metrics") or ()],
                "tags": tags.get(a.get("AlarmName"), {})})
            for a in items(outs, "MetricAlarms")]


def _log_groups(outs):
    tags = folder_tags(outs, "log-group-tags")
    return [("aws_cloudwatch_log_group", {
                "arn": g.get("logGroupArn") or (g.get("arn") or "").removesuffix(":*") or None,
                "name": g.get("logGroupName"), "retention_in_days": g.get("retentionInDays", 0),
                "kms_key_id": g.get("kmsKeyId"), "tags": tags.get(g.get("logGroupName"), {})})
            for g in items(outs, "logGroups")]


def _canary_arn(c):
    found = _ENGINE.match(c.get("EngineArn") or "")
    return f"arn:{found.group(1)}:synthetics:{found.group(2)}:{found.group(3)}:canary:{c.get('Name')}" \
        if found else None


def _canaries(outs):
    """(pairs, notices): the canaries; one whose ARN can't be told (no engine ARN yet) is named."""
    canaries = items(outs, "Canaries")
    return ([("aws_synthetics_canary", {
                "arn": _canary_arn(c), "name": c.get("Name"), "runtime_version": c.get("RuntimeVersion"),
                "artifact_s3_location": c.get("ArtifactS3Location"), "execution_role_arn": c.get("ExecutionRoleArn"),
                "schedule": [{"expression": (c.get("Schedule") or {}).get("Expression"),
                              "duration_in_seconds": (c.get("Schedule") or {}).get("DurationInSeconds")}],
                "tags": c.get("Tags") or {}})
             for c in canaries if _canary_arn(c)],
            tuple(f"synthetics: canary {c.get('Name')} has no engine ARN to tell its ARN by (not created yet?); "
                  f"not read" for c in canaries if not _canary_arn(c)))


def _topics(outs):
    tags = folder_tags(outs, "topic-tags")
    return [("aws_sns_topic", {"arn": t.get("TopicArn"), "name": t["TopicArn"].rsplit(":", 1)[-1],
                               "tags": tags.get(t["TopicArn"].rsplit(":", 1)[-1], {})})
            for t in items(outs, "Topics") if t.get("TopicArn")]


def monitor_pairs(outs):
    """(pairs, notices): the metric alarms, log groups, canaries and SNS topics, with their tags."""
    canaries, notices = _canaries(outs)
    return [*_alarms(outs), *_log_groups(outs), *canaries, *_topics(outs)], notices


def tags_path(folder, name):
    """Where the collector saves a monitoring resource's tags: folder/<name, percent-encoded>.json."""
    return f"{folder}/{file_name(name)}.json"
