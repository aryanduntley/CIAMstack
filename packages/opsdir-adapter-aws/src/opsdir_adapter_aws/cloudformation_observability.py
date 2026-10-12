"""The observability CloudFormation stacks declare, normalized to the Terraform attribute names the shared mapping
reads (opsdir_adapter_aws.inventory: log destinations, alarms, canaries). Properties come resolved. Pure.

  AWS::Logs::LogGroup       -> aws_cloudwatch_log_group (its retention, key)
  AWS::CloudWatch::Alarm    -> aws_cloudwatch_metric_alarm (what it evaluates, its actions)
  AWS::Synthetics::Canary   -> aws_synthetics_canary (its schedule, artifact location; its ARN from its name and
                               the stack's partition, region and account: the type has no Arn attribute)
"""
from .cloudformation_values import number, tag_map

OBSERVABILITY_TYPES = ("AWS::Logs::LogGroup", "AWS::CloudWatch::Alarm", "AWS::Synthetics::Canary")
_ALARM = {"alarm_description": "AlarmDescription", "namespace": "Namespace", "metric_name": "MetricName",
          "statistic": "Statistic", "extended_statistic": "ExtendedStatistic", "period": "Period",
          "evaluation_periods": "EvaluationPeriods", "datapoints_to_alarm": "DatapointsToAlarm",
          "comparison_operator": "ComparisonOperator", "threshold": "Threshold", "unit": "Unit",
          "treat_missing_data": "TreatMissingData"}


def _of(declared, type_):
    return [(lid, p, pid) for lid, t, p, _, pid in declared if t == type_]


def _alarm(lid, p, pid, names):
    return {"id": pid, "arn": names.get(f"{lid}.Arn"), "alarm_name": p.get("AlarmName") or pid,
            **{tf: number(p[cfn]) for tf, cfn in _ALARM.items() if p.get(cfn) is not None},
            "alarm_actions": list(p.get("AlarmActions") or ()), "ok_actions": list(p.get("OKActions") or ()),
            "insufficient_data_actions": list(p.get("InsufficientDataActions") or ()),
            "dimensions": {d.get("Name"): d.get("Value") for d in p.get("Dimensions") or () if isinstance(d, dict)},
            "metric_query": [{"id": q.get("Id")} for q in p.get("Metrics") or () if isinstance(q, dict)],
            "tags": tag_map(p.get("Tags"))}


def _canary(p, pid, names):
    name = p.get("Name") or pid
    where = (names.get("AWS::Partition"), names.get("AWS::Region"), names.get("AWS::AccountId"))
    schedule = p.get("Schedule") or {}
    return {"id": name, "name": name,
            "arn": f"arn:{where[0]}:synthetics:{where[1]}:{where[2]}:canary:{name}" if all(where) else None,
            "runtime_version": p.get("RuntimeVersion"), "artifact_s3_location": p.get("ArtifactS3Location"),
            "execution_role_arn": p.get("ExecutionRoleArn"), "handler": (p.get("Code") or {}).get("Handler"),
            "schedule": [{"expression": schedule.get("Expression"),
                          "duration_in_seconds": number(schedule.get("DurationInSeconds"))}] if schedule else [],
            "tags": tag_map(p.get("Tags"))}


def observability_stack_pairs(declared, names):
    """(Terraform resource type, attributes) pairs of observability among a stack's declared resources."""
    return [*(("aws_cloudwatch_log_group", {
                  "arn": (names.get(f"{lid}.Arn") or "").removesuffix(":*") or None,
                  "name": p.get("LogGroupName") or pid,
                  "retention_in_days": int(p["RetentionInDays"]) if str(p.get("RetentionInDays", "")).isdigit()
                  else None, "kms_key_id": p.get("KmsKeyId"), "tags": tag_map(p.get("Tags"))})
              for lid, p, pid in _of(declared, "AWS::Logs::LogGroup")),
            *(("aws_cloudwatch_metric_alarm", _alarm(lid, p, pid, names))
              for lid, p, pid in _of(declared, "AWS::CloudWatch::Alarm")),
            *(("aws_synthetics_canary", _canary(p, pid, names))
              for _, p, pid in _of(declared, "AWS::Synthetics::Canary"))]
