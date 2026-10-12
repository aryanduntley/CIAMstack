"""AWS monitoring from Terraform state: CloudWatch log groups as log destinations (retention, 0 never expiring),
SNS topics an alarm notifies as alert channels (other topics stay stream carriers), CloudWatch metric alarms and
Synthetics canaries as what the cloud runs, each naming the alert rule or canary it realizes (tag Realizes). The AWS
CLI's outputs of the same resources read as the same record (tags saved by name; a canary's ARN from its engine's)."""
import json

from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.inventory import state_resources

PAGE, EVENTS = "arn:aws:sns:us-east-1:111122223333:ciam-page", "arn:aws:sns:us-east-1:111122223333:ciam-events"
LOGIN = "arn:aws:synthetics:us-east-1:111122223333:canary:ciam-login"


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


STATE = _state(
    ("aws_sns_topic", "page", {"arn": PAGE, "name": "ciam-page", "tags": {"Role": "alerts-page"}}),
    ("aws_sns_topic", "events", {"arn": EVENTS, "name": "ciam-events", "tags": {"Role": "audit-events"}}),
    ("aws_cloudwatch_log_group", "audit", {"arn": "arn:logs:audit", "name": "/ciam/audit", "retention_in_days": 400,
                                           "tags": {"Role": "audit-logs"}}),
    ("aws_cloudwatch_log_group", "debug", {"arn": "arn:logs:debug", "name": "/ciam/debug", "retention_in_days": 0}),
    ("aws_cloudwatch_metric_alarm", "lag", {"arn": "arn:cw:alarm:ds-lag", "alarm_name": "ds-replication-lag",
                                            "namespace": "CIAM/DS", "metric_name": "ReplicationDelay",
                                            "alarm_actions": [PAGE], "ok_actions": [PAGE],
                                            "tags": {"Realizes": "replication-lag"}}),
    ("aws_cloudwatch_metric_alarm", "math", {"arn": "arn:cw:alarm:errors", "alarm_name": "ldaps-errors",
                                             "metric_query": [{"id": "e1"}]}),
    ("aws_synthetics_canary", "login", {"arn": LOGIN, "name": "ciam-login",
                                        "schedule": [{"expression": "rate(5 minutes)"}],
                                        "tags": {"Realizes": "login"}}))


def _of(kind):
    return {r.ref: r for r in state_resources(STATE)[0] if r.kind == kind}


def test_a_topic_an_alarm_notifies_is_an_alert_channel_and_others_carry_streams():
    assert {ref: (r.attrs, r.role) for ref, r in _of("channel").items()} == {
        PAGE: ({"ciamChannelKind": ("topic",)}, "alerts-page")}
    assert set(_of("stream")) == {EVENTS}


def test_log_groups_keep_logs_for_their_retention():
    assert {ref: (r.attrs["ciamRetentionDays"], r.role) for ref, r in _of("logs").items()} == {
        "arn:logs:audit": (("400",), "audit-logs"), "arn:logs:debug": (("0",), None)}


def test_alarms_and_canaries_name_what_they_realize():
    alarms, canaries = _of("alarm"), _of("canary")
    lag = alarms["arn:cw:alarm:ds-lag"]
    assert (lag.name, lag.role, lag.attrs) == ("ds-replication-lag", "alarm-replication-lag", {
        "ciamMetric": ("CIAM/DS ReplicationDelay",), "ciamRealizes": ("replication-lag",),
        "ciamNotifies": (PAGE,)})
    assert (alarms["arn:cw:alarm:errors"].attrs, alarms["arn:cw:alarm:errors"].role) == (
        {"ciamMetric": ("metric query",)}, None)                     # untagged: named, not recorded
    login = canaries[LOGIN]
    assert (login.role, login.attrs) == ("canary-login", {"ciamInterval": ("5m",), "ciamRealizes": ("login",)})


CLI = {
    "alarms.json": {"MetricAlarms": [
        {"AlarmArn": "arn:cw:alarm:ds-lag", "AlarmName": "ds-replication-lag", "Namespace": "CIAM/DS",
         "MetricName": "ReplicationDelay", "AlarmActions": [PAGE], "OKActions": [PAGE], "InsufficientDataActions": []},
        {"AlarmArn": "arn:cw:alarm:errors", "AlarmName": "ldaps-errors", "Metrics": [{"Id": "e1"}]}]},
    "alarm-tags/ds-replication-lag.json": {"Tags": [{"Key": "Realizes", "Value": "replication-lag"}]},
    "log-groups.json": {"logGroups": [
        {"logGroupName": "/ciam/audit", "arn": "arn:logs:audit:*", "logGroupArn": "arn:logs:audit",
         "retentionInDays": 400},
        {"logGroupName": "/ciam/debug", "arn": "arn:logs:debug:*"}]},
    "log-group-tags/%2Fciam%2Faudit.json": {"tags": {"Role": "audit-logs"}},
    "canaries.json": {"Canaries": [
        {"Name": "ciam-login", "Schedule": {"Expression": "rate(5 minutes)"}, "Tags": {"Realizes": "login"},
         "EngineArn": "arn:aws:lambda:us-east-1:111122223333:function:cwsyn-ciam-login-1a2b:3"},
        {"Name": "ciam-new", "Schedule": {"Expression": "rate(1 hour)"}}]},
    "topics.json": {"Topics": [{"TopicArn": PAGE}, {"TopicArn": EVENTS}]},
    "topic-tags/ciam-page.json": {"Tags": [{"Key": "Role", "Value": "alerts-page"}]},
    "topic-tags/ciam-events.json": {"Tags": [{"Key": "Role", "Value": "audit-events"}]}}
KINDS = ("channel", "stream", "logs", "alarm", "canary")


def test_the_cli_reads_the_same_monitoring_as_state():
    resources, notices = cli_resources({p: json.dumps(doc) for p, doc in CLI.items()})
    assert {r.ref: r for r in resources if r.kind in KINDS} == \
        {r.ref: r for r in state_resources(STATE)[0] if r.kind in KINDS}
    assert ("synthetics: canary ciam-new has no engine ARN to tell its ARN by (not created yet?); not read"
            in notices)
    assert not [n for n in notices if "not an AWS CLI output" in n]       # every tags file is recognized
