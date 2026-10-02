"""AWS monitoring from Terraform state: CloudWatch log groups as log destinations (retention, 0 never expiring),
SNS topics an alarm notifies as alert channels (other topics stay stream carriers), CloudWatch metric alarms and
Synthetics canaries as what the cloud runs, each naming the alert rule or canary it realizes (tag Realizes)."""
import json

from opsdir_adapter_aws.inventory import state_resources


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


STATE = _state(
    ("aws_sns_topic", "page", {"arn": "arn:sns:page", "name": "ciam-page", "tags": {"Role": "alerts-page"}}),
    ("aws_sns_topic", "events", {"arn": "arn:sns:events", "name": "ciam-events", "tags": {"Role": "audit-events"}}),
    ("aws_cloudwatch_log_group", "audit", {"arn": "arn:logs:audit", "name": "/ciam/audit", "retention_in_days": 400,
                                           "tags": {"Role": "audit-logs"}}),
    ("aws_cloudwatch_log_group", "debug", {"arn": "arn:logs:debug", "name": "/ciam/debug", "retention_in_days": 0}),
    ("aws_cloudwatch_metric_alarm", "lag", {"arn": "arn:cw:alarm:ds-lag", "alarm_name": "ds-replication-lag",
                                            "namespace": "CIAM/DS", "metric_name": "ReplicationDelay",
                                            "alarm_actions": ["arn:sns:page"], "ok_actions": ["arn:sns:page"],
                                            "tags": {"Realizes": "replication-lag"}}),
    ("aws_cloudwatch_metric_alarm", "math", {"arn": "arn:cw:alarm:errors", "alarm_name": "ldaps-errors",
                                             "metric_query": [{"id": "e1"}]}),
    ("aws_synthetics_canary", "login", {"arn": "arn:synthetics:login", "name": "ciam-login",
                                        "schedule": [{"expression": "rate(5 minutes)"}],
                                        "tags": {"Realizes": "login"}}))


def _of(kind):
    return {r.ref: r for r in state_resources(STATE)[0] if r.kind == kind}


def test_a_topic_an_alarm_notifies_is_an_alert_channel_and_others_carry_streams():
    assert {ref: (r.attrs, r.role) for ref, r in _of("channel").items()} == {
        "arn:sns:page": ({"ciamChannelKind": ("topic",)}, "alerts-page")}
    assert set(_of("stream")) == {"arn:sns:events"}


def test_log_groups_keep_logs_for_their_retention():
    assert {ref: (r.attrs["ciamRetentionDays"], r.role) for ref, r in _of("logs").items()} == {
        "arn:logs:audit": (("400",), "audit-logs"), "arn:logs:debug": (("0",), None)}


def test_alarms_and_canaries_name_what_they_realize():
    alarms, canaries = _of("alarm"), _of("canary")
    lag = alarms["arn:cw:alarm:ds-lag"]
    assert (lag.name, lag.role, lag.attrs) == ("ds-replication-lag", "alarm-replication-lag", {
        "ciamMetric": ("CIAM/DS ReplicationDelay",), "ciamRealizes": ("replication-lag",),
        "ciamNotifies": ("arn:sns:page",)})
    assert (alarms["arn:cw:alarm:errors"].attrs, alarms["arn:cw:alarm:errors"].role) == (
        {"ciamMetric": ("metric query",)}, None)                     # untagged: named, not recorded
    login = canaries["arn:synthetics:login"]
    assert (login.role, login.attrs) == ("canary-login", {"ciamInterval": ("5m",), "ciamRealizes": ("login",)})
