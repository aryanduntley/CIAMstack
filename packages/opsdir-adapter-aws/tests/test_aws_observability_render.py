"""CloudWatch alarms and log groups rendered from the record: each delivered alert rule through the alarm binding
realizing it (its metric, name and role), the condition in CloudWatch's terms, the channel's SNS topic; log groups
keeping logs as long as recorded, raised to a retention CloudWatch allows."""
from opsdir.domains.observability.naming import ALERT_RULES
from opsdir_adapter_aws.observability import render_alarms, render_log_groups, retention
from network_fixtures import ALPHA, entry, model

TOPIC = "arn:aws:sns:us-east-1:111122223333:ciam-page"


def _rule(cn, **attrs):
    return entry(ALERT_RULES, cn, "ciamAlertRule", **attrs).replace(
        "objectClass: ciamAlertRule", "objectClass: ciamObject\nobjectClass: ciamAlertRule")


TREE = (f"dn: {ALERT_RULES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: alert-rules\n",
        _rule("replication-lag", ciamSignal="replication-delay", ciamTargetRole="ds", ciamComparison="gt",
              ciamThreshold="5000 ms", ciamEvaluationPeriod="5m", ciamAlertRole="alerts-page"),
        _rule("login-failures", ciamSignal="login-failures", ciamComparison="gt", ciamThreshold="50 /min",
              ciamEvaluationPeriod="10m", ciamAlertRole="alerts-page"),
        _rule("heap", ciamSignal="heap-used", ciamComparison="ge", ciamThreshold="90 %", ciamAlertRole="alerts-page"),
        _rule("disk", ciamSignal="disk-free", ciamComparison="eq", ciamThreshold="0", ciamAlertRole="alerts-page"),
        _rule("unalarmed", ciamSignal="cert-expiry", ciamComparison="lt", ciamThreshold="30 d",
              ciamAlertRole="alerts-page"),
        _rule("elsewhere", ciamSignal="cert-expiry", ciamAlertRole="alerts-ticket"))


def _alarm(cn, realizes, metric, **extra):
    return entry(ALPHA, cn, "ciamAlarmBinding", ciamBindingRole=f"alarm-{realizes}", ciamRealizes=realizes,
                 ciamProviderRef=f"arn:aws:cloudwatch:us-east-1:111122223333:alarm:{cn}", ciamMetric=metric, **extra)


ALPHA_BINDINGS = (
    entry(ALPHA, "page", "ciamAlertChannel", ciamBindingRole="alerts-page", ciamChannelKind="topic",
          ciamProviderRef=TOPIC),
    _alarm("ds-replication-lag", "replication-lag", "CIAM/DS ReplicationDelay"),
    _alarm("pf-login-failures", "login-failures", "CIAM/PingFederate LoginFailures"),
    _alarm("ds-heap", "heap", "CWAgent mem_used_percent"),
    _alarm("ds-disk", "disk", "CWAgent disk_free"),
    entry(ALPHA, "audit", "ciamLogDestination", ciamBindingRole="audit-logs", ciamDestinationKind="log-group",
          ciamRetentionDays="400", ciamProviderRef="arn:aws:logs:us-east-1:111122223333:log-group:/ciam/audit"),
    entry(ALPHA, "ops", "ciamLogDestination", ciamBindingRole="ops-logs", ciamDestinationKind="log-group",
          ciamRetentionDays="45", ciamProviderRef="arn:aws:logs:us-east-1:111122223333:log-group:/ciam/ops:*"),
    entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
          ciamProviderRef="splunk://ciam"),
)


def _alpha():
    _, alpha, _ = model(alpha=ALPHA_BINDINGS, tree=TREE)
    return alpha


def test_a_rule_renders_through_the_alarm_realizing_it():
    text = "\n".join(render_alarms(_alpha()))
    assert ('resource "aws_cloudwatch_metric_alarm" "ds_replication_lag" {\n'
            '  alarm_name          = "ds-replication-lag"\n'
            '  alarm_description   = "Alert rule replication-lag: replication-delay gt 5000 ms (opsdir)"\n'
            '  namespace           = "CIAM/DS"\n'
            '  metric_name         = "ReplicationDelay"\n'
            '  statistic           = "Average"\n'
            '  period              = 60\n'
            '  evaluation_periods  = 5\n'
            '  comparison_operator = "GreaterThanThreshold"\n'
            '  threshold           = 5000\n'
            '  unit                = "Milliseconds"\n'
            f'  alarm_actions       = ["{TOPIC}"]\n'
            f'  ok_actions          = ["{TOPIC}"]\n') in text
    assert ('  tags = {\n    Realizes    = "replication-lag"\n    BindingRole = "alarm-replication-lag"\n  }'
            in text)


def test_rates_are_counted_per_window_and_shares_in_percent():
    text = "\n".join(render_alarms(_alpha()))
    login = text.split('"pf_login_failures" {', 1)[1].split("}", 1)[0]
    assert 'statistic           = "Sum"' in login and "threshold           = 50" in login
    assert 'unit                = "Count"' in login and "evaluation_periods  = 10" in login
    heap = text.split('"ds_heap" {', 1)[1].split("}", 1)[0]
    assert "threshold           = 90" in heap and 'unit                = "Percent"' in heap


def test_what_cloudwatch_cant_say_or_nothing_realizes_is_named():
    notes = [x for x in render_alarms(_alpha()) if x.startswith("#")]
    assert notes == [
        "# NOTE: alert rule disk: not rendered: CloudWatch has no comparison 'eq'",
        "# NOTE: alert rule unalarmed: not rendered: no alarm in alpha/prod realizes it (a ciamAlarmBinding with "
        "ciamRealizes unalarmed): record the one the cloud runs, or let Prometheus evaluate it"]
    # elsewhere goes to alerts-ticket, which alpha doesn't bind: the planner's blocker, not rendered or named here


def test_log_groups_keep_logs_as_long_as_cloudwatch_allows():
    text = "\n".join(render_log_groups(_alpha()))
    assert ('resource "aws_cloudwatch_log_group" "audit" {\n  name              = "/ciam/audit"\n'
            "  retention_in_days = 400\n") in text
    assert "# 45 days isn't a CloudWatch retention: raised to 60" in text and 'name              = "/ciam/ops"' in text
    assert "siem" not in text
    assert [retention(d) for d in (0, 1, 731, 4000)] == [
        (0, None), (1, None), (731, None), (0, "4000 days is longer than CloudWatch keeps logs (3653): kept "
                                               "indefinitely")]
