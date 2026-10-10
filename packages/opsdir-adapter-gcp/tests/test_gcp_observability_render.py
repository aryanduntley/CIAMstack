"""Cloud Monitoring alert policies and Cloud Logging buckets rendered from the record: each delivered alert rule
through the alarm binding realizing it (its metric type, name and role), the condition held for the rule's period,
the channel's notification channel; log buckets keeping logs as recorded, named for locking under legal hold, never
locked here."""
from opsdir.domains.observability.naming import ALERT_RULES, LOG_ROUTES
from opsdir_adapter_gcp.observability import bucket_retention, render_buckets, render_policies
from network_fixtures import BETA, entry, model

PROJECT = "projects/example-standby"
CHANNEL = f"{PROJECT}/notificationChannels/1001"


def _intent(base, oc, cn, **attrs):
    return entry(base, cn, oc, **attrs).replace(f"objectClass: {oc}", f"objectClass: ciamObject\nobjectClass: {oc}")


TREE = (f"dn: {ALERT_RULES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: alert-rules\n",
        _intent(ALERT_RULES, "ciamAlertRule", "replication-lag", ciamSignal="replication-delay",
                ciamTargetRole="ds", ciamComparison="gt", ciamThreshold="5000 ms", ciamEvaluationPeriod="5m",
                ciamAlertRole="alerts-page"),
        _intent(ALERT_RULES, "ciamAlertRule", "login-failures", ciamSignal="login-failures", ciamComparison="gt",
                ciamThreshold="50 /min", ciamAlertRole="alerts-page"),
        f"dn: {LOG_ROUTES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: log-routes\n",
        _intent(LOG_ROUTES, "ciamLogRoute", "audit", ciamLogKind="audit", ciamLogDestinationRole="audit-logs",
                ciamRetentionDays="400", ciamLegalHold="TRUE"))

BETA_BINDINGS = (
    entry(BETA, "page", "ciamAlertChannel", ciamBindingRole="alerts-page", ciamChannelKind="paging-service",
          ciamProviderRef=CHANNEL),
    entry(BETA, "ds-replication-lag", "ciamAlarmBinding", ciamBindingRole="alarm-replication-lag",
          ciamRealizes="replication-lag", ciamProviderRef=f"{PROJECT}/alertPolicies/2001",
          ciamMetric="custom.googleapis.com/ds/replication_delay"),
    entry(BETA, "pf-login-failures", "ciamAlarmBinding", ciamBindingRole="alarm-login-failures",
          ciamRealizes="login-failures", ciamProviderRef=f"{PROJECT}/alertPolicies/2002", ciamMetric="log query"),
    entry(BETA, "audit", "ciamLogDestination", ciamBindingRole="audit-logs", ciamDestinationKind="log-group",
          ciamRetentionDays="400", ciamProviderRef=f"{PROJECT}/locations/global/buckets/ciam-audit"),
    entry(BETA, "ops", "ciamLogDestination", ciamBindingRole="ops-logs", ciamDestinationKind="log-group",
          ciamRetentionDays="0", ciamProviderRef=f"{PROJECT}/locations/global/buckets/ciam-ops"),
)


def _beta():
    _, _, beta = model(beta=BETA_BINDINGS, tree=TREE)
    return beta


def test_a_rule_renders_through_the_alarm_realizing_it():
    text = "\n".join(render_policies(_beta()))
    assert ('resource "google_monitoring_alert_policy" "ds_replication_lag" {\n'
            '  display_name = "ds-replication-lag"\n  combiner     = "OR"\n') in text
    assert ('    condition_threshold {\n'
            '      # compared in milliseconds: the metric must report milliseconds\n'
            '      filter          = "metric.type = \\"custom.googleapis.com/ds/replication_delay\\""\n'
            '      comparison      = "COMPARISON_GT"\n'
            '      threshold_value = 5000\n'
            '      duration        = "300s"\n'
            '      aggregations {\n'
            '        alignment_period   = "60s"\n'
            '        per_series_aligner = "ALIGN_MEAN"\n') in text
    assert f'notification_channels = ["{CHANNEL}"]' in text
    assert 'realizes    = "replication-lag"' in text and 'bindingrole = "alarm-replication-lag"' in text


def test_a_log_based_alarm_is_named():
    assert [x for x in render_policies(_beta()) if x.startswith("#")] == [
        "# NOTE: alert rule login-failures: not rendered: its alarm is a log-based alert and the record holds no "
        "query"]


def test_log_buckets_keep_logs_as_recorded_and_are_named_for_locking_under_legal_hold():
    text = "\n".join(render_buckets(_beta()))
    audit = text.split('"audit" {', 1)[1].split("\n}", 1)[0]
    assert "# under legal hold: lock it (locked = true) once its retention is confirmed" in audit
    assert 'project        = "example-standby"' in audit and 'bucket_id      = "ciam-audit"' in audit
    assert "retention_days = 400" in audit
    assert not any(line.strip().startswith("locked") for line in audit.splitlines())       # never locked here
    assert "# indefinitely is longer than a log bucket keeps logs (3650): kept 3650" in text
    assert bucket_retention(30) == (30, None)
