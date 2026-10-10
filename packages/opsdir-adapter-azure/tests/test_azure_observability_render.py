"""Azure Monitor metric alerts and Log Analytics workspaces rendered from the record: each delivered alert rule
through the alarm binding realizing it, on the target role's virtual machines, with the window Azure allows and the
channel's action group; workspaces keeping logs within what a workspace allows."""
from opsdir.domains.observability.naming import ALERT_RULES
from opsdir_adapter_azure.observability import iso_duration, render_alerts, render_workspaces, workspace_retention
from network_fixtures import BETA, entry, model

BETA_SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
INSIGHTS = f"{BETA_SUB}/resourceGroups/rg-ciam/providers/Microsoft.Insights"
GROUP = f"{INSIGHTS}/actionGroups/ag-ciam-page"


def _rule(cn, **attrs):
    return entry(ALERT_RULES, cn, "ciamAlertRule", **attrs).replace(
        "objectClass: ciamAlertRule", "objectClass: ciamObject\nobjectClass: ciamAlertRule")


TREE = (f"dn: {ALERT_RULES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: alert-rules\n",
        _rule("replication-lag", ciamSignal="replication-delay", ciamTargetRole="ds", ciamComparison="gt",
              ciamThreshold="5000 ms", ciamEvaluationPeriod="5m", ciamSeverity="sev2", ciamAlertRole="alerts-page"),
        _rule("login-failures", ciamSignal="login-failures", ciamTargetRole="web", ciamComparison="gt",
              ciamThreshold="50 /min", ciamEvaluationPeriod="10m", ciamAlertRole="alerts-page"),
        _rule("queried", ciamSignal="login-failures", ciamTargetRole="web", ciamComparison="gt",
              ciamThreshold="5", ciamAlertRole="alerts-page"),
        _rule("not-equal", ciamSignal="heap-used", ciamTargetRole="ds", ciamComparison="ne", ciamThreshold="0",
              ciamAlertRole="alerts-page"))


def _alarm(cn, realizes, metric):
    return entry(BETA, cn, "ciamAlarmBinding", ciamBindingRole=f"alarm-{realizes}", ciamRealizes=realizes,
                 ciamProviderRef=f"{INSIGHTS}/metricAlerts/{cn}", ciamMetric=metric)


BETA_BINDINGS = (
    entry(BETA, "page", "ciamAlertChannel", ciamBindingRole="alerts-page", ciamChannelKind="action-group",
          ciamProviderRef=GROUP),
    _alarm("ds-replication-lag", "replication-lag", "Microsoft.Compute/virtualMachines ReplicationDelay"),
    _alarm("web-login-failures", "login-failures", "CIAM LoginFailures"),
    _alarm("web-queried", "queried", "log query"),
    _alarm("ds-heap", "not-equal", "Microsoft.Compute/virtualMachines Heap"),
    entry(BETA, "audit", "ciamLogDestination", ciamBindingRole="audit-logs", ciamDestinationKind="workspace",
          ciamRetentionDays="400", ciamProviderRef=f"{BETA_SUB}/resourceGroups/rg-ciam/providers/"
                                                   "Microsoft.OperationalInsights/workspaces/law-ciam-audit"),
    entry(BETA, "forever", "ciamLogDestination", ciamBindingRole="forever-logs", ciamDestinationKind="workspace",
          ciamRetentionDays="0", ciamProviderRef=f"{BETA_SUB}/resourceGroups/rg-ciam/providers/"
                                                 "Microsoft.OperationalInsights/workspaces/law-ciam-forever"),
)


def _beta():
    _, _, beta = model(beta=BETA_BINDINGS, tree=TREE)
    return beta


def test_a_rule_renders_on_its_roles_virtual_machines():
    text = "\n".join(render_alerts(_beta()))
    lag = text.split('resource "azurerm_monitor_metric_alert" "ds_replication_lag" {', 1)[1].split("\n}", 1)[0]
    assert 'name                     = "ds-replication-lag"' in lag
    assert "scopes                   = [azurerm_linux_virtual_machine.ds_1.id, azurerm_linux_virtual_machine.ds_2.id]" \
        in lag
    assert 'target_resource_type     = "Microsoft.Compute/virtualMachines"' in lag
    assert "severity                 = 2" in lag and 'window_size              = "PT5M"' in lag
    assert ('    # compared in milliseconds: the metric must report milliseconds\n'
            '    metric_namespace = "Microsoft.Compute/virtualMachines"\n'
            '    metric_name      = "ReplicationDelay"\n'
            '    aggregation      = "Average"\n'
            '    operator         = "GreaterThan"\n'
            '    threshold        = 5000\n') in lag
    assert f'action_group_id = "{GROUP}"' in lag and 'Realizes    = "replication-lag"' in lag


def test_a_rate_is_the_total_over_the_window_azure_allows():
    text = "\n".join(render_alerts(_beta()))
    login = text.split('"web_login_failures" {', 1)[1].split("\n}", 1)[0]
    assert 'window_size         = "PT15M"' in login and 'frequency           = "PT5M"' in login
    assert "# 50 /min as the total over the window" in login
    assert 'aggregation      = "Total"' in login and "threshold        = 750" in login       # 50/min over 15 minutes
    assert "target_resource_type" not in login                                               # one VM: web-1


def test_what_a_metric_alert_cant_say_is_named():
    notes = [x for x in render_alerts(_beta()) if x.startswith("#")]
    assert notes == [
        "# NOTE: alert rule not-equal: not rendered: a metric alert has no comparison 'ne'",
        "# NOTE: alert rule queried: not rendered: its alarm is a log query alert and the record holds no query"]


def test_workspaces_keep_logs_within_what_a_workspace_allows():
    text = "\n".join(render_workspaces(_beta()))
    assert 'name                = "law-ciam-audit"' in text and "retention_in_days   = 400" in text
    assert "# indefinitely is longer than a workspace keeps logs (730): kept 730" in text
    assert [workspace_retention(d) for d in (7, 90)] == [
        (30, "7 days is less than a workspace keeps logs: raised to 30"), (90, None)]
    assert [iso_duration(s) for s in (60, 900, 21600, 86400)] == ["PT1M", "PT15M", "PT6H", "P1D"]
