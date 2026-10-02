"""Azure monitoring from Terraform state: action groups as alert channels, Log Analytics workspaces as log
destinations (retention), metric and log-query alerts and Application Insights standard web tests as what the cloud
runs, each naming the alert rule or canary it realizes (tag Realizes)."""
import json

from opsdir_adapter_azure.inventory import state_resources

AG = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/ag-page"


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


STATE = _state(
    ("azurerm_monitor_action_group", "page", {"id": AG, "name": "ag-page", "tags": {"Role": "alerts-page"}}),
    ("azurerm_log_analytics_workspace", "audit", {"id": "/ws/audit", "name": "law-audit", "retention_in_days": 90,
                                                  "tags": {"Role": "audit-logs"}}),
    ("azurerm_monitor_metric_alert", "lag", {"id": "/alerts/lag", "name": "ds-replication-lag",
                                             "criteria": [{"metric_namespace": "Microsoft.Compute/virtualMachines",
                                                           "metric_name": "Percentage CPU"}],
                                             "action": [{"action_group_id": AG}],
                                             "tags": {"Realizes": "replication-lag"}}),
    ("azurerm_monitor_scheduled_query_rules_alert_v2", "logins", {"id": "/alerts/logins", "name": "login-failures",
                                                                  "action": [{"action_groups": [AG]}],
                                                                  "tags": {"Realizes": "login-failures"}}),
    ("azurerm_application_insights_standard_web_test", "login", {"id": "/tests/login", "name": "ciam-login",
                                                                 "frequency": 300, "tags": {"Realizes": "login"}}))


def _of(kind):
    return {r.ref: r for r in state_resources(STATE)[0] if r.kind == kind}


def test_action_groups_deliver_alerts_and_workspaces_keep_logs():
    assert {ref: (r.attrs, r.role) for ref, r in _of("channel").items()} == {
        AG: ({"ciamChannelKind": ("action-group",)}, "alerts-page")}
    assert {ref: (r.attrs, r.role) for ref, r in _of("logs").items()} == {
        "/ws/audit": ({"ciamDestinationKind": ("workspace",), "ciamRetentionDays": ("90",)}, "audit-logs")}


def test_alerts_and_web_tests_name_what_they_realize():
    alarms = _of("alarm")
    assert {ref: (r.role, r.attrs) for ref, r in alarms.items()} == {
        "/alerts/lag": ("alarm-replication-lag", {"ciamMetric": ("Microsoft.Compute/virtualMachines Percentage CPU",),
                                                  "ciamNotifies": (AG,), "ciamRealizes": ("replication-lag",)}),
        "/alerts/logins": ("alarm-login-failures", {"ciamMetric": ("log query",), "ciamNotifies": (AG,),
                                                    "ciamRealizes": ("login-failures",)})}
    login = _of("canary")["/tests/login"]
    assert (login.role, login.attrs) == ("canary-login", {"ciamInterval": ("5m",), "ciamRealizes": ("login",)})
