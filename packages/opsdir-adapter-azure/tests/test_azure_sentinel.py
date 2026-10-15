"""Microsoft Sentinel on a Log Analytics workspace: a SIEM index on a workspace is rendered as the workspace, Sentinel
turned on for it, and each detection on it as a scheduled analytics rule counting events per window; what isn't
rendered is named; routes ship to it like any workspace, their tables keeping logs as long in all as recorded; and
state reads it back as the same SIEM index and detections."""
import json

from opsdir.core.notes import note_comment
from opsdir.domains.observability.naming import ALERT_RULES
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_azure.inventory import state_resources
from opsdir_adapter_azure.log_collection import total_retention
from opsdir_adapter_azure.observability import render_workspaces, workspace_id
from opsdir_adapter_azure.sentinel import (base_query, detection_query, is_sentinel, keeps, render_sentinel,
                                           sentinel_notes)
from network_fixtures import BETA, entry, model

WS = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam/providers/"
      "Microsoft.OperationalInsights/workspaces/law-ciam-sentinel")
RULE_ID = f"{WS}/providers/Microsoft.SecurityInsights/alertRules/ciam-login-failures"
QUERY = 'CiamSecurity_CL | where RawData has "FAILURE"'


def _rule(cn, **attrs):
    return (f"dn: cn={cn},{ALERT_RULES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamAlertRule\n"
            f"cn: {cn}\n" + "".join(f"{k}: {v}\n" for k, v in attrs.items()))


TREE = (f"dn: {ALERT_RULES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: alert-rules\n",
        _rule("login-failures", ciamSignal="login-failures", ciamComparison="gt", ciamThreshold="50 /min",
              ciamEvaluationPeriod="5m", ciamSeverity="sev1", ciamAlertRole="alerts-page"),
        _rule("too-fast", ciamSignal="logins", ciamComparison="gt", ciamThreshold="5 /min",
              ciamEvaluationPeriod="1m", ciamAlertRole="alerts-page"))
SENTINEL = entry(BETA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                 ciamProviderRef=WS, ciamRetentionDays="90", ciamTotalRetentionDays="365")
BINDINGS = (SENTINEL,
            entry(BETA, "page", "ciamAlertChannel", ciamBindingRole="alerts-page", ciamChannelKind="action-group",
                  ciamProviderRef="/subscriptions/0/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/ag"),
            entry(BETA, "det-login", "ciamAlarmBinding", ciamBindingRole="alarm-login-failures",
                  ciamProviderRef=RULE_ID, ciamRealizes="login-failures", ciamMetric=QUERY,
                  ciamLogDestinationRole="siem"),
            entry(BETA, "det-fast", "ciamAlarmBinding", ciamBindingRole="alarm-too-fast",
                  ciamProviderRef=f"{WS}/providers/Microsoft.SecurityInsights/alertRules/ciam-too-fast",
                  ciamRealizes="too-fast", ciamMetric=QUERY, ciamLogDestinationRole="siem"))


def _beta(*bindings):
    _, _, beta = model(beta=bindings or BINDINGS, tree=TREE)
    return beta


def _siem(m):
    return next(b for b in m.bindings if b.dn.startswith("cn=siem,"))


def test_a_siem_index_on_a_workspace_is_sentinel_and_the_azure_adapter_keeps_it():
    m = _beta()
    assert is_sentinel(_siem(m)) and keeps(m, _siem(m))
    splunk = entry(BETA, "splunk", "ciamLogDestination", ciamBindingRole="splunk", ciamDestinationKind="siem-index",
                   ciamProviderRef="ciam_security")
    other = _beta(*BINDINGS, splunk)
    index = next(b for b in other.bindings if b.dn.startswith("cn=splunk,"))
    assert not keeps(other, index) and workspace_id(other, index) is None
    assert workspace_id(m, _siem(m)) == "${azurerm_log_analytics_workspace.siem.id}"


def test_the_workspace_sentinel_and_each_detection_as_a_scheduled_analytics_rule():
    m = _beta()
    workspaces = "\n".join(as_text(render_workspaces(m)))
    assert 'name                = "law-ciam-sentinel"' in workspaces and "retention_in_days   = 90" in workspaces
    text = "\n".join(as_text(render_sentinel(m)))
    assert ('resource "azurerm_sentinel_log_analytics_workspace_onboarding" "siem" {\n'
            "  workspace_id = azurerm_log_analytics_workspace.siem.id\n}") in text
    assert 'resource "azurerm_sentinel_alert_rule_scheduled" "det_login" {' in text
    rule = text.split('"det_login" {', 1)[1].split("\n}", 1)[0]
    for line in ('name                       = "ciam-login-failures"',
                 "log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.siem.workspace_id",
                 'display_name               = "login-failures"',
                 'description                = "opsdir: realizes alert rule login-failures"',
                 'severity                   = "High"', 'query_frequency            = "PT5M"',
                 'query_period               = "PT5M"', 'trigger_operator           = "GreaterThan"',
                 "trigger_threshold          = 0"):
        assert line in rule, line
    assert "det_fast" not in text.split("# NOTE")[0]
    assert ("# NOTE: alert rule too-fast: not rendered: its evaluation period (60s) is shorter than Sentinel runs a "
            "scheduled rule (every 5 minutes at the most often)") in text


def test_the_query_counts_events_per_window_and_reads_back_as_written():
    m = _beta()
    from opsdir.domains.observability.alarms import condition
    rule = next(e for e in m.d.entries.values() if e.dn.startswith("cn=login-failures,"))
    wrapped = detection_query(QUERY, rule, condition(rule))
    assert wrapped == (f"{QUERY} | summarize events = count() by bin(TimeGenerated, 60s) | where events > 50 | "
                       "summarize breaching = count() | where breaching >= 5")
    assert base_query(wrapped) == QUERY and base_query("SecurityEvent | take 1") == "SecurityEvent | take 1"


def test_what_sentinel_leaves_to_a_person_is_named():
    texts = [(n.severity, note_comment(n)) for n in sentinel_notes(_beta())]
    assert ("note", "NOTE: log destination siem: keeps logs 365 days in all on the tables opsdir renders for its "
            "routes "
            "(Ciam<route>_CL); its other tables (Sentinel's own, the containers' ContainerLogV2) keep the workspace's "
            "retention unless set by hand") in texts
    assert [s for s, t in texts if "too-fast" in t] == ["blocker"]


def test_a_routes_table_keeps_logs_as_long_in_all_as_recorded():
    m = _beta()
    assert total_retention(_siem(m)) == (("total_retention_in_days", 365),)
    forever = _beta(SENTINEL.replace("ciamTotalRetentionDays: 365", "ciamTotalRetentionDays: 0"))
    assert total_retention(_siem(forever))[-1] == ("total_retention_in_days", 4383)


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


def test_state_reads_sentinel_back_as_the_siem_index_and_its_detections():
    from opsdir_adapter_azure.sentinel import detection_query as wrap
    from opsdir.domains.observability.alarms import condition
    rule = next(e for e in _beta().d.entries.values() if e.dn.startswith("cn=login-failures,"))
    state = _state(
        ("azurerm_log_analytics_workspace", "siem", {"id": WS, "name": "law-ciam-sentinel", "retention_in_days": 90}),
        ("azurerm_log_analytics_workspace", "plain", {"id": "/ws/plain", "name": "law-plain"}),
        ("azurerm_sentinel_log_analytics_workspace_onboarding", "siem", {"id": "/onboard", "workspace_id": WS}),
        ("azurerm_sentinel_alert_rule_scheduled", "det", {
            "id": RULE_ID, "name": "ciam-login-failures", "log_analytics_workspace_id": WS,
            "description": "opsdir: realizes alert rule login-failures",
            "query": wrap(QUERY, rule, condition(rule))}))
    found = {r.ref: r for r in state_resources(state)[0]}
    assert found[WS].attrs["ciamDestinationKind"] == ("siem-index",)
    assert found["/ws/plain"].attrs["ciamDestinationKind"] == ("workspace",)
    det = found[RULE_ID]
    assert (det.kind, det.role, det.attrs, dict(det.links)) == (
        "alarm", "alarm-login-failures", {"ciamRealizes": ("login-failures",), "ciamMetric": (QUERY,)},
        {"ciamLogDestinationRole": WS})
