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
                 "log_analytics_workspace_id = azurerm_log_analytics_workspace.siem.id",
                 "depends_on                 = [azurerm_sentinel_log_analytics_workspace_onboarding.siem]",
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
            "routes (their Ciam<route>_CL tables, and ContainerLogV2 for containers' logs); its other tables "
            "(Sentinel's own) keep the workspace's retention unless set by hand") in texts
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


# ------------------------------------------------------------------ ARM / Bicep (milestone 109, task 571)
def test_an_arm_render_deploys_sentinel_on_the_workspace_at_the_stable_api():
    from types import SimpleNamespace
    from opsdir_format_terraform.hcl import TfFile, ref, tf_block
    from opsdir_adapter_azure.arm_types import arm_translation
    rg = ref("data.azurerm_resource_group.main.name")
    root = TfFile("", (
        tf_block("data", ["azurerm_resource_group", "main"], [("name", "rg-a")]),
        tf_block("resource", ["azurerm_log_analytics_workspace", "siem"], [
            ("name", "law-ciam"), ("location", ref("data.azurerm_resource_group.main.location")),
            ("resource_group_name", rg), ("sku", "PerGB2018"), ("retention_in_days", 90)]),
        tf_block("resource", ["azurerm_sentinel_log_analytics_workspace_onboarding", "siem"], [
            ("workspace_id", ref("azurerm_log_analytics_workspace.siem.id"))]),
        tf_block("resource", ["azurerm_sentinel_alert_rule_scheduled", "det"], [
            ("name", "ciam-login-failures"),
            ("log_analytics_workspace_id", ref("azurerm_log_analytics_workspace.siem.id")),
            ("depends_on", [ref("azurerm_sentinel_log_analytics_workspace_onboarding.siem")]),
            ("display_name", "login-failures"), ("description", "opsdir: realizes alert rule login-failures"),
            ("severity", "High"), ("query", QUERY), ("query_frequency", "PT5M"), ("query_period", "PT5M"),
            ("trigger_operator", "GreaterThan"), ("trigger_threshold", 0), ("enabled", True)])))
    m = SimpleNamespace(dn="env=prod,cloud=alpha,ou=environments,dc=ciam-ops", label="alpha/prod")
    t = arm_translation(m, {"terraform/main.tf": root}, "Azure infrastructure")
    places = {k: v for k, v in t.placements["terraform"].items() if "sentinel" in k}
    assert len(places) == 2 and {v.kind for v in places.values()} == {"template"}  # nothing kept in Terraform
    resources = {r.type: r for (_, k), tpl in t.templates.items() for r in tpl.resources}
    onboarding = resources["Microsoft.SecurityInsights/onboardingStates"]
    rule = resources["Microsoft.SecurityInsights/alertRules"]
    assert onboarding.api_version == rule.api_version == "2025-09-01" and onboarding.name == "default"
    assert rule.fields["kind"] == "Scheduled" and rule.name == "ciam-login-failures"
    assert rule.scope == onboarding.scope                     # the workspace, never the onboarding
    assert {k: rule.properties[k] for k in ("queryFrequency", "suppressionEnabled", "triggerOperator",
                                             "triggerThreshold")} == {
        "queryFrequency": "PT5M", "suppressionEnabled": False, "triggerOperator": "GreaterThan",
        "triggerThreshold": 0}


def test_the_arm_read_back_puts_sentinels_parts_under_the_workspace_they_extend():
    """An extension resource (its scope the workspace) has its ID under the workspace, as Azure gives it: the
    onboarding makes the workspace a SIEM index and the rule is the detection the record names by that ID."""
    from opsdir_adapter_azure.arm import arm_resources
    scope = "[resourceId('Microsoft.OperationalInsights/workspaces', 'law-ciam-sentinel')]"
    template = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0", "resources": [
                    {"type": "Microsoft.OperationalInsights/workspaces", "apiVersion": "2025-07-01",
                     "name": "law-ciam-sentinel", "location": "eastus2", "properties": {"retentionInDays": 90}},
                    {"type": "Microsoft.SecurityInsights/onboardingStates", "apiVersion": "2025-09-01",
                     "scope": scope, "name": "default"},
                    {"type": "Microsoft.SecurityInsights/alertRules", "apiVersion": "2025-09-01", "scope": scope,
                     "name": "ciam-login-failures", "kind": "Scheduled",
                     "properties": {"description": "opsdir: realizes alert rule login-failures", "query": QUERY}}]}
    deployment = {"id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam/providers/"
                        "Microsoft.Resources/deployments/ciam", "properties": {}}
    found = {r.ref: r for r in arm_resources({"d/template.json": json.dumps(template),
                                              "d/deployment.json": json.dumps(deployment)})[0]}
    assert found[WS].attrs["ciamDestinationKind"] == ("siem-index",)
    assert (found[RULE_ID].kind, found[RULE_ID].role) == ("alarm", "alarm-login-failures")


# ------------------------------------------------------------------ the Azure CLI reader (milestone 109, task 571)
def test_the_cli_reads_sentinel_back_like_state_and_ignores_rules_it_doesnt_render():
    from opsdir.domains.observability.alarms import condition
    from opsdir_adapter_azure.cli import cli_resources
    rule = next(e for e in _beta().d.entries.values() if e.dn.startswith("cn=login-failures,"))
    si = "/providers/Microsoft.SecurityInsights"
    texts = {
        "workspaces.json": json.dumps([
            {"id": WS, "name": "law-ciam-sentinel", "type": "Microsoft.OperationalInsights/workspaces",
             "retentionInDays": 90},
            {"id": "/subscriptions/0/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/plain",
             "name": "plain", "type": "Microsoft.OperationalInsights/workspaces"}]),
        "sentinel-onboardingStates-law-ciam-sentinel.json": json.dumps({"value": [
            {"id": f"{WS}{si}/onboardingStates/default", "name": "default",
             "type": "Microsoft.SecurityInsights/onboardingStates", "properties": {}}]}),
        "sentinel-alertRules-law-ciam-sentinel.json": json.dumps({"value": [
            {"id": RULE_ID, "name": "ciam-login-failures", "type": "Microsoft.SecurityInsights/alertRules",
             "kind": "Scheduled", "properties": {"displayName": "login-failures",
                                                 "description": "opsdir: realizes alert rule login-failures",
                                                 "query": detection_query(QUERY, rule, condition(rule))}},
            {"id": f"{WS}{si}/alertRules/builtin-fusion", "name": "builtin-fusion",
             "type": "Microsoft.SecurityInsights/alertRules", "kind": "Fusion", "properties": {}}]}),
        "sentinel-onboardingStates-plain.json": json.dumps({"value": []})}
    found = {r.ref: r for r in cli_resources(texts)[0]}
    assert found[WS].attrs["ciamDestinationKind"] == ("siem-index",)          # not flipped to a plain workspace
    plain = next(r for ref_, r in found.items() if ref_.endswith("/workspaces/plain"))
    assert plain.attrs["ciamDestinationKind"] == ("workspace",)
    det = found[RULE_ID]
    assert (det.kind, det.role, det.attrs["ciamMetric"], dict(det.links)) == (
        "alarm", "alarm-login-failures", (QUERY,), {"ciamLogDestinationRole": WS})
    assert not any("builtin-fusion" in ref_ for ref_ in found)


def test_the_collector_asks_each_workspace_for_its_sentinel_parts_at_the_stable_api():
    from opsdir_adapter_azure.collect import _details
    done = {"workspaces.json": json.dumps([{"id": WS, "name": "law-ciam-sentinel"}])}
    steps = dict(_details(_beta(), "rg-ciam", done))
    for kind in ("onboardingStates", "alertRules"):
        argv = steps[f"sentinel-{kind}-law-ciam-sentinel.json"].argv
        assert argv[:4] == ("az", "rest", "--method", "get")
        assert argv[argv.index("--url") + 1].endswith(
            f"{WS}/providers/Microsoft.SecurityInsights/{kind}?api-version=2025-09-01")


# ---------------------------------------------------------- ATT&CK and entity mappings (milestone 109, task 572)
ROWS_QUERY = "CiamSecurity_CL | where RawData has 'FAILURE' | summarize n = count() by UserPrincipalName, IPAddress"
SPRAY = (f"dn: cn=password-spray,{ALERT_RULES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamAlertRule\n"
         "cn: password-spray\nciamSignal: login-failures\nciamEvaluationPeriod: 15m\nciamSeverity: sev1\n"
         "ciamAlertRole: alerts-page\nciamAttackTactic: credential-access\nciamAttackTechnique: T1110.003\n"
         "ciamAttackTechnique: T1078.004\n")
ROWS = entry(BETA, "det-spray", "ciamAlarmBinding", ciamBindingRole="alarm-password-spray",
             ciamProviderRef=f"{WS}/providers/Microsoft.SecurityInsights/alertRules/ciam-password-spray",
             ciamRealizes="password-spray", ciamMetric=ROWS_QUERY, ciamLogDestinationRole="siem",
             ciamDetectionMode="rows", ciamEntityMapping=("account name=UserPrincipalName", "ip address=IPAddress"))


def _rows_model():
    _, _, beta = model(beta=(*BINDINGS, ROWS), tree=(*TREE, SPRAY))
    return beta


def test_a_rows_detection_runs_as_written_one_alert_per_row_with_its_entities_and_attack_mapping():
    m = _rows_model()
    text = "\n\n".join(as_text(render_sentinel(m)))
    rule = text.split('resource "azurerm_sentinel_alert_rule_scheduled" "det_spray"', 1)[1].split("\n}\n", 1)[0]
    assert f"query                      = {json.dumps(ROWS_QUERY)}" in rule and "summarize breaching" not in rule
    for line in ('query_frequency            = "PT15M"', 'tactics                    = ["CredentialAccess"]',
                 'techniques                 = ["T1110", "T1078"]', 'aggregation_method = "AlertPerResult"',
                 'entity_type = "Account"', 'identifier  = "Name"', 'column_name = "UserPrincipalName"',
                 'entity_type = "IP"', 'identifier  = "Address"', 'column_name = "IPAddress"'):
        assert line in rule, line
    assert "# NOTE: alert rule password-spray: its sub-techniques T1110.003, T1078.004" in text


def test_attack_v20_tactics_render_as_the_v18_tactic_sentinel_names_with_a_note():
    from opsdir_adapter_azure.sentinel import sentinel_tactic
    assert [sentinel_tactic(t) for t in ("stealth", "defense-impairment", "defense-evasion", "credential-access")] == [
        "DefenseEvasion", "DefenseEvasion", "DefenseEvasion", "CredentialAccess"]
    spray = SPRAY.replace("ciamAttackTactic: credential-access\n",
                          "ciamAttackTactic: stealth\nciamAttackTactic: defense-impairment\n")
    _, _, m = model(beta=(*BINDINGS, ROWS), tree=(*TREE, spray))
    text = "\n\n".join(as_text(render_sentinel(m)))
    assert 'tactics                    = ["DefenseEvasion"]' in text
    assert ("# NOTE: alert rule password-spray: its ATT&CK tactics stealth, defense-impairment are rendered as "
            "DefenseEvasion: Sentinel follows ATT&CK v18") in text


def test_state_reads_a_rows_detection_back_with_its_mode_and_entities():
    state = _state(("azurerm_sentinel_alert_rule_scheduled", "det", {
        "id": "/rules/spray", "name": "ciam-password-spray", "log_analytics_workspace_id": WS,
        "description": "opsdir: realizes alert rule password-spray", "query": ROWS_QUERY,
        "entity_mapping": [{"entity_type": "Account", "field_mapping": [
            {"identifier": "Name", "column_name": "UserPrincipalName"}]},
            {"entity_type": "IP", "field_mapping": [{"identifier": "Address", "column_name": "IPAddress"}]}]}))
    det = {r.ref: r for r in state_resources(state)[0]}["/rules/spray"]
    assert det.attrs["ciamDetectionMode"] == ("rows",)
    assert det.attrs["ciamEntityMapping"] == ("account name=UserPrincipalName", "ip address=IPAddress")


def test_the_arm_form_carries_attack_entities_and_grouping():
    from types import SimpleNamespace
    from opsdir_format_terraform.hcl import Block, TfFile, ref, tf_block
    from opsdir_adapter_azure.arm_types import arm_translation
    root = TfFile("", (
        tf_block("data", ["azurerm_resource_group", "main"], [("name", "rg-a")]),
        tf_block("resource", ["azurerm_log_analytics_workspace", "siem"], [
            ("name", "law-ciam"), ("location", ref("data.azurerm_resource_group.main.location")),
            ("resource_group_name", ref("data.azurerm_resource_group.main.name")), ("sku", "PerGB2018")]),
        tf_block("resource", ["azurerm_sentinel_alert_rule_scheduled", "det"], [
            ("name", "spray"), ("log_analytics_workspace_id", ref("azurerm_log_analytics_workspace.siem.id")),
            ("display_name", "password-spray"), ("severity", "High"), ("query", ROWS_QUERY),
            ("query_frequency", "PT15M"), ("query_period", "PT15M"), ("trigger_operator", "GreaterThan"),
            ("trigger_threshold", 0), ("enabled", True), ("tactics", ["CredentialAccess"]), ("techniques", ["T1110"]),
            ("event_grouping", Block((("aggregation_method", "AlertPerResult"),))),
            ("entity_mapping", Block((("entity_type", "Account"), ("field_mapping", Block((
                ("identifier", "Name"), ("column_name", "UserPrincipalName")))))))])))
    m = SimpleNamespace(dn="env=prod,cloud=alpha,ou=environments,dc=ciam-ops", label="alpha/prod")
    t = arm_translation(m, {"terraform/main.tf": root}, "Azure infrastructure")
    rule = next(r for (_, k), tpl in t.templates.items() for r in tpl.resources
                if r.type == "Microsoft.SecurityInsights/alertRules")
    assert rule.properties["tactics"] == ["CredentialAccess"] and rule.properties["techniques"] == ["T1110"]
    assert rule.properties["eventGroupingSettings"] == {"aggregationKind": "AlertPerResult"}
    assert rule.properties["entityMappings"] == [
        {"entityType": "Account", "fieldMappings": [{"identifier": "Name", "columnName": "UserPrincipalName"}]}]


# ------------------------------------------- incidents, custom details, sub-techniques (milestone 109, task 592)
def _block(text, name):
    return text.split(f'resource "azurerm_sentinel_alert_rule_scheduled" "{name}"', 1)[1].split("\n}\n", 1)[0]


def test_a_rows_detection_groups_its_alerts_by_its_entities_and_shows_its_other_columns():
    text = "\n\n".join(as_text(render_sentinel(_rows_model())))
    rule = _block(text, "det_spray")
    assert 'custom_details = {\n    n = "n"\n  }' in rule                 # n: the column no entity mapping uses
    assert ("  incident {\n    create_incident_enabled = true\n    grouping {\n      enabled                 = true\n"
            '      lookback_duration       = "PT15M"\n      reopen_closed_incidents = false\n'
            '      entity_matching_method  = "Selected"\n      by_entities             = ["Account", "IP"]\n'
            "    }\n  }") in rule
    count = _block(text, "det_login")                    # a count detection: Sentinel's default, an incident per alert
    assert "incident" not in count and "custom_details" not in count


def test_a_rows_detection_mapping_no_entity_groups_its_alerts_of_the_period_into_one_incident():
    plain = ROWS.replace("ciamEntityMapping: account name=UserPrincipalName\nciamEntityMapping: ip address=IPAddress\n",
                         "")
    assert "ciamEntityMapping" not in plain
    _, _, m = model(beta=(*BINDINGS, plain), tree=(*TREE, SPRAY))
    rule = _block("\n\n".join(as_text(render_sentinel(m))), "det_spray")
    assert 'entity_matching_method  = "AnyAlert"' in rule and "by_entities" not in rule
    assert 'n                 = "n"' in rule and 'UserPrincipalName = "UserPrincipalName"' in rule


def test_the_result_columns_are_read_from_the_searchs_last_stage_naming_them():
    from opsdir_adapter_azure.sentinel import result_columns
    assert result_columns(ROWS_QUERY) == ("n", "UserPrincipalName", "IPAddress")
    assert result_columns("T | project a, b = strcat(x, ',', y), c | where a > 1 | take 5") == ("a", "b", "c")
    assert result_columns('T | where M has "x | y" | distinct A, B | sort by A desc') == ("A", "B")
    assert result_columns("T | summarize by bin(TimeGenerated, 1h), User") == ("TimeGenerated", "User")
    for unread in ("T", "T | extend a = 1", "T | summarize count() by A", "T | project ['a b']",
                   "T | project-away a"):
        assert result_columns(unread) is None, unread


def test_what_custom_details_and_grouping_leave_to_a_person_is_named():
    from opsdir_adapter_azure.sentinel import MAX_CUSTOM_DETAILS
    wide = " | project " + ", ".join(f"c{i} = x" for i in range(MAX_CUSTOM_DETAILS + 1))
    many = ROWS.replace(f"ciamMetric: {ROWS_QUERY}\n",
                        f"ciamMetric: T{wide}, UserPrincipalName, IPAddress, AVeryLongColumnNameIndeed\n")
    long_ = SPRAY.replace("ciamEvaluationPeriod: 15m", "ciamEvaluationPeriod: 8d")
    _, _, m = model(beta=(*BINDINGS, many), tree=(*TREE, long_))
    text = "\n\n".join(as_text(render_sentinel(m)))
    rule = _block(text, "det_spray")
    assert 'lookback_duration       = "P7D"' in rule and 'query_period               = "P8D"' in rule
    details = rule.split("custom_details = {", 1)[1].split("}", 1)[0]
    assert 'c19 = "c19"' in details and "c20" not in details and "AVeryLong" not in details
    assert ("# NOTE: alert rule password-spray: its result columns c20, AVeryLongColumnNameIndeed aren't custom "
            "details: Sentinel takes 20 per rule, each key 20 characters at most") in text
    assert ("# NOTE: alert rule password-spray: its incidents group the alerts of 7 days, not of its whole evaluation "
            "period (691200s)") in text
    unread = ROWS.replace(f"ciamMetric: {ROWS_QUERY}\n", "ciamMetric: T | extend n = 1\n")
    _, _, m = model(beta=(*BINDINGS, unread), tree=(*TREE, SPRAY))
    text = "\n\n".join(as_text(render_sentinel(m)))
    assert "custom_details" not in _block(text, "det_spray")
    assert "# NOTE: alert rule password-spray: its search's result columns aren't rendered as custom details" in text
    assert "nor has the alertRules API's stable version (2025-09-01; only its previews)" in text


def _translated_rule(*extra):
    from types import SimpleNamespace
    from opsdir_format_terraform.hcl import TfFile, ref, tf_block
    from opsdir_adapter_azure.arm_types import arm_translation
    root = TfFile("", (
        tf_block("data", ["azurerm_resource_group", "main"], [("name", "rg-a")]),
        tf_block("resource", ["azurerm_log_analytics_workspace", "siem"], [
            ("name", "law-ciam"), ("location", ref("data.azurerm_resource_group.main.location")),
            ("resource_group_name", ref("data.azurerm_resource_group.main.name")), ("sku", "PerGB2018")]),
        tf_block("resource", ["azurerm_sentinel_alert_rule_scheduled", "det"], [
            ("name", "spray"), ("log_analytics_workspace_id", ref("azurerm_log_analytics_workspace.siem.id")),
            ("display_name", "password-spray"), ("severity", "High"), ("query", ROWS_QUERY),
            ("query_frequency", "PT15M"), ("query_period", "PT15M"), ("trigger_operator", "GreaterThan"),
            ("trigger_threshold", 0), ("enabled", True), *extra])))
    m = SimpleNamespace(dn="env=prod,cloud=alpha,ou=environments,dc=ciam-ops", label="alpha/prod")
    t = arm_translation(m, {"terraform/main.tf": root}, "Azure infrastructure")
    return next(r for (_, k), tpl in t.templates.items() for r in tpl.resources
                if r.type == "Microsoft.SecurityInsights/alertRules")


def test_the_arm_form_carries_custom_details_and_the_incident_configuration():
    from opsdir_format_terraform.hcl import Block
    rule = _translated_rule(("custom_details", {"n": "n"}), ("incident", Block((
        ("create_incident_enabled", True), ("grouping", Block((
            ("enabled", True), ("lookback_duration", "PT15M"), ("reopen_closed_incidents", False),
            ("entity_matching_method", "Selected"), ("by_entities", ["Account", "IP"]))))))))
    assert rule.properties["customDetails"] == {"n": "n"}
    assert rule.properties["incidentConfiguration"] == {"createIncident": True, "groupingConfiguration": {
        "enabled": True, "lookbackDuration": "PT15M", "reopenClosedIncident": False, "matchingMethod": "Selected",
        "groupByEntities": ["Account", "IP"]}}
    assert "subTechniques" not in rule.properties                 # not in the stable alertRules API (2025-09-01)


ARM_RULE = {"id": "/rules/spray", "name": "ciam-password-spray", "type": "Microsoft.SecurityInsights/alertRules",
            "kind": "Scheduled", "properties": {
                "displayName": "password-spray", "description": "opsdir: realizes alert rule password-spray",
                "query": ROWS_QUERY, "tactics": ["CredentialAccess"], "techniques": ["T1110"],
                "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
                "entityMappings": [{"entityType": "Account", "fieldMappings": [
                    {"identifier": "Name", "columnName": "UserPrincipalName"}]}],
                "customDetails": {"n": "n"},
                "incidentConfiguration": {"createIncident": True, "groupingConfiguration": {
                    "enabled": True, "lookbackDuration": "PT15M", "reopenClosedIncident": False,
                    "matchingMethod": "Selected", "groupByEntities": ["Account"]}}}}


def test_the_cli_reads_a_rules_new_fields_in_azurerms_shape_as_state_holds_them():
    from opsdir_adapter_azure.cli_monitor import monitor_items
    (kind, a), = monitor_items([("microsoft.securityinsights/alertrules", ARM_RULE)])
    assert kind == "azurerm_sentinel_alert_rule_scheduled"
    assert (a["tactics"], a["techniques"], a["event_grouping"], a["custom_details"]) == (
        ["CredentialAccess"], ["T1110"], [{"aggregation_method": "AlertPerResult"}], {"n": "n"})
    assert a["incident"] == [{"create_incident_enabled": True, "grouping": [{
        "enabled": True, "lookback_duration": "PT15M", "reopen_closed_incidents": False,
        "entity_matching_method": "Selected", "by_entities": ["Account"], "by_alert_details": [],
        "by_custom_details": []}]}]
    (_, bare), = monitor_items([("microsoft.securityinsights/alertrules", {**ARM_RULE, "properties": {}})])
    assert (bare["incident"], bare["custom_details"], bare["event_grouping"]) == ([], {}, [])


def test_a_rows_rule_with_incidents_and_custom_details_reads_back_alike_from_state_and_the_cli():
    """The round trip: the new fields follow from the detection, so state and the CLI read back the same detection,
    adding nothing the record would show as drift."""
    from opsdir_adapter_azure.cli import cli_resources
    from opsdir_adapter_azure.cli_monitor import monitor_items
    texts = {"sentinel-alertRules-law-ciam-sentinel.json": json.dumps({"value": [
        {**ARM_RULE, "id": f"{WS}/providers/Microsoft.SecurityInsights/alertRules/ciam-password-spray"}]})}
    from_cli = next(r for r in cli_resources(texts)[0] if r.kind == "alarm")
    (_, a), = monitor_items([("microsoft.securityinsights/alertrules", ARM_RULE)])
    from_state = {r.ref: r for r in state_resources(_state(("azurerm_sentinel_alert_rule_scheduled", "det", {
        **a, "log_analytics_workspace_id": WS})))[0]}["/rules/spray"]
    expected = {"ciamRealizes": ("password-spray",), "ciamMetric": (ROWS_QUERY,), "ciamDetectionMode": ("rows",),
                "ciamEntityMapping": ("account name=UserPrincipalName",)}
    assert from_state.attrs == from_cli.attrs == expected
