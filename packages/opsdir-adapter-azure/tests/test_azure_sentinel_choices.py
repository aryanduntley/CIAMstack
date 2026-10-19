"""Microsoft Sentinel's own choices for a detection (milestone 129; the adapter's auxiliary class azSentinelRule on
its alarm binding): a rows detection as a near-real-time rule, alert details taken from its results and suppression,
rendered in Terraform and Bicep/ARM (NRT rules kept in Terraform beside Bicep/ARM), refused where Sentinel can't do
them, its NRT rules counted against the workspace's limits by the planner, and read back from state, the CLI and ARM so
a choice changed in the portal shows as drift."""
import json
from types import SimpleNamespace

from opsdir.core.directory import one
from opsdir.core.notes import note_comment
from opsdir.core.standard import registry_ldif
from opsdir.connectors.registry import core_fragments
from opsdir.domains.observability.naming import ALERT_RULES
from opsdir_format_terraform.hcl import Block, TfFile, as_text, ref, tf_block
from opsdir_adapter_azure.schema import CHOICES, FRAGMENT, SENTINEL_RULE
from opsdir_adapter_azure.sentinel import (MAX_NRT_ENABLED, MIN_SUPPRESSION, check_nrt_quota, render_sentinel,
                                           rule_choices, sentinel_notes)
from network_fixtures import BETA, entry, model
from support import SUPERS, imported_directory
from test_azure_sentinel import BINDINGS, SPRAY, TREE, WS

ROWS_QUERY = ("CiamSecurity_CL | where RawData has 'FAILURE' | summarize n = count() by UserPrincipalName, IPAddress, "
              "Sev, Url")
SPRAY_ID = f"{WS}/providers/Microsoft.SecurityInsights/alertRules/ciam-password-spray"


def _classed(text):
    """An alarm binding's LDIF record with the auxiliary class azSentinelRule added."""
    return text.replace("objectClass: ciamAlarmBinding\n",
                        f"objectClass: ciamAlarmBinding\nobjectClass: {SENTINEL_RULE}\n")


def _spray(**choices):
    """The password-spray rows detection, with the Sentinel choices given (and the class carrying them)."""
    return _classed(entry(BETA, "det-spray", "ciamAlarmBinding", ciamBindingRole="alarm-password-spray",
                          ciamProviderRef=SPRAY_ID, ciamRealizes="password-spray", ciamMetric=ROWS_QUERY,
                          ciamLogDestinationRole="siem", ciamDetectionMode="rows",
                          ciamEntityMapping=("account name=UserPrincipalName", "ip address=IPAddress"), **choices))


def _model(*bindings, tree=(*TREE, SPRAY)):
    _, _, beta = model(beta=(*BINDINGS, *bindings), tree=tree)
    return beta


def _text(m):
    return "\n\n".join(as_text(render_sentinel(m)))


def _block(text, kind, name):
    return text.split(f'resource "{kind}" "{name}"', 1)[1].split("\n}\n", 1)[0]


def test_the_schema_is_the_adapters_own_auxiliary_class_under_its_arc():
    assert FRAGMENT.arc == "1.3.6.1.4.1.32473.3.7" and FRAGMENT.origin == "azure"
    (cls,) = FRAGMENT.classes
    assert (cls.name, cls.kind, cls.sup, cls.must, cls.may) == (SENTINEL_RULE, "AUXILIARY", "top", (), CHOICES)
    assert all(a.name.startswith("azSentinel") for a in FRAGMENT.attributes)
    assert SENTINEL_RULE in registry_ldif((*core_fragments(), FRAGMENT))


# ------------------------------------------------------------------ near-real-time rules
def test_a_rows_detection_runs_as_a_near_real_time_rule_without_a_schedule():
    text = _text(_model(_spray(azSentinelRuleKind="nrt")))
    rule = _block(text, "azurerm_sentinel_alert_rule_nrt", "det_spray")
    for line in ('name                       = "ciam-password-spray"', 'aggregation_method = "AlertPerResult"',
                 'entity_type = "Account"', 'lookback_duration       = "PT15M"',
                 "depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.siem]"):
        assert line in rule, line
    for absent in ("query_frequency", "query_period", "trigger_operator", "trigger_threshold"):
        assert absent not in rule, absent
    assert '"azurerm_sentinel_alert_rule_scheduled" "det_spray"' not in text
    assert '"azurerm_sentinel_alert_rule_scheduled" "det_login"' in text      # the others stay scheduled


def test_an_nrt_rule_needs_no_five_minute_period_but_groups_incidents_over_five_minutes_at_least():
    short = SPRAY.replace("ciamEvaluationPeriod: 15m", "ciamEvaluationPeriod: 1m")
    rule = _block(_text(_model(_spray(azSentinelRuleKind="nrt"), tree=(*TREE, short))),
                  "azurerm_sentinel_alert_rule_nrt", "det_spray")
    assert 'lookback_duration       = "PT5M"' in rule
    scheduled = _text(_model(_spray(), tree=(*TREE, short)))       # a scheduled rule still can't run every minute
    assert "det_spray" not in scheduled.split("# NOTE")[0]


def _count(**choices):
    """The model with its count detection login-failures making the Sentinel choices given."""
    text = entry(BETA, "det-login", "ciamAlarmBinding", ciamBindingRole="alarm-login-failures",
                 ciamProviderRef=f"{WS}/providers/Microsoft.SecurityInsights/alertRules/ciam-login-failures",
                 ciamRealizes="login-failures", ciamMetric="CiamSecurity_CL", ciamLogDestinationRole="siem",
                 **choices)
    _, _, m = model(beta=(*(b for b in BINDINGS if "cn=det-login," not in b), _classed(text)), tree=TREE)
    return m


def test_a_count_detection_asked_to_run_near_real_time_is_refused():
    m = _count(azSentinelRuleKind="nrt")
    texts = [(n.severity, note_comment(n)) for n in sentinel_notes(m)]
    assert "det_login" not in _text(m).split("# NOTE")[0]
    assert ("blocker", "NOTE: alert rule login-failures: not rendered: it asks for a near-real-time analytics rule "
            "(azSentinelRuleKind nrt), which runs every minute over what arrived since its last run, with no lookback: "
            "a count detection's windows over its evaluation period can't be counted there (make it a rows "
            "detection, its threshold in its search)") in texts


# ------------------------------------------------------------------ alert details and suppression
CHOSEN = dict(azSentinelAlertName="Password spray on {{UserPrincipalName}} from {{IPAddress}}",
              azSentinelAlertDescription="{{n}} failures", azSentinelSeverityColumn="Sev",
              azSentinelTacticsColumn="Sev", azSentinelAlertProperty=("AlertLink=Url", "ProductName=Sev"),
              azSentinelSuppression="1h")


def test_alert_details_and_suppression_render_on_a_scheduled_rule():
    rule = _block(_text(_model(_spray(**CHOSEN))), "azurerm_sentinel_alert_rule_scheduled", "det_spray")
    assert 'suppression_enabled        = true' in rule and 'suppression_duration       = "PT1H"' in rule
    override = rule.split("alert_details_override {", 1)[1].split("\n  }\n", 1)[0]
    for line in ('display_name_format  = "Password spray on {{UserPrincipalName}} from {{IPAddress}}"',
                 'description_format   = "{{n}} failures"', 'severity_column_name = "Sev"',
                 'tactics_column_name  = "Sev"', 'name  = "AlertLink"', 'value = "Url"', 'name  = "ProductName"'):
        assert line in override, line
    assert override.count("dynamic_property {") == 2


def test_alert_details_and_suppression_render_on_an_nrt_rule_too():
    rule = _block(_text(_model(_spray(azSentinelRuleKind="nrt", **CHOSEN))), "azurerm_sentinel_alert_rule_nrt",
                  "det_spray")
    assert "alert_details_override {" in rule and 'suppression_duration       = "PT1H"' in rule


def test_a_rule_without_choices_renders_as_before():
    rule = _block(_text(_model(_spray())), "azurerm_sentinel_alert_rule_scheduled", "det_spray")
    assert "suppression" not in rule and "alert_details_override" not in rule


def test_choices_sentinel_cant_take_are_refused_with_a_blocker():
    refused = {
        "suppression": (dict(azSentinelSuppression="2d"), "its suppression (2d) isn't one Sentinel takes (5 minutes "
                                                          "to 24 hours, in whole minutes)"),
        "seconds": (dict(azSentinelSuppression="330s"), "its suppression (330s) isn't one"),
        "column": (dict(azSentinelAlertName="On {{Missing}}", azSentinelAlertProperty="AlertLink=Other"),
                   "its alert details name result columns its search doesn't return (Missing, Other; it returns n, "
                   "UserPrincipalName, IPAddress, Sev, Url)")}
    for name, (choices, why) in refused.items():
        m = _model(_spray(**choices))
        assert "det_spray" not in _text(m).split("# NOTE")[0], name
        assert any(n.severity == "blocker" and why in note_comment(n) for n in sentinel_notes(m)), name
    assert MIN_SUPPRESSION == 300


def test_a_count_detection_takes_a_plain_alert_name_but_no_result_columns():
    plain = _text(_count(azSentinelAlertName="CIAM login failures", azSentinelSuppression="30m"))
    rule = _block(plain, "azurerm_sentinel_alert_rule_scheduled", "det_login")
    assert 'display_name_format = "CIAM login failures"' in rule and '"PT30M"' in rule
    m = _count(azSentinelSeverityColumn="Sev")
    assert any(n.severity == "blocker" and "its alert details name result columns (Sev), and a count detection's "
               "results are only its count of breaching windows" in note_comment(n) for n in sentinel_notes(m))


# ------------------------------------------------------------------ the NRT quota (a planner finding)
def _many(count, workspace="siem"):
    """count alert rules, each realized by an NRT detection on the workspace: (rules, detections)."""
    names = tuple(f"nrt-{workspace}-{i}" for i in range(count))
    return (tuple(SPRAY.replace("password-spray", n) for n in names),
            tuple(_classed(entry(BETA, f"det-{n}", "ciamAlarmBinding", ciamBindingRole=f"alarm-{n}",
                                 ciamProviderRef=f"{WS}/providers/Microsoft.SecurityInsights/alertRules/{n}",
                                 ciamRealizes=n, ciamMetric=ROWS_QUERY, ciamLogDestinationRole=workspace,
                                 ciamDetectionMode="rows", azSentinelRuleKind="nrt"))
                  for n in names))


def _quota(*groups, extra=()):
    m = _model(*extra, *(b for _, bs in groups for b in bs), tree=(*TREE, *(r for rs, _ in groups for r in rs)))
    return check_nrt_quota(SimpleNamespace(d=m.d, dst=m, cutover=None))


def test_nrt_rules_within_the_workspace_limit_are_fine():
    found = _quota(_many(3))
    assert not found.blockers and not found.actions
    assert found.ok == ("beta/prod's Sentinel workspace siem gets 3 near-real-time analytics rules, within Sentinel's "
                        "50 enabled per workspace (rules made outside opsdir count too).",)
    assert _quota() == ((), (), (), (), ())                         # no NRT rule: nothing to say


def test_more_nrt_rules_than_a_workspace_takes_block_the_plan():
    found = _quota(_many(MAX_NRT_ENABLED + 1))
    (blocker,) = found.blockers
    assert blocker[0] == "Monitoring" and blocker[1].startswith(
        "beta/prod's render puts 51 near-real-time analytics rules in Sentinel workspace siem: Sentinel takes 50 "
        "enabled NRT rules per workspace (100 in all, disabled ones included: its service limits).")


def test_nrt_rules_over_fifty_across_workspaces_ask_to_confirm_the_per_customer_limit():
    other = entry(BETA, "siem2", "ciamLogDestination", ciamBindingRole="siem2", ciamDestinationKind="siem-index",
                  ciamProviderRef=WS.replace("law-ciam-sentinel", "law-ciam-sentinel-2"), ciamRetentionDays="90")
    found = _quota(_many(30), _many(30, "siem2"), extra=(other,))
    assert not found.blockers
    (action,) = found.actions
    assert "60 near-real-time analytics rules in its Sentinel workspaces together (siem 30, siem2 30)" in action[1]
    assert "its NRT overview says 50 NRT rules per customer" in action[1]


# ------------------------------------------------------------------ Bicep / ARM
def _translated(kind, *extra):
    from opsdir_adapter_azure.arm_types import arm_translation
    root = TfFile("", (
        tf_block("data", ["azurerm_resource_group", "main"], [("name", "rg-a")]),
        tf_block("resource", ["azurerm_log_analytics_workspace", "siem"], [
            ("name", "law-ciam"), ("location", ref("data.azurerm_resource_group.main.location")),
            ("resource_group_name", ref("data.azurerm_resource_group.main.name")), ("sku", "PerGB2018")]),
        tf_block("resource", ["azurerm_sentinel_log_analytics_workspace_onboarding", "siem"], [
            ("workspace_id", ref("azurerm_log_analytics_workspace.siem.id"))]),
        tf_block("resource", [kind, "det"], [
            ("name", "spray"), ("log_analytics_workspace_id", ref("azurerm_log_analytics_workspace.siem.id")),
            ("depends_on", [ref("azurerm_sentinel_log_analytics_workspace_onboarding.siem")]),
            ("display_name", "password-spray"), ("severity", "High"), ("query", ROWS_QUERY), *extra])))
    m = SimpleNamespace(dn="env=prod,cloud=alpha,ou=environments,dc=ciam-ops", label="alpha/prod")
    return arm_translation(m, {"terraform/main.tf": root}, "Azure infrastructure")


OVERRIDE = ("alert_details_override", Block((("display_name_format", "On {{UserPrincipalName}}"),
                                             ("severity_column_name", "Sev"),
                                             ("dynamic_property", Block((("name", "AlertLink"), ("value", "Url")))))))


def test_the_arm_form_carries_alert_details_and_suppression():
    t = _translated("azurerm_sentinel_alert_rule_scheduled", ("query_frequency", "PT15M"), ("query_period", "PT15M"),
                    ("trigger_operator", "GreaterThan"), ("trigger_threshold", 0), ("enabled", True),
                    ("suppression_enabled", True), ("suppression_duration", "PT1H"), OVERRIDE)
    rule = next(r for (_, k), tpl in t.templates.items() for r in tpl.resources
                if r.type == "Microsoft.SecurityInsights/alertRules")
    assert (rule.properties["suppressionEnabled"], rule.properties["suppressionDuration"]) == (True, "PT1H")
    assert rule.properties["alertDetailsOverride"] == {
        "alertDisplayNameFormat": "On {{UserPrincipalName}}", "alertSeverityColumnName": "Sev",
        "alertDynamicProperties": [{"alertProperty": "AlertLink", "value": "Url"}]}
    plain = _translated("azurerm_sentinel_alert_rule_scheduled", ("query_frequency", "PT15M"),
                        ("query_period", "PT15M"), ("trigger_operator", "GreaterThan"), ("trigger_threshold", 0))
    rule = next(r for (_, k), tpl in plain.templates.items() for r in tpl.resources
                if r.type == "Microsoft.SecurityInsights/alertRules")
    assert (rule.properties["suppressionEnabled"], rule.properties["suppressionDuration"]) == (False, "PT5H")
    assert "alertDetailsOverride" not in rule.properties


def test_an_nrt_rule_stays_in_terraform_beside_a_bicep_render():
    t = _translated("azurerm_sentinel_alert_rule_nrt", ("enabled", True), OVERRIDE,
                    ("event_grouping", Block((("aggregation_method", "AlertPerResult"),))))
    (place,) = (v for k, v in t.placements["terraform"].items() if "alert_rule" in k)
    assert place.kind != "template" and "have no NRT kind" in place.detail
    assert not any(r.type == "Microsoft.SecurityInsights/alertRules" for tpl in t.templates.values()
                   for r in tpl.resources)
    (head, items), = t.side.values()
    side = "\n".join(as_text(items))
    assert 'resource "azurerm_sentinel_alert_rule_nrt" "det"' in side and "alert_details_override {" in side
    assert "log_analytics_workspace_id = var.azurerm_log_analytics_workspace_siem_id" in side


# ------------------------------------------------------------------ read back
def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


NRT_STATE = {"id": SPRAY_ID, "name": "ciam-password-spray", "log_analytics_workspace_id": WS,
             "description": "opsdir: realizes alert rule password-spray", "query": ROWS_QUERY,
             "suppression_enabled": True, "suppression_duration": "PT1H",
             "alert_details_override": [{"display_name_format": "On {{UserPrincipalName}}", "description_format": "",
                                         "severity_column_name": "Sev", "tactics_column_name": "",
                                         "dynamic_property": [{"name": "AlertLink", "value": "Url"}]}]}
CHOICES_READ = {"azSentinelRuleKind": ("nrt",), "azSentinelAlertName": ("On {{UserPrincipalName}}",),
                "azSentinelSeverityColumn": ("Sev",), "azSentinelAlertProperty": ("AlertLink=Url",),
                "azSentinelSuppression": ("1h",)}


def test_state_reads_an_nrt_rule_back_with_its_choices():
    from opsdir_adapter_azure.inventory import state_resources
    found = state_resources(_state(("azurerm_sentinel_alert_rule_nrt", "det", NRT_STATE)))[0]
    det = {r.ref: r for r in found}[SPRAY_ID]
    assert (det.kind, det.role) == ("alarm", "alarm-password-spray")
    assert {k: v for k, v in det.attrs.items() if k in CHOICES} == CHOICES_READ
    assert det.attrs["ciamDetectionMode"] == ("rows",)
    off = {**NRT_STATE, "suppression_enabled": False, "alert_details_override": []}
    assert rule_choices("azurerm_sentinel_alert_rule_scheduled", off) == {}


ARM_NRT = {"id": SPRAY_ID, "name": "ciam-password-spray", "type": "Microsoft.SecurityInsights/alertRules",
           "kind": "NRT", "properties": {
               "displayName": "password-spray", "description": "opsdir: realizes alert rule password-spray",
               "query": ROWS_QUERY, "suppressionEnabled": True, "suppressionDuration": "PT1H",
               "alertDetailsOverride": {"alertDisplayNameFormat": "On {{UserPrincipalName}}",
                                        "alertSeverityColumnName": "Sev",
                                        "alertDynamicProperties": [{"alertProperty": "AlertLink", "value": "Url"}]}}}


def test_the_cli_and_arm_read_an_nrt_rule_and_its_choices_as_state_does():
    from opsdir_adapter_azure.arm import arm_resources
    from opsdir_adapter_azure.cli import cli_resources
    from opsdir_adapter_azure.cli_monitor import monitor_items
    (kind, a), = monitor_items([("microsoft.securityinsights/alertrules", ARM_NRT)])
    assert kind == "azurerm_sentinel_alert_rule_nrt"
    assert rule_choices(kind, a) == CHOICES_READ
    texts = {"sentinel-alertRules-law-ciam-sentinel.json": json.dumps({"value": [ARM_NRT]})}
    from_cli = next(r for r in cli_resources(texts)[0] if r.kind == "alarm")
    assert {k: v for k, v in from_cli.attrs.items() if k in CHOICES} == CHOICES_READ
    scope = "[resourceId('Microsoft.OperationalInsights/workspaces', 'law-ciam-sentinel')]"
    template = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0", "resources": [
                    {"type": "Microsoft.SecurityInsights/alertRules", "apiVersion": "2025-10-01-preview",
                     "scope": scope, "name": "ciam-password-spray", "kind": "NRT",
                     "properties": ARM_NRT["properties"]}]}
    deployment = {"id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam/providers/"
                        "Microsoft.Resources/deployments/ciam", "properties": {}}
    found = {r.ref: r for r in arm_resources({"d/template.json": json.dumps(template),
                                              "d/deployment.json": json.dumps(deployment)})[0]}
    assert {k: v for k, v in found[SPRAY_ID].attrs.items() if k in CHOICES} == CHOICES_READ


ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record(*det_classes, **det_attrs):
    return imported_directory((), {**SUPERS, SENTINEL_RULE: "top"}, (
        _row("cloud=main,ou=environments,dc=ciam-ops", ("ciamCloud",), cloud="main", ciamCloudProvider="azure",
             ciamRegion="eastus2"),
        _row(ENV, ("ciamEnvironment",), env="prod"),
        _row(B, ("organizationalUnit",), ou="bindings"),
        _row(f"cn=siem,{B}", ("ciamLogDestination",), cn="siem", ciamBindingRole="siem",
             ciamDestinationKind="siem-index", ciamProviderRef=WS),
        _row(f"cn=det-spray,{B}", ("ciamAlarmBinding", *det_classes), cn="det-spray",
             ciamBindingRole="alarm-password-spray", ciamProviderRef=SPRAY_ID, ciamRealizes="password-spray",
             ciamMetric=ROWS_QUERY, ciamDetectionMode="rows", ciamLogDestinationRole="siem", **det_attrs)))


def _imported_detection(d, *rules):
    from opsdir_adapter_azure.inventory import read_terraform_state
    imported = read_terraform_state({"main/prod/terraform.tfstate": _state(*rules)}, d, ())
    return next(e for _, es in imported.groups for e in es if e.dn.startswith("cn=det-spray,"))


def test_an_import_gives_the_detection_the_class_and_choices_its_source_holds():
    det = _imported_detection(_record(), ("azurerm_sentinel_alert_rule_nrt", "det", NRT_STATE))
    assert SENTINEL_RULE in det.classes
    assert {k: v for k, v in det.attrs.items() if k in CHOICES} == CHOICES_READ


def test_a_render_with_choices_reads_back_as_the_record_holds_them():
    """The round trip: the rendered rules, as the state applying them would record, give the detection back its
    choices and class, nothing more."""
    from opsdir_adapter_azure.inventory import read_terraform_state
    from opsdir_adapter_azure.observability import render_workspaces
    from opsdir_adapter_azure.rendered_state import rendered_states
    m = _model(_spray(azSentinelRuleKind="nrt", **CHOSEN))
    main = ('data "azurerm_resource_group" "main" {\n  name = "rg-ciam"\n}\n\n'
            + "\n\n".join(as_text((*render_workspaces(m), *render_sentinel(m)))) + "\n")
    d = _record(SENTINEL_RULE, azSentinelRuleKind="nrt", **CHOSEN)
    imported = read_terraform_state(rendered_states({"main/prod/main.tf": main}, d, "main/prod"), d, ())
    det = next(e for _, es in imported.groups for e in es if e.dn.startswith("cn=det-spray,"))
    held = next(e for e in d.entries.values() if e.dn.startswith("cn=det-spray,"))
    assert det.classes == held.classes and det.attrs["ciamProviderRef"] == (SPRAY_ID,)
    assert {k: set(v) for k, v in det.attrs.items() if k in CHOICES} == \
        {k: set(v) for k, v in held.attrs.items() if k in CHOICES}


def test_a_choice_dropped_in_the_portal_is_drift_and_one_kept_changes_nothing():
    d = _record(SENTINEL_RULE, azSentinelRuleKind="nrt", azSentinelSuppression="1h", azSentinelAlertName="Old")
    scheduled = {**NRT_STATE, "suppression_enabled": False, "alert_details_override": []}
    det = _imported_detection(d, ("azurerm_sentinel_alert_rule_scheduled", "det", scheduled))
    assert not any(k in det.attrs for k in CHOICES)                  # read as the source holds it: none
    same = _imported_detection(_record(SENTINEL_RULE, **{k: v for k, v in CHOICES_READ.items()}),
                               ("azurerm_sentinel_alert_rule_nrt", "det", NRT_STATE))
    held = next(e for e in _record(SENTINEL_RULE, **CHOICES_READ).entries.values() if e.dn.startswith("cn=det-spray,"))
    assert {k: set(v) for k, v in same.attrs.items()} == {k: set(v) for k, v in held.attrs.items()}
    assert same.classes.count(SENTINEL_RULE) == 1 and one(same, "azSentinelRuleKind") == "nrt"
