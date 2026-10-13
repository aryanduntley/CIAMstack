"""Cloud security services on Azure: Defender for Cloud plans merged across the services that need them (one pricing per
plan), the Defender Vulnerability Management setting, Defender CSPM and a policy assignment per framework's built-in
initiative, continuous export to a Log Analytics workspace; in Azure Government every plan rendered, with a comment
where one of Microsoft's availability pages lists it as unavailable; configuration recording, identity, services kept by
someone else and other clouds' baselines in comments; all read back from Terraform state, and from the Azure CLI's
outputs of the same services as the same record."""
import json
import re

from opsdir.core.directory import make_entry
from opsdir.core.inventory import environment_groups, resource
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_azure.cli import cli_resources
from opsdir_adapter_azure.security import render_security, security_resources
from network_fixtures import ALPHA, entry, model

PARTY = "cn=landing-zone,ou=owners,dc=ciam-ops"
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
          f"dn: {PARTY}\nobjectClass: top\nobjectClass: ciamParty\ncn: landing-zone\nciamOwnerKind: team\n")
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
WORKSPACE = f"{SUB}/resourceGroups/rg-sec/providers/Microsoft.OperationalInsights/workspaces/sec-logs"
LOGS = entry(ALPHA, "security-logs", "ciamLogDestination", ciamBindingRole="security-logs",
             ciamDestinationKind="workspace", ciamProviderRef=WORKSPACE)


def svc(cn, kind, **more):
    return entry(ALPHA, cn, "ciamSecurityService", ciamBindingRole=cn, ciamSecurityKind=kind, **more)


def _render(*services, gov=False):
    _, alpha, _ = model(alpha=(LOGS, *services), tree=OWNERS)
    if gov:
        alpha = alpha._replace(cloud=make_entry(alpha.cloud.dn, alpha.cloud.classes,
                                                {**alpha.cloud.attrs, "ciamCloudEnvironment": ("usgovernment",)}))
    return "\n\n".join(as_text(render_security(alpha)))


DETECTION = svc("defender", "threat-detection", ciamFindingsRole="security-logs",
                ciamSecurityCoverage=("control-plane", "identity", "network", "compute", "containers", "storage"))


def test_defender_plans_are_merged_one_per_plan():
    out = _render(DETECTION, svc("mdvm", "vulnerability-scanning", ciamSecurityCoverage=("compute", "containers")))
    assert out.count('resource "azurerm_security_center_subscription_pricing" "virtualmachines"') == 1
    assert [p for p in ("Arm", "VirtualMachines", "Containers", "StorageAccounts", "KeyVaults")
            if f'resource_type = "{p}"' in out] == ["Arm", "VirtualMachines", "Containers", "StorageAccounts"]
    assert 'subplan       = "P2"' in out and '"ContainerRegistriesVulnerabilityAssessments"' in out
    assert 'vulnerability_assessment_provider = "MdeTvm"' in out
    assert "# defender: identity: Microsoft Entra ID Protection (Defender for Cloud has no plan for identity)" in out
    assert "Azure Government" not in out


def test_findings_go_to_the_workspace_by_continuous_export():
    out = _render(DETECTION)
    assert 'data "azurerm_subscription" "current"' in out
    assert f'resource_id = "{WORKSPACE}"' in out and 'event_source = "Alerts"' in out
    assert "# NOTE" not in _render(svc("defender", "threat-detection", ciamFindingsRole="nowhere"))
    hub = entry(ALPHA, "event-hub", "ciamLogDestination", ciamBindingRole="event-hub", ciamDestinationKind="other",
                ciamProviderRef=f"{SUB}/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns/eventhubs/sec")
    assert "# NOTE: defender's findings to event-hub: not rendered: event-hub is no Log Analytics workspace or Event " \
           "Hub" in _render(hub, svc("defender", "threat-detection", ciamFindingsRole="event-hub"))


def test_in_azure_government_every_plan_is_rendered_with_a_comment_where_a_page_lists_it_unavailable():
    out = _render(svc("defender", "threat-detection", ciamSecurityCoverage=("containers", "databases", "applications")),
                  svc("mdvm", "vulnerability-scanning"), gov=True)
    for plan in ("Containers", "CosmosDbs", "AppServices", "Api"):
        assert f'resource_type = "{plan}"' in out
    assert out.count("rendered, confirm with the account team") == 5
    assert "list Defender for App Service as unavailable in Azure Government" in out
    assert "lists integrated vulnerability assessment for machines as not available" in out


def test_posture_assigns_each_framework_s_built_in_initiative():
    out = _render(svc("cspm", "posture",
                      ciamComplianceStandard=("nist-800-171-r2", "cmmc-l2", "dod-il5", "hitrust"),
                      ciamSecurityBaseline=("microsoft-cloud-security-benchmark", "aws-foundational")))
    assert 'resource_type = "CloudPosture"' in out
    assert 'display_name = "NIST SP 800-171 Rev. 2"' in out and 'display_name = "CMMC 2.0 Level 2"' in out
    assert "policy_definition_id = data.azurerm_policy_set_definition.nist_800_171_r2.id" in out
    assert "# cspm: Defender for Cloud assigns the Microsoft cloud security benchmark itself" in out
    assert "# cspm: Azure has no built-in initiative here for dod-il5, hitrust (not rendered)" in out
    assert "# cspm: aws-foundational: another cloud's baseline, not Azure's (not rendered)" in out
    gov = _render(svc("cspm", "posture", ciamComplianceStandard=("cmmc-l2", "dod-il5")), gov=True)
    assert 'display_name = "DoD Impact Level 5"' in gov and "list CMMC Level 3, not CMMC 2.0 Level 2" in gov


def test_config_recording_is_a_comment_and_services_kept_elsewhere_render_for_their_keeper():
    assert _render(svc("changes", "config-recording")) == (
        "# changes: Azure records resource changes itself (Resource Graph change history, 14 days): nothing to "
        "enable; a longer ciamRetentionDays renders an export keeping them")
    assert _render(svc("org-defender", "threat-detection", ciamManagedBy=PARTY)) == _render(
        svc("org-defender", "threat-detection"))           # the same blocks, placed by its keeper (render_files)


STATE = [("azurerm_security_center_subscription_pricing", {
             "id": f"{SUB}/providers/Microsoft.Security/pricings/{p}", "tier": tier, "resource_type": p,
             "subplan": sub, "extension": [{"name": x} for x in ext]})
         for p, tier, sub, ext in (("VirtualMachines", "Standard", "P2", ()), ("Arm", "Standard", None, ()),
                                   ("KeyVaults", "Free", None, ()),
                                   ("Containers", "Standard", None, ("ContainerRegistriesVulnerabilityAssessments",)),
                                   ("CloudPosture", "Standard", None, ()))] + [
    ("azurerm_security_center_server_vulnerability_assessments_setting",
     {"id": f"{SUB}/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings/AzureServersSetting",
      "vulnerability_assessment_provider": "MdeTvm"}),
    ("azurerm_subscription_policy_assignment", {"id": f"{SUB}/providers/Microsoft.Authorization/policyAssignments/a",
                                                "display_name": "NIST SP 800-171 Rev. 2"}),
    ("azurerm_subscription_policy_assignment", {"id": f"{SUB}/providers/Microsoft.Authorization/policyAssignments/b",
                                                "display_name": "Allowed locations"}),
    ("azurerm_security_center_automation", {"name": "defender-export", "action": [{"resource_id": WORKSPACE}],
                                            "source": [{"event_source": "Alerts"}]})]


def test_the_services_are_read_back_from_state():
    found = {r.attrs["ciamSecurityKind"][0]: (r.ref, dict(r.attrs), dict(r.links)) for r in security_resources(STATE)}
    assert found["threat-detection"] == (f"{SUB}/providers/Microsoft.Security/pricings/defender", {
        "ciamSecurityKind": ("threat-detection",), "ciamSecurityCoverage": ("control-plane", "network", "compute",
                                                                             "containers"),
        "ciamAuditScope": ("account",), "ciamAllRegions": ("TRUE",)}, {"ciamFindingsRole": WORKSPACE})
    assert found["vulnerability-scanning"][1]["ciamSecurityCoverage"] == ("compute", "containers")
    assert {k: v for k, v in found["posture"][1].items() if k.startswith("ciamCompliance") or "Baseline" in k} == {
        "ciamComplianceStandard": ("nist-800-171-r2",), "ciamSecurityBaseline": ("microsoft-cloud-security-benchmark",)}


def test_the_workspace_s_role_is_where_findings_go():
    d, *_ = model(alpha=())
    workspace = resource("logs", WORKSPACE, {"ciamDestinationKind": "workspace"}, name="sec-logs",
                         role="security-logs")
    groups, _ = environment_groups(d, "alpha/prod", (workspace, *security_resources(STATE)))
    placed = {e.dn.split(",")[0]: dict(e.attrs) for _, entries in groups for e in entries
              if "ciamSecurityService" in e.classes}
    assert placed["cn=defender-for-cloud"]["ciamFindingsRole"] == ("security-logs",)
    assert placed["cn=defender-for-cloud"]["ciamBindingRole"] == ("threat-detection",)




def test_the_subscription_data_source_matches_the_audit_trail_s_so_the_root_keeps_one():
    from opsdir_adapter_azure.audit import render_trails
    trail = entry(ALPHA, "activity-log", "ciamAuditTrail", ciamBindingRole="activity-log", ciamAuditScope="account",
                  ciamAuditEvents=("control-plane",), ciamLogDestinationRole="security-logs")
    _, alpha, _ = model(alpha=(LOGS, trail, DETECTION), tree=OWNERS)
    data = 'data "azurerm_subscription" "current" {\n}'
    out = (*as_text(render_trails(alpha)), *as_text(render_security(alpha)))
    assert out.count(data) == 2      # terraform.render keeps the first of identical data sources
    kept = tuple(x for i, x in enumerate(out) if not (x.startswith('data "') and x in out[:i]))
    assert kept.count(data) == 1


# ------------------------------------------------------------------ incident routes
INCIDENT_WS = f"{SUB}/resourceGroups/rg-sec/providers/Microsoft.OperationalInsights/workspaces/incidents"
GROUP = f"{SUB}/resourceGroups/rg-sec/providers/Microsoft.Insights/actionGroups/security-incidents"
INCIDENT_LOGS = entry(ALPHA, "incident-logs", "ciamLogDestination", ciamBindingRole="incident-logs",
                      ciamDestinationKind="workspace", ciamProviderRef=INCIDENT_WS)
PAGER = entry(ALPHA, "security-incidents", "ciamAlertChannel", ciamBindingRole="security-incidents",
              ciamChannelKind="pager", ciamProviderRef=GROUP)


def test_findings_at_or_above_the_incident_severity_go_to_the_incident_workspace():
    out = _render(INCIDENT_LOGS,
                  svc("defender", "threat-detection", ciamFindingsRole="security-logs",
                      ciamIncidentRole="incident-logs",
                      ciamIncidentSeverity="medium", ciamSecurityCoverage=("control-plane",)),
                  svc("cspm", "posture", ciamIncidentRole="incident-logs", ciamIncidentSeverity="critical"))
    automation = out[out.index('resource "azurerm_security_center_automation" "defender_incidents"'):]
    automation = automation[:automation.index("\n}") + 2]
    assert automation.count("rule_set {") == 2 and 'property_path  = "Severity"' in automation
    assert ['expected_value = "high"' in automation, 'expected_value = "medium"' in automation,
            'expected_value = "low"' in automation] == [True, True, False]
    assert f'resource_id = "{INCIDENT_WS}"' in automation
    assert 'type        = "Workspace"' in automation
    cspm = out[out.index('resource "azurerm_security_center_automation" "cspm_incidents"'):]
    assert 'property_path  = "properties.metadata.severity"' in cspm and 'expected_value = "High"' in cspm
    assert "RegulatoryComplianceAssessment" not in cspm
    assert "# cspm: Defender has no critical severity: its high findings go to incident-logs" in out


def test_an_action_group_is_paged_by_a_log_alert_on_security_alert():
    out = _render(PAGER, svc("defender", "threat-detection", ciamFindingsRole="security-logs",
                             ciamIncidentRole="security-incidents", ciamSecurityCoverage=("control-plane",)))
    assert 'resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_incidents"' in out
    assert f'scopes               = ["{WORKSPACE}"]' in out and f'action_groups = ["{GROUP}"]' in out
    assert 'query                   = "SecurityAlert | where AlertSeverity in (\\"High\\")"' in out
    assert "severity             = 1" in out
    out = _render(PAGER, svc("defender", "threat-detection", ciamIncidentRole="security-incidents"))
    assert out.endswith("# NOTE: defender's incidents to security-incidents: not rendered: a log alert on "
                        "SecurityAlert needs the service's findings exported to a Log Analytics workspace "
                        "(its ciamFindingsRole)")


def test_incident_routes_are_read_back():
    from opsdir_adapter_azure.security import severity_rule_sets
    rules = [{"rule": [{"property_path": "Severity", "operator": "Equals", "expected_value": v,
                        "property_type": "String"}]} for v in ("high", "medium")]
    state = [*STATE,
             ("azurerm_security_center_automation", {"name": "cspm-incidents", "action": [{"resource_id": INCIDENT_WS}],
                                                     "source": [{"event_source": "Assessments", "rule_set": [
                                                         {"rule": [{"property_path": "properties.metadata.severity",
                                                                    "expected_value": "High"}]}]}]}),
             ("azurerm_security_center_automation", {"name": "unused", "action": [{"resource_id": INCIDENT_WS}],
                                                     "source": [{"event_source": "SubAssessments",
                                                                 "rule_set": rules}]}),
             ("azurerm_monitor_scheduled_query_rules_alert_v2", {
                 "id": f"{SUB}/resourceGroups/rg-sec/providers/Microsoft.Insights/scheduledQueryRules/"
                       "defender-incidents",
                 "criteria": [{"query": 'SecurityAlert\n| where AlertSeverity in ("High", "Medium")'}],
                 "action": [{"action_groups": [GROUP]}]})]
    found = {r.attrs["ciamSecurityKind"][0]: r for r in security_resources(state)}
    assert (found["threat-detection"].links["ciamIncidentRole"],
            found["threat-detection"].attrs["ciamIncidentSeverity"]) \
        == (GROUP, ("medium",))
    assert found["threat-detection"].links["ciamFindingsRole"] == WORKSPACE
    assert (found["posture"].links["ciamIncidentRole"], found["posture"].attrs["ciamIncidentSeverity"]) == (
        INCIDENT_WS, ("high",))
    assert severity_rule_sets("RegulatoryComplianceAssessment", "high") == ()


def test_a_security_alert_log_alert_is_not_read_as_an_alarm():
    from opsdir_adapter_azure.inventory import _alarms
    alert = ("azurerm_monitor_scheduled_query_rules_alert_v2", {
        "id": "x", "criteria": [{"query": 'SecurityAlert | where AlertSeverity in ("High")'}],
        "action": [{"action_groups": [GROUP]}]})
    assert _alarms([alert]) == ()


def test_vulnerability_findings_and_recommendations_page_an_action_group_from_their_tables():
    out = _render(PAGER, svc("mdvm", "vulnerability-scanning", ciamFindingsRole="security-logs",
                             ciamIncidentRole="security-incidents", ciamIncidentSeverity="medium"),
                  svc("cspm", "posture", ciamFindingsRole="security-logs", ciamIncidentRole="security-incidents"))
    assert ('"SecurityNestedRecommendation | where RecommendationSeverity in (\\"High\\", \\"Medium\\") and '
            'RecommendationState != \\"Healthy\\""') in out
    assert ('"SecurityRecommendation | where RecommendationSeverity in (\\"High\\") and RecommendationState != '
            '\\"Healthy\\""') in out
    state = [("azurerm_security_center_subscription_pricing", {
                 "id": f"{SUB}/providers/Microsoft.Security/pricings/CloudPosture", "tier": "Standard",
                 "resource_type": "CloudPosture"}),
             ("azurerm_monitor_scheduled_query_rules_alert_v2", {
                 "id": "x", "action": [{"action_groups": [GROUP]}], "criteria": [{
                     "query": 'SecurityRecommendation | where RecommendationSeverity in ("High") and '
                              'RecommendationState != "Healthy"'}]})]
    found = {r.attrs["ciamSecurityKind"][0]: r for r in security_resources(state)}
    assert (found["posture"].links.get("ciamIncidentRole"), found["posture"].attrs["ciamIncidentSeverity"]) == (
        GROUP, ("high",))



# ------------------------------------------------------------------ the same services from the Azure CLI
CLI = {
    "pricings.json": {"value": [
        {"id": f"{SUB}/providers/Microsoft.Security/pricings/{p}", "name": p, "type": "Microsoft.Security/pricings",
         "pricingTier": tier, "subPlan": sub, "extensions": [{"name": x, "isEnabled": "True"} for x in ext]
         + [{"name": "AgentlessVmScanning", "isEnabled": "False"}]}
        for p, tier, sub, ext in (("VirtualMachines", "Standard", "P2", ()), ("Arm", "Standard", None, ()),
                                  ("KeyVaults", "Free", None, ()),
                                  ("Containers", "Standard", None, ("ContainerRegistriesVulnerabilityAssessments",)),
                                  ("CloudPosture", "Standard", None, ()))]},
    "va.json": {"id": f"{SUB}/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings/AzureServersSetting",
                "name": "AzureServersSetting", "kind": "AzureServersSetting",
                "type": "Microsoft.Security/serverVulnerabilityAssessmentsSettings",
                "properties": {"selectedProvider": "MdeTvm"}},
    "policy-assignments.json": [
        {"id": f"{SUB}/providers/Microsoft.Authorization/policyAssignments/a", "name": "a", "scope": SUB,
         "type": "Microsoft.Authorization/policyAssignments", "displayName": "NIST SP 800-171 Rev. 2"},
        {"id": f"{SUB}/providers/Microsoft.Authorization/policyAssignments/b", "name": "b", "scope": SUB,
         "type": "Microsoft.Authorization/policyAssignments", "displayName": "Allowed locations"}],
    "automations.json": [{"id": f"{SUB}/resourceGroups/rg-sec/providers/Microsoft.Security/automations/defender-export",
                          "name": "defender-export", "type": "Microsoft.Security/automations",
                          "properties": {"isEnabled": True, "sources": [{"eventSource": "Alerts"}],
                                         "actions": [{"actionType": "Workspace", "workspaceResourceId": WORKSPACE}]}}]}


def test_the_cli_reads_the_same_services_as_state():
    resources, _ = cli_resources({p: json.dumps(d) for p, d in CLI.items()})
    assert [r for r in resources if r.kind == "security"] == list(security_resources(STATE))


def test_an_assignment_below_the_subscription_isnt_posture():
    nested = {**CLI, "policy-assignments.json": [{**CLI["policy-assignments.json"][0],
                                                  "scope": f"{SUB}/resourceGroups/rg-app"}]}
    posture, = [r for r in cli_resources({p: json.dumps(d) for p, d in nested.items()})[0]
                if r.kind == "security" and r.attrs["ciamSecurityKind"] == ("posture",)]
    assert "ciamComplianceStandard" not in posture.attrs


# ------------------------------------------------------------------ Event Hub export, security contacts (5.7b)
HUB_ID = f"{SUB}/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns/eventhubs/sec"
SEND = entry(ALPHA, "sec-send", "ciamSecretRef", ciamBindingRole="sec-hub-send", ciamRefUri="azkv://ciam-kv/sec-hub-send")
STREAM = entry(ALPHA, "sec-hub", "ciamStreamBinding", ciamBindingRole="sec-hub", ciamStreamKind="event-hub",
               ciamProviderRef=HUB_ID, ciamSendSecretRole="sec-hub-send")
MAIL = entry(ALPHA, "soc-mail", "ciamAlertChannel", ciamBindingRole="soc-mail", ciamChannelKind="email",
             ciamProviderRef="mailto:soc@example.test")


def test_findings_go_to_an_event_hub_with_the_connection_string_its_send_secret_holds():
    out = _render(STREAM, SEND, svc("defender", "threat-detection", ciamFindingsRole="sec-hub"))
    assert 'type              = "EventHub"' in out and f'resource_id       = "{HUB_ID}"' in out
    assert "connection_string = data.azurerm_key_vault_secret.defender_export.value" in out
    assert 'data "azurerm_key_vault_secret" "defender_export"' in out and 'name                = "ciam-kv"' in out
    assert "Terraform state keeps it (sensitive): protect the state" in out
    unsent = STREAM.replace("ciamSendSecretRole: sec-hub-send\n", "")
    assert "names no secret holding its connection string (ciamSendSecretRole)" in _render(
        unsent, svc("defender", "threat-detection", ciamFindingsRole="sec-hub"))


def test_email_channels_are_the_subscription_s_one_security_contact():
    out = _render(MAIL, svc("defender", "threat-detection", ciamFindingsRole="soc-mail"),
                  svc("scanner", "vulnerability-scanning", ciamFindingsRole="soc-mail"))
    assert out.count('resource "azurerm_security_center_contact"') == 1
    assert 'email               = "soc@example.test"' in out and "alerts_to_admins    = true" in out
    assert "# defender: its findings reach soc@example.test as Defender's security contact" in out
    assert "# NOTE" not in out


def test_incidents_by_email_name_the_minimum_severity_only_the_preview_api_sets():
    out = _render(MAIL, svc("defender", "threat-detection", ciamFindingsRole="security-logs",
                            ciamIncidentRole="soc-mail", ciamIncidentSeverity="high"))
    assert "# defender: its incidents reach soc@example.test as Defender's security contact; Defender's own minimum " \
           "alert severity (high) is set only by the securityContacts 2023-12-01-preview API" in out


# ------------------------------------------------------------------ organization-wide (5.7b, decision 2777)
def _organization(*records, mg="corp-security"):
    from opsdir.core.interchange.ldif import LdifRecord
    change = LdifRecord("cloud=alpha,ou=environments,dc=ciam-ops", "modify", {}, (
        ("add", "objectClass", ("ciamCloudAccount",)), *((("replace", "ciamManagementRef", (mg,)),) if mg else ())))
    _, alpha, _ = model(alpha=(LOGS, *records), tree=OWNERS, changes=(change,))
    from opsdir.domains.governance.keepers import ORGANIZATION
    items = render_security(alpha)
    org = [x for x in items if getattr(x, "origin", None) and x.origin.startswith(ORGANIZATION)]
    return "\n\n".join(as_text(tuple(x for x in items if x not in org))), "\n\n".join(as_text(tuple(org)))


def test_an_organization_wide_service_enables_its_plans_on_the_management_group():
    own, org = _organization(svc("defender", "threat-detection", ciamAuditScope="organization",
                                 ciamFindingsRole="security-logs",
                                 ciamSecurityCoverage=("control-plane", "compute", "applications")))
    assert "azurerm_security_center_subscription_pricing" not in own and 'event_source = "Alerts"' in own
    assert "# defender: organization-wide: enabled for every account by" in own
    assert 'name = "5eb6d64a-4086-4d7a-92da-ec51aed0332d"' in own + org      # Servers, by its GUID (a lookup)
    assert re.search(r'resource "azurerm_management_group_policy_assignment" "defender_virtualmachines" \{', org)
    assert re.search(r'management_group_id += var\.management_group_id', org) and 'type = "SystemAssigned"' in org
    assert "for_each           = toset(data.azurerm_policy_definition.defender_arm.role_definition_ids)" in org
    assert ("principal_id       = azurerm_management_group_policy_assignment.defender_arm.identity[0].principal_id"
            in org)
    assert re.search(r'resource "azurerm_management_group_policy_remediation" "defender_appservices"', org)
    assert "# defender: no built-in policy enables Defender plan Api at scale (an audit policy only)" in own + org
    assert 'variable "management_group_id"' in own + org


def test_organization_wide_posture_assigns_its_frameworks_on_the_management_group_or_is_said_so():
    own, org = _organization(svc("cspm", "posture", ciamAuditScope="organization",
                                 ciamComplianceStandard="nist-800-171-r2"))
    assert 'name = "72f8cee7-2937-403d-84a1-a4e3e57f3c21"' in own + org
    assert 'display_name         = "NIST SP 800-171 Rev. 2"' in org
    own, org = _organization(svc("cspm", "posture", ciamAuditScope="organization"), mg=None)
    assert org == "" and "the record doesn't name the management group (ciamManagementRef)" in own


# ------------------------------------------------------------------ change history kept longer (5.7b, decision 2777)
def test_changes_kept_longer_than_resource_graph_does_are_copied_hourly_into_log_analytics():
    out = _render(svc("changes", "config-recording", ciamFindingsRole="security-logs", ciamRetentionDays="2557"))
    assert 'name      = "CiamResourceChanges_CL"' in out or re.search(r'name +\= "CiamResourceChanges_CL"', out)
    assert re.search(r"retention_in_days += 730", out) and re.search(r"total_retention_in_days += 2922", out)
    assert "Log Analytics keeps rows beyond 730 days in whole years, at most 4383: 2557 days kept 2922" in out
    assert 'resource "azurerm_monitor_data_collection_endpoint" "changes_changes"' in out
    assert re.search(r'output_stream += "Custom-CiamResourceChanges_CL"', out)
    assert 'resource "azurerm_logic_app_workflow" "changes_changes"' in out and "azapi" not in out
    assert 'resource "azurerm_logic_app_trigger_recurrence" "changes_changes"' in out
    assert 'resource "azurerm_logic_app_action_custom" "changes_changes_keep_changes"' in out
    assert "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01" in out
    assert ("${azurerm_monitor_data_collection_endpoint.changes_changes.logs_ingestion_endpoint}/dataCollectionRules/"
            "${azurerm_monitor_data_collection_rule.changes_changes.immutable_id}/streams/Custom-ResourceChanges"
            ) in out
    assert '"audience" : "https://monitor.azure.com"' in out and '"$top" : 1000' in out
    assert 'role_definition_name = "Reader"' in out and 'role_definition_name = "Monitoring Metrics Publisher"' in out
    gov = _render(svc("changes", "config-recording", ciamFindingsRole="security-logs", ciamRetentionDays="90"),
                  gov=True)
    assert "https://management.usgovcloudapi.net" in gov and '"audience" : "https://monitor.azure.us"' in gov
    assert "total_retention_in_days" not in gov


def test_changes_kept_longer_without_a_workspace_are_said_so():
    out = _render(svc("changes", "config-recording", ciamRetentionDays="90"))
    assert "# NOTE: changes: keeping resource changes 90 days, longer than Resource Graph's 14, needs a Log " \
           "Analytics workspace" in out
