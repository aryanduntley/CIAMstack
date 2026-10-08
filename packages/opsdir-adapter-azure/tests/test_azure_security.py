"""Cloud security services on Azure: Defender for Cloud plans merged across the services that need them (one pricing per
plan), the Defender Vulnerability Management setting, Defender CSPM and a policy assignment per framework's built-in
initiative, continuous export to a Log Analytics workspace; in Azure Government every plan rendered, with a comment
where one of Microsoft's availability pages lists it as unavailable; configuration recording, identity, services kept by
someone else and other clouds' baselines in comments; all read back from Terraform state."""
from opsdir.core.directory import make_entry
from opsdir.core.inventory import environment_groups, resource
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
    return "\n\n".join(render_security(alpha))


DETECTION = svc("defender", "threat-detection", ciamFindingsRole="security-logs",
                ciamSecurityCoverage=("control-plane", "identity", "network", "compute", "containers", "storage"))


def test_defender_plans_are_merged_one_per_plan():
    out = _render(DETECTION, svc("mdvm", "vulnerability-scanning", ciamSecurityCoverage=("compute", "containers")))
    assert out.count('resource "azurerm_security_center_subscription_pricing" "virtualmachines"') == 1
    assert [p for p in ("Arm", "VirtualMachines", "Containers", "StorageAccounts", "KeyVaults")
            if f'resource_type = "{p}"' in out] == ["Arm", "VirtualMachines", "Containers", "StorageAccounts"]
    assert 'subplan       = "P2"' in out and '"ContainerRegistriesVulnerabilityAssessments"' in out
    assert 'vulnerability_assessment_provider = "MdeTvm"' in out
    assert "# defender: Defender for Cloud has no plan for identity" in out
    assert "Azure Government" not in out


def test_findings_go_to_the_workspace_by_continuous_export():
    out = _render(DETECTION)
    assert 'data "azurerm_subscription" "current"' in out
    assert f'resource_id = "{WORKSPACE}"' in out and 'event_source = "Alerts"' in out
    assert "# NOTE" not in _render(svc("defender", "threat-detection", ciamFindingsRole="nowhere"))
    hub = entry(ALPHA, "event-hub", "ciamLogDestination", ciamBindingRole="event-hub", ciamDestinationKind="other",
                ciamProviderRef=f"{SUB}/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns/eventhubs/sec")
    assert "# NOTE: defender's findings to event-hub: not rendered: continuous export is rendered to a Log Analytics " \
           "workspace" in _render(hub, svc("defender", "threat-detection", ciamFindingsRole="event-hub"))


def test_in_azure_government_every_plan_is_rendered_with_a_comment_where_a_page_lists_it_unavailable():
    out = _render(svc("defender", "threat-detection", ciamSecurityCoverage=("containers", "databases", "applications")),
                  svc("mdvm", "vulnerability-scanning"), gov=True)
    for plan in ("Containers", "CosmosDbs", "AppServices", "Api"):
        assert f'resource_type = "{plan}"' in out
    assert out.count("rendered, confirm with the account team") == 5
    assert "list Defender for App Service as unavailable in Azure Government" in out
    assert "lists integrated vulnerability assessment for machines as not available" in out


def test_posture_assigns_each_framework_s_built_in_initiative():
    out = _render(svc("cspm", "posture", ciamAuditScope="organization",
                      ciamComplianceStandard=("nist-800-171-r2", "cmmc-l2", "dod-il5", "hitrust"),
                      ciamSecurityBaseline=("microsoft-cloud-security-benchmark", "aws-foundational")))
    assert 'resource_type = "CloudPosture"' in out
    assert 'display_name = "NIST SP 800-171 Rev. 2"' in out and 'display_name = "CMMC 2.0 Level 2"' in out
    assert "policy_definition_id = data.azurerm_policy_set_definition.nist_800_171_r2.id" in out
    assert "# cspm: Defender for Cloud assigns the Microsoft cloud security benchmark itself" in out
    assert "# cspm: Azure has no built-in initiative here for dod-il5, hitrust (not rendered)" in out
    assert "# cspm: aws-foundational: another cloud's baseline, not Azure's (not rendered)" in out
    assert "# cspm: organization-wide: enable it on the management group with Azure Policy" in out
    gov = _render(svc("cspm", "posture", ciamComplianceStandard=("cmmc-l2", "dod-il5")), gov=True)
    assert 'display_name = "DoD Impact Level 5"' in gov and "list CMMC Level 3, not CMMC 2.0 Level 2" in gov


def test_config_recording_and_services_kept_elsewhere_are_comments():
    assert _render(svc("changes", "config-recording")) == (
        "# changes: Azure records resource changes itself (Resource Graph change history, about 14 days): nothing to "
        "enable; keeping them longer needs an export (not rendered)")
    assert _render(svc("org-defender", "threat-detection", ciamManagedBy=PARTY)) == (
        "# Security service org-defender (threat-detection): kept by landing-zone, not rendered here")


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
    out = (*render_trails(alpha), *render_security(alpha))
    assert out.count(data) == 2      # terraform.render keeps the first of identical data sources
    kept = tuple(x for i, x in enumerate(out) if not (x.startswith('data "') and x in out[:i]))
    assert kept.count(data) == 1
