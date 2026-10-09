"""Control-plane audit trails on Azure: an account trail the platform keeps rendered as the subscription's Activity Log
diagnostic setting (audit categories) into its storage account or Log Analytics workspace; trails kept by someone
else, organization trails and other destinations named, not rendered; data events and integrity without an immutable
container noted. Read back from Terraform state, the CLI and ARM templates: the subscription's diagnostic settings with
where their records go as that object store's or workspace's role."""
import json

from opsdir.core.inventory import environment_groups, resource
from opsdir_adapter_azure.arm import arm_resources
from opsdir_adapter_azure.audit import render_trails, trail_events, trail_resources
from opsdir_adapter_azure.cli import cli_resources
from network_fixtures import ALPHA, entry, model

SUBSCRIPTION = "/subscriptions/00000000-0000-0000-0000-000000000000"
ACCOUNT = f"{SUBSCRIPTION}/resourceGroups/rg-ciam/providers/Microsoft.Storage/storageAccounts/stciamaudit"
CONTAINER = f"{ACCOUNT}/blobServices/default/containers/insights-activity-logs"
WORKSPACE = f"{SUBSCRIPTION}/resourceGroups/rg-ciam/providers/Microsoft.OperationalInsights/workspaces/law-audit"
PARTY = "cn=landing-zone,ou=owners,dc=ciam-ops"
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
          f"dn: {PARTY}\nobjectClass: top\nobjectClass: ciamParty\ncn: landing-zone\nciamOwnerKind: team\n")
STORE = entry(ALPHA, "activity-logs", "ciamObjectStore", ciamBindingRole="activity-logs",
              ciamStorageRef="azblob://stciamaudit/insights-activity-logs", ciamProviderRef=CONTAINER)
LAW = entry(ALPHA, "law-audit", "ciamLogDestination", ciamBindingRole="audit-logs", ciamDestinationKind="workspace",
            ciamProviderRef=WORKSPACE)
SIEM = entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index")


def _trail(cn, destination, **more):
    return entry(ALPHA, cn, "ciamAuditTrail", **{"ciamBindingRole": cn, "ciamAuditScope": "account",
                                                 "ciamLogDestinationRole": destination, **more})


def test_an_account_trail_the_platform_keeps_is_the_subscription_s_diagnostic_setting():
    trails = (_trail("activity-log", "activity-logs", ciamAuditEvents=("control-plane", "data-write"),
                     ciamAllRegions="TRUE", ciamIntegrityValidation="TRUE",
                     ciamProviderRef=f"{SUBSCRIPTION}/providers/Microsoft.Insights/diagnosticSettings/ciam-activity"),
              _trail("to-workspace", "audit-logs"),
              _trail("org-trail", "audit-logs", ciamManagedBy=PARTY),
              _trail("org-own", "audit-logs", ciamAuditScope="organization"),
              _trail("to-siem", "siem"))
    _, alpha, _ = model(alpha=(STORE, LAW, SIEM, *trails), tree=OWNERS)
    out = render_trails(alpha)
    assert out[0] == 'data "azurerm_subscription" "current" {\n}'
    assert out[1] == ('''resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  # data-write events: each resource's own diagnostic settings log them (not rendered)
  # integrity: Azure keeps no digest of the Activity Log; keep it in a container with a locked immutability '''
                      '''policy (ciamStorageImmutability compliance)
  name               = "ciam-activity"
  target_resource_id = data.azurerm_subscription.current.id
  storage_account_id = "''') + ACCOUNT + '''"
  enabled_log {
    category = "Administrative"
  }
  enabled_log {
    category = "Security"
  }
  enabled_log {
    category = "Policy"
  }
}'''
    assert out[2:] == (
        "# NOTE: audit trail org-own: not rendered: Azure has no organization trail: each subscription's Activity Log "
        "is exported by its own diagnostic setting (the landing zone's policy deploys them); record it kept by the "
        "landing zone (ciamManagedBy)",
        "# Audit trail org-trail (account): kept by landing-zone, not rendered here",
        "# NOTE: audit trail to-siem: not rendered: Azure exports the Activity Log to a storage account, a Log "
        "Analytics workspace or an event hub, and siem is none of those", out[-1])
    assert 'log_analytics_workspace_id = "' + WORKSPACE + '"' in out[-1]


def _locked(mode):
    return entry(ALPHA, "activity-logs", "ciamObjectStore", ciamBindingRole="activity-logs",
                 ciamStorageRef="azblob://stciamaudit/audit", ciamStorageImmutability=mode, ciamStorageLockDays="365")


def test_a_locked_container_proves_integrity_and_another_container_is_named():
    _, alpha, _ = model(alpha=(_locked("compliance"),
                               _trail("activity-log", "activity-logs", ciamIntegrityValidation="TRUE")))
    out = render_trails(alpha)
    assert out[1] == ("# NOTE: Azure writes the Activity Log to container insights-activity-logs of storage account "
                      "stciamaudit, not audit: record that container as the object store")
    assert "storage_account_id = azurerm_storage_account.stciamaudit.id" in out[2] and "integrity" not in out[2]


def test_an_unlocked_container_doesn_t_prove_integrity():
    _, alpha, _ = model(alpha=(_locked("governance"),
                               _trail("activity-log", "activity-logs", ciamIntegrityValidation="TRUE")))
    assert "# integrity: Azure keeps no digest" in render_trails(alpha)[2]


def test_the_activity_a_setting_exports_comes_from_its_categories():
    assert trail_events({"enabled_log": [{"category": "Administrative"}]}) == ("control-plane",)
    assert trail_events({"enabled_log": [{"category": "ServiceHealth"}]}) == ()
    assert trail_events({"log": [{"category": "Administrative", "enabled": False}]}) == ()


def _placed(resources):
    d, *_ = model(alpha=(STORE, LAW))
    groups, _ = environment_groups(d, "alpha/prod", resources)
    return [(e.dn.split(",")[0], dict(e.attrs)) for _, entries in groups for e in entries
            if "ciamAuditTrail" in e.classes]


def test_a_subscription_setting_is_read_back_with_its_container_s_role():
    setting = {"id": f"{SUBSCRIPTION}|ciam-activity", "name": "ciam-activity", "target_resource_id": SUBSCRIPTION,
               "storage_account_id": ACCOUNT, "enabled_log": [{"category": "Administrative"}, {"category": "Policy"}]}
    resource_own = {**setting, "name": "account-diag", "target_resource_id": ACCOUNT}
    trail, = trail_resources([("azurerm_monitor_diagnostic_setting", setting)])
    assert trail_resources([("azurerm_monitor_diagnostic_setting", resource_own)]) == ()
    container = resource("storage", CONTAINER, {"ciamStorageRef": "azblob://stciamaudit/insights-activity-logs"},
                         name="insights-activity-logs")
    assert _placed((container, trail)) == [("cn=ciam-activity", {
        "cn": ("ciam-activity",), "ciamBindingRole": ("audit-trail",),
        "ciamProviderRef": (f"{SUBSCRIPTION}/providers/Microsoft.Insights/diagnosticSettings/ciam-activity",),
        "ciamAuditScope": ("account",), "ciamAuditEvents": ("control-plane",), "ciamAllRegions": ("TRUE",),
        "ciamLogDestinationRole": ("activity-logs",)})]


def test_the_cli_s_subscription_settings_are_read_the_same_way():
    listed = {"value": [{"id": f"{SUBSCRIPTION}/providers/microsoft.insights/diagnosticSettings/ciam-activity",
                         "name": "ciam-activity", "type": "Microsoft.Insights/diagnosticSettings",
                         "workspaceId": WORKSPACE, "storageAccountId": None,
                         "logs": [{"category": "Administrative", "enabled": True},
                                  {"category": "Security", "enabled": False}]}]}
    resources, _ = cli_resources({"diagnostic-settings.json": json.dumps(listed)})
    trails = [r for r in resources if r.kind == "audit"]
    assert [(r.ref, dict(r.attrs), dict(r.links)) for r in trails] == [(
        f"{SUBSCRIPTION}/providers/Microsoft.Insights/diagnosticSettings/ciam-activity",
        {"ciamAuditScope": ("account",), "ciamAuditEvents": ("control-plane",), "ciamAllRegions": ("TRUE",)},
        {"ciamLogDestinationRole": WORKSPACE})]


def test_an_arm_template_s_subscription_setting_is_read_and_a_resource_s_own_is_not():
    template = {"$schema": "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#",
                "resources": [
                    {"type": "Microsoft.Insights/diagnosticSettings", "apiVersion": "2021-05-01-preview",
                     "name": "ciam-activity", "properties": {
                         "workspaceId": WORKSPACE, "logs": [{"category": "Administrative", "enabled": True}]}},
                    {"type": "Microsoft.Insights/diagnosticSettings", "apiVersion": "2021-05-01-preview",
                     "name": "kv-diag", "scope": "[resourceId('Microsoft.KeyVault/vaults', 'kv')]", "properties": {
                         "workspaceId": WORKSPACE, "logs": [{"category": "AuditEvent", "enabled": True}]}}]}
    resources, _ = arm_resources({"main.json": json.dumps(template)})
    assert [(r.name, r.attrs["ciamAuditEvents"]) for r in resources if r.kind == "audit"] == [
        ("ciam-activity", ("control-plane",))]
