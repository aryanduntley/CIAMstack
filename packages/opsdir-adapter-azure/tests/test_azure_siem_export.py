"""Log Analytics forwarded on to a SIEM (milestone 109, task 574): a workspace whose log destination forwards to a SIEM
index exports the tables its routes land in to an existing Event Hub (named by ID: no namespace or rule resource, so no
SAS key in state); reading the hub is the SIEM team's action, with Azure Government's support statement; what can't be
rendered is a blocker; the ARM form is the workspace's dataExports child."""
from opsdir.connectors.registry import services
from opsdir.core.contract import LogSource
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.observability.naming import LOG_ROUTES
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_azure.siem_export import exported_tables, render_siem_export, siem_export_notes
from network_fixtures import ALPHA, entry, model

WS = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-logs/providers/"
      "Microsoft.OperationalInsights/workspaces/law-ops")
HUB = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-logs/providers/"
       "Microsoft.EventHub/namespaces/ehns-siem/eventhubs/ciam-logs")
SOURCES = (LogSource("ds", "servers", "logs/access", "text", "access"),)
OU = "dn: {}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {}\n"
TREE = (OU.format(LOG_ROUTES, "log-routes"),
        f"dn: cn=access-logs,{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\n"
        "cn: access-logs\nciamLogKind: access\nciamPublishedBy: ds\nciamLogDestinationRole: ops-logs\n")


def _bindings(hub=HUB, forwards="siem"):
    return (entry(ALPHA, "ops", "ciamLogDestination", ciamBindingRole="ops-logs", ciamDestinationKind="workspace",
                  ciamProviderRef=WS, ciamForwardsToRole=forwards, ciamStreamRole="siem-hub"),
            entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                  ciamProviderRef="ciam_security"),
            *((entry(ALPHA, "siem-hub", "ciamStreamBinding", ciamBindingRole="siem-hub", ciamStreamKind="event-hub",
                     ciamProviderRef=hub),) if hub else ()))


def _alpha(**kw):
    root = LdifRecord(f"cn=ds-1,{ALPHA}", "modify", {}, (("add", "ciamInstallRoot", ("/opt/ds",)),))
    _, alpha, _ = model(alpha=_bindings(**kw), tree=TREE, changes=(root,))
    return alpha


def _services():
    return services()._replace(logs=lambda m: SOURCES)


def test_a_forwarded_workspace_exports_its_route_tables_to_the_existing_hub():
    alpha = _alpha()
    ops = next(b for b in alpha.bindings if b.dn.startswith("cn=ops,"))
    assert exported_tables(alpha, ops, _services()) == ("CiamAccessLogs_CL",)
    text = "\n\n".join(as_text(render_siem_export(alpha, _services())))
    for line in ('resource "azurerm_log_analytics_data_export_rule" "ops"', 'name                    = "to-siem"',
                 "resource_group_name     = data.azurerm_resource_group.main.name",
                 "workspace_resource_id   = azurerm_log_analytics_workspace.ops.id",
                 f'destination_resource_id = "{HUB}"', 'table_names             = ["CiamAccessLogs_CL"]'):
        assert line in text, line
    assert "azurerm_eventhub" not in text and "authorization_rule" not in text        # no SAS key in state
    (action,) = siem_export_notes(alpha, _services())
    assert action.severity == "action" and "Event Hub" in action.text


def test_without_a_hub_it_is_a_blocker():
    alpha = _alpha(hub=None)
    assert "azurerm_log_analytics_data_export_rule" not in "\n".join(as_text(render_siem_export(alpha, _services())))
    (blocker,) = siem_export_notes(alpha, _services())
    assert blocker.severity == "blocker" and "an existing Event Hub" in blocker.text


def test_the_arm_form_is_the_workspace_data_export():
    from types import SimpleNamespace
    from opsdir_format_terraform.hcl import TfFile, ref, tf_block
    from opsdir_adapter_azure.arm_types import arm_translation
    root = TfFile("", (
        tf_block("data", ["azurerm_resource_group", "main"], [("name", "rg-logs")]),
        tf_block("resource", ["azurerm_log_analytics_workspace", "ops"], [
            ("name", "law-ops"), ("location", ref("data.azurerm_resource_group.main.location")),
            ("resource_group_name", ref("data.azurerm_resource_group.main.name")), ("sku", "PerGB2018")]),
        *render_siem_export(_alpha(), _services())))
    t = arm_translation(SimpleNamespace(dn=ALPHA, label="alpha/prod"), {"terraform/main.tf": root}, "x")
    export = next(r for (_, k), tpl in t.templates.items() for r in tpl.resources
                  if r.type == "Microsoft.OperationalInsights/workspaces/dataExports")
    assert export.properties == {"destination": {"resourceId": HUB}, "tableNames": ["CiamAccessLogs_CL"],
                                 "enable": True}
