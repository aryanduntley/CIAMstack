"""Product logs from an environment's servers to Log Analytics: per route a custom table and a data collection rule
(one workspace), a text source and stream per file and install root, all lines or those of the route's kinds (KQL
on the JSON in RawData), an association per server; what can't ship, or ships differently, named."""
from opsdir.connectors.registry import services
from opsdir.core.contract import LogSource
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.naming import LOG_ROUTES
from opsdir_adapter_azure.log_collection import log_collection_notes, render_log_collection, table_name
from network_fixtures import ALPHA, entry, model

WS = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/"
      "Microsoft.OperationalInsights/workspaces/{}")
SOURCES = (LogSource("ds", "servers", "logs/errors", "text", "error", line_start=r"^\["),
           LogSource("ds", "servers", "var/audit/*.json", "json-lines", "audit",
                     (("eventName", "AM-ACCESS-", "access"),)),
           LogSource("web", "servers", "log/web.log", "text", "access"))
OU = "dn: {}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {}\n"


def _route(cn, kinds, roles, dest):
    return (f"dn: cn={cn},{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\n"
            f"cn: {cn}\n" + "".join(f"ciamLogKind: {k}\n" for k in kinds)
            + "".join(f"ciamPublishedBy: {r}\n" for r in roles) + f"ciamLogDestinationRole: {dest}\n")


TREE = (OU.format(LOG_ROUTES, "log-routes"), _route("access-logs", ("access",), ("ds", "web"), "ops-logs"),
        _route("errors", ("error",), ("ds",), "siem"))
BINDINGS = (entry(ALPHA, "ops", "ciamLogDestination", ciamBindingRole="ops-logs", ciamDestinationKind="workspace",
                  ciamProviderRef=WS.format("law-ops")),
            entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                  ciamProviderRef="splunk://ciam"))


def _root(server, root):
    return LdifRecord(f"cn={server},{ALPHA}", "modify", {}, (("add", "ciamInstallRoot", (root,)),))


def _alpha():
    _, alpha, _ = model(alpha=BINDINGS, tree=TREE, changes=(_root("ds-1", "/opt/ds"), _root("ds-2", "/srv/ds"),
                                                            _root("web-1", "/opt/web")))
    return alpha


def _services():
    return services()._replace(logs=lambda m: SOURCES)


def test_a_route_is_a_custom_table_a_rule_with_a_stream_per_file_and_an_association_per_server():
    alpha = _alpha()
    assert [table_name(r) for r in log_routes(alpha.d)] == ["CiamAccessLogs_CL", "CiamErrors_CL"]
    hcl = "\n".join(render_log_collection(alpha, _services()))
    assert 'resource "azurerm_log_analytics_workspace_table_custom_log" "logs_access_logs"' in hcl
    assert 'name         = "CiamAccessLogs_CL"' in hcl
    assert "workspace_id = azurerm_log_analytics_workspace.ops.id" in hcl
    table, rule = hcl.split('resource "azurerm_monitor_data_collection_rule" ', 1)
    assert 'type = "dateTime"' in table and 'type = "datetime"' in rule     # each as its resource names it
    assert hcl.count("log_file {") == 3                   # ds audit under two roots, web's log
    assert all(f'file_patterns = ["/{root}/ds/var/audit/*.json"]' in hcl for root in ("opt", "srv"))
    assert ('transform_kql = "source | where tostring(parse_json(RawData)[\\"eventName\\"]) startswith_cs '
            '\\"AM-ACCESS-\\""') in hcl                    # some of the audit file's lines: access events
    assert 'transform_kql = "source"' in hcl              # all of web's log
    assert 'output_stream = "Custom-CiamAccessLogs_CL"' in hcl
    assert "depends_on = [azurerm_log_analytics_workspace_table_custom_log.logs_access_logs]" in hcl
    for host in ("ds_1", "ds_2", "web_1"):
        assert f"target_resource_id      = azurerm_linux_virtual_machine.{host}.id" in hcl
    assert "errors" not in hcl.split("logs_access_logs")[0]  # the SIEM route renders nothing


def test_what_isnt_shipped_or_ships_differently_is_named():
    notes = log_collection_notes(_alpha(), _services())
    assert notes[0].startswith("# NOTE: log route errors: /opt/ds/logs/errors not shipped: its destination siem isn't")
    assert any("Azure Monitor Agent (VM extension Microsoft.Azure.Monitor AzureMonitorLinuxAgent)" in n for n in notes)
    assert not any("Azure Government" in n for n in notes)
