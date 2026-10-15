"""Product logs from an environment's servers to Log Analytics: per route a custom table and a data collection rule
(one workspace), a text source and stream per file and install root, all lines or those of the route's kinds (KQL
on the JSON in RawData), an association per server; the Azure Monitor Agent extension on servers whose host baseline
doesn't bring it, with the VM's system-assigned identity; what can't ship, or ships differently, named."""
from opsdir.connectors.registry import services
from opsdir.core.contract import LogSource
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.compute.naming import BASELINES
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.naming import LOG_ROUTES
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_azure.log_collection import agent_hosts, log_collection_notes, render_log_collection, table_name
from opsdir_adapter_azure.terraform import render
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


BASELINE = (OU.format(BASELINES, "baselines")
            + f"\ndn: cn=ds,{BASELINES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamHostBaseline\n"
            "cn: ds\nciamTargetRole: ds\nciamHostAgent: azuremonitoragent 1.33.2\n")


def _root(server, root):
    return LdifRecord(f"cn={server},{ALPHA}", "modify", {}, (("add", "ciamInstallRoot", (root,)),))


def _alpha(tree=TREE):
    _, alpha, _ = model(alpha=BINDINGS, tree=tree, changes=(_root("ds-1", "/opt/ds"), _root("ds-2", "/srv/ds"),
                                                            _root("web-1", "/opt/web")))
    return alpha


def _services():
    return services()._replace(logs=lambda m: SOURCES)


def test_a_route_is_a_custom_table_a_rule_with_a_stream_per_file_and_an_association_per_server():
    alpha = _alpha()
    assert [table_name(r) for r in log_routes(alpha.d)] == ["CiamAccessLogs_CL", "CiamErrors_CL"]
    hcl = "\n".join(as_text(render_log_collection(alpha, _services())))
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
    found = log_collection_notes(_alpha(), _services())
    notes = _comments(found)
    assert {n.severity for n in found} == {"blocker"}
    assert notes[0].startswith("# NOTE: log route errors: /opt/ds/logs/errors not shipped: its destination siem isn't")
    assert not any("Azure Monitor Agent" in n for n in notes)   # installed here: nothing to name
    assert not any("Azure Government" in n for n in notes)


def test_the_agent_is_installed_on_each_server_shipping_logs_with_its_own_identity():
    alpha = _alpha()
    assert agent_hosts(alpha, _services()) == ("ds-1", "ds-2", "web-1")
    hcl = "\n".join(as_text(render_log_collection(alpha, _services())))
    assert hcl.count('resource "azurerm_virtual_machine_extension"') == 3
    ext = hcl.split('resource "azurerm_virtual_machine_extension" "ama_ds_1"', 1)[1].split("\n}", 1)[0]
    for line in ('name                       = "AzureMonitorLinuxAgent"',
                 "virtual_machine_id         = azurerm_linux_virtual_machine.ds_1.id",
                 'publisher                  = "Microsoft.Azure.Monitor"',
                 'type                       = "AzureMonitorLinuxAgent"',
                 "automatic_upgrade_enabled  = true"):
        assert line in ext
    out = render(alpha, _services())
    vm = out["terraform/main.tf"].split('resource "azurerm_linux_virtual_machine" "ds_1"', 1)[1].split("\n}", 1)[0]
    assert 'type = "SystemAssigned"' in vm
    assert "terraform/landing-zone/providers.tf" not in out        # no landing zone: the platform root names them
    assert ("# NOTE: resource providers: to register in the subscription before applying (azurerm 5.x registers "
            "none, and the environment has no landing zone to do it): Microsoft.Compute, Microsoft.Insights") \
        in out["terraform/providers.tf"]


def test_a_baseline_bringing_the_agent_keeps_it_out_and_is_named():
    alpha = _alpha(TREE + (BASELINE,))
    assert agent_hosts(alpha, _services()) == ("web-1",)
    hcl = "\n".join(as_text(render_log_collection(alpha, _services())))
    assert "ama_ds_1" not in hcl and "ama_web_1" in hcl
    assert ("# NOTE: role ds: the Azure Monitor Agent comes with its host baseline (azuremonitoragent 1.33.2), not "
            "installed here") in _comments(log_collection_notes(alpha, _services()))
    main = render(alpha, _services())["terraform/main.tf"]
    vm = main.split('resource "azurerm_linux_virtual_machine" "ds_1"', 1)[1].split("\n}", 1)[0]
    assert "SystemAssigned" not in vm


def _comments(notes):
    """The comments render_files writes for notes (flow 43)."""
    from opsdir.core.notes import note_comment
    return tuple(f"# {note_comment(n)}" for n in notes)