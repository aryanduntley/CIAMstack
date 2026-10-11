"""Product logs from an environment's servers to Log Analytics (core observability: log routes; what each route ships
and from which servers: domains/observability/sources), through the Azure Monitor Agent: per log route whose
destination here is a workspace, a data collection rule and the custom table it fills. Terraform only. Pure.

Per route: azurerm_log_analytics_workspace_table_custom_log Ciam<Route>_CL (TimeGenerated, RawData, FilePath,
Computer: a text log's columns), and azurerm_monitor_data_collection_rule dcr-ciam-<env>-<route> sending to that
workspace (one workspace per rule, as Microsoft's custom log pages say). Each file the route takes from a role's
servers, under each install root, is a log_file source of format text with a stream of its own (so each file has its
own transformation): `source` when the route takes all its lines, `source | where <its kinds>` (parse_json(RawData),
kql.kept) when only some. An association per server ties the rule to its virtual machine.
learn.microsoft.com/azure/azure-monitor/vm/data-collection-log-text, .../data-collection-log-json,
.../data-collection/data-collection-transformations-kql (research note 2352).

The agent itself: an azurerm_virtual_machine_extension AzureMonitorLinuxAgent (Microsoft.Azure.Monitor, automatic
upgrade) on each server shipping logs here, authenticating with its virtual machine's system-assigned identity
(terraform adds it), unless the role's host baseline in the environment lists the agent's package azuremonitoragent:
then Azure Policy or the image brings it, and that is named instead (user decision 2358, amending 2328).
learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-manage (research note 2354).

Named instead (# NOTE): a route whose destination here isn't a workspace; a file whose records span lines (the agent
starts a record only at a timestamp of a fixed set of formats, not a pattern: each line arrives as a record); per
role, that its host baseline brings the agent; and, in Azure Government, that custom text log collection there is to
be confirmed (research 2352: no Government row names it).
"""
import re

from opsdir.core.directory import one, rdn_value, values
from opsdir.domains.compute.hosts import baseline_for
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.sources import ALL, kept_clauses, shipments
from opsdir_format_terraform.hcl import Block, comment, ref, tf_block, tf_name
from .account import government, tagged
from .identities import LOC, RG
from .kql import field_of, kept
from .observability import workspace_id

TABLE, RULE, ASSOCIATION = ("azurerm_log_analytics_workspace_table_custom_log", "azurerm_monitor_data_collection_rule",
                            "azurerm_monitor_data_collection_rule_association")
COLUMNS = ("TimeGenerated", "RawData", "FilePath", "Computer")
# The columns' types as a table names them, and as a data collection rule's stream declaration does
TABLE_TYPES = {"TimeGenerated": "dateTime"}
STREAM_TYPES = {"TimeGenerated": "datetime"}
VM, EXTENSION = "azurerm_linux_virtual_machine", "azurerm_virtual_machine_extension"
AGENT = "azuremonitoragent"                 # the Azure Monitor Agent's Linux package, as a host baseline records it


def table_name(route):
    """The custom table a route's logs go to: Ciam<Route in CamelCase>_CL."""
    return "Ciam" + "".join(w.capitalize() for w in re.split(r"[^A-Za-z0-9]+", rdn_value(route)) if w) + "_CL"


def host_shipments(m, services):
    """Environment m's Shipments from its servers whose destination is a workspace here."""
    return tuple(x for x in shipments(m, log_routes(m.d), services.logs(m))
                 if x.on == "servers" and workspace_id(m, x.destination) is not None)


def baseline_agent(m, role):
    """The Azure Monitor Agent as role's host baseline in environment m records it ('azuremonitoragent 1.33'), or
    None: the agent then comes with the baseline (Azure Policy, the image), not from here."""
    b = baseline_for(m.d, role, m)
    return next((v for v in values(b, "ciamHostAgent") if v.split()[0].lower() == AGENT), None) if b else None


def agent_hosts(m, services):
    """Names of environment m's servers whose virtual machine gets the Azure Monitor Agent extension here: those
    shipping logs to a workspace whose role's host baseline doesn't bring the agent."""
    shipping = {h for x in host_shipments(m, services) for h in x.hosts}
    return tuple(rdn_value(s) for s in m.servers
                 if rdn_value(s) in shipping and baseline_agent(m, one(s, "ciamServerRole")) is None)


def _extension(m, h):
    return tf_block("resource", [EXTENSION, f"ama_{tf_name(h)}"], [
        ("#", "Azure Monitor Agent; authenticates with the VM's system-assigned identity (no settings)"),
        ("name", "AzureMonitorLinuxAgent"), ("virtual_machine_id", ref(f"{VM}.{tf_name(h)}.id")),
        ("publisher", "Microsoft.Azure.Monitor"), ("type", "AzureMonitorLinuxAgent"), ("type_handler_version", "1.0"),
        ("auto_upgrade_minor_version", True), ("automatic_upgrade_enabled", True),
        ("tags", tagged(m, {"ManagedBy": "opsdir"}))])


def transform(x):
    """A shipment's KQL transformation: all its lines, or those of the route's kinds."""
    if x.lines == ALL:
        return "source"
    return "source | where " + kept(kept_clauses(x.source, values(x.route, "ciamLogKind")), field_of("RawData"))


def _columns(types):
    return tuple(("column", Block((("name", c), ("type", types.get(c, "string"))))) for c in COLUMNS)


def _source(i, stream, x):
    return ("log_file", Block((("name", f"file{i}"), ("file_patterns", [x.path]), ("format", "text"),
                               ("streams", [stream]))))


def _flow(table, stream, x):
    return ("data_flow", Block((("streams", [stream]), ("destinations", ["workspace"]),
                                ("transform_kql", transform(x)), ("output_stream", f"Custom-{table}"))))


def _rule(m, n, route, table, dest, streams):
    return tf_block("resource", [RULE, n], [
        ("name", f"dcr-ciam-{rdn_value(m.env)}-{rdn_value(route)}"), ("location", LOC), ("resource_group_name", RG),
        ("description", f"Log route {rdn_value(route)}: product log files to {rdn_value(dest)} (opsdir)"),
        ("destinations", Block((("log_analytics", Block((("name", "workspace"),
                                                          ("workspace_resource_id", workspace_id(m, dest))))),))),
        ("data_sources", Block(tuple(_source(i, s, x) for i, (s, x) in enumerate(streams, 1)))),
        *(("stream_declaration", Block((("stream_name", s), *_columns(STREAM_TYPES)))) for s, _ in streams),
        *(_flow(table, s, x) for s, x in streams),
        ("depends_on", [ref(f"{TABLE}.{n}")]),
        ("tags", tagged(m, {"Realizes": rdn_value(route), "ManagedBy": "opsdir"}))])


def _route_blocks(m, route, found):
    n, table, dest = tf_name(f"logs_{rdn_value(route)}"), table_name(route), found[0].destination
    streams = tuple((f"Custom-{table[:-3]}File{i}", x) for i, x in enumerate(found, 1))
    hosts = tuple(dict.fromkeys(h for x in found for h in x.hosts))
    return (tf_block("resource", [TABLE, n], [
                ("name", table), ("workspace_id", workspace_id(m, dest)), ("plan", "Analytics"),
                *_columns(TABLE_TYPES)]),
            _rule(m, n, route, table, dest, streams),
            *(tf_block("resource", [ASSOCIATION, f"{n}_{tf_name(h)}"], [
                ("name", f"{rdn_value(route)}-{h}"), ("target_resource_id", ref(f"{VM}.{tf_name(h)}.id")),
                ("data_collection_rule_id", ref(f"{RULE}.{n}.id"))]) for h in hosts))


def render_log_collection(m, services):
    """HCL for environment m's servers' log routes: per route its custom table, data collection rule and
    associations; the Azure Monitor Agent extension on the servers it isn't brought to otherwise."""
    found = host_shipments(m, services)
    routes = {x.route.dn: x.route for x in found}
    return (*(b for dn, r in routes.items() for b in _route_blocks(m, r, tuple(x for x in found if x.route.dn == dn))),
            *(_extension(m, h) for h in agent_hosts(m, services)))


def log_collection_notes(m, services):
    """HCL comments naming what environment m's servers' log routes don't ship to Log Analytics, or ship differently,
    and what collecting them needs."""
    every = tuple(x for x in shipments(m, log_routes(m.d), services.logs(m)) if x.on == "servers")
    found = host_shipments(m, services)
    return tuple(dict.fromkeys((
        *(comment(f"NOTE: log route {rdn_value(x.route)}: {x.path} not shipped: its destination "
                  f"{rdn_value(x.destination)} isn't a Log Analytics workspace (kind workspace, a workspace ID)")
          for x in every if x.destination is not None and workspace_id(m, x.destination) is None),
        *(comment(f"NOTE: log route {rdn_value(x.route)}: {x.path}: records spanning lines arrive line by line (the "
                  "Azure Monitor Agent starts a record only at a timestamp of a fixed set of formats)")
          for x in found if x.source.line_start),
        *(comment(f"NOTE: role {role}: the Azure Monitor Agent comes with its host baseline ({agent}), not installed "
                  "here")
          for role, agent in ((r, baseline_agent(m, r)) for r in dict.fromkeys(x.source.server_role for x in found))
          if agent),
        *((comment("NOTE: Azure Government: collecting custom text logs with the Azure Monitor Agent is to be "
                   "confirmed there (no Government availability row names it)"),) if found and government(m) else ()))))
