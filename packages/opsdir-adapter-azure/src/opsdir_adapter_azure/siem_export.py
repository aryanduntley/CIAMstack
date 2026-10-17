"""Log Analytics logs forwarded on to a SIEM through Event Hubs (core observability: a log destination's
ciamForwardsToRole, milestone 109, decision 3301; research docs/research m109b). Pure.

A workspace log destination whose binding forwards to a SIEM index, through the existing Event Hub its ciamStreamRole
binds (an event-hub binding: its ciamProviderRef the hub's ID), gets a data export rule:
  azurerm_log_analytics_data_export_rule   on the workspace, exporting the tables this environment's routes land in
                                           (each server route's Ciam<route>_CL, ContainerLogV2 for containers' logs)
                                           to that hub, as new data arrives
The hub, its namespace and their access rules are named by ID and never rendered: Terraform's namespace and
authorization-rule resources export their SAS keys and connection strings into state. Reading the hub is the SIEM's:
an action note (Splunk's Add-on for Microsoft Cloud Services or Elastic's Azure Logs integration, each with its own
credential), and in Azure Government a note that Splunk calls its add-on unsupported there and its Data Inputs service
excludes Azure Government. A forwarding the render can't express (the workspace not one, no event hub bound, no table
to export) is a blocker note.
"""
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import one_role
from opsdir.core.notes import note, note_comment
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.siem import forwardings, is_siem
from opsdir.domains.observability.sources import shipments
from opsdir_format_terraform.hcl import comment, from_entry, tf_block, tf_name
from .account import government
from .container_logs import CONTAINER_TABLE
from .identities import RG
from .log_collection import host_shipments, table_name
from .observability import workspace_id

EXPORT = "azurerm_log_analytics_data_export_rule"
AREA = "Logs"


def _hub(m, b):
    """The Event Hub ID the forwarding's ciamStreamRole binds, or None."""
    s = one_role(m, one(b, "ciamStreamRole") or "")
    hub = one(s, "ciamProviderRef") if s is not None else None
    return hub if hub and "/providers/microsoft.eventhub/namespaces/" in hub.lower() else None


def exported_tables(m, b, services):
    """The tables of workspace destination b this environment's routes land in: each server route's custom table,
    and ContainerLogV2 when containers' logs go there, sorted."""
    servers = {table_name(x.route) for x in host_shipments(m, services) if x.destination.dn == b.dn}
    containers = any(x.on == "kubernetes" and x.destination is not None and x.destination.dn == b.dn
                     for x in shipments(m, log_routes(m.d), services.logs(m)))
    return tuple(sorted(servers | ({CONTAINER_TABLE} if containers else set())))


def _group(m, b):
    """The workspace's resource group: the environment's (where this render puts the workspace), else the one its
    recorded ID names."""
    rendered = workspace_id(m, b)
    if str(rendered).startswith("${"):
        return RG
    parts = str(rendered).split("/")
    lowered = [p.lower() for p in parts]
    return parts[lowered.index("resourcegroups") + 1] if "resourcegroups" in lowered else None


def lacking(m, b, services):
    """What a workspace's forwarding lacks to be rendered, in words."""
    return tuple(why for why, missing in (
        ("a Log Analytics workspace (kind workspace or siem-index, its ID recorded)", workspace_id(m, b) is None),
        ("an existing Event Hub (ciamStreamRole naming an event-hub binding whose ciamProviderRef is the hub's ID)",
         _hub(m, b) is None),
        ("a table to export (no route of this environment lands in the workspace)",
         workspace_id(m, b) is not None and not exported_tables(m, b, services))) if missing)


def _ours(m):
    return tuple((b, to) for b, to in forwardings(m) if to is not None and is_siem(to) and
                 one(b, "ciamDestinationKind") in ("workspace", "siem-index"))


def _blocked(m, b, to, services):
    return note(AREA, "blocker", f"log destination {rdn_value(b)}",
                f"not forwarded to {rdn_value(to)}: it needs {'; '.join(lacking(m, b, services))}",
                ("Record what is missing, or ship the logs to the SIEM another way (its forwarder or agent)",),
                b.dn, m.label)


def _export(m, b, services):
    return (tf_block("resource", [EXPORT, tf_name(rdn_value(b))], [
        ("name", f"to-{one(b, 'ciamForwardsToRole')}"), ("resource_group_name", _group(m, b)),
        ("workspace_resource_id", workspace_id(m, b)), ("destination_resource_id", _hub(m, b)),
        ("table_names", list(exported_tables(m, b, services))), ("enabled", True)]),)


def render_siem_export(m, services):
    """HCL (and comments) for environment m's workspaces forwarded on to a SIEM: a data export rule to the existing
    Event Hub, stamped with the log destination's entry; a forwarding it can't render as its blocker's comment."""
    if services is None:
        return ()
    return tuple(x for b, to in _ours(m) for x in from_entry(b.dn, (
        (comment(note_comment(_blocked(m, b, to, services))),) if lacking(m, b, services)
        else _export(m, b, services))))


def siem_export_notes(m, services):
    """The render notes of environment m's workspace forwardings: a blocker for each the render can't express; for
    each rendered, the SIEM team's consumer of the hub (and in Azure Government, Splunk's support statement)."""
    if services is None:
        return ()
    return tuple(n for b, to in _ours(m) for n in (
        (_blocked(m, b, to, services),) if lacking(m, b, services) else (
            note(AREA, "action", f"log destination {rdn_value(b)} forwarding",
                 f"the workspace exports {', '.join(exported_tables(m, b, services))} to the Event Hub {_hub(m, b)}; "
                 f"reading it into {rdn_value(to)} is the SIEM's",
                 ("Ask the SIEM team to read the hub (Splunk Add-on for Microsoft Cloud Services, or Elastic's Azure "
                  "Logs integration) with a consumer group and credential of its own; the hub must be in the "
                  "workspace's region",), b.dn, m.label),
            *((note(AREA, "note", f"log destination {rdn_value(b)} forwarding",
                    "in Azure Government, Splunk documents its Add-on for Microsoft Cloud Services as untested and "
                    "unsupported, and its Data Inputs service as unavailable",
                    ("Agree a supported way for the SIEM to read the hub there (a relay the SIEM team runs, or "
                     "Elastic's integration with its Government endpoint settings)",), b.dn, m.label),)
              if government(m) else ()))))
