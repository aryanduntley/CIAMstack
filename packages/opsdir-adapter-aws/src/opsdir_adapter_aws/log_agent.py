"""Product logs from an environment's servers to CloudWatch Logs (core observability: log routes; what each route
ships and from which servers: domains/observability/sources): a CloudWatch agent configuration per server role and
install root, placed by configuration management (Services.host_files: opsdir-adapter-ansible) and loaded beside the
host baseline's own configuration with append-config. Configure-only: the host baseline installs the agent. Pure.

Each log file a route takes whole (all its lines) to a destination that is a log group here (a ciamLogDestination of
kind log-group whose provider ref is the group's ARN) is one collect_list entry: the file's glob under the servers'
install root, the group's name, a stream per instance and file, and the pattern a record's first line starts with
when records span lines. No retention: the group's Terraform keeps it (fragments disagreeing on it can stop the
agent). With FIPS endpoints the agent sends to CloudWatch Logs' FIPS endpoint (endpoint_override).
docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html

Named in main.tf instead, each a render note (log_notes, flow 43) written as its comment: a file a route takes only
some lines of (the agent filters raw lines with regular
expressions, not JSON fields), a destination that isn't a log group here, a glob (the agent ships only the most
recently modified file it matches), and a role no workload principal lets write to the group (permit write-logs
<destination role>: the servers' instance role gets its grants from the record).
"""
import json

from opsdir.core.contract import HostFile
from opsdir.core.directory import one, rdn_value
from opsdir.core.notes import RECORD, note
from opsdir.domains.estate.residency import fips_endpoints
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.sources import ALL, shipments, unpermitted
from .observability import group_name

# how to handle a route's destination that isn't a CloudWatch log group (also Fluent Bit's)
DESTINATION_HOW = (f"Bind the route's destination role to a log destination of kind log-group with its log group ARN "
                   f"(ciamProviderRef), {RECORD}",)

AGENT = "/opt/aws/amazon-cloudwatch-agent"
CONFIG = f"{AGENT}/etc/opsdir-logs.json"
RELOAD = (f"{AGENT}/bin/amazon-cloudwatch-agent-ctl", "-a", "append-config", "-m", "ec2", "-s", "-c",
          f"file:{CONFIG}")


def log_group(b):
    """The log group name of a log destination binding of kind log-group, or None."""
    return group_name(b) if b is not None and one(b, "ciamDestinationKind") == "log-group" else None


def host_shipments(m, services):
    """The Shipments of environment m from its servers (its log routes and the LogSources its adapters declare)."""
    return tuple(x for x in shipments(m, log_routes(m.d), services.logs(m)) if x.on == "servers")


def _shipped(x):
    return x.lines == ALL and log_group(x.destination) is not None


def _entry(x):
    return {"file_path": x.path, "log_group_name": log_group(x.destination),
            "log_stream_name": "{instance_id}/" + x.source.path.replace("*", "_"),
            **({"multi_line_start_pattern": x.source.line_start} if x.source.line_start else {})}


def agent_config(m, found):
    """The CloudWatch agent configuration (JSON text) shipping Shipments to their log groups."""
    region = one(m.cloud, "ciamRegion")
    entries = list({(e["file_path"], e["log_group_name"]): e for e in map(_entry, found)}.values())
    logs = {**({"endpoint_override": f"https://logs-fips.{region}.amazonaws.com"} if fips_endpoints(m) else {}),
            "logs_collected": {"files": {"collect_list": entries}}}
    return json.dumps({"logs": logs}, indent=2) + "\n"


def host_files(m, services):
    """Adapter host_files: one CloudWatch agent configuration per server role and install root of environment m."""
    found = tuple(x for x in host_shipments(m, services) if _shipped(x))
    groups = tuple(dict.fromkeys((x.role, x.hosts) for x in found))
    return tuple(HostFile(role, CONFIG, agent_config(m, tuple(x for x in found if (x.role, x.hosts) == (role, hosts))),
                          RELOAD, "0644", hosts) for role, hosts in groups)


def _note(m, x):
    """The render note of a server's log file the CloudWatch agent doesn't ship (a blocker), or ships only in part
    (a glob: an action), or None; a destination not bound here is the planner's."""
    subject, where = f"log route {rdn_value(x.route)}", f"{x.path} on {', '.join(x.hosts)}"
    if x.destination is None:
        return None
    if log_group(x.destination) is None:
        return note("Logs", "blocker", subject, f"{where} not shipped: its destination {rdn_value(x.destination)} "
                    "isn't a CloudWatch log group (kind log-group, a log group ARN)", DESTINATION_HOW, x.route.dn,
                    m.label)
    if x.lines != ALL:
        return note("Logs", "blocker", subject, f"{where} not shipped: the route takes only some of its lines, and "
                    "the CloudWatch agent can't tell them apart by their JSON fields",
                    (f"Have the route take every kind of log {x.path} holds, so the whole file ships, {RECORD}",
                     "Or pick the lines after they land (a CloudWatch Logs subscription or metric filter), by hand"),
                    x.route.dn, m.label)
    if "*" in x.source.path or "?" in x.source.path:
        return note("Logs", "action", subject, f"{where}: the CloudWatch agent ships only the most recently modified "
                    "file the glob matches",
                    ("Check that only one file matching it is written at a time; if several are, ship the others "
                     "another way, by hand",), x.route.dn, m.label)
    return None


def log_notes(m, services):
    """The render notes of what environment m's servers' log routes can't ship to CloudWatch, or ship only in part,
    each once (render_files writes their comments): a file's (_note), and a role no workload principal lets write
    to its destination (a blocker)."""
    found = host_shipments(m, services)
    return tuple(dict.fromkeys((
        *(n for n in (_note(m, x) for x in found) if n is not None),
        *(note("Logs", "blocker", f"role {role}", f"ships logs to {dest}, but no workload principal acting for it "
               f"holds the permit `write-logs {dest}`: its servers' instance role isn't granted the writes",
               (f"Grant a workload principal acting for role {role} the permit `write-logs {dest}`, {RECORD}",),
               None, m.label)
          for role, dest in unpermitted(m, tuple(x for x in found if _shipped(x)))))))
