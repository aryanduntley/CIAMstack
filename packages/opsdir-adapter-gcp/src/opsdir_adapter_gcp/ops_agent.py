"""Product logs from an environment's servers to Cloud Logging (core observability: log routes; what each route ships
and from which servers: domains/observability/sources), through the Ops Agent: a configuration per server role and
install root, placed by configuration management (Services.host_files: opsdir-adapter-ansible), and the part of each
route's log sink (log_sinks) that takes those files' lines. Configure-only: the host baseline installs the agent
(decision 2328). Pure.

/etc/google-cloud-ops-agent/config.yaml: per log file a route ships to a Cloud Logging bucket (all its lines, or some:
the sink filters them), a files receiver ciam_<role>_<file> on its glob under the servers' install root, recording the
file's path, in a pipeline of its own, its JSON lines parsed into jsonPayload (parse_json) for the sinks to read their
kinds. The agent merges it with its built-in configuration (the default syslog pipeline stays) and takes the
receiver's ID as the entries' log name, projects/<project>/logs/<receiver>, which the sink matches.
docs.cloud.google.com/monitoring/agent/ops-agent/configuration (research notes 2324, 2363).

Named in main.tf instead, each a render note (ops_agent_notes, flow 43) written as its comment: that the file
replaces a config.yaml the servers already have (the agent reads only that one), a file whose records span lines (the
agent groups only Java, Python and Go exceptions: each line arrives as an entry), and a role no workload principal
lets write logs (permit write-logs <destination role>: the servers' service account gets its grants from the
record).
"""
import re

from opsdir.core.contract import HostFile
from opsdir.core.directory import rdn_value, values
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import dump
from opsdir.core.manifest import header
from opsdir.core.notes import RECORD, note
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.sources import ALL, kept_clauses, shipments, unpermitted
from .logging_filter import all_of, field_of, kept, literal
from .observability import bucket_parts

CONFIG = "/etc/google-cloud-ops-agent/config.yaml"
RELOAD = ("systemctl", "restart", "google-cloud-ops-agent")
PARSE_JSON = "ciam_parse_json"
JSON_FORMATS = ("json-lines", "mixed")


def host_shipments(m, services):
    """Environment m's Shipments from its servers whose destination is a Cloud Logging bucket here."""
    return tuple(x for x in shipments(m, log_routes(m.d), services.logs(m))
                 if x.on == "servers" and bucket_parts(x.destination) is not None)


def receiver_id(x):
    """The Ops Agent receiver (and log name) of a server Shipment's file: ciam_<role>_<file>, the same under every
    install root."""
    return "ciam_" + re.sub(r"[^a-z0-9]+", "_", f"{x.role}_{x.source.path}".lower()).strip("_")


def agent_config(m, found):
    """The Ops Agent configuration (YAML text) collecting the files of Shipments sharing an install root."""
    files = {receiver_id(x): x for x in found}
    parsed = any(x.source.format in JSON_FORMATS for x in files.values())
    logging = {"receivers": {r: {"type": "files", "include_paths": [x.path], "record_log_file_path": True}
                             for r, x in files.items()},
               **({"processors": {PARSE_JSON: {"type": "parse_json"}}} if parsed else {}),
               "service": {"pipelines": {r: {"receivers": [r], **({"processors": [PARSE_JSON]}
                                                                  if x.source.format in JSON_FORMATS else {})}
                                         for r, x in files.items()}}}
    return header(m, "Ops Agent: product log files to Cloud Logging (merged with the agent's built-in configuration)",
                  YAML) + dump({"logging": logging}, indent_sequences=True)


def host_files(m, services):
    """Adapter host_files: one Ops Agent configuration per server role and install root of environment m."""
    found = host_shipments(m, services)
    groups = tuple(dict.fromkeys((x.role, x.hosts) for x in found))
    return tuple(HostFile(role, CONFIG, agent_config(m, tuple(x for x in found if (x.role, x.hosts) == (role, hosts))),
                          RELOAD, "0644", hosts) for role, hosts in groups)


def host_filter(x):
    """The query taking a server Shipment's lines: its receiver's log name and, when the route takes some of them,
    its kinds."""
    kinds = None if x.lines == ALL else kept(kept_clauses(x.source, values(x.route, "ciamLogKind")),
                                              field_of("jsonPayload"))
    return all_of(f"logName =~ {literal('/logs/' + receiver_id(x) + '$')}", kinds)


def ops_agent_notes(m, services):
    """The render notes of what environment m's servers' log routes ship differently, and what shipping them needs,
    each once (log_sink_notes gathers them; render_files writes their comments): the configuration replacing the
    servers' own (an action), records spanning lines (a note), a role no workload principal lets write logs (a
    blocker)."""
    found = host_shipments(m, services)
    return tuple(dict.fromkeys((
        *((note("Logs", "action", "Ops Agent configuration", f"opsdir renders it for configuration management to place "
                f"({CONFIG}); it replaces one the servers already have (the agent reads only that file): merge their "
                "own receivers and pipelines into it; the agent itself comes with the host baseline",
                (f"Before configuration management places {CONFIG}, merge the receivers and pipelines of the "
                 "servers' own file into it, by hand",), None, m.label),)
          if found else ()),
        *(note("Logs", "note", f"log route {rdn_value(x.route)}", f"{x.path}: records spanning lines arrive line by "
               "line (the Ops Agent groups only Java, Python and Go exceptions)", (), x.route.dn, m.label)
          for x in found if x.source.line_start),
        *(note("Logs", "blocker", f"role {role}", f"ships logs to {dest}, but no workload principal acting for it "
               f"holds the permit `write-logs {dest}`: its servers' service account isn't granted "
               "roles/logging.logWriter",
               (f"Grant a workload principal acting for role {role} the permit `write-logs {dest}`, {RECORD}",),
               None, m.label)
          for role, dest in unpermitted(m, found)))))
