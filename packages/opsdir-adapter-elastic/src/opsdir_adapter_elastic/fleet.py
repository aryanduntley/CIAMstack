"""Fleet policies shipping the products' log files on servers to an environment's Elastic data streams (decision on
task 555): Elastic Agent, enrolled in a Fleet agent policy per server role, reads each log file a route ships to an
Elastic data stream with a Custom Logs (Filestream) integration policy writing into the stream's dataset and namespace.
Pure: the policies as the Fleet API takes them (POST /api/fleet/agent_policies, POST
/api/fleet/package_policies?format=simplified), which the api and terraform targets write.

Per server role, the agent policy opsdir-<cloud>-<env>-<role> (its namespace the first stream's, the agents' own logs
and metrics monitored). Per role and log file, the integration policy opsdir-<cloud>-<env>-<role>-<file>: its paths
the file's glob under every install root the role's servers record (a root a server doesn't have matches nothing on
it), its dataset and namespace the stream's; JSON lines decoded into the event (an ndjson parser; ignoring the text
lines of a mixed file), records spanning lines joined from the source's line_start (a multiline parser), and, when the
routes take only some of its lines, the others dropped (a drop_event processor unless one of the clauses keeping the
routes' kinds holds, sources.kept_clauses: a rule's field starting with its prefix as a regexp, a field being there as
has_fields).

Named instead (server_notes): enrolling the role's servers in its agent policy (an action: the Fleet Server URL and
the policy's enrollment token are Fleet's, never rendered) and a file two routes ship to different streams (a blocker:
the first route's stream takes it).
"""
import re
from collections import namedtuple

from opsdir.core.directory import rdn_value, values
from opsdir.core.interchange.yaml_text import dump
from opsdir.core.notes import note
from opsdir.core.settings import setting_value
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.sources import SOME, kept_clauses, picks, shipments
from .naming import FILESTREAM_VERSION, fleet_name, stream_name, stream_parts

FILESTREAM = "filestream"                                    # the Custom Logs (Filestream) integration package
FILESTREAM_INPUT, FILESTREAM_STREAM = "filestream-filestream", "filestream.filestream"   # its input and stream keys
MONITORING = ["logs", "metrics"]                             # what an agent policy monitors of its agents

# One log file a server role ships to an Elastic data stream: role, source the LogSource, stream the data stream's
# name, paths its glob under each install root the role's servers record, hosts the servers, kinds the log kinds the
# routes shipping it there take (each once), routes their names.
FileShipment = namedtuple("FileShipment", ("role", "source", "stream", "paths", "hosts", "kinds", "routes"))


def elastic_shipments(m, services):
    """Environment m's Shipments whose destination is an Elastic data stream (naming.stream_name)."""
    return tuple(x for x in shipments(m, log_routes(m.d), services.logs(m))
                 if stream_name(x.destination) is not None)


def _log(x):
    return x.role, x.on, x.source.path, x.source.container


def first_streams(found):
    """{(role, place, source path, source container): the stream the first of Shipments found shipping that log of
    the role there ships it to}: what its policy reads it into."""
    keys = tuple(dict.fromkeys((_log(x), stream_name(x.destination)) for x in found))
    return {log: stream for log, stream in reversed(keys)}


def shipped(found):
    """The Shipments found shipping a log into the stream its first route ships it to (first_streams)."""
    first = first_streams(found)
    return tuple(x for x in found if first[_log(x)] == stream_name(x.destination))


def clashes(found):
    """The Shipments found not shipped: a log of a role its first route ships to another stream (first_streams),
    once per route and log."""
    first = first_streams(found)
    return tuple({(x.route.dn, _log(x)): x for x in found if first[_log(x)] != stream_name(x.destination)}.values())


def clash_note(m, x, first, what):
    """The blocker of a Shipment x not shipped (clashes) of environment m: what (its log in words) already goes to
    the stream first (first_streams) names."""
    return note("Logs", "blocker", f"log route {rdn_value(x.route)}", f"{what} on role {x.role} not shipped to "
                f"{stream_name(x.destination)}: another route already ships it to {first[_log(x)]}, and its "
                "integration policy reads it into that stream",
                ("Send both routes' logs to one data stream, or have the Elastic team reroute them in an ingest "
                 "pipeline",), x.route.dn, m.label)


def file_shipments(found):
    """The FileShipments of server Shipments found, a file once per role: into the stream its first route ships it to
    (the others are clashes)."""
    kept = tuple(x for x in shipped(found) if x.on == "servers")

    def of(log):
        xs = tuple(x for x in kept if _log(x) == log)
        return FileShipment(log[0], xs[0].source, stream_name(xs[0].destination),
                            tuple(dict.fromkeys(x.path for x in xs)),
                            tuple(dict.fromkeys(h for x in xs for h in x.hosts)),
                            tuple(dict.fromkeys(kind for x in xs for kind in values(x.route, "ciamLogKind"))),
                            tuple(dict.fromkeys(rdn_value(x.route) for x in xs)))
    return tuple(of(log) for log in dict.fromkeys(map(_log, kept)))


def parsers(source):
    """The filestream parsers reading a LogSource's lines: records spanning lines joined from its line_start
    (multiline), then JSON lines decoded into the event (ndjson; a mixed file's text lines left as they are)."""
    return [*([{"multiline": {"type": "pattern", "pattern": source.line_start, "negate": True, "match": "after"}}]
              if source.line_start else []),
            *([{"ndjson": {"target": "", "overwrite_keys": True,
                           **({"add_error_key": True} if source.format == "json-lines" else
                              {"ignore_decoding_error": True})}}]
              if source.format in ("json-lines", "mixed") else [])]


def _match(rule):
    field, prefix = rule
    return {"has_fields": [field]} if prefix == "" else {"regexp": {field: "^" + re.escape(prefix)}}


def _any(conditions):
    return conditions[0] if len(conditions) == 1 else {"or": list(conditions)}


def _clause(c):
    parts = (*((_match(c.match),) if c.match else ()), *(({"not": _any(tuple(map(_match, c.excluded)))},)
                                                          if c.excluded else ()))
    return None if not parts else parts[0] if len(parts) == 1 else {"and": list(parts)}


def line_filter(source, kinds):
    """The processors keeping only the lines of a LogSource of the log kinds a route takes, when it takes only some
    of them: a drop_event unless a kept clause holds (sources.kept_clauses); [] when it takes them all."""
    clauses = tuple(map(_clause, kept_clauses(source, kinds))) if picks(source, kinds) == SOME else ()
    if not clauses or None in clauses:
        return []
    kept = _any(clauses)
    dropped = kept["not"] if set(kept) == {"not"} else {"not": kept}    # not (not x): x
    return [{"drop_event": {"when": dropped}}]


def routes_named(names):
    """The log routes names (route names) in words, for a policy's description: log route a, log routes a, b."""
    return f"log route{'s' if len(names) > 1 else ''} {', '.join(names)}"


def agent_policy(name, namespace, description):
    """An agent policy as POST /api/fleet/agent_policies takes it: its ID and name, namespace and description, the
    agents' logs and metrics monitored."""
    return {"id": name, "name": name, "namespace": namespace, "description": description,
            "monitoring_enabled": list(MONITORING)}


def package_policy(name, description, namespace, agent, package, inputs):
    """An integration policy as POST /api/fleet/package_policies?format=simplified takes it: its ID and name,
    description, namespace, agent policy (its ID), package ((name, version)) and inputs ({input: {enabled, streams:
    {stream: {enabled, vars}}}})."""
    return {"id": name, "name": name, "description": description, "namespace": namespace, "policy_ids": [agent],
            "package": {"name": package[0], "version": package[1]}, "inputs": inputs}


def file_policy(m, f, version):
    """The Custom Logs (Filestream) integration policy of FileShipment f of environment m (filestream package version
    version), in its role's agent policy."""
    _, dataset, namespace = stream_parts(f.stream)
    found = (("parsers", parsers(f.source)), ("processors", line_filter(f.source, f.kinds)))
    variables = {"paths": list(f.paths), "data_stream.dataset": dataset, **{k: dump(v) for k, v in found if v}}
    return package_policy(fleet_name(m, f.role, f.source.path), f"opsdir: {f.source.path} on role {f.role} into "
                          f"{f.stream} ({routes_named(f.routes)})", namespace, fleet_name(m, f.role),
                          (FILESTREAM, version), {FILESTREAM_INPUT: {"enabled": True, "streams": {
                              FILESTREAM_STREAM: {"enabled": True, "vars": variables}}}})


def server_policies(m, services):
    """(agent policies, integration policies) shipping environment m's log files on servers to its Elastic data
    streams: an agent policy per server role, an integration policy per role and file."""
    files = file_shipments(elastic_shipments(m, services))
    version = setting_value(m.d, FILESTREAM_VERSION)
    roles = tuple(dict.fromkeys(f.role for f in files))
    return (tuple(agent_policy(fleet_name(m, role), stream_parts(next(f.stream for f in files if f.role == role))[2],
                               f"opsdir: Elastic Agent on role {role}'s servers in {m.label}") for role in roles),
            tuple(file_policy(m, f, version) for f in files))


def server_notes(m, services):
    """The render notes of shipping environment m's log files on servers to its Elastic data streams: per server role
    enrolling its servers in its agent policy (an action), a file two routes ship to different streams (a blocker)."""
    found = tuple(x for x in elastic_shipments(m, services) if x.on == "servers")
    files, version, first = file_shipments(found), setting_value(m.d, FILESTREAM_VERSION), first_streams(found)
    return (
        *(note("Logs", "action", f"Elastic Agent on role {role}",
               f"its servers' log files reach the Elastic data streams through the Fleet agent policy "
               f"{fleet_name(m, role)} (rendered); enrolling the servers is the Elastic team's, and the Fleet Server "
               "URL and the policy's enrollment token are Fleet's, never rendered",
               (f"Install Elastic Agent on {', '.join(hosts) or 'its servers (none recorded)'} enrolled in "
                f"{fleet_name(m, role)}: elastic-agent install --url <Fleet Server URL> --enrollment-token <its "
                "enrollment token>",
                f"Applying the API documents: install the {FILESTREAM} integration package {version} first (POST "
                f"/api/fleet/epm/packages/{FILESTREAM}/{version}); the Terraform installs it"), None, m.label)
          for role in dict.fromkeys(f.role for f in files)
          for hosts in (tuple(dict.fromkeys(h for f in files if f.role == role for h in f.hosts)),)),
        *(clash_note(m, x, first, x.source.path) for x in clashes(found)))
