"""What the Splunk add-on renders for an environment (decision 3046): the opsdir_ciam app's indexes.conf and
savedsearches.conf, the Universal Forwarder's inputs.conf for the servers whose logs go to a Splunk index (HostFiles,
placed by configuration management), and the render notes of what it leaves to the Splunk team. Pure.

indexes.conf: a stanza per Splunk index the environment keeps logs in (naming.kept_indexes), with Splunk's paths under
$SPLUNK_DB, frozenTimePeriodInSecs from its searchable days (ciamRetentionDays) and, when it keeps them longer in all
(ciamTotalRetentionDays), the archive: archiver.enableDataArchive and archiver.coldStorageRetentionPeriod (total days,
archive included). Buckets freeze only when every event in them is older, and a size limit (maxTotalDataSizeMB) can
freeze them sooner: the days are a ceiling the record states, not a guarantee (the importer names the size limit).

savedsearches.conf: a scheduled search per alert rule a detection realizes on a Splunk index here
(alarms.detection_specs): the detection's search (ciamMetric) counted per window and compared with the rule's
threshold, firing when every window of the rule's evaluation period breaches (alarms.detection_condition), run as often
as that period, over it. Its description names the rule, which the importers read back. A rows detection (core
ciamDetectionMode rows) runs its search as written, every evaluation period of its rule (5 minutes when none) over
that period, its alert actions applied to each result (alert.digest_mode = 0: one alert per row). Where the stack
declares Splunk Enterprise Security (offering enterprise-security), each is an ES correlation search, with its ATT&CK
annotations, notable and risk objects (es.correlation_settings); elsewhere ATT&CK and entity mappings are notes. An
alert rule adopting a product's declared detection that no alarm binding here realizes is a saved search too, its SPL
written from the rule's canonical selector and the declaration's mapping, its window fixed or sliding (adopted).

inputs.conf: per server role and install root, a [monitor://<file>] per log file a route ships to a Splunk index, with
the index and a sourcetype (_json for JSON lines, else ciam:<role>:<file>). A file is monitored once.

Named instead, each a render note written as its comment: installing the app (an action), the forwarders' outputs
(the Splunk team's: an action), detections not rendered (alarms.alarm_note), the ATT&CK and entity mappings a
detection records that aren't rendered and what ES leaves to the Splunk team (es), retention Splunk can't express, files
shipped whole where the route takes only some of their lines, records spanning lines, container output on Kubernetes
(kubernetes: installing the collector chart after its HEC token Secret is filled, through the External Secrets objects
rendered with it where they can be; a blocker for what is missing) and a file two routes ship to different indexes (a
blocker).
"""
import re

from opsdir.core.contract import HostFile
from opsdir.core.directory import one, rdn_value
from opsdir.core.formats import INI
from opsdir.core.inventory import duration_seconds
from opsdir.core.manifest import header
from opsdir.core.notes import note, note_comment
from opsdir.core.settings import setting_value
from opsdir.domains.observability.alarms import alarm_note, detection_condition, detection_specs
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.retention import INDEFINITE, retention_days
from opsdir.domains.observability.siem import described, detection_index, detection_mode
from opsdir.domains.observability.sources import ALL, shipments
from .adopted import TRIGGER, adopted_notes, native_stanzas, rendered_rules
from .aws_pull import ADDON, AWS_APP, AWS_INPUTS, aws_pull_notes, input_stanzas
from .conf import write_conf
from .es import correlation_settings, es_notes, platform_notes
from .kubernetes import collector_notes, render_collectors
from .naming import (APP, FORWARDER_HOME, INDEXES, SAVED_SEARCHES, enterprise_security, index_name,
                     kept_indexes)
from .schedule import cron_schedule

DAY = 86400
OPERATORS = {"gt": ">", "ge": ">="}
ROWS_PERIOD = 300                   # a rows detection's period when its rule records none


def splunk_shipments(m, services):
    """Environment m's Shipments whose destination is a Splunk index (naming.index_name)."""
    return tuple(x for x in shipments(m, log_routes(m.d), services.logs(m)) if index_name(x.destination) is not None)


def index_stanza(b):
    """The indexes.conf stanza of a Splunk index log destination b."""
    name, days = index_name(b), retention_days(b)
    total = int(one(b, "ciamTotalRetentionDays")) if one(b, "ciamTotalRetentionDays") is not None else None
    archived = total not in (None, INDEFINITE) and (days in (None, INDEFINITE) or total > days)
    return (name, (("homePath", f"$SPLUNK_DB/{name}/db"), ("coldPath", f"$SPLUNK_DB/{name}/colddb"),
                   ("thawedPath", f"$SPLUNK_DB/{name}/thaweddb"),
                   *((("frozenTimePeriodInSecs", str(days * DAY)),) if days not in (None, INDEFINITE) else ()),
                   *((("archiver.enableDataArchive", "true"), ("archiver.coldStorageRetentionPeriod", str(total)))
                     if archived else ())))


def detection_search(metric, rule, c):
    """The scheduled search of a detection: its search (metric) counted per window, each window compared with the
    rule's threshold, returning a row when every window of the period breaches."""
    return (f"{metric} | bin _time span={c.window}s | stats count by _time | where count "
            f"{OPERATORS[one(rule, 'ciamComparison')]} {c.threshold} | stats count AS breaching "
            f"| where breaching >= {c.windows}")


def rows_period(s):
    """A rows detection spec's period in seconds: its rule's ciamEvaluationPeriod, else ROWS_PERIOD."""
    return duration_seconds(one(s.rule, "ciamEvaluationPeriod")) or ROWS_PERIOD


def _detection(s):
    """(condition or None, cron schedule, why it isn't rendered or None) of detection spec s: a rows detection has no
    condition (its search holds its threshold) and runs every period of its rule."""
    if detection_mode(s.alarm) == "rows":
        cron, late = cron_schedule(rows_period(s))
        return None, cron, late
    c, why = detection_condition(s.rule)
    cron, late = cron_schedule(c.window * c.windows) if c is not None else (None, None)
    return c, cron, why or late


def splunk_detections(m):
    """Environment m's detection AlarmSpecs on a Splunk index it renders (the rest are another SIEM's, or a base
    environment's)."""
    return tuple(s for s in detection_specs(m)
                 if s.keeper is None and index_name(detection_index(m, s.alarm)) is not None)


def search_stanza(m, s):
    """The savedsearches.conf stanza of environment m's detection spec s, or None when it isn't rendered
    (detection_notes): an ES correlation search where m runs Splunk Enterprise Security."""
    c, cron, why = _detection(s)
    if s.why or why:
        return None
    rows = c is None
    period = rows_period(s) if rows else c.window * c.windows
    search = one(s.alarm, "ciamMetric") if rows else detection_search(one(s.alarm, "ciamMetric"), s.rule, c)
    return (one(s.alarm, "ciamProviderRef"),
            (("description", described(rdn_value(s.rule))), ("search", search),
             ("is_scheduled", "1"), ("cron_schedule", cron), ("dispatch.earliest_time", f"-{period}s"),
             ("dispatch.latest_time", "now"), *TRIGGER, ("disabled", "0"),
             *((("alert.digest_mode", "0"),) if rows else ()),
             *(correlation_settings(s) if enterprise_security(m) else ())))


def detection_notes(m):
    """The render notes of environment m's Splunk detections not rendered: no search recorded (a note), a condition
    a saved search can't count (a blocker)."""
    def of(s):
        _, _, why = _detection(s)
        return alarm_note(m, s) if s.why else alarm_note(m, s, why) if why else None
    return tuple(n for n in map(of, splunk_detections(m)) if n is not None)


def mapping_notes(m, services):
    """The render notes of what environment m's rendered Splunk detections, and the adopting rules rendered from a
    product's declaration (adopted.rendered_rules), record of ATT&CK and entities: an ES correlation search's
    (es.es_notes) where it runs Splunk Enterprise Security, else what a saved search can't hold (es.platform_notes)."""
    rendered = tuple(s for s in splunk_detections(m) if search_stanza(m, s) is not None)
    adopted = rendered_rules(m, services)
    return es_notes(m, rendered, adopted) if enterprise_security(m) else platform_notes(m, rendered, adopted)


def _retention_notes(m):
    return (
        *(note("Logs", "action", f"Splunk index {index_name(b)}", f"kept {what} indefinitely in the record, which "
               f"Splunk can't say (it freezes by age): {key} not rendered, so Splunk's default applies",
               (f"Set {key} for index {index_name(b)} by hand to the longest the obligations need",), b.dn, m.label)
          for b in kept_indexes(m)
          for what, key, v in (("searchable", "frozenTimePeriodInSecs", one(b, "ciamRetentionDays")),
                               ("in all", "archiver.coldStorageRetentionPeriod", one(b, "ciamTotalRetentionDays")))
          if v == str(INDEFINITE)),
        *(note("Logs", "note", f"Splunk index {index_name(b)}", "records no retention (ciamRetentionDays): "
               "frozenTimePeriodInSecs not rendered, so the index keeps what Splunk is set to",
               ("Read what Splunk keeps into the record (splunk/rest), or record the retention the obligations need",),
               b.dn, m.label)
          for b in kept_indexes(m) if one(b, "ciamRetentionDays") is None))


def _first_per_file(found):
    """{file path: the first server Shipment shipping it}: a forwarder monitors a file once."""
    return {p: next(x for x in found if x.on == "servers" and x.path == p)
            for p in dict.fromkeys(x.path for x in found if x.on == "servers")}


def _route_notes(m, found, services):
    seen = _first_per_file(found)
    clashes = tuple(x for x in found if x.on == "servers" and seen[x.path] is not x
                    and index_name(seen[x.path].destination) != index_name(x.destination))
    return (
        *collector_notes(m, found, services),
        *(note("Logs", "note", f"log route {rdn_value(x.route)}", f"{x.path} on role {x.role} is shipped whole: the "
               "Universal Forwarder doesn't filter lines by their fields, so lines of the kinds the route doesn't "
               "take reach the index too", (), x.route.dn, m.label)
          for x in found if x.on == "servers" and x.lines != ALL and seen[x.path] is x),
        *(note("Logs", "note", f"log route {rdn_value(x.route)}", f"{x.path}: records spanning lines are joined where "
               "Splunk parses the data (props.conf line breaking), which the Splunk team sets", (), x.route.dn,
               m.label)
          for x in found if x.on == "servers" and x.source.line_start and seen[x.path] is x),
        *(note("Logs", "blocker", f"log route {rdn_value(x.route)}", f"{x.path} on role {x.role} not shipped to "
               f"{index_name(x.destination)}: route {rdn_value(seen[x.path].route)} already ships it to "
               f"{index_name(seen[x.path].destination)}, and a forwarder monitors a file once",
               ("Send both routes' logs to one index, or have the Splunk team route them at the indexer",),
               x.route.dn, m.label)
          for x in clashes))


def _team_notes(m, found, rendered, adopted):
    servers = any(x.on == "servers" for x in found)
    return (
        *((note("Logs", "action", f"Splunk app {APP}", "rendered for the Splunk team to install where indexes and "
                "searches run; opsdir doesn't install it",
                ("Splunk Enterprise: deploy the app to the indexers and search heads (deployment server or cluster "
                 "manager)",
                 "Splunk Cloud Platform: create the indexes with these values through its index management, and "
                 "install the saved searches as an app"), None, m.label),) if rendered else ()),
        *((note("Logs", "action", "Splunk forwarding", "the forwarders' inputs are rendered (configuration "
                "management places them); where they send (outputs.conf, or Splunk Cloud's forwarder credentials "
                "package) is the Splunk team's",
                ("Confirm the servers' Universal Forwarders send to the indexers keeping these indexes",), None,
                m.label),) if servers else ()),
        *((note("Monitoring", "action", "Splunk alert actions", "the detections' saved searches fire, but who they "
                "notify (their alert actions) is set in Splunk, not rendered",
                ("Set each detection's alert actions to the channel its alert rule names",), None, m.label),)
          if adopted or any(search_stanza(m, s) for s in splunk_detections(m)) else ()))


def render_notes(m, services):
    """Adapter notes: what environment m's Splunk render leaves out or to a person."""
    found = splunk_shipments(m, services)
    rendered = bool(kept_indexes(m) or splunk_detections(m))
    return (*_team_notes(m, found, rendered, rendered_rules(m, services)), *_retention_notes(m),
            *detection_notes(m), *adopted_notes(m, services), *mapping_notes(m, services),
            *_route_notes(m, found, services), *aws_pull_notes(m))


def _comments(notes):
    return "".join(f"# {note_comment(n)}\n" for n in notes) + ("\n" if notes else "")


def render(m, services):
    """Adapter render_env: environment m's opsdir_ciam app when it keeps logs in a Splunk index or runs a detection on
    one: indexes.conf, the render notes as comments at its top, and savedsearches.conf when a detection (or an
    adopting rule: adopted) renders; the Splunk Add-on for AWS's inputs.conf (app opsdir_ciam_aws) when a forwarding is
    pulled from S3 through SQS (aws_pull)."""
    indexes, searches = kept_indexes(m), splunk_detections(m)
    if not indexes and not searches:
        return {}
    collectors = render_collectors(m, splunk_shipments(m, services), services)
    notes = render_notes(m, services)
    stanzas = (*(x for x in (search_stanza(m, s) for s in searches) if x is not None), *native_stanzas(m, services))
    pulls = input_stanzas(m)
    return {INDEXES: write_conf(header(m, f"Splunk indexes (app {APP})", INI) + _comments(notes),
                                tuple(index_stanza(b) for b in indexes)),
            **({SAVED_SEARCHES: write_conf(header(m, f"Splunk saved searches: the detections (app {APP})", INI),
                                           stanzas)} if stanzas else {}),
            **({AWS_INPUTS: write_conf(header(m, f"{ADDON} inputs: CloudWatch Logs pulled from S3 through SQS (app "
                                              f"{AWS_APP})", INI), pulls)} if pulls else {}),
            **collectors}


def sourcetype(x):
    """A server Shipment's sourcetype: _json for a JSON-lines file, else ciam:<role>:<file name without extension>."""
    if x.source.format == "json-lines":
        return "_json"
    stem = x.source.path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    return f"ciam:{x.role}:" + re.sub(r"[^a-z0-9_]+", "_", stem.lower()).strip("_")


def inputs_conf(m, found):
    """The forwarder's inputs.conf (text) for server Shipments sharing an install root: a monitor per file, the first
    route shipping it naming the index."""
    first = tuple(_first_per_file(found).values())
    return write_conf(header(m, "Splunk Universal Forwarder inputs: product log files to Splunk indexes", INI),
                      tuple((f"monitor://{x.path}", (("index", index_name(x.destination)),
                                                     ("sourcetype", sourcetype(x)), ("disabled", "false")))
                            for x in first))


def host_files(m, services):
    """Adapter host_files: one forwarder inputs.conf per server role and install root of environment m shipping logs
    to a Splunk index, at <forwarder home>/etc/apps/opsdir_ciam/local/inputs.conf, the forwarder restarted when it
    changes."""
    found = tuple(x for x in splunk_shipments(m, services) if x.on == "servers")
    home = setting_value(m.d, FORWARDER_HOME).rstrip("/")
    groups = tuple(dict.fromkeys((x.role, x.hosts) for x in found))
    return tuple(HostFile(role, f"{home}/etc/apps/{APP}/local/inputs.conf",
                          inputs_conf(m, tuple(x for x in found if (x.role, x.hosts) == (role, hosts))),
                          (f"{home}/bin/splunk", "restart"), "0644", hosts) for role, hosts in groups)
