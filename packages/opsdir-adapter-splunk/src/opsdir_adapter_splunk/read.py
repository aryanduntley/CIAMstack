"""What Splunk keeps of an environment, read into its log destinations and detections (the observability domain's
import kinds logs and alarm): its indexes' retention and its saved searches. Two importers, one placement. Pure.

splunk/rest reads the management API's answers saved per environment, <cloud>/<env>/indexes.json (GET
/services/data/indexes?output_mode=json&count=0) and <cloud>/<env>/saved-searches.json (GET
/servicesNS/-/-/saved/searches?output_mode=json&count=0), as the collector saves them (collect.py) or an operator
saved them. splunk/conf reads <cloud>/<env>/indexes.conf and savedsearches.conf: the files the render writes, read back
(the round trip), or an app's own.

An index is a log destination of kind siem-index named by its index name (ciamProviderRef): its searchable days from
frozenTimePeriodInSecs (whole days), its days in all from archiver.coldStorageRetentionPeriod when the archive is on
(archiver.enableDataArchive); a setting the source doesn't give is left as the record has it, never read as zero.
Splunk's own indexes (named with a leading underscore) are left out; others the record doesn't have are counted
unless the role map names their role. An index the record holds that also freezes its oldest data past a size
(maxTotalDataSizeMB) is named: its days are a ceiling, not a guarantee.

A saved search is a detection (an alarm binding, ciamProviderRef its name) realizing the alert rule its description
names (`opsdir: realizes alert rule <rule>`, as the render writes it; binding role alarm-<rule>, as every cloud's
alarm for the rule binds), searching the index its search names first (index=<name>), its search (ciamMetric) the one
the render wrapped with the rule's condition when it is one, else the search as written. Saved searches naming no
rule and not in the record are counted.

What a source says about the environment's other log destinations and alarms (a cloud's) is not this importer's: the
placement's notices about them are left out.
"""
import json
import re

from opsdir.core.directory import get, rdn_value
from opsdir.core.environment import env_dn, env_model, of_class
from opsdir.core.inventory import layout_import, realization_roles, resource
from opsdir.domains.observability.siem import detection_index, realized_in
from .conf import read_conf
from .naming import index_name

DAY = 86400
_WRAPPED = re.compile(r"^(?P<base>.*) \| bin _time span=\d+s \| stats count by _time \| where count >=? \S+ "
                      r"\| stats count AS breaching \| where breaching >= \d+$", re.DOTALL)
_INDEX = re.compile(r"(?:^|\s)index\s*=\s*\"?([a-z0-9][a-z0-9_-]*)")
_UNREPORTED = "is in the record but not in what the cloud reports"
REST_FILES = ("indexes.json", "saved-searches.json")
CONF_FILES = ("indexes.conf", "savedsearches.conf")


def base_search(search):
    """A saved search's own search: the one the render wrapped with a rule's condition, else the search as written."""
    found = _WRAPPED.match(search or "")
    return found.group("base") if found else (search or "")


def _on(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def index_resource(name, settings):
    """(Resource of kind logs, notices) of one index's settings ({setting: value} as Splunk gives them)."""
    frozen = settings.get("frozenTimePeriodInSecs")
    seconds = int(frozen) if frozen not in (None, "") and str(frozen).isdigit() else None
    total = settings.get("archiver.coldStorageRetentionPeriod")
    archived = _on(settings.get("archiver.enableDataArchive", "")) and str(total or "").isdigit()
    return (resource("logs", name, {"ciamDestinationKind": "siem-index",
                                    "ciamRetentionDays": seconds // DAY if seconds is not None else None,
                                    "ciamTotalRetentionDays": total if archived else None}, name=name),
            (f"Splunk index {name}: frozenTimePeriodInSecs {seconds} isn't whole days; read as {seconds // DAY}",)
            if seconds is not None and seconds % DAY else ())


def search_resource(name, settings):
    """The Resource of kind alarm of one saved search's settings ({setting: value})."""
    rule = realized_in(settings.get("description"))
    role, realizes = realization_roles({"Realizes": rule} if rule else {}, "alarm")
    search = base_search(settings.get("search"))
    index = _INDEX.search(search)
    return resource("alarm", name, {"ciamRealizes": realizes, "ciamMetric": search or None},
                    {"ciamLogDestinationRole": index.group(1)} if index else None, name=name, role=role)


def resources_of(indexes, searches):
    """(resources, notices) of an environment's indexes and saved searches, each ((name, {setting: value}), ...)."""
    read = tuple(index_resource(n, s) for n, s in indexes if not n.startswith("_"))
    return ((*(r for r, _ in read), *(search_resource(n, s) for n, s in searches)),
            tuple(x for _, ns in read for x in ns))


def _entries(text, what):
    try:
        doc = json.loads(text)
    except ValueError:
        return None, f"{what}: not JSON"
    entries = doc.get("entry") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        return None, f"{what}: no entry list (the API's JSON answer, output_mode=json)"
    return tuple((e["name"], {k: v for k, v in (e.get("content") or {}).items()})
                 for e in entries if isinstance(e, dict) and isinstance(e.get("name"), str)), None


def parse_rest(files):
    """(resources, notices) of one environment's REST answers ({file name: text})."""
    read = {f: _entries(files[f], f) for f in REST_FILES if f in files}
    indexes, searches = (read.get(f, ((), None))[0] or () for f in REST_FILES)
    resources, notices = resources_of(indexes, searches)
    return resources, (*(p for _, p in read.values() if p), *notices)


def parse_conf(files):
    """(resources, notices) of one environment's .conf files ({file name: text})."""
    indexes, searches = (tuple((n, dict(pairs)) for n, pairs in read_conf(files.get(f, ""))
                               if n != "default") for f in CONF_FILES)
    return resources_of(indexes, searches)


def _others(d, spec):
    """The names of environment spec's log destinations and alarms that aren't Splunk's: what a Splunk source says
    nothing about."""
    if get(d, env_dn(spec)) is None:
        return frozenset()
    m = env_model(d, spec)
    splunk = {e.dn for e in of_class(m, "ciamLogDestination") if index_name(e) is not None} | \
             {e.dn for e in of_class(m, "ciamAlarmBinding") if index_name(detection_index(m, e)) is not None}
    return frozenset(rdn_value(e) for c in ("ciamLogDestination", "ciamAlarmBinding") for e in of_class(m, c)
                     if e.dn not in splunk)


def _own(d, imported):
    """Imported without the placement's notices about the environments' entries that aren't Splunk's."""
    def kept(n):
        spec, _, rest = n.partition(": ")
        return not (n.endswith(_UNREPORTED) and any(rest.startswith(f"{x} (") for x in _others(d, spec)))
    return imported._replace(notices=tuple(n for n in imported.notices if kept(n)))


def _size_limits(d, files, suffix):
    """Notices naming the indexes an environment records that also freeze past a size (REST answers only)."""
    def recorded(spec):
        if get(d, env_dn(spec)) is None:
            return set()
        return {index_name(e) for e in of_class(env_model(d, spec), "ciamLogDestination")} - {None}
    return tuple(f"{spec}: Splunk index {name} also freezes its oldest data past maxTotalDataSizeMB {limit}: its "
                 "days are a ceiling, not a guarantee"
                 for path in sorted(files) if path.endswith(suffix) and path.count("/") == 2
                 for spec in ("/".join(path.split("/")[:2]),)
                 for name, settings in (_entries(files[path], path)[0] or ())
                 if name in recorded(spec) for limit in (settings.get("maxTotalDataSizeMB"),)
                 if limit not in (None, "", "0", 0))


def read_rest(files, d, patterns=(), at=None):
    """Importer splunk/rest: the management API's indexes and saved searches per <cloud>/<env>/."""
    imported = _own(d, layout_import(files, d, None, "Splunk", parse_rest, REST_FILES, "Splunk REST answers",
                                     "indexes.json", summarize=("logs", "alarm")))
    return imported._replace(notices=(*imported.notices, *_size_limits(d, files, "/indexes.json")))


def read_conf_files(files, d, patterns=(), at=None):
    """Importer splunk/conf: indexes.conf and savedsearches.conf per <cloud>/<env>/."""
    return _own(d, layout_import(files, d, None, "Splunk", parse_conf, CONF_FILES, "Splunk .conf files",
                                 "indexes.conf", summarize=("logs", "alarm")))
