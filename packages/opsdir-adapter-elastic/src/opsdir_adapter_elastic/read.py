"""What Elastic keeps of an environment, read into its log destinations and detections (the observability domain's
import kinds logs and alarm): its data streams' retention and its detection rules. Two importers, one per API, each
reading <cloud>/<env>/ folders as the collectors save them (collect.py) or the render writes them (the round trip).
Pure.

elastic/elasticsearch reads data-streams.json (GET /_data_stream), ilm-policies.json (GET /_ilm/policy),
slm-policies.json (GET /_slm/policy) and component-templates.json (GET _component_template; the render's). A logs data
stream is a log destination of kind siem-index named by the stream (ciamProviderRef). Its searchable days: when the
data stream lifecycle manages it (next_generation_managed_by), its data_retention (none: kept indefinitely); else its
ILM policy's delete phase min_age (no delete phase: kept indefinitely; days not whole are named), the policy being the
one the stream reports (ilm_policy), else the one its dataset's component template attaches, else the one whose _meta
names the stream (the render's). Its days in all, when a snapshot policy covers the stream (config.indices): searchable
days plus the policy's retention expire_after (none: kept indefinitely), its repository the archive (ciamArchiveRef).
What the answers don't give is left as the record has it, never read as zero. Streams of other types (metrics-...) and
system ones (a leading dot) are left out.

elastic/kibana reads detection-rules.json (GET /api/detection_engine/rules/_find; its further pages
detection-rules.<n>.json) or detection-rules.ndjson (an export, or the render's import file). A rule is a detection
(an alarm binding, ciamProviderRef its rule_id) realizing the alert rule its description names (siem.described;
binding role alarm-<rule>), searching the data stream its query names first (ES|QL FROM, else its index list), its
search the one the render wrapped with the rule's condition, else the query as written, and its language when it isn't
ES|QL (ciamSearchLanguage kuery, lucene, eql); a rule of another type than ES|QL is named: its condition isn't read.

elastic/kibana reports each data stream a rule searches as a log destination of kind siem-index alone (what links the
rule to the record's stream): what the record holds of it is unchanged, and streams no rule searches aren't named.
What the answers say about the environment's other log destinations and alarms (a cloud's, another SIEM's) is not
these importers' (siem.own_notices).
"""
import json
import re
from fnmatch import fnmatchcase

from opsdir.core.inventory import layout_import, realization_roles, resource
from opsdir.domains.observability.retention import INDEFINITE
from opsdir.domains.observability.siem import UNREPORTED, own_notices, realized_in
from .detections import base_query, source_of
from .naming import NATIVE, custom_template, is_stream, keeps

DAY = 86400
DSL = "Data stream lifecycle"               # next_generation_managed_by of a stream the data stream lifecycle manages
_DURATION = re.compile(r"^(?P<n>\d+)(?P<unit>d|h|m|s|ms|micros|nanos)$")
_SECONDS = {"d": DAY, "h": 3600, "m": 60, "s": 1, "ms": 0.001, "micros": 1e-6, "nanos": 1e-9}
DATA_STREAMS, ILM_POLICIES, SLM_POLICIES = "data-streams.json", "ilm-policies.json", "slm-policies.json"
COMPONENT_TEMPLATES = "component-templates.json"
ES_FILES = (DATA_STREAMS, ILM_POLICIES, SLM_POLICIES, COMPONENT_TEMPLATES)
RULE_FILES = ("detection-rules.json", "detection-rules.ndjson")
_PAGE = re.compile(r"^detection-rules(\.\d+)?\.json$")     # the _find answer's pages (collect.page_path)
_UNSEARCHED = f"(ciamLogDestination) {UNREPORTED}"   # a stream no rule searches: the rules say nothing of it


def es_days(text):
    """(whole days, None) of an Elasticsearch duration (90d, 12h, 0ms), (days rounded down, why) when it isn't whole
    days, or (None, why) when it isn't a duration."""
    found = _DURATION.match(str(text or "").strip())
    if not found:
        return None, f"{text!r} isn't a duration"
    seconds = int(found.group("n")) * _SECONDS[found.group("unit")]
    days = int(seconds // DAY)
    return days, None if seconds % DAY == 0 else f"{text} isn't whole days; read as {days}"


def _json(files, name):
    """(document, problem) of a file of files ({name: text}): None and no problem when absent."""
    if name not in files:
        return None, None
    try:
        return json.loads(files[name]), None
    except ValueError:
        return None, f"{name}: not JSON"


def _template_policies(doc):
    """{component template name: the ILM policy its settings attach} of GET _component_template's answer."""
    def policy(settings):
        index = settings.get("index", {}) if isinstance(settings, dict) else {}
        nested = index.get("lifecycle", {}).get("name") if isinstance(index, dict) else None
        return nested or (settings or {}).get("index.lifecycle.name")
    return {t.get("name"): policy(((t.get("component_template") or {}).get("template") or {}).get("settings") or {})
            for t in (doc or {}).get("component_templates", ()) if isinstance(t, dict)}


def _streams(streams, policies):
    """{stream name: its GET _data_stream entry ({} when only a policy's _meta names it)}: logs data streams only."""
    named = {s.get("name"): s for s in (streams or {}).get("data_streams", ()) if isinstance(s, dict)}
    by_meta = {p.get("policy", {}).get("_meta", {}).get("data_stream"): {} for p in (policies or {}).values()
               if isinstance(p, dict)}
    return {n: s for n, s in {**by_meta, **named}.items() if n and is_stream(n)}


def _policy_of(name, entry, policies, templates):
    """The name of the ILM policy managing data stream name ({} entry: as only a policy's _meta names it)."""
    meta = next((p for p, v in (policies or {}).items()
                 if isinstance(v, dict) and v.get("policy", {}).get("_meta", {}).get("data_stream") == name), None)
    return entry.get("ilm_policy") or templates.get(custom_template(name)) or meta


def _searchable(name, entry, policies, templates):
    """(searchable days or None, notices) of data stream name."""
    if entry.get("next_generation_managed_by") == DSL:
        retention = (entry.get("lifecycle") or {}).get("data_retention")
        days, why = es_days(retention) if retention else (INDEFINITE, None)
        return days, ((f"Elastic data stream {name}: data_retention {why}",) if why else ())
    policy = (policies or {}).get(_policy_of(name, entry, policies, templates) or "")
    if not isinstance(policy, dict):
        return None, ()
    delete = policy.get("policy", {}).get("phases", {}).get("delete")
    if delete is None:
        return INDEFINITE, ()
    days, why = es_days(delete.get("min_age", "0ms"))
    return days, ((f"Elastic data stream {name}: ILM delete min_age {why}",) if why else ())


def _archive(name, days, snapshots):
    """(days in all or None, the snapshot repository or None) of data stream name kept days searchable: the longest
    snapshot policy covering it."""
    def covers(p):
        indices = p.get("config", {}).get("indices", ())
        return any(fnmatchcase(name, i) for i in ((indices,) if isinstance(indices, str) else indices))

    def expiry(p):
        expire = p.get("retention", {}).get("expire_after")
        return es_days(expire)[0] if expire else INDEFINITE
    found = tuple(p["policy"] for p in (snapshots or {}).values()
                  if isinstance(p, dict) and isinstance(p.get("policy"), dict) and covers(p["policy"]))
    if days in (None, INDEFINITE) or not found:
        return None, None
    longest = max(found, key=lambda p: float("inf") if expiry(p) == INDEFINITE else expiry(p))
    extra = expiry(longest)
    return (INDEFINITE if extra == INDEFINITE else days + extra if extra is not None else None,
            longest.get("repository"))


def parse_elasticsearch(files):
    """(resources, notices) of one environment's Elasticsearch answers ({file name: text})."""
    read = {f: _json(files, f) for f in ES_FILES}
    streams, policies, snapshots, templates = (read[f][0] for f in ES_FILES)
    by_template = _template_policies(templates)

    def of(name, entry):
        days, notices = _searchable(name, entry, policies, by_template)
        total, repository = _archive(name, days, snapshots)
        return resource("logs", name, {"ciamDestinationKind": "siem-index", "ciamRetentionDays": days,
                                       "ciamTotalRetentionDays": total, "ciamArchiveRef": repository},
                        name=name), notices
    found = tuple(of(n, e) for n, e in _streams(streams, policies).items())
    return (tuple(r for r, _ in found),
            (*(p for _, p in read.values() if p), *(n for _, ns in found for n in ns)))


def _rules(files):
    """(rule documents, problems) of detection-rules.json and its further pages (the _find answer's data) and
    detection-rules.ndjson (one rule per line; an export's summary line left out)."""
    found, problems = [], []
    for name in sorted(f for f in files if _PAGE.match(f)):
        doc, problem = _json(files, name)
        problems += [problem] if problem else []
        found += [r for r in (doc or {}).get("data", ()) if isinstance(r, dict)]
    for n, line in enumerate(files.get(RULE_FILES[1], "").splitlines(), 1):
        try:
            item = json.loads(line) if line.strip() else None
        except ValueError:
            problems.append(f"{RULE_FILES[1]} line {n}: not JSON")
            continue
        found += [item] if isinstance(item, dict) and item.get("rule_id") else []
    return tuple(found), tuple(problems)


def rule_resource(rule):
    """(the Resource of kind alarm of one detection rule (as the API gives it), notices)."""
    kind = rule.get("type") or "query"
    language = rule.get("language") or (NATIVE if kind == NATIVE else "kuery")
    search = base_query(rule.get("query")) if language == NATIVE else (rule.get("query") or "")
    index = rule.get("index") or ()
    source = source_of(search) if language == NATIVE else (index[0] if index else None)
    realizes = realized_in(rule.get("description"))
    role, realizes = realization_roles({"Realizes": realizes} if realizes else {}, "alarm")
    return (resource("alarm", rule["rule_id"], {"ciamRealizes": realizes, "ciamMetric": search or None,
                                                 "ciamSearchLanguage": language if language != NATIVE else None},
                     {"ciamLogDestinationRole": source} if source and is_stream(source) else None,
                     name=rule["rule_id"], role=role),
            (f"Elastic detection rule {rule['rule_id']}: a {kind} rule: its search is read, not its condition (opsdir "
             "renders detections as ES|QL rules)",) if kind != NATIVE else ())


def parse_kibana(files):
    """(resources, notices) of one environment's detection rules ({file name: text}), with each data stream they search
    as a log destination of kind siem-index and nothing else (what links a rule to the stream the record holds; its
    retention is elastic/elasticsearch's)."""
    rules, problems = _rules(files)
    found = tuple(rule_resource(r) for r in rules)
    streams = dict.fromkeys(r.links["ciamLogDestinationRole"] for r, _ in found if r.links)
    return ((*(r for r, _ in found),
             *(resource("logs", x, {"ciamDestinationKind": "siem-index"}, name=x) for x in streams)),
            (*problems, *(n for _, ns in found for n in ns)))


def read_elasticsearch(files, d, patterns=(), at=None):
    """Importer elastic/elasticsearch: the data streams' retention per <cloud>/<env>/."""
    return own_notices(d, layout_import(files, d, None, "Elastic", parse_elasticsearch, ES_FILES,
                                        "Elasticsearch answers", DATA_STREAMS, summarize=("logs",)), keeps)


def read_kibana(files, d, patterns=(), at=None):
    """Importer elastic/kibana: the detection rules per <cloud>/<env>/."""
    imported = own_notices(d, layout_import(files, d, None, "Elastic", parse_kibana, (".json", ".ndjson"),
                                            "Kibana detection rules", RULE_FILES[0], summarize=("alarm", "logs")),
                           keeps)
    return imported._replace(notices=tuple(n for n in imported.notices if not n.endswith(_UNSEARCHED)))
