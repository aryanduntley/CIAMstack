"""Elastic collectors (`opsdir collect`, core.contract Collector): the Elasticsearch and Kibana answers the importers
read, read-only. Pure: the core makes the requests.

Each reads the environment's first readable collection source for its importer (ciamCollectionSource: the
Elasticsearch endpoint for elastic/elasticsearch, the Kibana endpoint for elastic/kibana; its first location), with
the credential its ciamCredentialRole binding references (resolved when collecting, never stored) sent as
Authorization: ApiKey <key> when its ciamCredentialScheme is api-key (an Elasticsearch API key's encoded form, the way
to read with a dedicated reader), as Bearer for bearer, else as HTTP Basic for its ciamLoginName, and the CA
certificate its ciamCaRole binding references as the trust anchor.

elastic/elasticsearch: GET /_data_stream, /_ilm/policy and /_slm/policy, saved as data-streams.json, ilm-policies.json
and slm-policies.json; read-only privileges: cluster read_ilm and read_slm, index view_index_metadata on the logs
streams. elastic/kibana: GET /api/detection_engine/rules/_find, paged (per_page 1000), saved as detection-rules.json
and detection-rules.<page>.json for the pages after the first, in the Kibana space the estate setting
elastic-kibana-space names (/s/<space> unless it is the default); read-only privilege: Security, Rules and
Exceptions, Rules: Read (an API key's role descriptor for the kibana-.kibana application).
"""
import json

from opsdir.core.contract import Collector, Request
from opsdir.core.settings import setting_value
from opsdir.domains.governance.collection import readable_source, source_problems
from .naming import KIBANA_SPACE

ELASTICSEARCH, KIBANA = "elastic/elasticsearch", "elastic/kibana"
ES_CALLS = (("data-streams.json", "/_data_stream"), ("ilm-policies.json", "/_ilm/policy"),
            ("slm-policies.json", "/_slm/policy"))
RULES = "/api/detection_engine/rules/_find"
PER_PAGE = 1000


def credential(s):
    """How a Source's credential is sent: an API key as Authorization: ApiKey <key>, else its scheme with its login;
    None when it names none."""
    if not s.credential:
        return None
    return ("api-key", s.credential, None, "Authorization", "ApiKey ") if s.scheme == "api-key" else \
        (s.scheme, s.credential, s.login)


def _get(s, path):
    return Request(f"{s.locations[0].rstrip('/')}{path}", (), credential(s), s.ca)


def elasticsearch_steps(d, m, done, options):
    """The three GETs, against the first location of the environment's first readable elastic/elasticsearch source."""
    s = readable_source(m, ELASTICSEARCH)
    return () if s is None else tuple((f"{m.label}/{path}", _get(s, call)) for path, call in ES_CALLS)


def page_path(m, page):
    """Where a page of the rules is saved: detection-rules.json, then detection-rules.<page>.json."""
    return f"{m.label}/detection-rules.json" if page == 1 else f"{m.label}/detection-rules.{page}.json"


def _pages(done, m):
    """How many pages the first page's total says there are (1 until it is read)."""
    first = done.get(page_path(m, 1))
    try:
        total = int(json.loads(first).get("total", 0)) if first else 0
    except (ValueError, AttributeError):
        total = 0
    return max(1, -(-total // PER_PAGE))


def kibana_steps(d, m, done, options):
    """The pages of rules not read yet, against the first location of the environment's first readable elastic/kibana
    source, in the Kibana space the setting names."""
    s = readable_source(m, KIBANA)
    if s is None:
        return ()
    space = setting_value(d, KIBANA_SPACE)
    prefix = "" if space == KIBANA_SPACE.default else f"/s/{space}"
    return tuple((page_path(m, n), _get(s, f"{prefix}{RULES}?per_page={PER_PAGE}&page={n}"))
                 for n in range(1, _pages(done, m) + 1) if page_path(m, n) not in done)


def problems_of(importer):
    """The collector problems of an importer's sources: why they can't be read (an unbound credential or trust anchor,
    no location)."""
    def problems(d, m, options):
        return source_problems(m, importer)
    return problems


COLLECTORS = (Collector(ELASTICSEARCH, "environment", elasticsearch_steps, problems=problems_of(ELASTICSEARCH)),
              Collector(KIBANA, "environment", kibana_steps, problems=problems_of(KIBANA)))
