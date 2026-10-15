"""Splunk collector (`opsdir collect`, core.contract Collector): the management API answers splunk/rest reads,
read-only. Pure: the core makes the requests.

Where to read is the environment's collection source for splunk/rest (ciamCollectionSource: the management endpoint,
https://<host>:8089; its first location), with the credential its ciamCredentialRole binding references (resolved when
collecting, never stored) sent as Authorization: Bearer when its ciamCredentialScheme is bearer (a Splunk
authentication token, the way to read with a dedicated reader), else as HTTP Basic for its ciamLoginName, and the CA
certificate its ciamCaRole binding references as the trust anchor. Two GETs, saved under the environment's folder:
/services/data/indexes (every index the server knows, with its retention settings) and /servicesNS/-/-/saved/searches
(every saved search the credential may read), both output_mode=json&count=0. Reading needs no write capability: a
role listing indexes (indexes_list_all where the listing is restricted) and reading the saved searches' apps. HTTP
Event Collector tokens are for sending, never this.
"""
from opsdir.core.contract import Collector, Request
from opsdir.domains.governance.collection import collection_sources

IMPORTER = "splunk/rest"
CALLS = (("indexes.json", "/services/data/indexes?output_mode=json&count=0"),
         ("saved-searches.json", "/servicesNS/-/-/saved/searches?output_mode=json&count=0"))


def _credential(s):
    return (s.scheme, s.credential, s.login) if s.credential else None


def rest_steps(d, m, done, options):
    """The two GETs, against the first location of the environment's first readable collection source."""
    s = next((x for x in collection_sources(m, IMPORTER)
              if x.locations and not x.problems), None)
    if s is None:
        return ()
    return tuple((f"{m.label}/{path}", Request(f"{s.locations[0].rstrip('/')}{call}", (), _credential(s), s.ca))
                 for path, call in CALLS)


def source_problems(d, m, options):
    """Why the collection sources can't be read (an unbound credential or trust anchor, no location)."""
    return tuple(p for s in collection_sources(m, IMPORTER) for p in s.problems)


COLLECTORS = (Collector("rest", "environment", rest_steps, problems=source_problems),)
