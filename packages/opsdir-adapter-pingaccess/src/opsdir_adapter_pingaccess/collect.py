"""PingAccess collector (`opsdir collect`, core.contract Collector): the Admin API v3 responses pingaccess/admin-api
reads, read-only. Pure: the core makes the requests.

Where to read is the environment's collection source for pingaccess/admin-api (ciamCollectionSource: the admin node's
URL https://<host>:9000, or the servers of its role on a port; the first location of the first usable source), with
the credential its ciamCredentialRole binding references (resolved when collecting, never stored) sent as HTTP Basic
for its ciamLoginName (an Auditor: it reads every object but /config/*, /backup and agent configuration), or, when its
ciamCredentialScheme is bearer, as Authorization: Bearer (an OAuth access token minted outside opsdir, for an Admin
API that validates tokens), and the CA certificate its ciamCaRole binding references as the trust anchor. Every
request is a GET with X-XSRF-Header: PingAccess, from an explicit list (api.COLLECTIONS): /version, each collection
page by page (another page while the last came back full and differed from the one before it), each settings object,
then each application's resources. Never requested: the configuration export (it needs Administrator, so the
collector's credential would not be read-only: save an export by hand for pingaccess/export), backups, and agent or
engine configuration downloads (they generate key material). A collection the version doesn't have (404) is left
out."""
import json

from opsdir.core.contract import Collector, Request
from opsdir.domains.governance.collection import collection_sources
from .api import API, COLLECTIONS, ID, PAGE_SIZE, PAGING, RESOURCES, VERSION, XSRF
from .sources import response_items

IMPORTER = "pingaccess/admin-api"
SCHEMES = ("basic", "bearer")       # how the Admin API takes the credential (Basic administrators; OAuth tokens)
ABSENT = (404,)


def _credential(s):
    return (s.scheme, s.credential, s.login) if s.credential else None


def _get(s, path, query=""):
    return Request(f"{s.locations[0].rstrip('/')}{API}/{path}{query}", XSRF, _credential(s), s.ca, ABSENT)


def _page_items(done, path):
    try:
        doc = json.loads(done[path]) if path in done else None
    except ValueError:
        return None
    return response_items(doc) if doc is not None else None


def _ids(items):
    return tuple(i.get(ID) for i in items or ())


def pages(s, done, path):
    """The page requests of a collection asked so far: page 1, then each next page while the last one came back
    full and differs from the one before it (a PingAccess that ignores paging answers every page alike)."""
    def page(n):
        return f"{path}/page-{n}.json"

    def more(n):
        last, before = _page_items(done, page(n)), _page_items(done, page(n - 1)) if n > 1 else None
        return last is not None and len(last) >= PAGE_SIZE and _ids(last) != _ids(before)
    count = next(n for n in range(1, len(done) + 2) if not more(n))
    return tuple((page(n), _get(s, path, f"?{PAGING[0]}={n}&{PAGING[1]}={PAGE_SIZE}")) for n in range(1, count + 1))


def _applications(done):
    found = (i for p in sorted(done) if p.startswith("applications/page-") for i in _page_items(done, p) or ())
    return tuple(dict.fromkeys(str(i[ID]) for i in found if i.get(ID) is not None))


def api_steps(d, m, done, options):
    """The version, each collection and settings object, then each application's resources."""
    s = next((x for x in collection_sources(m, IMPORTER) if x.locations and not x.problems and x.scheme in SCHEMES),
             None)
    if s is None:
        return ()
    listed = tuple(c for c in COLLECTIONS if c.path != RESOURCES)
    return ((f"{VERSION}.json", _get(s, VERSION)),
            *((f"{c.path}.json", _get(s, c.path)) for c in listed if c.settings),
            *(r for c in listed if not c.settings for r in pages(s, done, c.path)),
            *(r for a in _applications(done) for r in pages(s, done, f"applications/{a}/resources")))


def source_problems(d, m, options):
    """Why the collection sources can't be read (an unbound credential or trust anchor, no location, a credential
    scheme the Admin API doesn't take)."""
    return tuple(p for s in collection_sources(m, IMPORTER) for p in (*s.problems, *_scheme_problem(s)))


def _scheme_problem(s):
    return (f"collection source `{s.name}`: credential scheme `{s.scheme}`: PingAccess's Admin API takes "
            f"{' or '.join(SCHEMES)}",) if s.scheme not in SCHEMES else ()


COLLECTORS = (Collector("admin-api", "environment", api_steps, problems=source_problems),)
