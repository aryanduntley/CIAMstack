"""PingIDM collector (`opsdir collect`, core.contract Collector): the project configuration pingidm/project reads,
from IDM's REST API, read-only. Pure: the core makes the requests.

Where to read is the environment's collection source for pingidm/project (ciamCollectionSource: IDM's URL, or the
servers of its role on a port; the first location of the first source), with the credential its ciamCredentialRole
binding references sent as X-OpenIDM-Username (its ciamLoginName) and X-OpenIDM-Password, and the CA certificate its
ciamCaRole binding references as the trust anchor. GET /openidm/config lists the configuration objects; each is read
with GET /openidm/config/<id> and saved where the project keeps it: conf/<id>.json, a factory configuration's
instance after a dash (provisioner.openicf/ldap -> conf/provisioner.openicf-ldap.json), without the "_id" the API adds.
Encrypted values ($crypto) stay as IDM holds them and are withheld by the importer; resolver/ properties files aren't
served over REST and aren't collected."""
import json

from opsdir.core.contract import Collector, Request
from opsdir.domains.governance.collection import collection_sources

IMPORTER = "pingidm/project"
API = (("Accept-API-Version", "resource=1.0"),)
LISTING = "_work/idm-config.json"


def conf_path(object_id):
    """Where the project keeps a configuration object: conf/<id>.json, a factory instance after a dash."""
    return f"conf/{object_id.replace('/', '-')}.json"


def without_id(text):
    """A configuration object as its file holds it: the API's "_id" left out."""
    try:
        doc = json.loads(text)
    except ValueError:
        return text
    return json.dumps({k: v for k, v in doc.items() if k != "_id"}, indent=2) if isinstance(doc, dict) else text


def _request(s, path, keep=None):
    return Request(f"{s.locations[0].rstrip('/')}{path}", API,
                   ("headers", s.credential, s.login, ("X-OpenIDM-Username", "X-OpenIDM-Password"))
                   if s.credential else None, s.ca, keep=keep)


def config_steps(d, m, done, options):
    """The listing, then each configuration object it names."""
    s = next((x for x in collection_sources(m, IMPORTER) if x.locations and not x.problems), None)
    if s is None:
        return ()
    try:
        listed = json.loads(done.get(LISTING) or "{}").get("configurations") or ()
    except (ValueError, AttributeError):
        listed = ()
    return ((LISTING, _request(s, "/openidm/config")),
            *((conf_path(c["_id"]), _request(s, f"/openidm/config/{c['_id']}", without_id))
              for c in listed if isinstance(c, dict) and c.get("_id")))


def source_problems(d, m, options):
    """Why the collection sources can't be read (an unbound credential or trust anchor, no location)."""
    return tuple(p for s in collection_sources(m, IMPORTER) for p in s.problems)


COLLECTORS = (Collector("project", "environment", config_steps, problems=source_problems),)
