"""EJBCA collector (`opsdir collect`, core.contract Collector): what ejbca/inventory reads of an EJBCA instance, from
its REST API, read-only and metadata only: GETs, and the certificate search, a POST of its criteria that changes
nothing (the only URL the collector declares a query: Collector queries; the core refuses any other POST). Pure: the
core makes the requests.

Where to read is the environment's collection sources for ejbca/inventory (ciamCollectionSource: ciamSourceRef
https://<host>:<port>/ejbca, one source per EJBCA instance; the client certificate its ciamCredentialRole binding
references, ciamCredentialScheme client-certificate: a PEM with the certificate, its chain and private key, resolved
when collecting, held in memory only, never stored; EJBCA maps it to the role the README states; the CA certificate
its ciamCaRole binding references as the trust anchor). EJBCA Community authenticates REST clients by client
certificate only.

Per source, saved as inventory.py reads them (each answer trimmed to what the importer reads):
  GET /v1/ca                                                   cas.json
  GET /v2/certificate/count                                    count.json (optional: refused, nothing to read)
  POST /v2/certificate/search, per CA it lists (not external), CA EQUAL <name>, sorted by issue date, PAGE_SIZE a
  page: page 1, then every further page its total names        certificates/<CA id>/page-<n>.json
  GET /v2/certificate/profile/<name>, per profile the certificates name (gone: nothing to read)
                                                               profiles/<name>.json
The REST protocols "REST Certificate Management" and "REST Certificate Management V2" must be enabled (System
Configuration, Protocol Configuration: both are off by default). One collection makes at most the core's call bound
(PAGE_SIZE certificates a page)."""
import json
import math
from urllib.parse import quote, urlsplit

from opsdir.core.contract import Collector, Request
from opsdir.core.sources import json_document
from opsdir.domains.governance.collection import collection_sources, readable_sources, scheme_problems
from .inventory import CAS, COUNT, PAGE_SIZE, ROOT, listed_cas, page_path, profile_names, profile_path, search_page

IMPORTER = "inventory"
SPEC = f"ejbca/{IMPORTER}"
SCHEMES = ("client-certificate",)
TAKES = "EJBCA's REST API takes a client certificate (client-certificate: mutual TLS)"
QUERIES = (r"/ejbca-rest-api/v2/certificate/search$",)
JSON = (("Accept", "application/json"),)
NOTHING, REFUSABLE = (404,), (403, 404)
# what the importer reads of each answer (the rest is dropped before anything sees it)
CA_FIELDS = ("id", "name", "subject_dn", "issuer_dn", "external")
CERT_FIELDS = ("base64Cert", "serialNumber", "subjectDN", "issuerDN", "notBefore", "expireDate", "status", "type",
               "revocationDate", "revocationReason", "certificateProfile", "endEntityProfile", "username")
PROFILE_FIELDS = ("certificate_profile_id", "available_cas", "extended_key_usages", "validity")


def kept(fields, items=None):
    """A Request keep function: a JSON answer reduced to the fields given (and, for each list field items names, its
    items to their fields); text that isn't a JSON object kept as it is (the importer names it)."""
    items = items or {}
    def trim(k, v):
        return [{f: x[f] for f in items[k] if f in x} for x in v if isinstance(x, dict)] \
            if k in items and isinstance(v, list) else v
    def keep(text):
        doc = json_document(text or "", dict)
        return json.dumps({k: trim(k, doc[k]) for k in fields if k in doc}, indent=1, sort_keys=True) \
            if doc is not None else text
    return keep


def base_of(location):
    """The REST API base of a source's location (https://<host>:<port>/ejbca), or None when it isn't an https URL."""
    parts = urlsplit(location or "")
    if parts.scheme != "https" or not parts.netloc:
        return None
    return f"https://{parts.netloc}{parts.path.rstrip('/') or '/ejbca'}/ejbca-rest-api"


def search_body(ca, page):
    """The read-only certificate search of one page of a CA's certificates."""
    return json.dumps({"pagination": {"page_size": PAGE_SIZE, "current_page": page},
                       "sort": {"property": "ISSUED_DATE", "operation": "ASC"},
                       "criteria": [{"property": "CA", "value": ca, "operation": "EQUAL"}]}, sort_keys=True)


def _get(s, url, keep, absent=NOTHING):
    return Request(url, JSON, ("client-certificate", s.credential, None), s.ca, absent, keep)


def _search(s, base, ca, page):
    keep = kept(("certificates", "pagination_summary"), {"certificates": CERT_FIELDS})
    return Request(f"{base}/v2/certificate/search", JSON, ("client-certificate", s.credential, None), s.ca, (), keep,
                   body=search_body(ca, page))


def _ca_steps(s, base, done, listed):
    """A CA's search pages: page 1, then each further one its total names."""
    first = done.get(page_path(s.name, listed["id"], 1))
    total = search_page(first)[1] if first is not None else None
    return tuple((page_path(s.name, listed["id"], n), _search(s, base, str(listed["name"]), n))
                 for n in range(1, max(1, math.ceil((total or 0) / PAGE_SIZE)) + 1))


def _source_steps(s, done):
    base = base_of(s.locations[0])
    at = lambda rel: f"{ROOT}{s.name}/{rel}"        # noqa: E731
    cas = tuple(c for c in listed_cas(done.get(at(CAS))) or () if not c.get("external"))
    pages = tuple(step for c in cas for step in _ca_steps(s, base, done, c))
    certs = tuple(c for p, _ in pages if p in done for c in search_page(done[p])[0])
    return ((at(CAS), _get(s, f"{base}/v1/ca", kept(("certificate_authorities",),
                                                     {"certificate_authorities": CA_FIELDS}))),
            (at(COUNT), _get(s, f"{base}/v2/certificate/count", kept(("count",)), REFUSABLE)),
            *pages,
            *((profile_path(s.name, n), _get(s, f"{base}/v2/certificate/profile/{quote(n, safe='')}",
                                             kept(PROFILE_FIELDS)))
              for n in profile_names(certs)))


def inventory_steps(d, m, done, options):
    """Each readable source: its CA list and count, each CA's search pages, then each certificate profile the
    certificates name."""
    return tuple({p: c for s in readable_sources(m, SPEC, SCHEMES) if base_of(s.locations[0])
                  for p, c in _source_steps(s, done)}.items())


def source_problems(d, m, options):
    """Why the collection sources can't be read: an unbound credential or trust anchor, no location, a scheme other
    than client-certificate, a location that isn't an https URL."""
    return (*scheme_problems(m, SPEC, SCHEMES, TAKES),
            *(f"collection source `{s.name}`: {s.locations[0]} isn't an https URL (https://<host>:<port>/ejbca)"
              for s in collection_sources(m, SPEC) if s.locations and not base_of(s.locations[0])))


COLLECTORS = (Collector(IMPORTER, "environment", inventory_steps, problems=source_problems, queries=QUERIES),)
