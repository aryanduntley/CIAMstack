"""Certificate Manager – SaaS collector (`opsdir collect`, core.contract Collector): what venafi/saas reads of a tenant,
read-only and metadata only. Pure: the core makes the requests. Its one call, the certificate search, is a POST because
its criteria don't fit a URL: the collector declares it its only read-only query (Collector queries), so the core
refuses any other POST.

Where to read is the environment's collection sources for venafi/saas (ciamCollectionSource: ciamSourceRef the
tenant's regional API address, https://api.venafi.cloud (US), https://api.eu.venafi.cloud, api.au, api.uk, api.sg or
api.ca (the vendor's pages also name https://api.venafi.eu for the EU: README); the credential its ciamCredentialRole
binding references, resolved when collecting and never stored: a user API key (ciamCredentialScheme api-key, sent as
the tppl-api-key header) or a service account's access token (bearer, Authorization: Bearer; it lasts 15 minutes and
is issued by the service account's token endpoint, outside opsdir)).

Per source, saved as saas.py reads them (each answer trimmed to what the importer reads):
  POST /outagedetection/v1/certificatesearch?excludeSupersededInstances=true  {"paging": {"pageNumber": n,
      "pageSize": PAGE_SIZE}}: search-0.json, then every page up to the one past the end its count says (it should be
      empty: the count is then the total)"""
import json
from urllib.parse import urlsplit

from opsdir.core.contract import Collector, Request
from opsdir.core.sources import json_document
from opsdir.domains.governance.collection import collection_sources, readable_sources, scheme_problems
from .saas import NAMES, page_path

IMPORTER = "venafi/saas"
SCHEMES = ("api-key", "bearer")
TAKES = ("Certificate Manager – SaaS takes a user API key (api-key: the tppl-api-key header) or a service account's "
         "access token (bearer)")
API_KEY_HEADER = "tppl-api-key"
SEARCH = "/outagedetection/v1/certificatesearch"
QUERIES = (rf"^{SEARCH}$",)
PAGE_SIZE = 50                   # certificates per page (vcert's own batch; the vendor documents no maximum)
JSON = (("Accept", "application/json"),)
# what the importer reads of each answer (the rest is dropped before anything sees it)
CERT_FIELDS = ("id", "managedCertificateId", "versionType", "certificateStatus", "fingerprint", "serialNumber",
               "subjectCN", "subjectDN", "issuerDN", "validityStart", "validityEnd", "certificateSource")
INSTANCE_FIELDS = ("hostname", "ipAddress", "port", "deploymentStatus")


def _only(doc, fields):
    return {k: doc[k] for k in fields if k in doc}


def trimmed(cert):
    """A certificate the search found reduced to CERT_FIELDS, its alternative names to NAMES and its instances to
    INSTANCE_FIELDS."""
    sans = cert.get("subjectAlternativeNamesByType")
    return {**_only(cert, CERT_FIELDS),
            **({"subjectAlternativeNamesByType": _only(sans, NAMES)} if isinstance(sans, dict) else {}),
            **({"instances": [_only(i, INSTANCE_FIELDS) for i in cert["instances"] if isinstance(i, dict)]}
               if isinstance(cert.get("instances"), list) else {})}


def kept_page(address):
    """A Request keep function: a search page reduced to its count and each certificate trimmed, with the address it
    was read from and the page size asked; text that isn't one is kept as it is (the importer names it)."""
    def keep(text):
        doc = json_document(text or "", dict)
        certs = doc.get("certificates") if doc is not None else None
        if not isinstance(certs, list):
            return text
        return json.dumps({"Address": address, "PageSize": PAGE_SIZE, "count": doc.get("count"),
                           "certificates": [trimmed(c) for c in certs if isinstance(c, dict)]}, indent=1,
                          sort_keys=True)
    return keep


def address_of(location):
    """The API's address a source's location names (https://<host>[:<port>], no path), or None."""
    parts = urlsplit(location or "")
    return (f"https://{parts.netloc}" if parts.scheme == "https" and parts.netloc and parts.path.strip("/") == ""
            and not parts.query else None)


def search_body(number):
    """The JSON text of the search for page number (from 0): every certificate, PAGE_SIZE per page."""
    return json.dumps({"paging": {"pageNumber": number, "pageSize": PAGE_SIZE}}, sort_keys=True)


def credential_of(s):
    """How a source's credential is sent: the tppl-api-key header for an API key, else Authorization: Bearer."""
    return ("api-key", s.credential, None, API_KEY_HEADER) if s.scheme == "api-key" else ("bearer", s.credential, None)


def _source_steps(s, done):
    address = address_of(s.locations[0])
    def page(number):
        return (page_path(s.name, number),
                Request(f"{address}{SEARCH}?excludeSupersededInstances=true", JSON, credential_of(s), s.ca, (),
                        kept_page(address), body=search_body(number)))
    first = json_document(done.get(page_path(s.name, 0)) or "", dict) or {}
    count = first.get("count") if isinstance(first.get("count"), int) else 0
    return (page(0), *(page(n) for n in range(1, -(-count // PAGE_SIZE) + 1)))


def saas_steps(d, m, done, options):
    """Each readable source's tenant: the first search page, then every page up to the one past the end its count
    says."""
    return tuple({p: c for s in readable_sources(m, IMPORTER, SCHEMES) if address_of(s.locations[0])
                  for p, c in _source_steps(s, done)}.items())


def saas_source_problems(d, m, options):
    """Why the collection sources can't be read: an unbound credential, no location, a credential scheme the API isn't
    read with, or a location that isn't an API address (https://<host>, no path)."""
    return (*scheme_problems(m, IMPORTER, SCHEMES, TAKES),
            *(f"collection source `{s.name}`: {s.locations[0]} isn't the tenant's API address "
              "(https://api.venafi.cloud or its regional host, no path)" for s in collection_sources(m, IMPORTER)
              if s.locations and not address_of(s.locations[0])))


SAAS_COLLECTORS = (Collector("saas", "environment", saas_steps, problems=saas_source_problems, queries=QUERIES),)
