"""Certificate Manager – Self-Hosted collector (`opsdir collect`, core.contract Collector): what venafi/certificates
reads of each policy folder, from the Web SDK, read-only (GETs only) and metadata only. Pure: the core makes the
requests.

Where to read is the environment's collection sources for venafi/certificates (ciamCollectionSource: ciamSourceRef
https://<host>[:<port>]/<folder path>, the folder's DN with / for \\ (https://tpp.example.test/VED/Policy/Example
Aero); one source per folder, its subfolders included; the OAuth access token its ciamCredentialRole binding
references, resolved when collecting and never stored, sent as Authorization: Bearer (ciamCredentialScheme bearer);
the CA certificate its ciamCaRole binding references as the trust anchor). Certificate Manager issues tokens only by
POST (/vedauth/authorize/oauth, /certificate or /integrated): getting one is the operator's, outside opsdir.

Per source, saved as certificates.py reads them (each answer trimmed to what the importer reads):
  GET /vedsdk/certificates/?ParentDnRecursive=<folder>&Limit=500&Offset=<n>&OptionalFields=Issuer,Subject
      certificates-<n>.json, the first page, then every page its TotalCount says there is
  GET /vedsdk/certificates/{<guid>}       details/<guid>.json, for each certificate listed, up to DETAIL_CALLS
A certificate gone or refused between the listing and its details (404, 403) is nothing to read: its details are then
unread, and the inventory incomplete. The public certificate itself is never fetched (its endpoint needs the
Certificate:Manage scope and, by its page, Private Key Read)."""
import json
from urllib.parse import quote, unquote, urlencode, urlsplit

from opsdir.core.contract import Collector, Request
from opsdir.core.sources import json_document
from opsdir.domains.governance.collection import collection_sources, readable_sources, scheme_problems
from .certificates import detail_path, guid_key, listing_pages, page_path

IMPORTER = "venafi/certificates"
SCHEMES = ("bearer",)
TAKES = ("Certificate Manager's Web SDK takes an OAuth access token: bearer (issued by POST /vedauth/authorize/..., "
         "outside opsdir)")
LIMIT = 500                    # certificates per page (the SDK's own default batch; the Web SDK documents no maximum)
DETAIL_CALLS = 1500            # details asked per collection, leaving room for the pages in the core's 2000 calls
OPTIONAL_FIELDS = "Issuer,Subject"
REFUSABLE = (403, 404)
# what the importer reads of each answer (the rest is dropped before anything sees it)
LIST_FIELDS = ("DN", "Guid", "Name", "ParentDn", "SchemaClass", "CreatedOn", "X509")
X509_FIELDS = ("CN", "Issuer", "Subject", "Serial", "Thumbprint", "ValidFrom", "ValidTo", "SANS")
DETAIL_FIELDS = ("Guid", "DN", "CreatedBy", "Disabled", "Consumers", "ManagementType", "CertificateAuthorityDN",
                 "Contact", "ProcessingDetails", "CertificateDetails")
NESTED_FIELDS = {"ProcessingDetails": ("InError", "InProcess", "Stage", "Status"),
                 "CertificateDetails": ("Issuer", "Subject", "Serial", "Thumbprint", "ValidFrom", "ValidTo",
                                        "SubjectAltNameDNS", "SubjectAltNameIPAddress", "RevocationStatus",
                                        "RevocationDate")}


def _only(doc, fields):
    return {k: doc[k] for k in fields if k in doc}


def kept_page(folder, address):
    """A Request keep function: a listing page reduced to its total and each certificate's LIST_FIELDS (X509 to
    X509_FIELDS), with the folder and address it was read from; text that isn't one is kept as it is (the importer
    names it)."""
    def keep(text):
        doc = json_document(text or "", dict)
        certs = doc.get("Certificates") if doc is not None else None
        if not isinstance(certs, list):
            return text
        trim = lambda c: {**_only(c, LIST_FIELDS), **({"X509": _only(c["X509"], X509_FIELDS)}      # noqa: E731
                                                      if isinstance(c.get("X509"), dict) else {})}
        return json.dumps({"Folder": folder, "Address": address, "TotalCount": doc.get("TotalCount"),
                           "Certificates": [trim(c) for c in certs if isinstance(c, dict)]}, indent=1, sort_keys=True)
    return keep


def kept_detail(text):
    """A Request keep function: a certificate's details reduced to DETAIL_FIELDS (ProcessingDetails and
    CertificateDetails to NESTED_FIELDS'); text that isn't one is kept as it is."""
    doc = json_document(text or "", dict)
    if doc is None:
        return text
    nested = {k: _only(doc[k], f) for k, f in NESTED_FIELDS.items() if isinstance(doc.get(k), dict)}
    return json.dumps({**_only(doc, DETAIL_FIELDS), **nested}, indent=1, sort_keys=True)


def folder_of(location):
    """(the Web SDK's address, the folder's DN) a source's location names (https://<host>/<folder path>, the path
    starting VED/), or None."""
    parts = urlsplit(location or "")
    path = unquote(parts.path).strip("/")
    return ((f"https://{parts.netloc}/vedsdk", "\\" + path.replace("/", "\\"))
            if parts.scheme == "https" and parts.netloc and path.split("/")[0].upper() == "VED" else None)


def _listed(source, done):
    """The GUIDs the pages collected so far list, in page order."""
    return tuple(dict.fromkeys(guid_key(c.get("Guid")) for _, doc in listing_pages(done, source) if doc
                               for c in doc.get("Certificates") or () if isinstance(c, dict)
                               and guid_key(c.get("Guid"))))


def _source_steps(s, done):
    address, folder = folder_of(s.locations[0])
    credential = ("bearer", s.credential, None)
    def page(offset):
        query = urlencode({"ParentDnRecursive": folder, "Limit": LIMIT, "Offset": offset,
                           "OptionalFields": OPTIONAL_FIELDS})
        return (page_path(s.name, offset), Request(f"{address}/certificates/?{query}", (), credential, s.ca, (),
                                                   kept_page(folder, address)))
    first = json_document(done.get(page_path(s.name, 0)) or "", dict) or {}
    total = first.get("TotalCount") if isinstance(first.get("TotalCount"), int) else 0
    return (page(0), *(page(o) for o in range(LIMIT, total, LIMIT)),
            *((detail_path(s.name, g), Request(f"{address}/certificates/{quote('{' + g + '}', safe='')}", (),
                                               credential, s.ca, REFUSABLE, kept_detail))
              for g in _listed(s.name, done)[:DETAIL_CALLS]))


def certificate_steps(d, m, done, options):
    """Each readable source's folder: its first listing page, then the pages its total says there are, then each
    listed certificate's details (at most DETAIL_CALLS)."""
    return tuple({p: c for s in readable_sources(m, IMPORTER, SCHEMES) if folder_of(s.locations[0])
                  for p, c in _source_steps(s, done)}.items())


def source_problems(d, m, options):
    """Why the collection sources can't be read: an unbound credential or trust anchor, no location, a credential
    scheme the Web SDK isn't read with, or a location naming no folder."""
    return (*scheme_problems(m, IMPORTER, SCHEMES, TAKES),
            *(f"collection source `{s.name}`: {s.locations[0]} names no folder (https://<host>/VED/Policy/<folder>)"
              for s in collection_sources(m, IMPORTER) if s.locations and not folder_of(s.locations[0])))


COLLECTORS = (Collector("certificates", "environment", certificate_steps, problems=source_problems),)
