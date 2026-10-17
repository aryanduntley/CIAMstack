"""Azure Key Vault certificates collector (`opsdir collect --adapter azure`, keyvault-certificates): what
azure/keyvault-certificates reads of each vault, from Key Vault's REST API, read-only (GETs only) and metadata only.
Pure: the core runs the calls.

Where to read is the environment's collection sources for azure/keyvault-certificates (ciamCollectionSource:
ciamSourceRef the vault's address, https://<vault>.vault.azure.net, or https://<vault>.vault.usgovcloudapi.net when
the cloud's ciamCloudEnvironment is usgovernment; one source per vault; no credential role). The collector signs
nothing in: every call is `az rest --method get` under the operator's own `az login`, checked first as cli-inventory
checks it (the subscription and cloud the record names), with the token's audience the cloud's Key Vault resource
(--resource). A next page is followed only on the vault's own address, so the token goes nowhere else.

Per source, saved as keyvault_certificates.py reads them (each answer trimmed to what the importer reads):
  GET /certificates?includePending=true&maxresults=25   certificates-<n>.json, then each page its nextLink names
  GET /certificates/contacts                            contacts.json (none set, or refused: nothing to read)
  GET /certificates/issuers                             issuers.json
  GET /certificates/{name}/versions                     versions/<name>-<n>.json, every page, per certificate listed
  GET /certificates/{name}/policy                       policies/<name>.json, per certificate listed
  GET /certificates/{name}/pending                      pending/<name>.json (none pending: nothing to read)
  GET /certificates/{name}/{version}                    certificates/<name>/<version>.json, per version listed, up to
                                                        DETAIL_CALLS
A certificate's answer carries its public certificate (cer) and the ids of its key and secret, never their material:
the ids are dropped before anything sees them, and the secret (the private key) is never asked for.

Least privilege: Key Vault Reader on the vault (certificates and issuers read; secrets' metadata, never values), or
the access policy certificate permissions get, list, getissuers and listissuers. Not Key Vault Certificate User: it
also reads secrets' values, which is where a certificate's private key is. Reading contacts takes managecontacts, which
also changes them: without it the contacts are left unread."""
import json
from functools import partial
from urllib.parse import quote, urlencode, urlsplit

from opsdir.core.contract import Collector, Command
from opsdir.core.directory import one
from opsdir.core.sources import json_document
from opsdir.domains.governance.collection import collection_sources, readable_sources
from .collect import identity_check
from .keyvault_certificates import (id_parts, page_path, pages, pending_path, policy_path, vault_path, version_path,
                                    versions_path)

IMPORTER = "azure/keyvault-certificates"
API_VERSION = "2025-07-01"
# the cloud (ciamCloudEnvironment) -> (its vaults' DNS suffix, the token audience Key Vault takes)
CLOUDS = {"public": ("vault.azure.net", "https://vault.azure.net"),
          "usgovernment": ("vault.usgovcloudapi.net", "https://vault.usgovcloudapi.net")}
MAX_RESULTS = 25               # Key Vault's largest page
DETAIL_CALLS = 1500            # version answers asked per collection, leaving room for the listings in the core's 2000
ABSENT = ("Not Found", "NotFound")   # nothing pending, no contacts set, a certificate gone since it was listed
# reading contacts takes managecontacts (certificatecontacts/write: it also changes them), which a read-only identity
# lacks: refused is nothing to read
CONTACTS_ABSENT = (*ABSENT, "Forbidden")
ATTRIBUTES = ("enabled", "nbf", "exp", "created", "updated")
ITEM_FIELDS = ("id", "x5t")
VERSION_FIELDS = ("id", "x5t", "cer")
POLICY_FIELDS = {"issuer": ("name", "cty", "cert_transparency"), "x509_props": ("subject", "sans", "validity_months")}
PENDING_FIELDS = ("status", "status_details", "cancellation_requested")


def _only(doc, fields):
    return {k: doc[k] for k in fields if k in doc}


def _attributes(doc):
    return {"attributes": _only(doc["attributes"], ATTRIBUTES)} if isinstance(doc.get("attributes"), dict) else {}


def _listing(doc):
    return {"value": [{**_only(i, ITEM_FIELDS), **_attributes(i)} for i in doc.get("value") or ()
                      if isinstance(i, dict)], "nextLink": doc.get("nextLink")}


def _dumps(doc):
    return json.dumps(doc, indent=1, sort_keys=True)


def kept_page(address, text):
    """A Command keep function's work: a certificate listing page reduced to each item's id, x5t and dates (tags
    dropped), its nextLink, and the vault's address it was read from; an error answer kept as its error; text that
    isn't JSON kept as it is (the importer names it)."""
    doc = json_document(text or "", dict)
    if doc is None:
        return text
    return _dumps({"Vault": address, **({"error": doc["error"]} if "error" in doc else _listing(doc))})


def kept_listing(text):
    """A version listing page reduced as a certificate listing page is (without the vault's address)."""
    doc = json_document(text or "", dict)
    return text if doc is None else _dumps(_listing(doc))


def kept_version(text):
    """A certificate version's answer reduced to its id, thumbprint, public certificate and dates: its key's and
    secret's ids (kid, sid), policy and tags dropped."""
    doc = json_document(text or "", dict)
    return text if doc is None else _dumps({**_only(doc, VERSION_FIELDS), **_attributes(doc)})


def kept_policy(text):
    """A certificate policy reduced to its issuer, lifetime actions, subject and names, and whether it is enabled
    (its key and secret properties dropped)."""
    doc = json_document(text or "", dict)
    if doc is None:
        return text
    nested = {k: _only(doc[k], f) for k, f in POLICY_FIELDS.items() if isinstance(doc.get(k), dict)}
    return _dumps({**nested, "lifetime_actions": doc.get("lifetime_actions") or [], **_attributes(doc)})


def kept_pending(text):
    """A pending operation reduced to its status, error and issuer's name (its CSR dropped)."""
    doc = json_document(text or "", dict)
    if doc is None:
        return text
    error = doc.get("error") if isinstance(doc.get("error"), dict) else None
    issuer = (doc.get("issuer") or {}).get("name") if isinstance(doc.get("issuer"), dict) else None
    return _dumps({**_only(doc, PENDING_FIELDS), **({"error": _only(error, ("code", "message"))} if error else {}),
                   **({"issuer": {"name": issuer}} if issuer else {})})


def kept_contacts(text):
    """The vault's certificate contacts reduced to their emails and names (phone numbers dropped)."""
    doc = json_document(text or "", dict)
    return text if doc is None else _dumps({"contacts": [_only(c, ("email", "name")) for c in doc.get("contacts")
                                                         or () if isinstance(c, dict)]})


def kept_issuers(text):
    """The vault's configured issuers reduced to their ids and providers."""
    doc = json_document(text or "", dict)
    return text if doc is None else _dumps({"value": [_only(i, ("id", "provider")) for i in doc.get("value") or ()
                                                      if isinstance(i, dict)], "nextLink": doc.get("nextLink")})


def vault_of(location, cloud):
    """(the vault's address, the token audience) a source's location names in a cloud (public or usgovernment):
    https://<vault>.<the cloud's vault suffix>, nothing after it; None when it names no vault of that cloud."""
    suffix, resource = CLOUDS.get(cloud or "public", (None, None))
    parts = urlsplit(location or "")
    host = (parts.hostname or "").lower()
    name = host[:-len(suffix) - 1] if suffix and host.endswith(f".{suffix}") else ""
    ok = parts.scheme == "https" and name and "." not in name and parts.path.strip("/") == "" and not parts.query
    return (f"https://{host}", resource) if ok else None


def _get(url, resource, keep, absent=()):
    return Command(("az", "rest", "--method", "get", "--url", url, "--resource", resource, "-o", "json"),
                   absent=tuple(absent), keep=keep)


def _url(address, path, **query):
    return f"{address}/{path}?{urlencode({'api-version': API_VERSION, **query})}"


def _next(address, listed):
    """The next page a paged listing's last page names, when it is on the vault's own address; else None."""
    link = (listed[-1][1] or {}).get("nextLink") if listed else None
    return link if isinstance(link, str) and link.startswith(f"{address}/") else None


def _paged(address, resource, keep, done, path_of, first):
    """(path, call) of every page of a listing read so far and the next one its last page names."""
    listed = pages(done, path_of)
    link = _next(address, listed)
    return ((path_of(0), _get(first, resource, keep)),
            *((path_of(len(listed)), _get(link, resource, keep)) for _ in (link,) if link))


def _source_steps(s, cloud, done):
    address, resource = vault_of(s.locations[0], cloud)
    get = partial(_get, resource=resource)
    listing = _paged(address, resource, partial(kept_page, address), done, lambda n: page_path(s.name, n),
                     _url(address, "certificates", includePending="true", maxresults=MAX_RESULTS))
    names = tuple(dict.fromkeys(p[0] for _, doc in pages(done, lambda n: page_path(s.name, n)) if doc
                                for i in doc.get("value") or () if isinstance(i, dict) and i.get("x5t")
                                for p in (id_parts(i.get("id")),) if p))
    per_name = tuple(c for n in names for c in (
        *_paged(address, resource, kept_listing, done, lambda k, n=n: versions_path(s.name, n, k),
                _url(address, f"certificates/{quote(n)}/versions", maxresults=MAX_RESULTS)),
        (policy_path(s.name, n), get(_url(address, f"certificates/{quote(n)}/policy"), keep=kept_policy)),
        (pending_path(s.name, n), get(_url(address, f"certificates/{quote(n)}/pending"), keep=kept_pending,
                                      absent=ABSENT))))
    versions = tuple((n, p[1]) for n in names for _, doc in pages(done, lambda k, n=n: versions_path(s.name, n, k))
                     if doc for i in doc.get("value") or () if isinstance(i, dict)
                     for p in (id_parts(i.get("id")),) if p and p[0] == n and p[1])
    return (*listing,
            (vault_path(s.name, "contacts"), get(_url(address, "certificates/contacts"), keep=kept_contacts,
                                                 absent=CONTACTS_ABSENT)),
            (vault_path(s.name, "issuers"), get(_url(address, "certificates/issuers"), keep=kept_issuers)),
            *per_name,
            *((version_path(s.name, n, v), get(_url(address, f"certificates/{quote(n)}/{quote(v)}"),
                                               keep=kept_version, absent=ABSENT))
              for n, v in versions[:DETAIL_CALLS]))


def keyvault_steps(d, m, done, options):
    """Each readable source's vault: its listing pages, contacts and issuers, then each listed certificate's version
    pages, policy and pending operation, then each version's answer (at most DETAIL_CALLS)."""
    cloud = one(m.cloud, "ciamCloudEnvironment")
    return tuple({p: c for s in readable_sources(m, IMPORTER) if vault_of(s.locations[0], cloud)
                  for p, c in _source_steps(s, cloud, done)}.items())


def keyvault_problems(d, m, options):
    """Why the collection sources can't be read: no location, or a location naming no vault of the environment's
    cloud."""
    cloud = one(m.cloud, "ciamCloudEnvironment") or "public"
    suffix = CLOUDS.get(cloud, ("<no Key Vault suffix known>",))[0]
    return tuple(p for s in collection_sources(m, IMPORTER) for p in (
        *s.problems, *((f"collection source `{s.name}`: {s.locations[0]} names no vault of the {cloud} cloud "
                        f"(https://<vault>.{suffix})",) if s.locations and not vault_of(s.locations[0], cloud)
                       else ())))


KEYVAULT_COLLECTOR = Collector("keyvault-certificates", "environment", keyvault_steps, identity_check,
                               keyvault_problems)
