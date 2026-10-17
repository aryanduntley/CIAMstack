"""CyberArk Certificate Manager – SaaS (formerly Venafi TLS Protect Cloud) inventory (the importer `venafi/saas`): the
certificates a tenant holds that the collector's identity can read, read into the core pki domain as a certificate
manager's inventory (domains.pki.managed), metadata only: never a key, and never a CA's issuance record. Pure.

The export holds, per collection source, the answers of POST /outagedetection/v1/certificatesearch as `opsdir collect`
saves them (saas_collect.py), each reduced to what is read here:
  venafi-saas/<source>/search-<n>.json   page n (from 0) of the search: the API's address (Address), the page size
                                         asked (PageSize), the total it reports (count) and its certificates; an Error
                                         instead when the search was refused
A source is one inventory (cn: its name; ciamProviderRef the API's address). Each certificate (cn: its id, lowercase)
is read from what the search says of it: the SHA-1 fingerprint, serial, subject, issuer, validity, the common and
alternative names (DNS and IP), its status (ACTIVE: active, RETIRED: management disabled, DELETED: deleted), how it
came to the tenant (certificateSource: a scan is discovered, else added) and where it is installed (each instance not
SUPERSEDED: hostname:port, its IP address when no host name). A certificate the search marks an earlier version
(versionType OLD) is renewed as the CURRENT one of the same managed certificate (managedCertificateId): ciamRenewedAs,
so the record's certificates matching it are renewed exactly. Owners, contacts and revocation aren't read: their field
names aren't settled by the vendor's pages (README).

The inventory is denied when the first page holds an error (the search was refused: what to grant is named), incomplete
when a page isn't one or is missing, fewer certificates were found than the count, or the page past the count's end
still held some, else complete.
"""
import re

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import fingerprint, gtime, gtime_of_iso, ou_entry
from opsdir.core.naming import rdn_safe
from opsdir.core.sources import json_document
from opsdir.domains.pki.inventory import inventory_group
from opsdir.domains.pki.managed import managed_entry, managed_inventory_entry
from opsdir.domains.pki.naming import MANAGED

ROOT, PAGE = "venafi-saas/", "search-"
STATES = {"ACTIVE": "active", "RETIRED": "disabled", "DELETED": "deleted"}     # certificateStatus -> ciamObjectState
OLD, CURRENT, SUPERSEDED = "OLD", "CURRENT", "SUPERSEDED"
NAMES = ("dNSName", "iPAddress")                    # the alternative names read (subjectAlternativeNamesByType)
# What the collector's identity needs (the vendor's pages don't settle whether Guest sees every certificate)
GRANT = ("give the collector's identity read access to the tenant's certificates: a user API key (tppl-api-key) of a "
         "user with the Guest role (read-only: certificates, requests, TLS endpoints, applications), or a service "
         "account's access token; whether Guest sees every certificate or only its teams' isn't settled by the "
         "vendor's pages: compare the count with the console")


def page_path(source, number):
    """Where a source's search page number (from 0) is kept in the export."""
    return f"{ROOT}{source}/{PAGE}{number}.json"


def sources(files):
    """The collection sources an export holds (each with a search page), in order."""
    pages = re.compile(rf"^{re.escape(ROOT)}([^/]+)/{PAGE}\d+\.json$")
    return tuple(sorted({m.group(1) for p in files for m in (pages.match(p),) if m}))


def search_pages(files, source):
    """((page number, the page's document or None), ...) of a source's search, by number."""
    found = re.compile(rf"^{re.escape(ROOT)}{re.escape(source)}/{PAGE}(\d+)\.json$")
    return tuple(sorted((int(m.group(1)), json_document(t or "", dict)) for p, t in files.items()
                        for m in (found.match(p),) if m))


def _strings(v):
    return tuple(x for x in (v if isinstance(v, list) else (v,)) if isinstance(x, str) and x.strip())


def cert_key(cert_id):
    """A certificate's id as the record names it: lowercase."""
    return str(cert_id or "").strip().lower()


def installed_at(cert):
    """Where the search says a certificate is installed: each instance not SUPERSEDED, as hostname:port (its IP
    address when it names no host name)."""
    return tuple(dict.fromkeys(f"{i.get('hostname') or i.get('ipAddress')}:{i.get('port')}"
                               for i in cert.get("instances") or () if isinstance(i, dict)
                               and i.get("deploymentStatus") != SUPERSEDED
                               and (i.get("hostname") or i.get("ipAddress")) and i.get("port") is not None))


def current_versions(certs):
    """{managedCertificateId: the id of its CURRENT version} among the certificates found."""
    return {c["managedCertificateId"]: cert_key(c.get("id")) for c in certs
            if c.get("versionType") == CURRENT and c.get("managedCertificateId") and cert_key(c.get("id"))}


def saas_facts(cert, current):
    """The managed certificate facts of one certificate the search found (current: current_versions'): the record's
    ciamManagedCertificate attributes."""
    sans = cert.get("subjectAlternativeNamesByType")
    sans = sans if isinstance(sans, dict) else {}
    cns = _strings(cert.get("subjectCN"))
    source = str(cert.get("certificateSource") or "")
    newer = current.get(cert.get("managedCertificateId")) if cert.get("versionType") == OLD else None
    return {"ciamSerialNumber": cert.get("serialNumber"),
            "ciamThumbprint": fingerprint(cert.get("fingerprint")) or None,
            "ciamSubject": cert.get("subjectDN") or (f"CN={cns[0]}" if cns else None),
            "ciamIssuer": cert.get("issuerDN"),
            "ciamNotBefore": gtime_of_iso(cert.get("validityStart")),
            "ciamNotAfter": gtime_of_iso(cert.get("validityEnd")),
            "ciamCertificateName": tuple(dict.fromkeys((*cns, *(n for k in NAMES for n in _strings(sans.get(k)))))),
            "ciamObjectState": STATES.get(cert.get("certificateStatus")),
            "ciamManagedOrigin": None if not source else "discovered" if re.search("SCAN|DISCOVER", source.upper())
            else "added", "ciamInstalledAt": installed_at(cert),
            "ciamRenewedAs": newer if newer and newer != cert_key(cert.get("id")) else None}


def search_problems(pages, found, count):
    """Why a source's search pages don't hold every certificate the tenant says it has: a page that isn't one, a page
    missing up to the one past the count's end, fewer found than the count, or the page past its end still holding
    some."""
    size = next((doc.get("PageSize") for _, doc in pages if doc and isinstance(doc.get("PageSize"), int)
                 and doc["PageSize"] > 0), None)
    read = {n: doc for n, doc in pages}
    unreadable = tuple(n for n, doc in pages if doc is None or not isinstance(doc.get("certificates"), list))
    last = -(-count // size) if size else 0                    # the page past the count's end
    missing = tuple(n for n in range(last + 1) if n not in read) if size else ()
    beyond = ((read.get(last) or {}).get("certificates") or ()) if size else ()
    return (*((f"{len(unreadable)} search page(s) not a search answer (page {', '.join(map(str, unreadable))})",)
              if unreadable else ()),
            *((f"search page(s) {', '.join(map(str, missing))} not read",) if missing else ()),
            *((f"{found} of {count} certificate(s) found",) if found < count else ()),
            *((f"the page past the count ({last}) still holds certificates: the count isn't the total",)
              if beyond else ()))


def read_source(d, source, files, when):
    """(Imported group, notices) of one collection source: its inventory and the certificates it holds."""
    pages = search_pages(files, source)
    first = pages[0][1] or {}
    address, error = first.get("Address"), first.get("Error")
    certs = tuple({cert_key(c.get("id")): c for _, doc in pages if doc and isinstance(doc.get("certificates"), list)
                   for c in doc["certificates"] if isinstance(c, dict) and cert_key(c.get("id"))}.values())
    count = max((doc.get("count") for _, doc in pages if doc and isinstance(doc.get("count"), int)),
                default=len(certs))
    unnamed = tuple(cert_key(c.get("id")) for c in certs if not rdn_safe(cert_key(c.get("id"))))
    current = current_versions(certs)
    read = tuple((cert_key(c.get("id")), saas_facts(c, current)) for c in certs
                 if cert_key(c.get("id")) not in unnamed)
    problems = ((f"the certificate search was refused ({error}): {GRANT}",) if error else
                (*search_problems(pages, len(certs), count),
                 *((f"{len(unnamed)} certificate id(s) can't be named in the record",) if unnamed else ())))
    state = "denied" if error else "incomplete" if problems else "complete"
    inventory = inventory_group(managed_inventory_entry(d, source, when, state, problems, (), address),
                                () if error else tuple(managed_entry(d, source, k, facts) for k, facts in read))
    earlier = sum(1 for _, facts in read if facts["ciamRenewedAs"])
    return inventory, (f"{source} ({address or 'address unknown'}): {0 if error else len(read)} certificate(s)"
                       + (f" ({earlier} earlier version(s))" if earlier and not error else "") + f", {state}"
                       + (f" ({'; '.join(problems)})" if problems else ""),)


def read_saas(files, d, patterns, at=None):
    """Imported: per collection source in the export, its certificate manager inventory, replacing the record's."""
    if at is None:
        return Imported((), (), ("an inventory is dated: give --at (when the tenant was searched)",))
    read = tuple(read_source(d, s, files, gtime(at)) for s in sources(files) if rdn_safe(s))
    return Imported(containers=(ou_entry(MANAGED),), groups=tuple(g for g, _ in read),
                    notices=(*(n for _, notices in read for n in notices),
                             *(f"source {s} can't be named in the record: left out" for s in sources(files)
                               if not rdn_safe(s)),
                             *(("no search pages (venafi-saas/<source>/search-<n>.json, as `opsdir collect` saves "
                                "them)",) if not sources(files) else ())))


SAAS_IMPORTER = Importer("saas", "Certificate Manager – SaaS (Venafi TLS Protect Cloud) tenant's certificates as a "
                                 "certificate manager's inventory, metadata only (the certificate search's answers as "
                                 "`opsdir collect` saves them)", read_saas)
