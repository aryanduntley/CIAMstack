"""Venafi / CyberArk Certificate Manager – Self-Hosted inventory (the importer `venafi/certificates`): the certificates
a policy folder and its subfolders hold, read into the core pki domain as a certificate manager's inventory
(domains.pki.managed), metadata only: never a key, and never a CA's issuance record. Pure.

The export holds, per collection source, the Web SDK's answers as `opsdir collect` saves them (collect.py) or
scripts/export-venafi.sh writes them, each reduced to what is read here:
  venafi/<source>/certificates-<offset>.json   GET /vedsdk/certificates/ pages (ParentDnRecursive=<folder>, Limit,
                                               Offset, OptionalFields=Issuer,Subject), each with the folder and the Web
                                               SDK's address it was read from (Folder, Address); an Error instead of
                                               Certificates when the listing was refused
  venafi/<source>/details/<guid>.json          GET /vedsdk/certificates/{guid}, per certificate listed
A source is one inventory (cn: its name; ciamInventoryPrefix the folder, ciamProviderRef the address). Each certificate
(cn: its GUID, without braces, lowercase) is read from its listing (X509: common name, alternative names, serial, SHA-1
thumbprint, validity, issuer, subject; DN: where it is filed) and its details, which say more where they say it: how
Certificate Manager manages it (ManagementType), whether that is disabled (Disabled), whether a discovery found it
(CreatedBy), who it notifies (Contact), the applications it is installed in (Consumers), the CA template it renews
through (CertificateAuthorityDN), what is wrong now (ProcessingDetails in error; a revocation pending or failed) and,
once revoked (RevocationStatus Complete or Confirmed), when (Certificate Manager records no reason: unspecified).
Certificate Manager gives no SHA-256 fingerprint: the record's certificates are matched by the thumbprint of the PEM
they hold, else by serial and issuer.

The inventory is denied when the first page holds an error (the listing was refused: what to grant is named),
incomplete when fewer certificates were listed than the folder's total, a page isn't one, or some certificates'
details weren't read (how they are managed is then unknown), else complete.
"""
import re

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import fingerprint, gtime, gtime_of_iso, ou_entry
from opsdir.core.naming import rdn_safe
from opsdir.core.sources import json_document
from opsdir.domains.pki.inventory import inventory_group
from opsdir.domains.pki.managed import managed_entry, managed_inventory_entry
from opsdir.domains.pki.naming import MANAGED

ROOT, PAGE, DETAILS = "venafi/", "certificates-", "details/"
# Certificate Manager's ManagementType -> the record's ciamManagement
MANAGEMENT = {"Unassigned": "unassigned", "Monitoring": "monitored", "Enrollment": "enrolled",
              "Provisioning": "provisioned"}
REVOKED_STATUSES = ("Complete", "Confirmed")       # RevocationStatus of a certificate whose revocation was done
TRUE = (True, 1, "1", "true", "True")
# What the collector's identity needs (the vendor's pages disagree: README, Least privilege)
GRANT = ("grant the collector's identity View and Read on the folder (inherited by its subfolders and certificates) "
         "and its API integration the OAuth scope `certificate`; the vendor's pages disagree whether listing also "
         "needs Private Key Read (GET Certificates' Requirements say so; its introduction and GET Certificates/{guid} "
         "say View and Read): grant Private Key Read only if View and Read are refused")


def guid_key(guid):
    """A certificate's GUID as the record names it: without braces, lowercase."""
    return str(guid or "").strip().strip("{}").lower()


def page_path(source, offset):
    """Where a source's listing page starting at offset is kept in the export."""
    return f"{ROOT}{source}/{PAGE}{offset}.json"


def detail_path(source, guid):
    """Where a source's certificate details are kept in the export."""
    return f"{ROOT}{source}/{DETAILS}{guid_key(guid)}.json"


def sources(files):
    """The collection sources an export holds (each with a listing page), in order."""
    pages = re.compile(rf"^{re.escape(ROOT)}([^/]+)/{PAGE}\d+\.json$")
    return tuple(sorted({m.group(1) for p in files for m in (pages.match(p),) if m}))


def _strings(v):
    return tuple(x for x in (v if isinstance(v, list) else (v,)) if isinstance(x, str) and x.strip())


def certificate_facts(listed, detail):
    """(the managed certificate facts of one listed certificate and its details (None: not read), notices): the
    record's ciamManagedCertificate attributes; what the details say wins over the listing."""
    x509, cd = listed.get("X509") or {}, (detail or {}).get("CertificateDetails") or {}
    said = lambda k: cd.get(k) or x509.get(k)        # noqa: E731
    sans = x509.get("SANS") if isinstance(x509.get("SANS"), dict) else {}
    cn = x509.get("CN") if isinstance(x509.get("CN"), str) else None
    names = (*_strings(cn), *_strings(sans.get("DNS")), *_strings(sans.get("IP")),
             *_strings(cd.get("SubjectAltNameDNS")), *_strings(cd.get("SubjectAltNameIPAddress")))
    detail = detail or {}
    processing = detail.get("ProcessingDetails") if isinstance(detail.get("ProcessingDetails"), dict) else {}
    revocation = cd.get("RevocationStatus")
    kind = detail.get("ManagementType")
    created = " ".join(_strings(detail.get("CreatedBy")))
    problems = (*((f"in error at stage {processing.get('Stage')}: {processing.get('Status') or 'no status given'}",)
                  if processing.get("InError") in TRUE else ()),
                *(("revocation requested, not yet done (Pending)",) if revocation == "Pending" else ()),
                *(("revocation failed (Failed)",) if revocation == "Failed" else ()))
    revoked = revocation in REVOKED_STATUSES
    facts = {"ciamSerialNumber": said("Serial"), "ciamThumbprint": fingerprint(said("Thumbprint")) or None,
             "ciamSubject": said("Subject") or (f"CN={cn}" if cn else None), "ciamIssuer": said("Issuer"),
             "ciamNotBefore": gtime_of_iso(said("ValidFrom")), "ciamNotAfter": gtime_of_iso(said("ValidTo")),
             "ciamCertificateName": tuple(dict.fromkeys(names)), "ciamManagerPath": listed.get("DN"),
             "ciamManagement": MANAGEMENT.get(kind), "ciamObjectState": None if not detail else
             "disabled" if detail.get("Disabled") in TRUE else "active",
             "ciamManagedOrigin": None if not created else "discovered" if "discovery" in created.lower() else "added",
             "ciamManagerContact": _strings(detail.get("Contact")),
             "ciamInstalledAt": _strings(detail.get("Consumers")),
             "ciamManagedAuthority": detail.get("CertificateAuthorityDN") or None, "ciamManagerProblem": problems,
             "ciamRevokedAt": gtime_of_iso(cd.get("RevocationDate")) if revoked else None,
             "ciamRevocationReason": "unspecified" if revoked else None}
    return facts, ((f"{listed.get('DN')}: ManagementType {kind!r} unknown: left out",) if kind and kind not in
                   MANAGEMENT else ())


def listing_pages(files, source):
    """((offset, the page's document or None), ...) of a source's listing, by offset."""
    found = re.compile(rf"^{re.escape(ROOT)}{re.escape(source)}/{PAGE}(\d+)\.json$")
    return tuple(sorted((int(m.group(1)), json_document(t or "", dict)) for p, t in files.items()
                        for m in (found.match(p),) if m))


def read_source(d, source, files, when):
    """(Imported group, notices) of one collection source: its inventory and the certificates it holds."""
    pages = listing_pages(files, source)
    first = pages[0][1] or {}
    folder, address, error = first.get("Folder"), first.get("Address"), first.get("Error")
    unreadable = tuple(o for o, doc in pages if doc is None or not isinstance(doc.get("Certificates"), list))
    listed = tuple({guid_key(c.get("Guid")): c for _, doc in pages if doc and isinstance(doc.get("Certificates"), list)
                    for c in doc["Certificates"] if isinstance(c, dict) and guid_key(c.get("Guid"))}.items())
    totals = tuple(doc.get("TotalCount") for _, doc in pages if doc and isinstance(doc.get("TotalCount"), int))
    total = max(totals, default=len(listed))
    details = {k: json_document(files.get(detail_path(source, k)) or "", dict) for k, _ in listed}
    unread = tuple(k for k, v in details.items() if v is None)
    unnamed = tuple(k for k, _ in listed if not rdn_safe(k))
    read = tuple((k, *certificate_facts(c, details[k])) for k, c in listed if k not in unnamed)
    problems = ((f"the listing of {folder or 'the folder'} was refused ({error}): {GRANT}",) if error else
                (*((f"{len(unreadable)} listing page(s) not a listing (offset {', '.join(map(str, unreadable))})",)
                   if unreadable else ()),
                 *((f"{len(listed)} of {total} certificate(s) listed",) if len(listed) < total else ()),
                 *((f"details of {len(unread)} certificate(s) not read (how each is managed, who it notifies, where "
                    "it is installed and what is wrong are unknown): collect again, or export the folder with "
                    "scripts/export-venafi.sh",) if unread else ()),
                 *((f"{len(unnamed)} GUID(s) can't be named in the record",) if unnamed else ())))
    state = "denied" if error else "incomplete" if problems else "complete"
    inventory = inventory_group(
        managed_inventory_entry(d, source, when, state, problems, (folder,) if folder else (), address),
        () if error else tuple(managed_entry(d, source, k, facts) for k, facts, _ in read))
    return inventory, (*(n for _, _, notices in read for n in notices),
                       f"{source} ({folder or 'folder unknown'}): {0 if error else len(read)} certificate(s), {state}"
                       + (f" ({'; '.join(problems)})" if problems else ""))


def read_certificates(files, d, patterns, at=None):
    """Imported: per collection source in the export, its certificate manager inventory, replacing the record's."""
    if at is None:
        return Imported((), (), ("an inventory is dated: give --at (when the folder was read)",))
    read = tuple(read_source(d, s, files, gtime(at)) for s in sources(files) if rdn_safe(s))
    return Imported(containers=(ou_entry(MANAGED),), groups=tuple(g for g, _ in read),
                    notices=(*(n for _, notices in read for n in notices),
                             *(f"source {s} can't be named in the record: left out" for s in sources(files)
                               if not rdn_safe(s)),
                             *(("no listings (venafi/<source>/certificates-<offset>.json, as `opsdir collect` saves "
                                "them)",) if not sources(files) else ())))


CERTIFICATES_IMPORTER = Importer("certificates", "Certificate Manager – Self-Hosted (Venafi) policy folders' "
                                                 "certificates as a certificate manager's inventory, metadata only "
                                                 "(the Web SDK's answers as `opsdir collect` or "
                                                 "scripts/export-venafi.sh save them)", read_certificates)
