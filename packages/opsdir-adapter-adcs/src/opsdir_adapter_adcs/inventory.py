"""AD CS inventory (the importer `adcs/inventory`): each CA's issued certificates, revocation endpoints and templates,
and the forest's certificate templates, read into the core pki domain's records (domains.pki.issued), metadata only.
Pure.

The export holds templates.ldif (templates.py; optional: without it, the record's templates name what the CAs say)
and one ca/<name>.json per CA, written on the CA host by scripts/Export-AdcsInventory.ps1 through the documented COM
interfaces (ICertView for the database, ICertAdmin2 for the configuration): never certutil's text output, whose
serialization Microsoft doesn't document. The JSON is this adapter's own contract (FORMAT, VERSION): UTC ISO 8601
times with Z, decimal integers, JSON null for nothing, strings as the CA holds them (a serial keeps its leading zeros),
the exporter's version, the CA's configuration string (COMPUTERNAME\\CANAME), name, DNS and NetBIOS names, whether it
read every row, its publication URL registry entries and its templates. Each row is one issued or revoked certificate
under the CA database's schema names (COLUMNS), with the SHA-256 and subject of its public certificate when the
exporter read it: no archived key or any other column is ever read (one present is named in a notice).

A row the importer can't read whole (no request id, a time without a zone, an unknown disposition) leaves the
inventory incomplete with why; an exporter error (the CA refused it) makes it denied. A revoked row's ciamRevokedAt is
its effective revocation time (Request.RevokedEffectiveWhen, else the processing time), its reason the RFC 5280 name or
the CA's value as it is (ciamRevocationReason, always present on a revoked row).
"""
import datetime as dt
import json
import re

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import children, fingerprint, gtime, one, ou_entry, rdn_value, values
from opsdir.core.naming import rdn_safe
from opsdir.domains.pki.inventory import inventory_group
from opsdir.domains.pki.issued import (TEMPLATE_CLASS, authority_entry, cert_inventory_entry, endpoint_entry,
                                       issued_entry, revocation_reason, template_entry, templates_group)
from opsdir.domains.pki.naming import AUTHORITIES, ISSUED, TEMPLATES
from .templates import read_templates, resolver
from .urls import CA_CERT_KINDS, CRL_KINDS, endpoints

FORMAT, VERSION = "opsdir-adcs-inventory", 1
TEMPLATES_FILE = "templates.ldif"
CA_ROOT = "ca/"
# what the importer reads of a row: the CA database's schema names (MS-CSRA), and what the exporter derives from the
# row's public certificate (RawCertificate)
COLUMNS = {"request": "RequestID", "serial": "SerialNumber", "not_before": "NotBefore", "not_after": "NotAfter",
           "template": "CertificateTemplate", "requester": "Request.RequesterName",
           "disposition": "Request.Disposition", "revoked_when": "Request.RevokedWhen",
           "revoked_effective": "Request.RevokedEffectiveWhen", "reason": "Request.RevokedReason",
           "sha256": "SHA256", "subject": "Subject"}
DISPOSITIONS = {20: "issued", 21: "revoked"}
KEY_COLUMNS = re.compile(r"archived|recoveryhash|privatekey", re.IGNORECASE)


def _time(v):
    """(GeneralizedTime or None, problem or None) of a JSON time: ISO 8601 with a zone (Z or an offset); one without
    a zone is refused (its time zone is unknown)."""
    if v is None:
        return None, None
    try:
        at = dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None, f"{v!r} isn't an ISO 8601 time"
    return (gtime(at), None) if at.tzinfo else (None, f"{v!r} has no time zone")


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else int(v) if isinstance(v, str) and \
        re.fullmatch(r"-?\d+", v.strip()) else None


def _sha256(v):
    hexed = re.sub(r"[^0-9a-f]", "", str(v or "").lower())
    return fingerprint(hexed) if len(hexed) == 64 else None


def row_facts(row, resolve):
    """(request id, issued certificate facts, problems) of one exported row; request id None when the row has none,
    facts None when it is neither issued nor revoked."""
    get = lambda k: row.get(COLUMNS[k])       # noqa: E731
    request, disposition = _int(get("request")), _int(get("disposition"))
    times = {k: _time(get(k)) for k in ("not_before", "not_after", "revoked_when", "revoked_effective")}
    revoked = disposition == 21
    raw_template = get("template")
    template = (resolve(raw_template) or str(raw_template)) if raw_template not in (None, "") else None
    problems = (*(f"request {request}: {COLUMNS[k]} {p}" for k, (_, p) in times.items() if p),
                *((f"request {request}: disposition {get('disposition')!r} is neither issued (20) nor revoked (21)",)
                  if disposition not in DISPOSITIONS else ()),
                *((f"request {request}: SHA256 {get('sha256')!r} isn't a SHA-256 hash",)
                  if get("sha256") not in (None, "") and not _sha256(get("sha256")) else ()))
    reason = _int(get("reason"))
    facts = {"ciamSerialNumber": str(get("serial")) if get("serial") not in (None, "") else None,
             "ciamFingerprint": _sha256(get("sha256")), "ciamSubject": get("subject") or None,
             "ciamNotBefore": times["not_before"][0], "ciamNotAfter": times["not_after"][0],
             "ciamTemplateName": template, "ciamRequester": get("requester") or None,
             "ciamRevokedAt": (times["revoked_effective"][0] or times["revoked_when"][0]) if revoked else None,
             "ciamRevocationReason": (revocation_reason(reason) if reason is not None else "unrecorded")
             if revoked else None}
    return request, (facts if disposition in DISPOSITIONS else None), problems


def _doc(text):
    try:
        doc = json.loads(text.lstrip("\ufeff"))        # Windows PowerShell 5.1 writes UTF-8 with a BOM
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _record_templates(d):
    """The record's templates in templates.py's shape, for resolving a CA's template values without templates.ldif."""
    return {rdn_value(t): {"display": one(t, "description"), "oid": one(t, "ciamTemplateOid"), "days": None,
                           "usages": values(t, "ciamExtendedKeyUsage")}
            for t in children(d, TEMPLATES, TEMPLATE_CLASS)}


def _ca_templates(listed, resolve):
    """The template names a CA issues from: each value it lists resolved to a template's name (its names and OIDs
    alike), else kept as it is."""
    return tuple(dict.fromkeys(resolve(v) or str(v) for v in listed if str(v).strip()))


def read_ca(d, path, doc, resolve, at):
    """((authority group, inventory group), notices) of one CA's export, or ((), notices) when it can't be read."""
    name = doc.get("caName")
    if doc.get("format") != FORMAT or doc.get("version") != VERSION:
        return (), (f"{path}: not a {FORMAT} version {VERSION} export: left out",)
    if not isinstance(name, str) or not rdn_safe(name):
        return (), (f"{path}: CA name {name!r} can't be named in the record: left out",)
    when, problem = _time(doc.get("exportedAt"))
    when = when or (gtime(at) if at is not None else None)
    if when is None:
        return (), (f"{path}: no exportedAt time ({problem or 'missing'}) and no --at: left out",)
    ca = {"dns": doc.get("dnsName"), "netbios": doc.get("netbiosName"), "name": name}
    crl, crl_notices = endpoints(doc.get("crlPublicationUrls") or (), CRL_KINDS, ca)
    aia, aia_notices = endpoints(doc.get("caCertPublicationUrls") or (), CA_CERT_KINDS, ca)
    numbered = tuple((kind, sum(1 for k, _, _ in (*crl, *aia)[:i + 1] if k == kind), url, template)
                     for i, (kind, url, template) in enumerate((*crl, *aia)))
    authority = inventory_group(authority_entry(d, name, doc.get("config"),
                                                _ca_templates(doc.get("templates") or (), resolve)),
                                tuple(endpoint_entry(d, name, kind, n, url, template)
                                      for kind, n, url, template in numbered))
    rows = [r for r in doc.get("rows") or () if isinstance(r, dict)]
    read = tuple(row_facts(r, resolve) for r in rows)
    error = doc.get("error")
    problems = (*((str(error),) if error else ()),
                *(("the exporter didn't read every row",) if not error and doc.get("complete") is not True else ()),
                *(p for _, _, ps in read for p in ps),
                *((f"{sum(1 for r, _, _ in read if r is None)} row(s) without a request id",)
                  if any(r is None for r, _, _ in read) else ()))
    state = "denied" if error else "incomplete" if problems else "complete"
    issued = tuple({request: issued_entry(d, name, request, facts) for request, facts, _ in read
                    if request is not None and not error and facts is not None}.values())
    stray = sorted({k for r in rows for k in r if k not in COLUMNS.values()})
    keys = [k for k in stray if KEY_COLUMNS.search(k)]
    notices = (*crl_notices, *aia_notices,
               *((f"{path}: key column(s) {', '.join(keys)}: never read (metadata only)",) if keys else ()),
               *((f"{path}: column(s) {', '.join(k for k in stray if k not in keys)} not read",)
                 if len(stray) > len(keys) else ()),
               f"{name}: {len(issued)} certificate(s), {len(numbered)} endpoint(s), {state}"
               + (f" ({'; '.join(problems)})" if problems else ""))
    return (authority, inventory_group(cert_inventory_entry(d, name, when, state, problems, doc.get("config")),
                                       issued)), notices


def read_inventory(files, d, patterns, at=None):
    """Imported: the forest's templates (from templates.ldif, replacing ou=certificate-templates) and, per CA
    export, its authority with its endpoints and its issued-certificate inventory, each replacing the record's."""
    templates, template_notices = read_templates(files[TEMPLATES_FILE]) if TEMPLATES_FILE in files else ({}, ())
    resolve = resolver(templates or _record_templates(d))
    exports = sorted(p for p in files if p.startswith(CA_ROOT) and p.endswith(".json"))
    docs = tuple((p, _doc(files[p])) for p in exports)
    read = tuple((p, read_ca(d, p, doc, resolve, at)) for p, doc in docs if doc is not None)
    template_group = (templates_group(d, tuple(template_entry(d, n, t["display"], t["oid"], t["days"], t["usages"])
                                               for n, t in templates.items())),) if TEMPLATES_FILE in files else ()
    return Imported(containers=(ou_entry(AUTHORITIES), ou_entry(ISSUED), ou_entry(TEMPLATES)),
                    groups=(*template_group, *(g for _, (groups, _) in read for g in groups)),
                    notices=(*template_notices,
                             *((f"templates: {len(templates)} template(s)",) if TEMPLATES_FILE in files else ()),
                             *(f"{p} isn't a JSON object: left out" for p, doc in docs if doc is None),
                             *(n for _, (_, notices) in read for n in notices),
                             *(("no CA exports (ca/<name>.json, scripts/Export-AdcsInventory.ps1)",)
                               if not exports else ())))


INVENTORY_IMPORTER = Importer("inventory", "AD CS CAs' issued certificates, revocation endpoints and templates, "
                                           "metadata only (ca/<name>.json from scripts/Export-AdcsInventory.ps1, "
                                           "templates.ldif)", read_inventory)
