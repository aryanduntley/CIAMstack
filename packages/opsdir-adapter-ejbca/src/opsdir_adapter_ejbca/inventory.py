"""EJBCA inventory (the importer `ejbca/inventory`): each CA an EJBCA instance runs, its revocation endpoints, its
certificate profiles as CA-scoped templates and the certificates it issued, read into the core pki domain's records
(domains.pki.issued), metadata only. Pure.

The export holds, per collection source (one EJBCA instance), the REST API's answers as `opsdir collect` saves them
(collect.py), or as an operator saves them with the same calls:
  ejbca/<source>/cas.json                                  GET /v1/ca
  ejbca/<source>/certificates/<CA id>/page-<n>.json        POST /v2/certificate/search, CA EQUAL <name>, page n of
                                                           PAGE_SIZE, sorted by issue date
  ejbca/<source>/profiles/<name, percent-encoded>.json     GET /v2/certificate/profile/<name>
  ejbca/<source>/count.json                                optional: GET /v2/certificate/count
A CA is named after its subject's common name (as an AD CS or Vault CA is), else its EJBCA name; ciamProviderRef is
its EJBCA name. An external CA (one EJBCA knows but doesn't run) isn't inventoried. A certificate (cn: its serial as
EJBCA gives it, upper-case hex) is read from its certificate (base64Cert, through opsdir-adapter-x509's
certificate_facts): serial, SHA-256, subject, validity; one whose profile doesn't store certificate data has EJBCA's
columns only (no SHA-256). Unlike Vault, EJBCA records the certificate profile each was issued from (its template,
'<CA>/<profile>') and the end entity it was issued to (ciamRequester: the username), and its revocation reason.

EJBCA's REST API doesn't give a CA's own CRL, OCSP or CA issuer URLs (they are CA settings; ConfigDump, which has
them, is Enterprise-only): the CA's revocation endpoints are those its most recently issued active certificate (its
own aside: a root's names nothing of itself; a sub-CA's certificate is its root's) names, what it is known to publish;
without one, the record's are kept. Its templates are the certificate
profiles its certificates name that still offer it (profiles.py); a profile nothing was issued from isn't listed
(Community's REST API lists no profiles).

A search the reader may not see answers with no certificates rather than refusing: a root CA always holds its own
certificate, so an empty root inventory is denied (the role lacks /ca_functionality/view_certificate/). The inventory
is incomplete when a page wasn't saved or isn't an answer, when the pages don't hold the total the search counted
(certificates issued or revoked while they were read: collect again) or when EJBCA counts more certificates than the
reader saw (count.json, when the role may read it: certificates of end entity profiles the role may not view are
left out of every search, silently)."""
import base64
import datetime as dt
import math
import textwrap
from functools import reduce
from urllib.parse import quote

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import get as get_entry, gtime, ou_entry, rdn_value
from opsdir.core.naming import rdn_safe
from opsdir.core.sources import json_document
from opsdir.domains.pki.inventory import inventory_group
from opsdir.domains.pki.issued import (authority_entry, ca_templates_groups, cert_inventory_entry, common_name,
                                       endpoint_entry, endpoints, issued_entry, revocation_reason)
from opsdir.domains.pki.naming import AUTHORITIES, ISSUED, TEMPLATES, authority_dn, template_dn
from opsdir_adapter_x509.certificates import certificate_facts
from opsdir_adapter_x509.verify import serial_hex
from .profiles import RIGHTS_UNREAD, profile_template

ROOT, CAS, COUNT = "ejbca/", "cas.json", "count.json"
PAGE_SIZE = 500                         # EJBCA's default Max Query Count: the most one search page holds
ACTIVE, REVOKED = (20, 21), (40, 60)    # EJBCA certificate statuses: active (21: expiry notice sent); revoked, archived
KINDS = ("crl", "delta-crl", "ocsp", "ca-issuers")      # the record's revocation endpoint kinds, in numbering order
DENIED = ("the search found none of its certificates, not even its own: the reader's role lacks "
          "/ca_functionality/view_certificate/ (EJBCA then answers every search with none)")


def page_path(source, ca_id, n):
    """The export path of a CA's n-th search page for a source."""
    return f"{ROOT}{source}/certificates/{ca_id}/page-{n}.json"


def profile_path(source, name):
    """The export path of a certificate profile's answer for a source."""
    return f"{ROOT}{source}/profiles/{quote(name, safe='')}.json"


def listed_cas(text):
    """The CAs a GET /v1/ca answer lists, or None when the text isn't one."""
    doc = json_document(text or "", dict)
    cas = doc.get("certificate_authorities") if doc is not None else None
    return tuple(c for c in cas if isinstance(c, dict) and c.get("name") and c.get("id") is not None) \
        if isinstance(cas, list) else None


def search_page(text):
    """(certificates, total_certs or None, problem or None) of a saved search page."""
    doc = json_document(text or "", dict)
    if doc is None:
        return (), None, "isn't a search answer"
    if "error_code" in doc:
        return (), None, f"EJBCA answered {doc.get('error_code')}: {doc.get('error_message')}"
    certs = doc.get("certificates")
    if not isinstance(certs, list):
        return (), None, "holds no certificates list"
    total = (doc.get("pagination_summary") or {}).get("total_certs")
    return (tuple(c for c in certs if isinstance(c, dict)),
            total if isinstance(total, int) and not isinstance(total, bool) else None, None)


def profile_names(certs):
    """The certificate profiles certificates name, in first-seen order."""
    return tuple(dict.fromkeys(str(c["certificateProfile"]) for c in certs if c.get("certificateProfile")))


def certificate_pem(b64):
    """The PEM of a base64Cert: base64 of the PEM body (EJBCA 9.6) or of the DER; None when there is none."""
    try:
        raw = base64.b64decode(b64 or "", validate=False)
    except ValueError:
        return None
    if raw[:3] == b"MII":
        body = "".join(raw.decode("ascii", errors="replace").split())
    elif raw[:1] == b"\x30":
        body = base64.b64encode(raw).decode()
    else:
        return None
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(body, 64)) + "\n-----END CERTIFICATE-----\n"


def _ms(v):
    """GeneralizedTime of EJBCA's milliseconds since 1970, or None (-1: none)."""
    ok = isinstance(v, int) and not isinstance(v, bool) and v > 0
    return gtime(dt.datetime.fromtimestamp(v / 1000, dt.timezone.utc)) if ok else None


def _serial(v):
    try:
        return serial_hex(int(str(v), 16))
    except ValueError:
        return None


def issued_facts(cert, ca):
    """(the issued-certificate facts of a search result, its certificate's x509 facts or None)."""
    x = certificate_facts(certificate_pem(cert.get("base64Cert")))
    status, reason, profile = cert.get("status"), cert.get("revocationReason"), cert.get("certificateProfile")
    revoked_at = _ms(cert.get("revocationDate"))
    revoked = status in REVOKED or revoked_at is not None
    code = reason if isinstance(reason, int) and not isinstance(reason, bool) and reason >= 0 else 0
    return ({"ciamSerialNumber": x["serial"] if x else _serial(cert.get("serialNumber")),
             "ciamFingerprint": x["sha256"] if x else None,
             "ciamSubject": x["subject"] if x else cert.get("subjectDN"),
             "ciamNotBefore": x["not_before"] if x else _ms(cert.get("notBefore")),
             "ciamNotAfter": x["not_after"] if x else _ms(cert.get("expireDate")),
             "ciamTemplateName": f"{ca}/{profile}" if profile else None,
             "ciamRequester": cert.get("username") or None,
             "ciamRevokedAt": revoked_at if revoked else None,
             "ciamRevocationReason": revocation_reason(code) if revoked else None}, x)


def _ca_name(listed):
    """The record's name of a CA as GET /v1/ca lists it: its subject's CN, else its EJBCA name; None if neither can
    be an RDN."""
    cn, name = common_name(listed.get("subject_dn")), str(listed["name"])
    return cn if cn and rdn_safe(cn) else name if rdn_safe(name) else None


def _search(files, source, listed):
    """(the distinct certificates a CA's saved pages hold, problems, whether its search found none) of one CA."""
    first = files.get(page_path(source, listed["id"], 1))
    total = search_page(first)[1] if first is not None else None
    pages = tuple((n, files.get(page_path(source, listed["id"], n)))
                  for n in range(1, max(1, math.ceil((total or 0) / PAGE_SIZE)) + 1))
    read = tuple((n, *(search_page(t) if t is not None else ((), None, "wasn't saved"))) for n, t in pages)
    certs = tuple({str(c.get("serialNumber")): c for _, cs, _, _ in read for c in cs}.values())
    failed = tuple(f"search page {n} {p}" for n, _, _, p in read if p)
    changed = sorted({t for _, _, t, _ in read if t is not None and t != total})
    problems = (*failed,
                *((f"the search counted {total} certificate(s), then {', '.join(map(str, changed))}, while its pages "
                   "were read: collect again",) if changed else ()),
                *((f"its pages hold {len(certs)} distinct certificate(s) of the {total} the search counted: "
                   "collect again",) if not failed and not changed and total is not None and len(certs) != total
                  else ()),
                *(("its search found certificates but gave no total",) if certs and total is None else ()))
    return certs, problems, first is not None and not failed and not certs


def _endpoints(d, ca, own, facts, when):
    """(revocation endpoint entries, notice) of a CA: those its most recently issued active certificate names (own:
    the CA's own subject, whose certificate is left aside), else the record's kept."""
    named = tuple((c, x) for c, _, x in facts if x and x["endpoints"] and c.get("status") in ACTIVE
                  and c.get("subjectDN") != own and x["not_after"] > when)
    if not named:
        held = get_entry(d, authority_dn(ca))
        kept = endpoints(d, held) if held is not None else ()
        return kept, (f"{ca}: no active certificate names its revocation endpoints (EJBCA's REST API doesn't give "
                      f"the CA's own): the record's {len(kept)} kept")
    cert, x = max(named, key=lambda p: (p[1]["not_before"], p[1]["serial"]))
    found = tuple((kind, n, url) for kind in KINDS
                  for n, url in enumerate((u for k, u in x["endpoints"] if k == kind), 1))
    return (tuple(endpoint_entry(d, ca, kind, n, url) for kind, n, url in found),
            f"{ca}: revocation endpoints as certificate {cert.get('serialNumber')} names them (EJBCA's REST API "
            "doesn't give the CA's own)")


def _template(d, ca, ejbca, source, files, certs, name):
    """(template entry or None, notices) of one certificate profile a CA's certificates name; one whose answer wasn't
    saved keeps the record's template."""
    doc = json_document(files.get(profile_path(source, name)) or "", dict)
    if doc is None or "error_code" in doc:
        return (get_entry(d, template_dn(f"{ca}/{name}")),
                (f"{ca}/{name}: certificate profile {name} wasn't read: the record's template kept",))
    through = tuple(dict.fromkeys(str(c["endEntityProfile"]) for c in certs
                                  if c.get("certificateProfile") == name and c.get("endEntityProfile")))
    return profile_template(d, ca, ejbca, name, doc, through)


def _templates(d, ca, ejbca, source, files, certs):
    """(the CA's template entries, notices): each certificate profile its certificates name that still offers it."""
    made = tuple(_template(d, ca, ejbca, source, files, certs, n) for n in profile_names(certs))
    return tuple(t for t, _ in made if t is not None), tuple(n for _, ns in made for n in ns)


def read_ca(d, source, listed, files, when, extra=()):
    """(Imported groups, notices) of one CA a source lists: its authority and endpoints, its inventory and its
    templates; extra: problems every CA of the source shares (EJBCA counting more than the reader saw)."""
    ca, ejbca = _ca_name(listed), str(listed["name"])
    certs, problems, empty = _search(files, source, listed)
    denied = empty and listed.get("subject_dn") == listed.get("issuer_dn")
    problems = (*problems, *extra)
    facts = tuple((c, *issued_facts(c, ca)) for c in certs)
    named = tuple((c, f, x) for c, f, x in facts if rdn_safe(str(c.get("serialNumber") or "")))
    issued = tuple(issued_entry(d, ca, str(c["serialNumber"]), f) for c, f, _ in named)
    found, where = _endpoints(d, ca, listed.get("subject_dn"), named, when)
    templates, template_notices = _templates(d, ca, ejbca, source, files, certs)
    state = "denied" if denied else "incomplete" if problems else "complete"
    problems = (DENIED, *problems) if denied else problems
    bare = sum(1 for _, _, x in named if x is None)
    notices = (where, *template_notices,
               *((f"{ca}: {len(certs) - len(named)} serial(s) can't be named in the record",)
                 if len(named) < len(certs) else ()),
               *((f"{ca}: {bare} certificate(s) without their certificate data (the profile doesn't store it): "
                  "EJBCA's columns only, no SHA-256",) if bare else ()),
               f"{ca} ({source}: {ejbca}): {len(issued)} certificate(s), {len(found)} endpoint(s), "
               f"{len(templates)} template(s), {state}" + (f" ({'; '.join(problems)})" if problems else ""))
    authority = inventory_group(authority_entry(d, name=ca, provider_ref=ejbca,
                                                templates=tuple(rdn_value(t) for t in templates)), found)
    inventory = inventory_group(cert_inventory_entry(d, ca, when, state, problems, provider_ref=ejbca), issued)
    return (authority, inventory, *ca_templates_groups(d, ca, templates)), notices


def _sources(files):
    found = {p[len(ROOT):-len(CAS) - 1] for p in files if p.startswith(ROOT) and p.endswith("/" + CAS)}
    return tuple(sorted(s for s in found if s and "/" not in s))


def _count_problem(files, source, cas):
    """The problem every CA of a source shares when EJBCA counts more certificates than the reader saw, or None."""
    doc = json_document(files.get(f"{ROOT}{source}/{COUNT}") or "", dict)
    count = doc.get("count") if doc is not None else None
    if not isinstance(count, int) or isinstance(count, bool):
        return None
    seen = sum(len(_search(files, source, c)[0]) for c in cas)
    return (f"EJBCA counts {count} certificate(s), the reader saw {seen} across the CAs it may read: certificates "
            "of CAs or end entity profiles its role may not view are left out") if seen < count else None


def _claim(acc, listed):
    """Fold step: (CAs with their record names and whether they are read, names taken): a CA named like one already
    read (another source's) isn't."""
    marked, taken = acc
    name = _ca_name(listed)
    ok = name is not None and name.lower() not in taken
    return (*marked, (listed, name, ok)), (taken | {name.lower()} if ok else taken)


def _read_source(d, source, files, when, taken):
    """(groups, notices, CA names taken) of one source."""
    cas = listed_cas(files.get(f"{ROOT}{source}/{CAS}"))
    if cas is None:
        return (), (f"{source}: cas.json isn't a GET /v1/ca answer",), taken
    run = tuple(c for c in cas if not c.get("external"))
    problem = _count_problem(files, source, run)
    marked, taken = reduce(_claim, run, ((), taken))
    read = tuple(read_ca(d, source, c, files, when, (problem,) if problem else ()) for c, _, ok in marked if ok)
    return (tuple(g for groups, _ in read for g in groups),
            (*(f"{source}: {c['name']} is an external CA (EJBCA doesn't issue from it): not inventoried"
               for c in cas if c.get("external")),
             *((f"{source}: the reader may not count EJBCA's certificates (count.json): that it sees every end "
                "entity profile's is the role's promise (README)",) if f"{ROOT}{source}/{COUNT}" not in files else ()),
             *(f"{source}: CA {c['name']} " + ("can't be named in the record" if name is None else
                                               f"is named {name} like another CA read: left out")
               for c, name, ok in marked if not ok),
             *(n for _, notices in read for n in notices)), taken)


def read_inventory(files, d, patterns, at=None):
    """Imported: per source in the export and per CA it lists, the CA with its revocation endpoints, its
    issued-certificate inventory and its certificate profiles as its own templates, each replacing the record's."""
    if at is None:
        return Imported((), (), ("an inventory is dated: give --at (when EJBCA was read)",))
    when = gtime(at)
    step = lambda acc, s: (lambda r: ((*acc[0], *r[0]), (*acc[1], *r[1]), r[2]))(      # noqa: E731
        _read_source(d, s, files, when, acc[2]))
    groups, notices, _ = reduce(step, _sources(files), ((), (), frozenset()))
    return Imported(containers=(ou_entry(AUTHORITIES), ou_entry(ISSUED), ou_entry(TEMPLATES)), groups=groups,
                    notices=(*notices, *((RIGHTS_UNREAD,) if groups else
                                         ("no EJBCA sources (ejbca/<source>/cas.json, as `opsdir collect` saves "
                                          "them)",))))


INVENTORY_IMPORTER = Importer("inventory", "EJBCA's CAs, revocation endpoints, certificate profiles and the "
                                           "certificates they issued, metadata only (the REST API's answers as "
                                           "`opsdir collect` saves them)", read_inventory)
