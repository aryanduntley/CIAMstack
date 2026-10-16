"""BMC Helix ITSM / Remedy collector (`opsdir collect`, core.contract Collector): the answers bmc-helix/change-requests
reads, from the AR System REST API, read-only (GETs only; never an entry written, never an approval answered). Pure:
the core makes the requests.

Where to read is an environment's collection source for bmc-helix/change-requests (ciamCollectionSource: the REST
server's base URL, Helix's https://<customer>-restapi.onbmc.com or an on-premises server's https://<host>:8008; the
first usable source), with the credential its ciamCredentialRole binding references (resolved when collecting, never
stored) and the CA certificate its ciamCaRole binding references as the trust anchor. The credential is a token
obtained outside opsdir: token, the JWT AR System's logon returns (POST /api/jwt/login), sent as "Authorization:
AR-JWT <jwt>"; or bearer, a BMC Helix SSO OAuth access token (documented for on-premises servers). opsdir never logs
on itself: a logon is a POST, and collection makes only GETs.

Calls, in rounds: each change the record's change records name (bmc-helix:<CRQ>), one qualified read each (GET
/api/arsys/v1/entry/CHG:Infrastructure Change?q='Infrastructure Change ID'="<CRQ>" with the fields the importer reads
and a limit of 2, so a duplicate is seen; no entry is a change not read); then, for each change read, its approval
signatures (GET /api/arsys/v1/entry/AP:Detail-Signature?q=('Request'="<its Request ID>" OR 'Request'="<CRQ>")), PAGE
at a time, the page after each that links a next one. Each answer is saved with only the requested values and the
links the importer reads."""
import json
from urllib.parse import quote, urlsplit

from opsdir.core.contract import Collector, Request
from opsdir.core.sources import json_document
from opsdir.domains.governance.collection import readable_source, scheme_problems
from opsdir.domains.governance.tickets import linked_numbers
from .changes import (APPROVAL_FIELDS, APPROVAL_FORM, CHANGE_FIELDS, CHANGE_FORM, NUMBER, NUMBER_TEXT, REQUEST_ID,
                      SYSTEM, answer_entries, ar_error, has_next)

IMPORTER = "bmc-helix/change-requests"
SCHEMES = ("token", "bearer")
TAKES = ("the server is read with token (the JWT AR System's logon, POST /api/jwt/login, returns: sent as AR-JWT) or "
         "bearer (a BMC Helix SSO OAuth access token), obtained outside opsdir")
PAGE = 100                         # signatures per page (a change has a few per approval phase)
HEADERS = (("Accept", "application/json"),)


def credential(s):
    """The Request credential of a collection source: a JWT after AR System's own prefix, or a bearer token."""
    return ("api-key", s.credential, None, "Authorization", "AR-JWT ") if s.scheme == "token" else \
        ("bearer", s.credential, None)


def entry_url(base, form, qualification, fields, limit, offset=0):
    """The URL of a qualified entry read of a form (GET /api/arsys/v1/entry/<form>), its fields' values only."""
    return (f"{base}/api/arsys/v1/entry/{quote(form, safe='')}?q={quote(qualification, safe='')}"
            f"&fields=values({','.join(quote(f, safe='') for f in fields)})&limit={limit}&offset={offset}")


def entries_view(fields):
    """What `opsdir collect` keeps of an entry answer: each entry's requested values and self link, and the answer's
    next link; text that isn't JSON, or an error answer, kept as it is (the importer names it)."""
    def keep(text):
        doc = json_document(text)
        if doc is None or ar_error(doc) or not isinstance(doc, dict):
            return text
        links = doc.get("_links") if isinstance(doc.get("_links"), dict) else {}
        return json.dumps({"entries": [{"values": {k: e["values"][k] for k in fields if k in e["values"]},
                                        **({"_links": {"self": e["_links"]["self"]}}
                                           if isinstance(e.get("_links"), dict) and "self" in e["_links"] else {})}
                                       for e in answer_entries(doc)],
                           **({"_links": {"next": links["next"]}} if links.get("next") else {})},
                          indent=1, sort_keys=True)
    return keep


def _request_id(text):
    """The Request ID of a change answer holding exactly one entry, or None."""
    entries = answer_entries(json_document(text)) if text else ()
    rid = str(entries[0]["values"].get(REQUEST_ID) or "") if len(entries) == 1 else ""
    return rid if NUMBER_TEXT.fullmatch(rid) else None


def _offsets(host, number, done):
    """The approval page offsets to have: each after a page that holds signatures and links a next one."""
    offsets = [0]
    while f"{host}/approval/{number}/{offsets[-1]}.json" in done:
        doc = json_document(done[f"{host}/approval/{number}/{offsets[-1]}.json"])
        rows = answer_entries(doc)
        if not rows or not has_next(doc):
            break
        offsets.append(offsets[-1] + len(rows))
    return tuple(offsets)


def change_steps(d, m, done, options):
    """Each linked change's entry; for each change read, its approval signature pages."""
    s = readable_source(m, IMPORTER, SCHEMES)
    if s is None:
        return ()
    base, cred = s.locations[0].rstrip("/"), credential(s)
    host = urlsplit(base).hostname or "server"
    numbers = tuple(n for n in linked_numbers(d, SYSTEM) if NUMBER_TEXT.fullmatch(n))
    changes = tuple((f"{host}/change/{n}.json",
                     Request(entry_url(base, CHANGE_FORM, f"'{NUMBER}' = \"{n}\"", CHANGE_FIELDS, 2), HEADERS, cred,
                             s.ca, keep=entries_view(CHANGE_FIELDS)))
                    for n in numbers)
    ids = {n: _request_id(done.get(f"{host}/change/{n}.json")) for n in numbers}
    approvals = tuple((f"{host}/approval/{n}/{offset}.json",
                       Request(entry_url(base, APPROVAL_FORM, f"('Request' = \"{ids[n]}\" OR 'Request' = \"{n}\")",
                                         APPROVAL_FIELDS, PAGE, offset), HEADERS, cred, s.ca,
                               keep=entries_view(APPROVAL_FIELDS)))
                      for n in numbers if ids[n] for offset in _offsets(host, n, done))
    return (*changes, *approvals)


def source_problems(d, m, options):
    """Why the collection sources can't be read (an unbound credential or trust anchor, no location, a credential
    scheme the server isn't read with here)."""
    return scheme_problems(m, IMPORTER, SCHEMES, TAKES)


COLLECTORS = (Collector("change-requests", "environment", change_steps, problems=source_problems),)
