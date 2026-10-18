"""ServiceNow collector (`opsdir collect`, core.contract Collector): the answers servicenow/change-requests reads, from
the instance's Table API, read-only (GETs only; never the Change Management API's writes, never a correlation field).
Pure: the core makes the requests.

Where to read is an environment's collection source for servicenow/change-requests (ciamCollectionSource: the
instance's base URL, https://<instance host>; the first usable source), with the credential its ciamCredentialRole
binding references (resolved when collecting, never stored) and the CA certificate its ciamCaRole binding references
as the trust anchor. The credential is sent as basic (a user's password, with ciamLoginName), bearer (an OAuth access
token minted outside opsdir, client credentials: opsdir never asks for one) or presented as a client certificate
(client-certificate: a PEM with the certificate, its chain and private key, loaded in memory only; the instance maps it
to the reading user: certificate-based authentication, README).

The tickets read are those the record's change records name (servicenow:<number>, in every environment), CHUNK
numbers per query: GET /api/now/table/change_request?sysparm_query=numberIN<numbers>^ORDERBYsys_id with the fields the
importer reads, raw and display values (sysparm_display_value=all), PAGE records a page, and the page after each
until one comes back empty (a short page doesn't end it: the API applies its limit before the reader's access rules).
Then the approval records of the changes found, the same way: sysapproval_approver?sysparm_query=sysapprovalIN
<sys_ids>^ORDERBYsys_id. When the operator names the work-ticket table (servicenow-ticket-table), the same numbers are
read from it too, with the fields a work ticket is read for (WORK_FIELDS): a linked number is a change or a work ticket,
and only the instance knows which. Each page is saved as <host>/<table>/<chunk>-<offset>.json with only the requested
fields of each record (answer_fields). The reader needs read access to those tables and fields only (README)."""
import json
from urllib.parse import quote, urlsplit

from opsdir.core.contract import Collector, Request
from opsdir.domains.governance.collection import readable_source, scheme_problems
from opsdir.domains.governance.tickets import linked_numbers
from .changes import (APPROVER_FIELDS, APPROVER_TABLE, CHANGE_FIELDS, CHANGE_TABLE, SYSTEM, WORK_FIELDS, answer_rows,
                      work_table)

IMPORTER = "servicenow/change-requests"
SCHEMES = ("basic", "bearer", "client-certificate")   # a user's password; an OAuth client-credentials access token
# minted outside opsdir; a client certificate the instance maps to a user (certificate-based authentication: mutual TLS)
TAKES = ("the instance is read with a user's password (basic), an OAuth access token (bearer) or a client certificate "
         "it maps to a user (client-certificate)")
CHUNK = 50                         # tickets per query (the URL stays short)
PAGE = 100                         # records per page: more than a chunk's tickets, so a chunk's second page is empty


def answer_fields(fields):
    """What `opsdir collect` keeps of a Table API answer: each record's requested fields only (text that isn't an
    answer kept as it is: the importer names it)."""
    def keep(text):
        try:
            doc = json.loads(text)
        except ValueError:
            return text
        if not isinstance(doc, dict) or not isinstance(doc.get("result"), list):
            return text
        rows = [{k: r[k] for k in fields if k in r} for r in doc["result"] if isinstance(r, dict)]
        return json.dumps({"result": rows}, indent=1, sort_keys=True)
    return keep


def page_path(host, table, chunk, offset):
    return f"{host}/{table}/{chunk}-{offset}.json"


def _request(s, table, query, fields, offset):
    params = (f"sysparm_query={quote(query)}&sysparm_fields={','.join(fields)}&sysparm_display_value=all"
              f"&sysparm_exclude_reference_link=true&sysparm_limit={PAGE}&sysparm_offset={offset}")
    return Request(f"{s.locations[0].rstrip('/')}/api/now/table/{table}?{params}", (),
                   (s.scheme, s.credential, s.login), s.ca, keep=answer_fields(fields))


def _chunks(items):
    return tuple(items[i:i + CHUNK] for i in range(0, len(items), CHUNK))


def _paged(host, table, chunk, done):
    """(offsets to have, rows read so far, finished) of one chunk's pages: each page after a non-empty one."""
    offsets, rows = [0], []
    while page_path(host, table, chunk, offsets[-1]) in done:
        found, _ = answer_rows(done[page_path(host, table, chunk, offsets[-1])])
        if not found:
            return tuple(offsets), tuple(rows), True
        rows.extend(found)
        offsets.append(offsets[-1] + PAGE)
    return tuple(offsets), tuple(rows), False


def _value(v):
    return str(v.get("value") or "") if isinstance(v, dict) else str(v or "")


def change_steps(d, m, done, options):
    """Each chunk of linked tickets' pages, from change_request and the work-ticket table when one is named; once every
    change_request chunk is read to an empty page, the approval records of the changes found, paged the same way."""
    s = readable_source(m, IMPORTER, SCHEMES)
    if s is None:
        return ()
    host = urlsplit(s.locations[0]).hostname or "instance"
    numbers = _chunks(linked_numbers(d, SYSTEM))
    work = work_table(d)[0]
    fields = {CHANGE_TABLE: CHANGE_FIELDS, **({work: WORK_FIELDS} if work else {})}
    reads = {t: [(i, *_paged(host, t, i, done)) for i in range(len(numbers))] for t in fields}
    steps = [(page_path(host, t, i, o), _request(s, t, f"numberIN{','.join(numbers[i])}^ORDERBYsys_id", fields[t], o))
             for t in fields for i, offsets, _, _ in reads[t] for o in offsets]
    if not all(finished for *_, finished in reads[CHANGE_TABLE]):
        return tuple(steps)
    ids = _chunks(tuple(dict.fromkeys(_value(r.get("sys_id")) for _, _, rows, _ in reads[CHANGE_TABLE] for r in rows
                                      if _value(r.get("sys_id")))))
    return (*steps, *((page_path(host, APPROVER_TABLE, i, o), _request(s, APPROVER_TABLE, f"sysapprovalIN"
                                                                      f"{','.join(ids[i])}^ORDERBYsys_id",
                                                                      APPROVER_FIELDS, o))
                      for i in range(len(ids)) for o in _paged(host, APPROVER_TABLE, i, done)[0]))


def source_problems(d, m, options):
    """Why the collection sources can't be read (an unbound credential or trust anchor, no location, a credential
    scheme the Table API isn't read with here)."""
    return scheme_problems(m, IMPORTER, SCHEMES, TAKES)


COLLECTORS = (Collector("change-requests", "environment", change_steps, problems=source_problems),)
