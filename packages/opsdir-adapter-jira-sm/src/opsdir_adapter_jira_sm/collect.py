"""Jira Service Management collector (`opsdir collect`, core.contract Collector): the answers jira-sm/change-requests
reads, from the site's REST APIs, read-only (GETs only; never an approval's answer, never a comment or a field
written). Pure: the core makes the requests.

Where to read is an environment's collection source for jira-sm/change-requests (ciamCollectionSource: the site's
base URL; the first usable source), with the credential its ciamCredentialRole binding references (resolved when
collecting, never stored) and the CA certificate its ciamCaRole binding references as the trust anchor. A Cloud site
(https://<site>.atlassian.net, a Government Cloud site https://<site>.atlassian-us-gov-mod.net, or the API gateway
https://api.atlassian.com/ex/jira/<cloudId> that scoped tokens and OAuth use) is read with REST v3, anything else as
Data Center with REST v2. The credential is sent as basic (Cloud: the account's email as ciamLoginName and an API
token; Data Center: a user's password) or bearer (a Data Center personal access token, or a Cloud OAuth 2.0 or scoped
token minted outside opsdir).

Calls, in rounds: the site's field list (GET /rest/api/{3|2}/field: the mapping's field names resolve through it);
then each issue the record's change records name (jira-sm:<KEY>), one GET each (GET /rest/api/{3|2}/issue/<KEY>
with the system fields and the mapped ones: one per linked ticket avoids search's lag and Data Center refusing a whole
query for one key it doesn't have; a 404 is a ticket not read, never a failure); then each issue's approval steps (GET
/rest/servicedeskapi/request/<KEY>/approval), page after page until one says it is the last (a 404, an issue that
isn't a request, has none). Each answer is saved with only what the importer reads (people as their ids: never a
display name or an email address)."""
import json
from urllib.parse import quote, urlsplit

from opsdir.core.contract import Collector, Request
from opsdir.core.sources import json_document
from opsdir.domains.governance.collection import readable_source, scheme_problems
from opsdir.domains.governance.tickets import linked_numbers
from .changes import ISSUE_FIELDS, KEY, SYSTEM, field_list, jira_error
from .mapping import field_refs, resolve_fields

IMPORTER = "jira-sm/change-requests"
SCHEMES = ("basic", "bearer")
TAKES = ("the site is read with basic (an account's email and API token, or a Data Center user's password) or "
         "bearer (a Data Center personal access token, or an OAuth or scoped token minted outside opsdir)")
PAGE = 50                          # approval steps per page (a request has a few)
HEADERS = (("Accept", "application/json"),)
CLOUD_SITES = (".atlassian.net", ".atlassian-us-gov-mod.net")
SLIM = ("id", "key", "name", "value", "accountId", "statusCategory")     # what a field's object keeps


def is_cloud(url):
    """Whether a base URL is a Jira Cloud site (REST v3) rather than Data Center (REST v2)."""
    u = urlsplit(url)
    return (u.hostname or "").lower().endswith(CLOUD_SITES) or "/ex/jira/" in u.path


def projected(project):
    """What `opsdir collect` keeps of a JSON answer: project(answer); text that isn't JSON, or an error answer, kept as
    it is (the importer names it)."""
    def keep(text):
        doc = json_document(text)
        return text if doc is None or jira_error(doc) else json.dumps(project(doc), indent=1, sort_keys=True)
    return keep


def _slim(v):
    if isinstance(v, list):
        return [_slim(x) for x in v]
    if isinstance(v, dict):
        return {k: _slim(v[k]) for k in SLIM if k in v}
    return v


def issue_view(fields):
    """An issue answer reduced to its id, key, self and the requested fields (their objects to ids, names, values)."""
    def view(doc):
        if not isinstance(doc, dict) or not isinstance(doc.get("fields"), dict):
            return doc
        return {**{k: doc[k] for k in ("id", "key", "self") if k in doc},
                "fields": {k: _slim(doc["fields"][k]) for k in fields if k in doc["fields"]}}
    return view


def _date(v):
    return {"iso8601": v["iso8601"]} if isinstance(v, dict) and "iso8601" in v else v


def approval_view(doc):
    """An approval page reduced to its paging and each step's id, decision, dates and approvers' ids and decisions."""
    if not isinstance(doc, dict) or not isinstance(doc.get("values"), list):
        return doc
    steps = [{**{k: s[k] for k in ("id", "finalDecision") if k in s},
              **{k: _date(s[k]) for k in ("createdDate", "completedDate") if k in s},
              "approvers": [{"approver": {k: a["approver"][k] for k in ("accountId", "key")
                                          if isinstance(a.get("approver"), dict) and k in a["approver"]},
                             "approverDecision": a.get("approverDecision")}
                            for a in s.get("approvers") or () if isinstance(a, dict)]}
             for s in doc["values"] if isinstance(s, dict)]
    return {**{k: doc[k] for k in ("start", "limit", "size", "isLastPage") if k in doc}, "values": steps}


def field_view(doc):
    """A field list reduced to each field's id, name, custom and schema."""
    return [{k: f[k] for k in ("id", "name", "custom", "schema") if k in f} for f in doc if isinstance(f, dict)] \
        if isinstance(doc, list) else doc


def _approval_starts(host, key, done):
    """The approval page offsets to have: each after a page that says it isn't the last and holds steps."""
    starts = [0]
    while f"{host}/approval/{key}/{starts[-1]}.json" in done:
        doc = json_document(done[f"{host}/approval/{key}/{starts[-1]}.json"])
        rows = doc.get("values") if isinstance(doc, dict) else None
        if not isinstance(rows, list) or not rows or doc.get("isLastPage") is not False:
            break
        starts.append(starts[-1] + len(rows))
    return tuple(starts)


def change_steps(d, m, done, options):
    """The field list; once read, each linked issue; for each issue read, its approval pages."""
    s = readable_source(m, IMPORTER, SCHEMES)
    if s is None:
        return ()
    base, cred = s.locations[0].rstrip("/"), (s.scheme, s.credential, s.login)
    api, host = f"{base}/rest/api/{3 if is_cloud(base) else 2}", urlsplit(base).hostname or "site"
    fields_path = f"{host}/field.json"
    first = ((fields_path, Request(f"{api}/field", HEADERS, cred, s.ca, keep=projected(field_view))),)
    if fields_path not in done:
        return first
    mapped, _ = resolve_fields(field_refs(d)[0], field_list(done[fields_path]))
    wanted = (*ISSUE_FIELDS, *sorted(set(mapped.values()) - set(ISSUE_FIELDS)))
    keys = tuple(k for k in linked_numbers(d, SYSTEM) if KEY.fullmatch(k))
    issues = tuple((f"{host}/issue/{k}.json", Request(f"{api}/issue/{quote(k)}?fields={','.join(wanted)}", HEADERS,
                                                      cred, s.ca, absent=(404,), keep=projected(issue_view(wanted))))
                   for k in keys)
    approvals = tuple((f"{host}/approval/{k}/{start}.json",
                       Request(f"{base}/rest/servicedeskapi/request/{quote(k)}/approval?start={start}&limit={PAGE}",
                               HEADERS, cred, s.ca, absent=(404,), keep=projected(approval_view)))
                      for k in keys if f"{host}/issue/{k}.json" in done for start in _approval_starts(host, k, done))
    return (*first, *issues, *approvals)


def source_problems(d, m, options):
    """Why the collection sources can't be read (an unbound credential or trust anchor, no location, a credential
    scheme the site isn't read with here)."""
    return scheme_problems(m, IMPORTER, SCHEMES, TAKES)


COLLECTORS = (Collector("change-requests", "environment", change_steps, problems=source_problems),)
