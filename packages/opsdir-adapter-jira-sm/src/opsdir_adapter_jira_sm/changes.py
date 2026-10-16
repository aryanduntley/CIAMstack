"""Jira Service Management change requests (the importer `jira-sm/change-requests`): the issues the record's change
records name (ciamTicketRef jira-sm:<KEY>) as Jira's REST APIs give them, with their approval steps, read through the
operator's mapping (mapping.py) into the record's ticket evidence (domains.governance.tickets): never an approval opsdir
acts on. Pure.

The export holds JSON answers, as `opsdir collect` saves them: <site host>/field.json (the field list),
<site host>/issue/<KEY>.json (GET /rest/api/{3|2}/issue/<KEY>) and <site host>/approval/<KEY>/<start>.json (GET
/rest/servicedeskapi/request/<KEY>/approval, page by page). Answers an operator saved are read too, by what they are:
an issue ({"key", "fields"}), a search answer ({"issues": [...]}, Cloud's /search/jql or Data Center's /search), a
field list (a list of {"id", "name"}), an approval page ({"values": [...]}) under approval/<KEY>/ or named
approval-<KEY>*.json. CSV and XML exports aren't read (README, Known limits).

What a ticket says:
  ciamTicketState         its status in neutral terms, only when the operator maps the status (jira-sm-status-states);
                          any other status is kept native only, never taken as closed or cancelled
  ciamTicketNativeState   the status's id and name
  ciamTicketApprovalStep  each approval step as Jira decided it (finalDecision): "<decision> <step id> created <time>
                          [ completed <time>]"
  ciamTicketApproval      the overall approval DERIVED from the steps' own decisions (Jira has no request-wide one; the
                          user's rule, task 551): any step declined, rejected; else any pending, requested; else at
                          least one step, all approved, and the neutral state past authorize (scheduled, implement,
                          review, closed), approved; otherwise unknown. No steps is unknown, never not-requested; an
                          approver's own decision never decides it
  ciamTicketApprover      each person asked, detail only: "<decision> <accountId or key> step <step id>" (identifiers,
                          never names)
  ciamTicketChangeType    the mapped change-type field's value when it is standard, normal or emergency (any case);
                          any other value is kept as a fact, with a notice
  planned / work window   the mapped planned-start, planned-end, work-start and work-end fields: date-times with their
                          offsets, read as UTC (a date without a time is refused: its time zone is unknown)
  ciamTicketFact          issuetype, status-category, resolution, created and updated, and every other mapped field
                          (risk, impact, ...) as "<role> <value>" (people as their ids)
  ciamProviderRef         the issue's id (its key changes when it moves); ciamDocUrl its self URL; ciamTitle its summary

Only issues the record links are read; others in the export are named in a notice. A linked issue missing from the
export is never removed (the record keeps what it last read, and the planner says it wasn't read)."""
import re

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import gtime, gtime_of_iso, ou_entry
from opsdir.core.naming import rdn_safe
from opsdir.core.sources import json_document
from opsdir.domains.governance.naming import TICKETS
from opsdir.domains.governance.schema import TICKET_CHANGE_TYPES
from opsdir.domains.governance.tickets import adapter_dn, linked_numbers, ticket_entry, ticket_group
from .mapping import (CHANGE_FIELDS, STATUS_STATES, WINDOW, field_refs, neutral_state, resolve_fields,
                      status_states, window_candidates)

SYSTEM = "jira-sm"
ISSUE_FIELDS = ("summary", "status", "resolution", "issuetype", "created", "updated")
CHANGE_TYPE = "change-type"
APPROVED_STATES = ("scheduled", "implement", "review", "closed")   # states past authorize: approval no longer pending
KEY = re.compile(r"[A-Z][A-Z0-9_]*-\d+")
DATE_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def jira_error(doc):
    """What an error answer says, or None."""
    if not isinstance(doc, dict):
        return None
    if isinstance(doc.get("errorMessages"), list) or isinstance(doc.get("errors"), dict):
        said = [*map(str, doc.get("errorMessages") or ()), *(f"{k}: {v}" for k, v in (doc.get("errors") or {}).items())]
        return "; ".join(said) or "(no message)"
    return str(doc["errorMessage"]) if "errorMessage" in doc and "values" not in doc else None


def _is_field_list(doc):
    return isinstance(doc, list) and bool(doc) and all(isinstance(f, dict) and "id" in f and "name" in f for f in doc)


def field_list(text):
    """The fields of a field list answer, or None."""
    doc = json_document(text)
    return tuple(doc) if _is_field_list(doc) else None


def approval_key(path):
    """The issue key of an approval answer file (.../approval/<KEY>/<start>.json, approval-<KEY>*.json), or None."""
    parts = path.split("/")
    if len(parts) >= 3 and parts[-3] == "approval" and KEY.fullmatch(parts[-2]):
        return parts[-2]
    found = re.match(r"approval-([A-Z][A-Z0-9_]*-\d+)", parts[-1])
    return found.group(1) if found else None


def _answers(files):
    """({key: issue}, {key: [approval page, ...]}, field list or None, notices) of the export."""
    issues, approvals, fields, notices = {}, {}, None, []
    for path in sorted(files):
        if not path.endswith(".json"):
            continue
        doc = json_document(files[path])
        error = jira_error(doc)
        if error:
            notices.append(f"{path}: Jira answered an error: {error}")
        elif _is_field_list(doc):
            fields = tuple(doc)
        elif isinstance(doc, dict) and isinstance(doc.get("values"), list) and approval_key(path):
            approvals.setdefault(approval_key(path), []).append(doc)
        elif isinstance(doc, dict) and (isinstance(doc.get("issues"), list) or "fields" in doc):
            for i in doc.get("issues") if isinstance(doc.get("issues"), list) else (doc,):
                if isinstance(i, dict) and isinstance(i.get("fields"), dict) and i.get("key"):
                    issues[str(i["key"])] = i
        else:
            notices.append(f"{path}: isn't a Jira answer (an issue, a search answer, an approval page under "
                           "approval/<KEY>/ or the field list)")
    return issues, approvals, fields, notices


def _steps(pages):
    """(the approval steps of a request's pages, once each by id, or None when no page says it is the last)."""
    if not pages or not any(p.get("isLastPage") is True for p in pages):
        return None
    steps = {str(s.get("id")): s for p in sorted(pages, key=lambda p: p.get("start") or 0)
             for s in p["values"] if isinstance(s, dict)}
    return tuple(steps.values())


def jira_time(v):
    """(GeneralizedTime, None) of an ISO 8601 date-time (its offset converted to UTC), or (None, why not)."""
    text = str(v or "")
    if DATE_TIME.match(text) and gtime_of_iso(text):
        return gtime_of_iso(text), None
    if DATE.fullmatch(text):
        return None, "a date without a time (its time zone is unknown): map a date-time field"
    return None, f"`{text}` isn't a date-time"


def field_text(v):
    """A field value as fact text: an option's value, a person's id, an object's name, a list's items, the value."""
    if isinstance(v, list):
        return ",".join(t for t in map(field_text, v) if t)
    if isinstance(v, dict):
        for k in ("value", "accountId", "key", "name", "id"):
            if v.get(k) not in (None, ""):
                return str(v[k])
        return ""
    return "" if v is None else str(v)


def _when(date):
    """GeneralizedTime of an approval's date object ({"iso8601", "jira", ...}), or '?'."""
    v = date.get("iso8601") or date.get("jira") if isinstance(date, dict) else None
    return gtime_of_iso(v) or "?" if v else "?"


def step_rows(steps):
    """The approval steps as ciamTicketApprovalStep values, by step id."""
    return tuple(sorted(f"{s.get('finalDecision') or '?'} {s.get('id') or '?'} created {_when(s.get('createdDate'))}"
                        + (f" completed {_when(s.get('completedDate'))}" if s.get("completedDate") else "")
                        for s in steps))


def approver_rows(steps):
    """The people each step asked, as ciamTicketApprover values (identifiers, never names)."""
    def who(a):
        p = a.get("approver") if isinstance(a.get("approver"), dict) else {}
        return p.get("accountId") or p.get("key") or p.get("name") or "?"
    return tuple(sorted(f"{a.get('approverDecision') or '?'} {who(a)} step {s.get('id') or '?'}"
                        for s in steps for a in s.get("approvers") or () if isinstance(a, dict)))


def overall_approval(steps, state):
    """The overall approval from the steps' own decisions (none: unknown), never from a single approver's."""
    decisions = [s.get("finalDecision") for s in steps or ()]
    if "declined" in decisions:
        return "rejected"
    if "pending" in decisions:
        return "requested"
    return "approved" if decisions and set(decisions) == {"approved"} and state in APPROVED_STATES else None


def ticket_facts(issue, steps, states, fields):
    """({ticket attribute: value}, problems) of one issue and its steps through the operator's mapping."""
    f = issue["fields"]
    status = f.get("status") if isinstance(f.get("status"), dict) else {}
    state = neutral_state(status, states)
    times = {attr: jira_time(f.get(fields[role])) if f.get(fields.get(role, "")) not in (None, "") else (None, None)
             for role, attr in WINDOW}
    windows = {role: times[attr] for role, attr in WINDOW}
    kind = field_text(f.get(fields.get(CHANGE_TYPE, ""))).strip()
    neutral_kind = kind.lower() if kind.lower() in TICKET_CHANGE_TYPES else None
    category = status.get("statusCategory") if isinstance(status.get("statusCategory"), dict) else {}
    facts = (("issuetype", field_text(f.get("issuetype"))), ("status-category", str(category.get("key") or "")),
             ("resolution", field_text(f.get("resolution"))), ("created", str(f.get("created") or "")),
             ("updated", str(f.get("updated") or "")),
             *((role, field_text(f.get(fid))) for role, fid in sorted(fields.items())
               if role not in dict(WINDOW) and not (role == CHANGE_TYPE and neutral_kind)))
    return ({"ciamTitle": str(f.get("summary") or "") or None,
             "ciamProviderRef": str(issue.get("id") or "") or None,
             "ciamDocUrl": str(issue.get("self") or "") or None,
             "ciamTicketState": state,
             "ciamTicketApproval": overall_approval(steps, state),
             "ciamTicketNativeState": f"{status.get('id') or '?'} {status.get('name') or ''}".strip(),
             "ciamTicketChangeType": neutral_kind,
             **{attr: times[attr][0] for _, attr in WINDOW},
             "ciamTicketApprovalStep": step_rows(steps or ()) or None,
             "ciamTicketApprover": approver_rows(steps or ()) or None,
             "ciamTicketFact": tuple(f"{k} {v}" for k, v in facts if v) or None},
            (*(f"{issue['key']}: {role} ({fields[role]}): {why}" for role, (_, why) in windows.items() if why),
             *((f"{issue['key']}: {CHANGE_TYPE} `{kind}` isn't standard, normal or emergency: kept as a fact",)
               if kind and not neutral_kind else ())))


def _missing_fields(issues, fields):
    absent = sorted(f"{fid} ({role})" for role, fid in fields.items()
                    if issues and not any(fid in i["fields"] for i in issues))
    return (f"the issues never carry {', '.join(absent)} (a field the reader can't see, or not on the change "
            "screens)",) if absent else ()


def _unmapped(reads, field_list_read):
    """Notices for the window fields the mapping doesn't name (with the site's candidates)."""
    roles = [role for role, _ in WINDOW if role not in reads]
    candidates = window_candidates(field_list_read)
    return (f"{CHANGE_FIELDS.name} maps no {', '.join(roles)} field: those times aren't read" +
            (f" (the site's fields named like them: {', '.join(candidates)})" if candidates else ""),) if roles else ()


def read_changes(files, d, patterns, at=None):
    """Imported: each linked issue the export holds, its own group (replacing only it); notices for the rest."""
    if at is None:
        return Imported((), (), ("ticket evidence is dated: give --at (when the export was taken)",))
    issues, approvals, fields_read, notices = _answers(files)
    sites = sorted({str(i.get("self") or "").split("/rest/", 1)[0] for i in issues.values()} - {""})
    if len(sites) > 1:
        return Imported((), (), (f"the export holds several sites ({', '.join(sites)}): import one at a time",))
    states, state_problems = status_states(d)
    refs, ref_problems = field_refs(d)
    fields, field_problems = resolve_fields(refs, fields_read)
    wanted = linked_numbers(d, SYSTEM)
    groups, unmapped, no_steps = [], {}, []
    for key in sorted(k for k in issues if k in wanted):
        issue = issues[key]
        if not issue.get("id") or not rdn_safe(key):
            notices.append(f"{key}: no issue id, or a key the record can't name: left out")
            continue
        steps = _steps(approvals.get(key))
        facts, problems = ticket_facts(issue, steps, states, fields)
        notices.extend(problems)
        if facts["ciamTicketState"] is None:
            unmapped.setdefault(facts["ciamTicketNativeState"], []).append(key)
        if steps is None:
            no_steps.append(key)
        groups.append(ticket_group(ticket_entry(d, SYSTEM, key, gtime(at), facts)))
    read = {g[1][0].attrs["cn"][0] for g in groups}
    unlinked = sorted(set(issues) - set(wanted))
    notices.extend((
        *state_problems, *ref_problems, *field_problems,
        *(_unmapped(fields, fields_read) if groups else ()),
        *_missing_fields([issues[k] for k in read], fields),
        *(f"status {s} isn't mapped in {STATUS_STATES.name}: the state of {', '.join(n)} is kept as Jira gives it "
          "(neutral state unknown)" for s, n in sorted(unmapped.items())),
        *((f"approvals not in the export, or not to their last page, for: {', '.join(no_steps)} (overall approval "
           "unknown)",) if no_steps else ()),
        *((f"not linked to a change record: {', '.join(unlinked)} (left out)",) if unlinked else ()),
        *((f"linked but not in the export: {', '.join(n for n in wanted if n not in read)} (the record keeps what it "
           "last read; nothing is removed)",) if any(n not in read for n in wanted) else ()),
        f"{len(groups)} ticket(s) read" + (f" from {sites[0]}" if sites else "")))
    return Imported(containers=(ou_entry(TICKETS), ou_entry(adapter_dn(SYSTEM))), groups=tuple(groups),
                    notices=tuple(notices))


CHANGES_IMPORTER = Importer("change-requests", "Jira Service Management change requests the record's changes name, "
                                               "with their approval steps, as evidence (REST answers: issues, "
                                               "approvals, the field list), through the operator's mapping settings",
                            read_changes)
