"""BMC Helix ITSM / Remedy change requests (the importer `bmc-helix/change-requests`): the change tickets the record's
change records name (ciamTicketRef bmc-helix:<Infrastructure Change ID>) as the AR System REST API gives them, with
their approval signatures, read into the record's ticket evidence (domains.governance.tickets): never an approval
opsdir acts on. The work orders they name (bmc-helix:<Work Order ID>, the work tickets findings were handed over by)
are read alongside, as work tickets (workorders.py). Pure.

The export holds JSON answers of GET /api/arsys/v1/entry/<form>, as `opsdir collect` saves them: <server host>/change/
<CRQ>.json (CHG:Infrastructure Change, qualified by the ticket's Infrastructure Change ID), <server host>/approval/
<CRQ>/<offset>.json (AP:Detail-Signature, page by page) and <server host>/workorder/<WO>.json (WOI:WorkOrderInterface,
qualified by its Work Order ID). Answers an operator saved are read too, by what they are: a list answer ({"entries":
[...]}) or a single entry ({"values": {...}}) whose values are a change (they hold an Infrastructure Change ID), a work
order (a Work Order ID) or approval signatures (an Approval Status); approval pages under approval/<CRQ>/ or named
approval-<CRQ>*.json. AR System's error answers ([{"messageType": "ERROR", ...}]) are named. CSV, ARX and XML report
exports aren't read (README, Known limits).

What a ticket says:
  ciamTicketState         its Change Request Status in neutral terms, by bmc-helix-status-states (states.py): any
                          status the setting doesn't map (Pending, Rejected, a customised one) is kept native only,
                          never taken as closed or cancelled
  ciamTicketNativeState   the Change Request Status as BMC gives it
  ciamTicketApprovalStep  each approval request (AP:Detail-Signature's Approval ID, one per approval phase and level)
                          as its signatures decide it: "<decision> <Approval ID> created <its first signature's
                          Create-Date-Sig>" (no completed time: a signature's modified date isn't when it was decided)
  ciamTicketApproval      rejected when the status is Rejected, else DERIVED from the steps (the user's rule, task 551;
                          tickets.derived_approval): BMC's change form holds no overall approval
  ciamTicketApprover      each signature, detail only: "<status> <Approver Signature, else Approvers> step <Approval
                          ID> updated <Modified-Date-Sig>[ phase <Phase>]" (login ids, never names)
  ciamTicketChangeType    Change Timing when it is Emergency, Normal or Standard; Expedited, Latent and No Impact are
                          kept as facts, with a notice
  planned / work window   Scheduled Start Date and Scheduled End Date, Actual Start Date and Actual End Date: date-times
                          with their offsets, read as UTC (a date without a time is refused: its time zone is unknown)
  ciamTicketFact          change-type (Project, Change, Release, ...), status-reason, risk-level, impact, urgency,
                          priority and last-modified, as BMC gives them
  ciamProviderRef         the entry's Request ID; ciamDocUrl its REST self link; ciamTitle its Description

A signature belongs to a change when its Request is the change's Request ID or its Infrastructure Change ID (BMC's
join stores the application's request id; which one ITSM stores is unverified) and its Application is CHG:
Infrastructure Change (or not given); signatures of another application are named and left out. Only changes the
record links are read; others in the export are named in a notice. A linked change missing from the export is never
removed (the record keeps what it last read, and the planner says it wasn't read). Work orders are read the same way,
by their Status through bmc-helix-work-order-states."""
import re
from urllib.parse import urlsplit

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import gtime, iso_date_time, ou_entry
from opsdir.core.naming import rdn_safe
from opsdir.core.sources import json_document
from opsdir.domains.governance.naming import TICKETS
from opsdir.domains.governance.tickets import (adapter_dn, approval_step, linked_numbers, ticket_entry, ticket_group,
                                               ticket_state_map)
from .states import STATUS_STATES, WORK_ORDER_STATES, change_type, overall_approval, step_decision
from .workorders import WINDOW, WO_NUMBER, WORK_ORDER_FORM, is_work_order, window_times, work_order_facts

SYSTEM = "bmc-helix"
CHANGE_FORM, APPROVAL_FORM = "CHG:Infrastructure Change", "AP:Detail-Signature"
NUMBER, REQUEST_ID, STATUS, TIMING = "Infrastructure Change ID", "Request ID", "Change Request Status", "Change Timing"
FACTS = (("Change Type", "change-type"), ("Status Reason", "status-reason"), ("Risk Level", "risk-level"),
         ("Impact", "impact"), ("Urgency", "urgency"), ("Priority", "priority"),
         ("Last Modified Date", "last-modified"))
CHANGE_FIELDS = (NUMBER, REQUEST_ID, "Description", STATUS, TIMING, *(f for f, _ in WINDOW), *(f for f, _ in FACTS))
APPROVAL_FIELDS = ("Detail-Sig-Id", "Approval ID", "Request", "Application", "Approval Status", "Approvers",
                   "Approver Signature", "Phase", "Create-Date-Sig", "Modified-Date-Sig")
NUMBER_TEXT = re.compile(r"[A-Za-z0-9_-]+")       # an id a qualification can quote as it is


def ar_error(doc):
    """What an AR System error answer says ([{"messageType": "ERROR", "messageText", ...}]), or None."""
    if not isinstance(doc, list) or not doc or not all(isinstance(m, dict) and "messageType" in m for m in doc):
        return None
    return "; ".join(" ".join(str(m.get(k) or "") for k in ("messageNumber", "messageText", "messageAppendedText")
                              ).strip() for m in doc) or "(no message)"


def answer_entries(doc):
    """The entries of an entry answer: a list answer's ({"entries": [...]}) or a single entry ({"values": {...}})."""
    if isinstance(doc, dict) and isinstance(doc.get("entries"), list):
        return tuple(e for e in doc["entries"] if isinstance(e, dict) and isinstance(e.get("values"), dict))
    return (doc,) if isinstance(doc, dict) and isinstance(doc.get("values"), dict) else ()


def has_next(doc):
    """Whether a list answer links a next page."""
    links = doc.get("_links") if isinstance(doc, dict) else None
    return bool(isinstance(links, dict) and links.get("next"))


def self_link(entry):
    """An entry's REST self link, or None."""
    links = (entry.get("_links") or {}).get("self") if isinstance(entry.get("_links"), dict) else None
    links = links if isinstance(links, list) else [links]
    return next((str(x["href"]) for x in links if isinstance(x, dict) and x.get("href")), None)


def approval_key(path):
    """The change number of an approval answer file (.../approval/<CRQ>/<offset>.json, approval-<CRQ>*.json), or
    None."""
    parts = path.split("/")
    if len(parts) >= 3 and parts[-3] == "approval" and NUMBER_TEXT.fullmatch(parts[-2]):
        return parts[-2]
    found = re.match(r"approval-([A-Za-z0-9_-]+?)(?:[-_.]\d+)?\.json$", parts[-1])
    return found.group(1) if found else None


def _answers(files):
    """(changes [entry, ...], work orders [entry, ...], signatures [values, ...], {CRQ: [page, ...]}, notices) of the
    export."""
    changes, work_orders, signatures, pages, notices = [], [], [], {}, []
    for path in sorted(files):
        if not path.endswith(".json"):
            continue
        doc = json_document(files[path])
        error, entries = ar_error(doc), answer_entries(doc)
        if error:
            notices.append(f"{path}: AR System answered an error: {error}")
            continue
        if approval_key(path) and isinstance(doc, dict) and "entries" in doc:
            pages.setdefault(approval_key(path), []).append(doc)
        changes.extend(e for e in entries if NUMBER in e["values"])
        work_orders.extend(e for e in entries if NUMBER not in e["values"] and WO_NUMBER in e["values"])
        signatures.extend(e["values"] for e in entries
                          if NUMBER not in e["values"] and WO_NUMBER not in e["values"]
                          and "Approval Status" in e["values"])
        if not entries and not (approval_key(path) and isinstance(doc, dict) and "entries" in doc):
            notices.append(f"{path}: isn't an AR System entry answer (a change of {CHANGE_FORM}, a work order of "
                           f"{WORK_ORDER_FORM} or signatures of {APPROVAL_FORM})")
    return changes, work_orders, signatures, pages, notices


def _text(v):
    return "" if v is None else str(v)


def _time(v):
    return iso_date_time(v)[0] if v not in (None, "") else None


def signatures_of(values, signatures):
    """(the approval signatures of a change, once each, those of another application with its Request) of the export's
    signatures: a signature is the change's when its Request is the change's Request ID or number."""
    ids = {_text(values.get(REQUEST_ID)), _text(values.get(NUMBER))} - {""}
    mine = {_text(s.get("Detail-Sig-Id")) or repr(sorted(s.items())): s for s in signatures
            if _text(s.get("Request")) in ids}.values()
    other = tuple(s for s in mine if _text(s.get("Application")) not in ("", CHANGE_FORM))
    return tuple(s for s in mine if s not in other), other


def steps_of(signatures):
    """((Approval ID, decision or None, first Create-Date-Sig as GeneralizedTime or None), ...) of a change's
    signatures, by Approval ID."""
    by_id = {}
    for s in signatures:
        by_id.setdefault(_text(s.get("Approval ID")) or "?", []).append(s)
    return tuple((aid, step_decision(s.get("Approval Status") for s in sigs),
                  min((t for t in (_time(s.get("Create-Date-Sig")) for s in sigs) if t), default=None))
                 for aid, sigs in sorted(by_id.items()))


def _token(v):
    return re.sub(r"\s+", "_", _text(v).strip())


def approver_rows(signatures):
    """The signatures as ciamTicketApprover values (login ids, never names)."""
    return tuple(sorted(f"{_token(s.get('Approval Status')).lower() or '?'} "
                        f"{_token(s.get('Approver Signature') or s.get('Approvers')) or '?'} step "
                        f"{_text(s.get('Approval ID')) or '?'} updated {_time(s.get('Modified-Date-Sig')) or '?'}"
                        + (f" phase {_text(s.get('Phase'))}" if _text(s.get("Phase")) else "")
                        for s in signatures))


def ticket_facts(entry, signatures, states):
    """({ticket attribute: value}, problems) of one change entry and its signatures (None: not read)."""
    v, number = entry["values"], _text(entry["values"].get(NUMBER))
    status, timing = _text(v.get(STATUS)), _text(v.get(TIMING))
    state, kind = states.get(status), change_type(timing)
    times = window_times(v)
    steps = steps_of(signatures) if signatures is not None else None
    decided = tuple(s for s in steps or () if s[1])
    facts = (*((slug, _text(v.get(f))) for f, slug in FACTS), *((("change-timing", timing),) if not kind else ()))
    return ({"ciamTitle": _text(v.get("Description")) or None,
             "ciamProviderRef": _text(v.get(REQUEST_ID)) or None,
             "ciamDocUrl": self_link(entry),
             "ciamTicketState": state,
             "ciamTicketApproval": overall_approval(status, (d for _, d, _ in decided) if steps is not None else (),
                                                    state),
             "ciamTicketNativeState": status or None,
             "ciamTicketChangeType": kind,
             **{attr: times[attr][0] for _, attr in WINDOW},
             "ciamTicketApprovalStep": tuple(approval_step(d, aid, created) for aid, d, created in decided) or None,
             "ciamTicketApprover": approver_rows(signatures or ()) or None,
             "ciamTicketFact": tuple(f"{k} {x}" for k, x in facts if x) or None},
            (*(f"{number}: {f}: {why}" for f, attr in WINDOW for why in (times[attr][1],) if why),
             *((f"{number}: {TIMING} `{timing}` isn't Emergency, Normal or Standard: kept as a fact",)
               if timing and not kind else ()),
             *(f"{number}: approval {aid} has only cancelled, closed or errored signatures: not a step"
               for aid, d, _ in steps or () if not d)))


def _complete(pages):
    """Whether a change's approval pages were read to the last (a page that links no next one)."""
    return bool(pages) and any(not has_next(p) for p in pages)


def _by_number(entries, field):
    """{number: {Request ID: entry}} of entry answers, by one number field."""
    found = {}
    for e in entries:
        found.setdefault(_text(e["values"].get(field)), {})[_text(e["values"].get(REQUEST_ID))] = e
    return found


def _ambiguous(number, found):
    """Whether a number's entries can't be read as one ticket: several, no Request ID, or a number the record can't
    name."""
    return len(found) > 1 or not rdn_safe(number) or "" in found


def _work_order_groups(d, orders, wanted, at):
    """(groups, {unmapped Status: [WO, ...]}, notices) of the linked work orders the export holds."""
    states, problems = ticket_state_map(d, WORK_ORDER_STATES)
    groups, unmapped, notices = [], {}, list(problems)
    for number in sorted(n for n in orders if n in wanted and is_work_order(n)):
        if _ambiguous(number, orders[number]):
            notices.append(f"{number}: several entries, no Request ID, or a number the record can't name: left out")
            continue
        entry = next(iter(orders[number].values()))
        facts, found = work_order_facts(entry["values"], self_link(entry), states)
        notices.extend(found)
        if facts["ciamTicketState"] is None:
            unmapped.setdefault(facts["ciamTicketNativeState"] or "(none)", []).append(number)
        groups.append(ticket_group(ticket_entry(d, SYSTEM, number, gtime(at), facts)))
    return groups, unmapped, notices


def read_changes(files, d, patterns, at=None):
    """Imported: each linked change and work order the export holds, its own group (replacing only it); notices for
    the rest."""
    if at is None:
        return Imported((), (), ("ticket evidence is dated: give --at (when the export was taken)",))
    changes, work_orders, signatures, pages, notices = _answers(files)
    hosts = sorted({urlsplit(self_link(e) or "").hostname or "" for e in (*changes, *work_orders)} - {""})
    if len(hosts) > 1:
        return Imported((), (), (f"the export holds several servers ({', '.join(hosts)}): import one at a time",))
    states, state_problems = ticket_state_map(d, STATUS_STATES)
    wanted = linked_numbers(d, SYSTEM)
    by_number, orders = _by_number(changes, NUMBER), _by_number(work_orders, WO_NUMBER)
    groups, unmapped, no_steps, foreign = [], {}, [], []
    for number in sorted(n for n in by_number if n in wanted and not is_work_order(n)):
        if _ambiguous(number, by_number[number]):
            notices.append(f"{number}: several entries, no Request ID, or a number the record can't name: left out")
            continue
        entry = next(iter(by_number[number].values()))
        mine, other = signatures_of(entry["values"], signatures)
        foreign.extend(f"{number} ({_text(s.get('Application'))})" for s in other)
        read = mine if _complete(pages.get(number)) else None
        facts, problems = ticket_facts(entry, read, states)
        notices.extend(problems)
        if facts["ciamTicketState"] is None:
            unmapped.setdefault(facts["ciamTicketNativeState"] or "(none)", []).append(number)
        if read is None:
            no_steps.append(number)
        groups.append(ticket_group(ticket_entry(d, SYSTEM, number, gtime(at), facts)))
    work_groups, work_unmapped, work_notices = _work_order_groups(d, orders, wanted, at)
    groups.extend(work_groups)
    notices.extend(work_notices)
    read_numbers = {g[1][0].attrs["cn"][0] for g in groups}
    unlinked = sorted((set(by_number) | set(orders)) - set(wanted) - {""})
    notices.extend((
        *state_problems,
        *(f"status {s} isn't mapped in {setting.name}: the state of {', '.join(n)} is kept as BMC gives it "
          "(neutral state unknown)"
          for setting, found in ((STATUS_STATES, unmapped), (WORK_ORDER_STATES, work_unmapped))
          for s, n in sorted(found.items())),
        *((f"approval signatures not in the export, or not to their last page, for: {', '.join(no_steps)} (overall "
           "approval unknown unless the status is Rejected)",) if no_steps else ()),
        *((f"signatures of another application left out: {', '.join(sorted(set(foreign)))}",) if foreign else ()),
        *((f"not linked to a change record: {', '.join(unlinked)} (left out)",) if unlinked else ()),
        *((f"linked but not in the export: {', '.join(n for n in wanted if n not in read_numbers)} (the record keeps "
           "what it last read; nothing is removed)",) if any(n not in read_numbers for n in wanted) else ()),
        f"{len(groups)} ticket(s) read" + (f" from {hosts[0]}" if hosts else "")))
    return Imported(containers=(ou_entry(TICKETS), ou_entry(adapter_dn(SYSTEM))), groups=tuple(groups),
                    notices=tuple(notices))


CHANGES_IMPORTER = Importer("change-requests", "BMC Helix ITSM / Remedy change requests the record's changes name, "
                                               "with their approval signatures, and the work orders they name, as "
                                               "evidence (AR System REST answers of CHG:Infrastructure Change, "
                                               "AP:Detail-Signature and WOI:WorkOrderInterface)", read_changes)
