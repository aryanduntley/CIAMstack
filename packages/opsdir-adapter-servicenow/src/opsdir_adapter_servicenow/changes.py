"""ServiceNow change requests (the importer `servicenow/change-requests`): the tickets the record's change records name
(ciamTicketRef servicenow:<number>) as ServiceNow's change_request and sysapproval_approver tables give them, read into
the record's ticket evidence (domains.governance.tickets): never an approval opsdir acts on. Pure. The work tickets the
record links are read the same way from the site-approved task-derived table the operator names (servicenow-ticket-
table, where drafts.py drafts them): below.

The export holds the two tables' answers, as the Table API gives them ({"result": [...]}) or as a list export in JSON
({"records": [...]}): <instance host>/change_request/<chunk>-<offset>.json and <instance host>/sysapproval_approver/
<chunk>-<offset>.json as `opsdir collect` saves its pages, or any change_request*.json and sysapproval_approver*.json
files (a folder named for the instance's host above them gives each ticket its address, ciamDocUrl; without one the
address isn't recorded). A field's value may be raw ("-2"), or raw and display together ({"value": "-2",
"display_value": "Scheduled"}, sysparm_display_value=all): only raw values are compared (raw date/times are UTC,
display ones are in the reading user's time zone), so a record whose state or times are display text only is left out
with a notice. An answer that is ServiceNow's error ({"error": ...}) is named in a notice.

What a ticket says:
  ciamTicketState         its state in neutral terms, only when its change model is one the operator names in an
                          estate setting: servicenow-standard-state-models (the models using ServiceNow's documented
                          standard state model, STATE_MODELS) or servicenow-legacy-state-models (the models still on the
                          pre-Geneva codes -5 Pending, 1 Open, 2 Work in Progress, 3 Closed Complete, 4 Closed
                          Incomplete, 7 Closed Skipped, mapped by servicenow-legacy-states, the operator's or the
                          default); '(none)' names the changes without a model. Codes differ between models (4 is
                          Canceled on the standard model, Closed Incomplete on the legacy one), so a model named in
                          neither (or in both) keeps its state native only, never taken as closed or cancelled
  ciamTicketNativeState   the raw state code and its label when the export has one
  ciamTicketApproval      change_request.approval, the change's overall approval: THE approval evidence; never inferred
                          from the approval records (one approved approver doesn't approve a change, and none doesn't
                          mean none was needed). Its raw values are mapped by servicenow-approval-values (default: the
                          documented not requested, requested, approved, rejected); any other value (an instance's
                          own) leaves the approval unknown, kept as the fact `approval <raw>`, with a notice
  ciamTicketApprover      each sysapproval_approver record of it, detail only: "<state> <approver sys_id> updated
                          <sys_updated_on>" (identifiers, never names; the update time is not when it was approved)
  ciamTicketChangeType    type (normal, standard, emergency), also kept as a fact
  planned / work window   start_date and end_date (planned), work_start and work_end (actual)
  ciamTicketFact          type, chg_model, close_code, assignment_group, cmdb_ci, requested_by, correlation_id,
                          correlation_display and sys_updated_on, raw (reference fields keep their sys_ids)
  ciamProviderRef         its sys_id; ciamTitle its short description

Work tickets: a linked number found in the work-ticket table (<instance host>/<table>/<chunk>-<offset>.json, or any
<table>*.json) is read as a work ticket (ciamTicketKind work): no approval and no approval records; ciamTicketState
through servicenow-ticket-states (the table's own codes: no default, a code not mapped keeps its state native only),
ciamTicketDue its due_date, ciamTicketWorkStart/End its work_start and work_end, ciamTicketFact WORK_FACT_FIELDS raw. A
number found in both tables is read as the change ticket.

One instance per record: an export from another instance than the one the record's tickets were read from (their
addresses) is refused (ticket numbers are only an instance's own, and not even unique there by default).

Only tickets the record links are read; other tickets in the export are named in a notice. A linked ticket missing
from the export is never removed (the record keeps what it last read, and the planner says it wasn't read: a Table
API page can come back short because its limit applies before the access rules). Every requested field the answers
never carry is named (the API ignores fields it doesn't know, or the reader may not see).
"""
import datetime as dt
import json
import re

from typing import NamedTuple
from urllib.parse import urlsplit

from opsdir.core.contract import Imported, Importer, Setting
from opsdir.core.directory import children, gtime, one, ou_entry
from opsdir.core.naming import rdn_safe
from opsdir.core.settings import setting_value
from opsdir.domains.governance.naming import TICKETS
from opsdir.domains.governance.schema import TICKET_APPROVALS, TICKET_CHANGE_TYPES
from opsdir.domains.governance.tickets import (TICKET_CLASS, WORK, adapter_dn, linked_numbers, ticket_entry,
                                               ticket_group, ticket_map, ticket_state_map)

SYSTEM = "servicenow"
# change_request numbers' prefix as the platform ships it: a missing number without it may be a work ticket
CHANGE_PREFIX = "CHG"
CHANGE_TABLE, APPROVER_TABLE = "change_request", "sysapproval_approver"
CHANGE_FIELDS = ("number", "sys_id", "state", "approval", "type", "chg_model", "start_date", "end_date", "work_start",
                 "work_end", "close_code", "short_description", "assignment_group", "cmdb_ci", "requested_by",
                 "correlation_id", "correlation_display", "sys_updated_on")
APPROVER_FIELDS = ("sys_id", "sysapproval", "approver", "state", "sys_updated_on")
FACT_FIELDS = ("type", "chg_model", "close_code", "assignment_group", "cmdb_ci", "requested_by", "correlation_id",
               "correlation_display", "sys_updated_on")
WINDOW = (("start_date", "ciamTicketPlannedStart"), ("end_date", "ciamTicketPlannedEnd"),
          ("work_start", "ciamTicketWorkStart"), ("work_end", "ciamTicketWorkEnd"))
CHANGE_TIMES = tuple(f for f, _ in WINDOW)
# What a work ticket's record is read for (any table derived from task has these fields)
WORK_FIELDS = ("number", "sys_id", "state", "short_description", "due_date", "work_start", "work_end",
               "assignment_group", "assigned_to", "priority", "impact", "urgency", "sys_class_name", "closed_at",
               "sys_updated_on")
WORK_FACT_FIELDS = ("assignment_group", "assigned_to", "priority", "impact", "urgency", "sys_class_name", "closed_at",
                    "sys_updated_on")
WORK_WINDOW = (("work_start", "ciamTicketWorkStart"), ("work_end", "ciamTicketWorkEnd"))
WORK_TIMES = ("due_date", "work_start", "work_end")
TABLE_NAME = re.compile(r"[a-z][a-z0-9_]*")
# The documented standard state model's codes (ServiceNow change management state model; a model uses it only when
# the operator says so: STANDARD_MODELS). The legacy (pre-Geneva) codes' map is the operator's setting LEGACY_STATES.
STATE_MODELS = {"standard": {"-5": "new", "-4": "assess", "-3": "authorize", "-2": "scheduled", "-1": "implement",
                             "0": "review", "3": "closed", "4": "cancelled"}}
NO_MODEL = "(none)"                # names, in the model settings, the changes without a change model
STANDARD_MODELS = Setting("servicenow-standard-state-models", "string", None,
                          "The ServiceNow change models (their sys_ids or names, comma-separated, as GET "
                          "/api/sn_chg_rest/change/model lists them; (none) for changes without a model) that use the "
                          "standard state model: their tickets' states are read in neutral terms; a model named in "
                          "neither this nor servicenow-legacy-state-models keeps its states as ServiceNow gives them")
LEGACY_MODELS = Setting("servicenow-legacy-state-models", "string", None,
                        "The ServiceNow change models (sys_ids or names, comma-separated; (none) for changes without "
                        "a model) whose changes still hold the legacy (pre-Geneva) state codes, read in neutral terms "
                        "through servicenow-legacy-states")
LEGACY_STATES = Setting("servicenow-legacy-states", "string", "-5=new, 1=assess, 2=implement, 3=closed, 4=closed, "
                        "7=cancelled",
                        "The legacy (pre-Geneva) change state codes in neutral terms ('<code>=<state>, ...': -5 "
                        "Pending, 1 Open, 2 Work in Progress, 3 Closed Complete, 4 Closed Incomplete, 7 Closed "
                        "Skipped by default); a code not mapped keeps its state as ServiceNow gives it")
APPROVAL_VALUES = Setting("servicenow-approval-values", "string", "not requested=not-requested, requested=requested, "
                          "approved=approved, rejected=rejected",
                          "change_request.approval's raw values in neutral terms ('<raw value>=<approval>, ...'); "
                          "an instance's other values leave the approval unknown, kept as a fact")
TICKET_TABLE = Setting("servicenow-ticket-table", "string", None,
                       "The site-approved table derived from task that work tickets are filed in (its name, e.g. "
                       "u_ciam_remediation; not change_request): work-ticket drafts are written for it (opsdir "
                       "tickets) and the linked tickets it holds are read back as work tickets")
TICKET_STATES = Setting("servicenow-ticket-states", "string", None,
                        "The work-ticket table's state codes in neutral terms ('<code>=<state>, ...'; base task's are "
                        "-5 Pending, 1 Open, 2 Work in Progress, 3 Closed Complete, 4 Closed Incomplete, 7 Closed "
                        "Skipped, a table may have its own); a code not mapped keeps its state as ServiceNow gives it")
SETTINGS = (STANDARD_MODELS, LEGACY_MODELS, LEGACY_STATES, APPROVAL_VALUES, TICKET_TABLE, TICKET_STATES)
# What the operator's estate settings say of the instance: the models on each state model (sys_ids or names, NO_MODEL),
# the legacy codes' neutral states, the approval field's raw values' neutral approvals, the work-ticket table (None:
# not named) and its codes' neutral states.
InstanceMaps = NamedTuple("InstanceMaps", [("standard", frozenset), ("legacy", frozenset), ("legacy_states", dict),
                                           ("approvals", dict), ("work_table", object), ("work_states", dict)])
RAW_TIME = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
RAW_STATE = re.compile(r"-?\d+")


def _doc(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


def _raw(v):
    """A field's raw value ('' when it has none): the value itself, or its 'value' when the export gives value and
    display (or a reference's link) together."""
    if isinstance(v, dict):
        v = v.get("value")
    return "" if v is None else str(v)


def _label(v):
    return str(v.get("display_value") or "") if isinstance(v, dict) else ""


def _table_of(path, work=None):
    """(instance host or None, table) of an export file: [<host>/]<table>/<page>.json or [<host>/]<table>*.json; None
    when it isn't one of the two tables' answers, or the work-ticket table's (work, when named)."""
    parts = path.split("/")
    if not parts[-1].endswith(".json") or len(parts) > 3:
        return None
    for t in sorted({APPROVER_TABLE, CHANGE_TABLE, *((work,) if work else ())}, key=lambda t: (-len(t), t)):
        if len(parts) >= 2 and parts[-2] == t:
            return (parts[0] if len(parts) == 3 else None), t
        if len(parts) <= 2 and parts[-1].startswith(t):
            return (parts[0] if len(parts) == 2 else None), t
    return None


def answer_rows(text):
    """(rows, problem) of one answer: its records ({"result": [...]} or {"records": [...]}), or none and why not."""
    doc = _doc(text)
    if isinstance(doc, dict) and isinstance(doc.get("error"), dict):
        e = doc["error"]
        return (), f"ServiceNow answered an error: {e.get('message', '')} {e.get('detail', '')}".strip()
    rows = next((doc[k] for k in ("result", "records") if isinstance(doc, dict) and isinstance(doc.get(k), list)),
                None)
    if rows is None:
        return (), "isn't a Table API answer or a JSON list export"
    return tuple(r for r in rows if isinstance(r, dict)), None


def _tables(files, work=None):
    """({table: rows}, hosts, notices) of the export; work: the work-ticket table, when named."""
    found, hosts, notices = {CHANGE_TABLE: [], APPROVER_TABLE: [], **({work: []} if work else {})}, set(), []
    for path in sorted(files):
        where = _table_of(path, work)
        if where is None:
            continue
        host, table = where
        rows, problem = answer_rows(files[path])
        if problem:
            notices.append(f"{path}: {problem}")
        hosts |= {host} if host else set()
        found[table].extend(rows)
    return found, tuple(sorted(hosts)), notices


def _time(raw):
    """GeneralizedTime of a raw ServiceNow date/time (UTC 'YYYY-MM-DD HH:MM:SS'), or None when it isn't one."""
    return gtime(dt.datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")) if RAW_TIME.fullmatch(raw or "") else None


def display_only(r, times=CHANGE_TIMES):
    """Why a record can't be compared (its state or times, the fields `times`, are display text, in an unknown time
    zone), or None."""
    state = _raw(r.get("state"))
    bad = [f for f in times if _raw(r.get(f)) and not RAW_TIME.fullmatch(_raw(r.get(f)))]
    if state and not RAW_STATE.fullmatch(state):
        bad.insert(0, "state")
    return f"{', '.join(bad)} given as display text, not raw values" if bad else None


def model_kind(r, maps):
    """(the state model a record's change model is named on: 'standard', 'legacy', 'both' (named in both settings:
    refused) or None, the model's description)."""
    model_raw, model_label = _raw(r.get("chg_model")), _label(r.get("chg_model"))
    text = f"{model_label} ({model_raw})" if model_label and model_raw else model_label or model_raw or NO_MODEL

    def named(models):
        return (model_raw in models if model_raw else NO_MODEL in models) or bool(model_label and model_label in models)
    on = tuple(k for k, models in (("standard", maps.standard), ("legacy", maps.legacy)) if named(models))
    return ("both" if len(on) == 2 else on[0] if on else None), text


def neutral_state(r, maps):
    """(neutral state or None, the model's kind (model_kind), the model's description)."""
    kind, text = model_kind(r, maps)
    codes = {"standard": STATE_MODELS["standard"], "legacy": maps.legacy_states}.get(kind, {})
    return codes.get(_raw(r.get("state"))), kind, text


def approver_rows(rows, change_sys_id):
    """The approval records of one change, as ciamTicketApprover values, by approver."""
    return tuple(sorted(f"{_raw(a.get('state')) or '?'} {_raw(a.get('approver')) or '?'} updated "
                        f"{_time(_raw(a.get('sys_updated_on'))) or '?'}"
                        for a in rows if _raw(a.get("sysapproval")) == change_sys_id))


def ticket_facts(r, approvers, host, maps):
    """The ticket attributes of one change_request record (domains.governance.tickets TICKET_ATTRS)."""
    state, _, _ = neutral_state(r, maps)
    code, label = _raw(r.get("state")), _label(r.get("state"))
    sys_id, approval = _raw(r.get("sys_id")), _raw(r.get("approval"))
    unmapped = (f"approval {approval}",) if approval and approval not in maps.approvals else ()
    return {"ciamTitle": _raw(r.get("short_description")) or None,
            "ciamProviderRef": sys_id,
            "ciamDocUrl": f"https://{host}/api/now/table/{CHANGE_TABLE}/{sys_id}" if host else None,
            "ciamTicketState": state,
            "ciamTicketApproval": maps.approvals.get(approval),
            "ciamTicketNativeState": f"{code} {label}".strip() or None,
            "ciamTicketChangeType": _raw(r.get("type")) if _raw(r.get("type")) in TICKET_CHANGE_TYPES else None,
            **{attr: _time(_raw(r.get(f))) for f, attr in WINDOW},
            "ciamTicketApprover": approvers,
            "ciamTicketFact": (*unmapped, *(f"{f} {_raw(r.get(f))}" for f in FACT_FIELDS if _raw(r.get(f)))) or None}


def work_facts(r, host, table, maps):
    """The ticket attributes of one work-ticket record of the operator's table: a work ticket, never an approval."""
    code, label, sys_id = _raw(r.get("state")), _label(r.get("state")), _raw(r.get("sys_id"))
    return {"ciamTitle": _raw(r.get("short_description")) or None,
            "ciamProviderRef": sys_id,
            "ciamDocUrl": f"https://{host}/api/now/table/{table}/{sys_id}" if host else None,
            "ciamTicketKind": WORK,
            "ciamTicketState": maps.work_states.get(code),
            "ciamTicketNativeState": f"{code} {label}".strip() or None,
            "ciamTicketDue": _time(_raw(r.get("due_date"))),
            **{attr: _time(_raw(r.get(f))) for f, attr in WORK_WINDOW},
            "ciamTicketFact": tuple(f"{f} {_raw(r.get(f))}" for f in WORK_FACT_FIELDS if _raw(r.get(f))) or None}


def _missing_fields(rows, fields, table):
    absent = [f for f in fields if rows and not any(f in r for r in rows)]
    return (f"{table}: the answers never carry {', '.join(absent)} (a field the API doesn't know is ignored, or the "
            "reader can't see it)",) if absent else ()


def _models(d, setting):
    text = setting_value(d, setting) or ""
    return frozenset(m.strip() for m in text.split(",") if m.strip())


def work_table(d):
    """(the work-ticket table servicenow-ticket-table names, or None: not named or not usable; why not usable)."""
    table = (setting_value(d, TICKET_TABLE) or "").strip()
    if table and (not TABLE_NAME.fullmatch(table) or table in (CHANGE_TABLE, APPROVER_TABLE)):
        return None, (f"{TICKET_TABLE.name}: `{table}` isn't a table work tickets can be filed in (a ServiceNow table "
                      f"name, lower case, not {CHANGE_TABLE} or {APPROVER_TABLE})",)
    return table or None, ()


def instance_maps(d):
    """(InstanceMaps of the operator's estate settings, the settings' problems)."""
    legacy_states, state_problems = ticket_state_map(d, LEGACY_STATES)
    approvals, approval_problems = ticket_map(d, APPROVAL_VALUES, TICKET_APPROVALS, "a ticket approval")
    table, table_problems = work_table(d)
    work_states, work_problems = ticket_state_map(d, TICKET_STATES) if table else ({}, ())
    return (InstanceMaps(_models(d, STANDARD_MODELS), _models(d, LEGACY_MODELS), legacy_states, approvals, table,
                         work_states),
            (*state_problems, *approval_problems, *table_problems, *work_problems))


def instance_hosts(d):
    """The instance hosts the record's tickets were read from (their addresses, ciamDocUrl), sorted."""
    return tuple(sorted({urlsplit(one(t, "ciamDocUrl")).hostname for t in children(d, adapter_dn(SYSTEM), TICKET_CLASS)
                         if one(t, "ciamDocUrl")} - {None}))


def _model_notices(by_kind):
    """Notices of the change models whose states stay native ({(kind, model): numbers}: kind None or 'both')."""
    named = f"{STANDARD_MODELS.name} or {LEGACY_MODELS.name}"
    return tuple(f"change model {m} " + ("isn't named in " + named if kind is None else
                                         f"is named in both {STANDARD_MODELS.name} and {LEGACY_MODELS.name}")
                 + f": the state of {', '.join(n)} is kept as ServiceNow gives it (neutral state unknown)"
                 for (kind, m), n in sorted(by_kind.items(), key=lambda kv: kv[0][1]))


def _left_out(r, times):
    """Why a linked record is left out (no sys_id, a number the record can't name, display-only values), or None."""
    number, why = _raw(r.get("number")), display_only(r, times)
    if not _raw(r.get("sys_id")) or not rdn_safe(number):
        return f"{number or '(no number)'}: no sys_id, or a number the record can't name: left out"
    if why:
        return (f"{number}: {why} (their time zone is unknown): left out; export raw values "
                "(sysparm_display_value=false or all)")
    return None


def _by_number(rows):
    return sorted({_raw(r.get("sys_id")) or _raw(r.get("number")): r for r in rows}.values(),
                  key=lambda r: _raw(r.get("number")))


def read_changes(files, d, patterns, at=None):
    """Imported: each linked ticket the export holds, its own group (replacing only it); notices for the rest."""
    if at is None:
        return Imported((), (), ("ticket evidence is dated: give --at (when the export was taken)",))
    maps, problems = instance_maps(d)
    tables, hosts, notices = _tables(files, maps.work_table)
    if len(hosts) > 1:
        return Imported((), (), (f"the export holds several instances ({', '.join(hosts)}): import one at a time",))
    host, wanted = (hosts[0] if hosts else None), linked_numbers(d, SYSTEM)
    others = tuple(h for h in instance_hosts(d) if h != host)
    if host and others:
        return Imported((), (), (f"the record's ServiceNow tickets were read from {', '.join(others)}; this export "
                                 f"is from {host}: one instance per record (ticket numbers are only an instance's "
                                 "own)",))
    notices.extend(problems)
    changes, works = _by_number(tables[CHANGE_TABLE]), _by_number(tables.get(maps.work_table, ()))
    unlinked = sorted({_raw(r.get("number")) for r in (*changes, *works)} - set(wanted) - {""})
    groups, unknown_models, unmapped, unknown_states = [], {}, {}, {}
    for r in changes:
        number, why = _raw(r.get("number")), _left_out(r, CHANGE_TIMES)
        if number not in wanted:
            continue
        if why:
            notices.append(why)
            continue
        _, kind, model = neutral_state(r, maps)
        if kind in (None, "both"):
            unknown_models.setdefault((kind, model), []).append(number)
        if _raw(r.get("approval")) and _raw(r.get("approval")) not in maps.approvals:
            unmapped.setdefault(_raw(r.get("approval")), []).append(number)
        approvers = approver_rows(tables[APPROVER_TABLE], _raw(r.get("sys_id")))
        groups.append(ticket_group(ticket_entry(d, SYSTEM, number, gtime(at),
                                                ticket_facts(r, approvers, host, maps))))
    as_change = {g[1][0].attrs["cn"][0] for g in groups}
    for r in works:
        number, why = _raw(r.get("number")), _left_out(r, WORK_TIMES)
        if number not in wanted or number in as_change:
            continue
        if why:
            notices.append(why)
            continue
        if _raw(r.get("state")) not in maps.work_states:
            unknown_states.setdefault(_raw(r.get("state")) or "(none)", []).append(number)
        groups.append(ticket_group(ticket_entry(d, SYSTEM, number, gtime(at),
                                                work_facts(r, host, maps.work_table, maps))))
    read, both = {g[1][0].attrs["cn"][0] for g in groups}, sorted(as_change & {_raw(r.get("number")) for r in works})
    notices.extend((
        *_missing_fields(tables[CHANGE_TABLE], CHANGE_FIELDS, CHANGE_TABLE),
        *_missing_fields(tables[APPROVER_TABLE], APPROVER_FIELDS, APPROVER_TABLE),
        *_missing_fields(tables.get(maps.work_table, ()), WORK_FIELDS, maps.work_table),
        *_model_notices(unknown_models),
        *(f"work-ticket state `{c}` of {', '.join(n)} isn't mapped in {TICKET_STATES.name}: kept as ServiceNow gives "
          "it (neutral state unknown)" for c, n in sorted(unknown_states.items())),
        *((f"{', '.join(both)}: in both {CHANGE_TABLE} and {maps.work_table}: read as the change ticket",)
          if both else ()),
        *(f"approval `{v}` of {', '.join(n)} isn't mapped in {APPROVAL_VALUES.name}: approval unknown (kept as a "
          "fact)" for v, n in sorted(unmapped.items())),
        *((f"not linked to a change record: {', '.join(unlinked)} (left out)",) if unlinked else ()),
        *((f"linked but not in the export: {', '.join(n for n in wanted if n not in read)} (the record keeps what it "
           "last read; nothing is removed)"
           + ("" if maps.work_table or all(n.upper().startswith(CHANGE_PREFIX) for n in wanted if n not in read)
              else f"; a work ticket is read from the table {TICKET_TABLE.name} names, and it isn't set"),)
          if any(n not in read for n in wanted) else ()),
        *(("no instance folder (<host>/change_request/...): the tickets' addresses aren't recorded"
           + (f", nor is it checked that they are {', '.join(instance_hosts(d))}'s" if instance_hosts(d) else ""),)
          if groups and host is None else ()),
        f"{len(groups)} ticket(s) read" + (f" from {host}" if host else "")))
    return Imported(containers=(ou_entry(TICKETS), ou_entry(adapter_dn(SYSTEM))), groups=tuple(groups),
                    notices=tuple(notices))


CHANGES_IMPORTER = Importer("change-requests", "ServiceNow change requests the record's changes name, with their "
                                               "approval records, and their work tickets, as evidence (Table API "
                                               "answers or JSON list exports of change_request, sysapproval_approver "
                                               "and the work-ticket table)", read_changes)
