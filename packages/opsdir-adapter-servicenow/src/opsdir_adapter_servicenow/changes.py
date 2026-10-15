"""ServiceNow change requests (the importer `servicenow/change-requests`): the tickets the record's change records name
(ciamTicketRef servicenow:<number>) as ServiceNow's change_request and sysapproval_approver tables give them, read into
the record's ticket evidence (domains.governance.tickets): never an approval opsdir acts on. Pure.

The export holds the two tables' answers, as the Table API gives them ({"result": [...]}) or as a list export in JSON
({"records": [...]}): <instance host>/change_request/<chunk>-<offset>.json and <instance host>/sysapproval_approver/
<chunk>-<offset>.json as `opsdir collect` saves its pages, or any change_request*.json and sysapproval_approver*.json
files (a folder named for the instance's host above them gives each ticket its address, ciamDocUrl; without one the
address isn't recorded). A field's value may be raw ("-2"), or raw and display together ({"value": "-2",
"display_value": "Scheduled"}, sysparm_display_value=all): only raw values are compared (raw date/times are UTC,
display ones are in the reading user's time zone), so a record whose state or times are display text only is left out
with a notice. An answer that is ServiceNow's error ({"error": ...}) is named in a notice.

What a ticket says:
  ciamTicketState         its state in neutral terms, only when its change model is one the operator names in the
                          estate setting servicenow-standard-state-models (the models using ServiceNow's documented
                          standard state model, STATE_MODELS): codes differ between models (legacy ones use 1 Open,
                          2 Work in Progress, 7 Closed Skipped), so any other model's state is kept native only, never
                          taken as closed or cancelled
  ciamTicketNativeState   the raw state code and its label when the export has one
  ciamTicketApproval      change_request.approval, the change's overall approval: THE approval evidence; never inferred
                          from the approval records (one approved approver doesn't approve a change, and none doesn't
                          mean none was needed)
  ciamTicketApprover      each sysapproval_approver record of it, detail only: "<state> <approver sys_id> updated
                          <sys_updated_on>" (identifiers, never names; the update time is not when it was approved)
  planned / work window   start_date and end_date (planned), work_start and work_end (actual)
  ciamTicketFact          type, chg_model, close_code, assignment_group, cmdb_ci, requested_by, correlation_id,
                          correlation_display and sys_updated_on, raw (reference fields keep their sys_ids)
  ciamProviderRef         its sys_id; ciamTitle its short description

Only tickets the record links are read; other tickets in the export are named in a notice. A linked ticket missing
from the export is never removed (the record keeps what it last read, and the planner says it wasn't read: a Table
API page can come back short because its limit applies before the access rules). Every requested field the answers
never carry is named (the API ignores fields it doesn't know, or the reader may not see).
"""
import datetime as dt
import json
import re

from opsdir.core.contract import Imported, Importer, Setting
from opsdir.core.directory import gtime, ou_entry
from opsdir.core.naming import rdn_safe
from opsdir.core.settings import setting_value
from opsdir.domains.governance.naming import TICKETS
from opsdir.domains.governance.tickets import adapter_dn, linked_numbers, ticket_entry, ticket_group

SYSTEM = "servicenow"
CHANGE_TABLE, APPROVER_TABLE = "change_request", "sysapproval_approver"
CHANGE_FIELDS = ("number", "sys_id", "state", "approval", "type", "chg_model", "start_date", "end_date", "work_start",
                 "work_end", "close_code", "short_description", "assignment_group", "cmdb_ci", "requested_by",
                 "correlation_id", "correlation_display", "sys_updated_on")
APPROVER_FIELDS = ("sys_id", "sysapproval", "approver", "state", "sys_updated_on")
FACT_FIELDS = ("type", "chg_model", "close_code", "assignment_group", "cmdb_ci", "requested_by", "correlation_id",
               "correlation_display", "sys_updated_on")
WINDOW = (("start_date", "ciamTicketPlannedStart"), ("end_date", "ciamTicketPlannedEnd"),
          ("work_start", "ciamTicketWorkStart"), ("work_end", "ciamTicketWorkEnd"))
# The documented standard state model's codes (ServiceNow change management state model; a model uses it only when
# the operator says so: STANDARD_MODELS). Data: another model's map would be another entry here.
STATE_MODELS = {"standard": {"-5": "new", "-4": "assess", "-3": "authorize", "-2": "scheduled", "-1": "implement",
                             "0": "review", "3": "closed", "4": "cancelled"}}
# change_request.approval's raw values (README: confirm on the instance); any other value is kept as a fact only
APPROVALS = {"not requested": "not-requested", "requested": "requested", "approved": "approved",
             "rejected": "rejected"}
STANDARD_MODELS = Setting("servicenow-standard-state-models", "string", None,
                          "The ServiceNow change models (their sys_ids or names, comma-separated, as GET "
                          "/api/sn_chg_rest/change/model lists them) that use the standard state model: only their "
                          "tickets' states are read in neutral terms; any other model's are kept as ServiceNow gives "
                          "them")
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


def _table_of(path):
    """(instance host or None, table) of an export file: [<host>/]<table>/<page>.json or [<host>/]<table>*.json; None
    when it isn't one of the two tables' answers."""
    parts = path.split("/")
    if not parts[-1].endswith(".json") or len(parts) > 3:
        return None
    for t in (APPROVER_TABLE, CHANGE_TABLE):
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


def _tables(files):
    """({table: rows}, hosts, notices) of the export."""
    found, hosts, notices = {CHANGE_TABLE: [], APPROVER_TABLE: []}, set(), []
    for path in sorted(files):
        where = _table_of(path)
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


def display_only(r):
    """Why a change record can't be compared (its state or times are display text, in an unknown time zone), or
    None."""
    state = _raw(r.get("state"))
    bad = [f for f, _ in WINDOW if _raw(r.get(f)) and not RAW_TIME.fullmatch(_raw(r.get(f)))]
    if state and not RAW_STATE.fullmatch(state):
        bad.insert(0, "state")
    return f"{', '.join(bad)} given as display text, not raw values" if bad else None


def neutral_state(r, models):
    """(neutral state or None, the model when it isn't one the operator named as standard, else None)."""
    model_raw, model_label = _raw(r.get("chg_model")), _label(r.get("chg_model"))
    standard = bool(models) and (model_raw in models or (model_label and model_label in models))
    if not standard:
        return None, (f"{model_label} ({model_raw})" if model_label and model_raw else model_label or model_raw
                      or "(none)")
    return STATE_MODELS["standard"].get(_raw(r.get("state"))), None


def approver_rows(rows, change_sys_id):
    """The approval records of one change, as ciamTicketApprover values, by approver."""
    return tuple(sorted(f"{_raw(a.get('state')) or '?'} {_raw(a.get('approver')) or '?'} updated "
                        f"{_time(_raw(a.get('sys_updated_on'))) or '?'}"
                        for a in rows if _raw(a.get("sysapproval")) == change_sys_id))


def ticket_facts(r, approvers, host, models):
    """The ticket attributes of one change_request record (domains.governance.tickets TICKET_ATTRS)."""
    state, _ = neutral_state(r, models)
    code, label = _raw(r.get("state")), _label(r.get("state"))
    sys_id = _raw(r.get("sys_id"))
    return {"ciamTitle": _raw(r.get("short_description")) or None,
            "ciamProviderRef": sys_id,
            "ciamDocUrl": f"https://{host}/api/now/table/{CHANGE_TABLE}/{sys_id}" if host else None,
            "ciamTicketState": state,
            "ciamTicketApproval": APPROVALS.get(_raw(r.get("approval"))),
            "ciamTicketNativeState": f"{code} {label}".strip() or None,
            **{attr: _time(_raw(r.get(f))) for f, attr in WINDOW},
            "ciamTicketApprover": approvers,
            "ciamTicketFact": tuple(f"{f} {_raw(r.get(f))}" for f in FACT_FIELDS if _raw(r.get(f))) or None}


def _missing_fields(rows, fields, table):
    absent = [f for f in fields if rows and not any(f in r for r in rows)]
    return (f"{table}: the answers never carry {', '.join(absent)} (a field the API doesn't know is ignored, or the "
            "reader can't see it)",) if absent else ()


def _models(d):
    text = setting_value(d, STANDARD_MODELS) or ""
    return frozenset(m.strip() for m in text.split(",") if m.strip())


def read_changes(files, d, patterns, at=None):
    """Imported: each linked ticket the export holds, its own group (replacing only it); notices for the rest."""
    if at is None:
        return Imported((), (), ("ticket evidence is dated: give --at (when the export was taken)",))
    tables, hosts, notices = _tables(files)
    if len(hosts) > 1:
        return Imported((), (), (f"the export holds several instances ({', '.join(hosts)}): import one at a time",))
    host, wanted, models = (hosts[0] if hosts else None), linked_numbers(d, SYSTEM), _models(d)
    changes = {_raw(r.get("sys_id")) or _raw(r.get("number")): r for r in tables[CHANGE_TABLE]}.values()
    unlinked = sorted({_raw(r.get("number")) for r in changes} - set(wanted) - {""})
    groups, unknown_models = [], {}
    for r in sorted(changes, key=lambda r: _raw(r.get("number"))):
        number, why = _raw(r.get("number")), display_only(r)
        if number not in wanted:
            continue
        if not _raw(r.get("sys_id")) or not rdn_safe(number):
            notices.append(f"{number or '(no number)'}: no sys_id, or a number the record can't name: left out")
            continue
        if why:
            notices.append(f"{number}: {why} (their time zone is unknown): left out; export raw values "
                           "(sysparm_display_value=false or all)")
            continue
        _, model = neutral_state(r, models)
        if model is not None:
            unknown_models.setdefault(model, []).append(number)
        approvers = approver_rows(tables[APPROVER_TABLE], _raw(r.get("sys_id")))
        groups.append(ticket_group(ticket_entry(d, SYSTEM, number, gtime(at),
                                                ticket_facts(r, approvers, host, models))))
    read = {g[1][0].attrs["cn"][0] for g in groups}
    notices.extend((
        *_missing_fields(tables[CHANGE_TABLE], CHANGE_FIELDS, CHANGE_TABLE),
        *_missing_fields(tables[APPROVER_TABLE], APPROVER_FIELDS, APPROVER_TABLE),
        *(f"change model {m} isn't named in {STANDARD_MODELS.name}: the state of {', '.join(n)} is kept as "
          "ServiceNow gives it (neutral state unknown)" for m, n in sorted(unknown_models.items())),
        *((f"not linked to a change record: {', '.join(unlinked)} (left out)",) if unlinked else ()),
        *((f"linked but not in the export: {', '.join(n for n in wanted if n not in read)} (the record keeps what it "
           "last read; nothing is removed)",) if any(n not in read for n in wanted) else ()),
        *(("no instance folder (<host>/change_request/...): the tickets' addresses aren't recorded",)
          if groups and host is None else ()),
        f"{len(groups)} ticket(s) read" + (f" from {host}" if host else "")))
    return Imported(containers=(ou_entry(TICKETS), ou_entry(adapter_dn(SYSTEM))), groups=tuple(groups),
                    notices=tuple(notices))


CHANGES_IMPORTER = Importer("change-requests", "ServiceNow change requests the record's changes name, with their "
                                               "approval records, as evidence (Table API answers or JSON list "
                                               "exports of change_request and sysapproval_approver)", read_changes)
