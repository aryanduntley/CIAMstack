"""ServiceNow change requests as ticket evidence: the importer servicenow/change-requests reads the tickets the record's
change records link (Table API answers or JSON list exports of change_request and sysapproval_approver) into their own
entries under ou=tickets, raw values only, the state in neutral terms only for the change models the operator names
as standard; the collector pages the instance's Table API read-only. Nothing is ever written under ou=changes."""
import datetime as dt
import json
from urllib.parse import parse_qs, urlsplit

from opsdir.connectors.collecting import collect
from opsdir.core.directory import get, one, subtree, values, within
from opsdir.domains.governance.naming import CHANGES
from opsdir.domains.governance.tickets import IN_STEP, REJECTED, linked, ticket_dn
from opsdir_adapter_servicenow.adapter import ADAPTER
from opsdir_adapter_servicenow.changes import (APPROVER_FIELDS, CHANGE_FIELDS, CHANGES_IMPORTER, STANDARD_MODELS,
                                               STATE_MODELS, answer_rows, display_only, read_changes)
from opsdir_adapter_servicenow.collect import CHUNK, COLLECTORS, PAGE, answer_fields, change_steps, source_problems
from network_fixtures import ALPHA, entry, model
from support import after_import

AT = dt.datetime(2026, 9, 23, 9, 0, tzinfo=dt.timezone.utc)
HOST = "example.service-now.test"
NORMAL = "11aa"         # a change model's sys_id the operator names as on the standard state model


def _v(value, label=None):
    return {"value": value, "display_value": label if label is not None else value}


def _change_record(number, sys_id, state, approval, model=NORMAL, **extra):
    return {"number": _v(number), "sys_id": _v(sys_id), "state": _v(state, f"label {state}"),
            "approval": _v(approval), "type": _v("normal", "Normal"), "chg_model": _v(model, "Normal"),
            "start_date": _v("2026-09-24 02:00:00", "09/23/2026 22:00:00"),
            "end_date": _v("2026-09-24 06:00:00", "09/24/2026 02:00:00"), "work_start": _v(""), "work_end": _v(""),
            "close_code": _v(""), "short_description": _v(f"Ticket {number}"), "assignment_group": _v("g1", "CAB"),
            "cmdb_ci": _v(""), "requested_by": _v("u1", "A Person"), "correlation_id": _v(""),
            "correlation_display": _v(""), "sys_updated_on": _v("2026-09-22 10:00:00"), **extra}


def _changes(*numbers):
    return tuple(f"dn: cn={cn},{CHANGES}\nobjectClass: top\nobjectClass: ciamChange\ncn: {cn}\nciamTitle: {cn}\n"
                 f"ciamChangeStatus: approved\nciamTicketRef: servicenow:{n}\nciamPlannedAt: 20260924000000Z\n"
                 for cn, n in numbers)


TREE = (f"dn: {CHANGES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: changes\n",
        "dn: ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: settings\n",
        f"dn: cn={STANDARD_MODELS.name},ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamObject\n"
        f"objectClass: ciamEstateSetting\ncn: {STANDARD_MODELS.name}\nciamEstateValue: {NORMAL}, Emergency\n",
        *_changes(("CHG-1", "CHG0001"), ("CHG-2", "CHG0002"), ("CHG-3", "CHG0003")))
APPROVERS = [{"sys_id": _v("a1"), "sysapproval": _v("s1"), "approver": _v("u9", "Some Approver"),
              "state": _v("approved", "Approved"), "sys_updated_on": _v("2026-09-21 10:00:00")},
             {"sys_id": _v("a2"), "sysapproval": _v("s2"), "approver": _v("u8"), "state": _v("approved"),
              "sys_updated_on": _v("2026-09-21 11:00:00")}]


def _answer(rows):
    return json.dumps({"result": rows})


def _export(*records, approvers=APPROVERS, host=HOST):
    root = f"{host}/" if host else ""
    return {f"{root}change_request/0-0.json": _answer(list(records)), f"{root}change_request/0-100.json": _answer([]),
            f"{root}sysapproval_approver/0-0.json": _answer(approvers)}


def _read(*records, tree=TREE, **kw):
    d, _, _ = model(tree=tree)
    imported = read_changes(_export(*records, **kw), d, (), AT)
    return d, imported, after_import(d, imported)


def test_registered_as_an_itsm_add_on_with_its_importer_collector_and_setting():
    assert (ADAPTER.kind, ADAPTER.applies, ADAPTER.importers, ADAPTER.collectors, ADAPTER.settings) == (
        "itsm", None, (CHANGES_IMPORTER,), COLLECTORS, (STANDARD_MODELS,))
    assert STANDARD_MODELS.default is None                  # which models are standard is the operator's to say


def test_a_linked_ticket_is_read_as_evidence_under_ou_tickets():
    d, imported, after = _read(_change_record("CHG0001", "s1", "-2", "approved"),
                               _change_record("CHG0099", "s9", "-1", "approved"))
    t = get(after, ticket_dn("servicenow", "CHG0001"))
    assert dict(t.attrs) == {
        "cn": ("CHG0001",), "ciamImportedAt": ("20260923090000Z",), "ciamTitle": ("Ticket CHG0001",),
        "ciamProviderRef": ("s1",), "ciamDocUrl": (f"https://{HOST}/api/now/table/change_request/s1",),
        "ciamTicketState": ("scheduled",), "ciamTicketApproval": ("approved",),
        "ciamTicketNativeState": ("-2 label -2",), "ciamTicketChangeType": ("normal",),
        "ciamTicketPlannedStart": ("20260924020000Z",),
        "ciamTicketPlannedEnd": ("20260924060000Z",), "ciamTicketApprover": ("approved u9 updated 20260921100000Z",),
        "ciamTicketFact": ("type normal", f"chg_model {NORMAL}", "assignment_group g1", "requested_by u1",
                           "sys_updated_on 2026-09-22 10:00:00")}
    assert get(after, ticket_dn("servicenow", "CHG0099")) is None
    assert "not linked to a change record: CHG0099 (left out)" in imported.notices
    assert "linked but not in the export: CHG0002, CHG0003 (the record keeps what it last read; nothing is removed)" \
        in imported.notices
    assert not any(within(g[0], CHANGES) for g in imported.groups)       # evidence never lands on a change record
    assert {e.dn: e for e in subtree(after, CHANGES)} == {e.dn: e for e in subtree(d, CHANGES)}


def test_the_approval_is_the_changes_own_never_inferred_from_approval_records():
    _, _, after = _read(_change_record("CHG0002", "s2", "-3", "requested"))
    t = get(after, ticket_dn("servicenow", "CHG0002"))
    assert one(t, "ciamTicketApproval") == "requested"         # u8 approved, the change is still requested
    assert values(t, "ciamTicketApprover") == ("approved u8 updated 20260921110000Z",)


def test_drift_follows_from_what_was_read():
    _, _, after = _read(_change_record("CHG0001", "s1", "-2", "approved"),
                        _change_record("CHG0002", "s2", "-3", "rejected"))
    assert {one(link.change, "cn"): link.states for link in linked(after)} == {
        "CHG-1": (IN_STEP,), "CHG-2": (REJECTED,), "CHG-3": ("not-imported",)}


def test_a_model_the_operator_hasnt_named_keeps_its_state_native_only():
    _, imported, after = _read(_change_record("CHG0001", "s1", "3", "approved", model="legacy1"),
                               _change_record("CHG0002", "s2", "4", "approved", chg_model=_v("")))
    for number in ("CHG0001", "CHG0002"):
        assert one(get(after, ticket_dn("servicenow", number)), "ciamTicketState") is None   # never closed/cancelled
    assert one(get(after, ticket_dn("servicenow", "CHG0001")), "ciamTicketNativeState") == "3 label 3"
    assert [n for n in imported.notices if n.startswith("change model")] == [
        "change model (none) isn't named in servicenow-standard-state-models: the state of CHG0002 is kept as "
        "ServiceNow gives it (neutral state unknown)",
        "change model Normal (legacy1) isn't named in servicenow-standard-state-models: the state of CHG0001 is kept "
        "as ServiceNow gives it (neutral state unknown)"]


def test_a_model_named_by_its_name_maps_too_and_the_standard_codes_are_data():
    _, _, after = _read(_change_record("CHG0001", "s1", "4", "approved", model="e1",
                                       chg_model={"value": "e1", "display_value": "Emergency"}))
    assert one(get(after, ticket_dn("servicenow", "CHG0001")), "ciamTicketState") == "cancelled"
    assert set(STATE_MODELS["standard"].values()) == {"new", "assess", "authorize", "scheduled", "implement",
                                                      "review", "closed", "cancelled"}


def test_without_the_setting_no_model_is_standard():
    _, _, after = _read(_change_record("CHG0001", "s1", "-2", "approved"), tree=(TREE[0], *TREE[3:]))
    assert one(get(after, ticket_dn("servicenow", "CHG0001")), "ciamTicketState") is None


def test_display_only_values_are_left_out_their_time_zone_unknown():
    shown = _change_record("CHG0001", "s1", "Scheduled", "approved", start_date="09/23/2026 22:00:00")
    shown = {k: (v["value"] if isinstance(v, dict) else v) for k, v in shown.items()}
    assert display_only(shown) == "state, start_date given as display text, not raw values"
    _, imported, after = _read(shown)
    assert get(after, ticket_dn("servicenow", "CHG0001")) is None
    assert any(n.startswith("CHG0001: state, start_date given as display text") for n in imported.notices)


def test_raw_only_answers_and_list_exports_read_without_an_instance_folder():
    raw = {k: v["value"] for k, v in _change_record("CHG0001", "s1", "0", "approved").items()}
    d, _, _ = model(tree=TREE)
    imported = read_changes({"change_request.json": json.dumps({"records": [raw]})}, d, (), AT)
    t = get(after_import(d, imported), ticket_dn("servicenow", "CHG0001"))
    assert one(t, "ciamTicketState") == "review" and one(t, "ciamTicketNativeState") == "0"
    assert one(t, "ciamDocUrl") is None
    assert ("no instance folder (<host>/change_request/...): the tickets' addresses aren't recorded"
            in imported.notices)


def test_fields_the_answers_never_carry_errors_dating_and_instances_are_named():
    partial = {k: v for k, v in _change_record("CHG0001", "s1", "-2", "approved").items() if k != "work_end"}
    d, _, _ = model(tree=TREE)
    files = {**_export(partial), f"{HOST}/sysapproval_approver/0-100.json":
             json.dumps({"error": {"message": "User Not Authenticated", "detail": "Required to provide Auth"}})}
    notices = read_changes(files, d, (), AT).notices
    assert ("change_request: the answers never carry work_end (a field the API doesn't know is ignored, or the "
            "reader can't see it)") in notices
    assert (f"{HOST}/sysapproval_approver/0-100.json: ServiceNow answered an error: User Not Authenticated Required "
            "to provide Auth") in notices
    assert read_changes(files, d, (), None).notices == ("ticket evidence is dated: give --at (when the export was "
                                                        "taken)",)
    two = {**_export(_change_record("CHG0001", "s1", "-2", "approved")), "other.test/change_request/0-0.json": "{}"}
    assert read_changes(two, d, (), AT).groups == ()
    assert answer_rows("<html/>") == ((), "isn't a Table API answer or a JSON list export")


def _source(**extra):
    return (entry(ALPHA, "itsm", "ciamCollectionSource", ciamBindingRole="itsm",
                  ciamImporter="servicenow/change-requests",
                  ciamSourceRef=f"https://{HOST}/", ciamCredentialRole="itsm-reader", ciamLoginName="opsdir.reader",
                  **extra),
            entry(ALPHA, "itsm-reader", "ciamSecretRef", ciamBindingRole="itsm-reader",
                  ciamRefUri="fake://kv/itsm-reader"))


TABLES = {"change_request": [_change_record("CHG0001", "s1", "-2", "approved", secret_note=_v("not kept"))],
          "sysapproval_approver": APPROVERS}


def _serve(request):
    url = urlsplit(request.url)
    q, table = parse_qs(url.query), url.path.rsplit("/", 1)[1]
    offset, limit = int(q["sysparm_offset"][0]), int(q["sysparm_limit"][0])
    return json.dumps({"result": TABLES[table][offset:offset + limit]}), None


def test_the_collector_reads_the_linked_tickets_then_their_approvals_page_by_page():
    _, alpha, _ = model(alpha=_source(), tree=TREE)
    first = change_steps(alpha.d, alpha, {}, {})
    assert [p for p, _ in first] == [f"{HOST}/change_request/0-0.json"]
    req = first[0][1]
    q = parse_qs(urlsplit(req.url).query)
    assert req.url.startswith(f"https://{HOST}/api/now/table/change_request?")
    assert q["sysparm_query"] == ["numberINCHG0001,CHG0002,CHG0003^ORDERBYsys_id"]
    assert q["sysparm_fields"] == [",".join(CHANGE_FIELDS)] and q["sysparm_display_value"] == ["all"]
    assert (q["sysparm_limit"], q["sysparm_offset"]) == ([str(PAGE)], ["0"]) and PAGE > CHUNK
    assert req.credential == ("basic", "fake://kv/itsm-reader", "opsdir.reader")
    c = collect("servicenow/change-requests", COLLECTORS[0], alpha.d, alpha, _serve)
    assert c.problems == () and sorted(c.files) == [f"{HOST}/change_request/0-0.json",
                                                    f"{HOST}/change_request/0-100.json",
                                                    f"{HOST}/sysapproval_approver/0-0.json",
                                                    f"{HOST}/sysapproval_approver/0-100.json"]
    approvals = parse_qs(urlsplit(next(call.provenance for call in c.calls if "sysapproval_approver/0-0" in call.path)
                                  [4:]).query)
    assert approvals["sysparm_query"] == ["sysapprovalINs1^ORDERBYsys_id"]
    assert approvals["sysparm_fields"] == [",".join(APPROVER_FIELDS)]
    assert "secret_note" not in "".join(c.files.values())           # only the requested fields are kept
    after = after_import(alpha.d, read_changes(c.files, alpha.d, (), AT))
    assert one(get(after, ticket_dn("servicenow", "CHG0001")), "ciamTicketState") == "scheduled"


def test_a_short_page_doesnt_end_the_reading_only_an_empty_one_does():
    _, alpha, _ = model(alpha=_source(), tree=TREE)
    one_row = _answer([TABLES["change_request"][0]])
    steps = change_steps(alpha.d, alpha, {f"{HOST}/change_request/0-0.json": one_row}, {})
    assert [p for p, _ in steps] == [f"{HOST}/change_request/0-0.json", f"{HOST}/change_request/0-100.json"]
    assert answer_fields(("number",))("<html/>") == "<html/>"


def test_a_scheme_the_table_api_isnt_read_with_here_is_refused_with_why():
    _, alpha, _ = model(alpha=_source(ciamCredentialScheme="token"), tree=TREE)
    assert source_problems(alpha.d, alpha, {}) == (
        "collection source `itsm`: credential scheme `token`: the instance is read with a user's password (basic) "
        "or an OAuth access token (bearer)",)
    assert change_steps(alpha.d, alpha, {}, {}) == ()
