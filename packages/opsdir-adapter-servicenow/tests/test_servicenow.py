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
from opsdir.core.contract import TicketRequest
from opsdir.connectors.handoff import request_lines
from opsdir.domains.governance.tickets import IN_STEP, REJECTED, is_work, linked, ticket_dn
from opsdir_adapter_servicenow.adapter import ADAPTER
from opsdir_adapter_servicenow.changes import (APPROVAL_VALUES, APPROVER_FIELDS, CHANGE_FIELDS, CHANGES_IMPORTER,
                                               LEGACY_MODELS, LEGACY_STATES, SETTINGS, STANDARD_MODELS, STATE_MODELS,
                                               TICKET_STATES, TICKET_TABLE, WORK_FIELDS, answer_rows, display_only,
                                               instance_hosts, instance_maps, model_kind, read_changes, work_table)
from opsdir_adapter_servicenow.collect import CHUNK, COLLECTORS, PAGE, answer_fields, change_steps, source_problems
from opsdir_adapter_servicenow.drafts import DRAFT_SETTINGS, TICKET_FIELDS, TICKET_GROUPS, ticket_draft
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
    assert (ADAPTER.kind, ADAPTER.applies, ADAPTER.importers, ADAPTER.collectors, ADAPTER.settings,
            ADAPTER.ticket_draft) == ("itsm", None, (CHANGES_IMPORTER,), COLLECTORS, (*SETTINGS, *DRAFT_SETTINGS),
                                      ticket_draft)
    assert SETTINGS == (STANDARD_MODELS, LEGACY_MODELS, LEGACY_STATES, APPROVAL_VALUES, TICKET_TABLE, TICKET_STATES)
    assert DRAFT_SETTINGS == (TICKET_GROUPS, TICKET_FIELDS)
    assert STANDARD_MODELS.default is None and LEGACY_MODELS.default is None   # which models: the operator's to say
    assert {s.default for s in (TICKET_TABLE, TICKET_STATES, *DRAFT_SETTINGS)} == {None}   # site-specific


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
    assert ("linked but not in the export: CHG0002, CHG0003 (the record keeps what it last read; nothing is "
            "removed)") in imported.notices                     # change numbers: no work-ticket hint
    assert not any(within(g[0], CHANGES) for g in imported.groups)       # evidence never lands on a change record
    assert {e.dn: e for e in subtree(after, CHANGES)} == {e.dn: e for e in subtree(d, CHANGES)}


def test_a_missing_number_that_isnt_a_change_number_says_where_work_tickets_are_read_from():
    _, imported, _ = _read(_change_record("CHG0001", "s1", "-2", "approved"),
                           tree=(*TREE, *_changes(("CHG-4", "TASK0001"))))
    assert ("linked but not in the export: CHG0002, CHG0003, TASK0001 (the record keeps what it last read; nothing "
            "is removed); a work ticket is read from the table servicenow-ticket-table names, and it isn't set"
            ) in imported.notices


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
        "change model (none) isn't named in servicenow-standard-state-models or servicenow-legacy-state-models: the "
        "state of CHG0002 is kept as ServiceNow gives it (neutral state unknown)",
        "change model Normal (legacy1) isn't named in servicenow-standard-state-models or "
        "servicenow-legacy-state-models: the state of CHG0001 is kept as ServiceNow gives it (neutral state "
        "unknown)"]


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
        "collection source `itsm`: credential scheme `token`: the instance is read with a user's password (basic), "
        "an OAuth access token (bearer) or a client certificate it maps to a user (client-certificate)",)
    assert change_steps(alpha.d, alpha, {}, {}) == ()


def _setting(name, value):
    return (f"dn: cn={name},ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamObject\n"
            f"objectClass: ciamEstateSetting\ncn: {name}\nciamEstateValue: {value}\n")


LEGACY_TREE = (*TREE, _setting(LEGACY_MODELS.name, "legacy1, (none)"))


def test_legacy_models_read_the_pre_geneva_codes_through_their_own_map():
    _, imported, after = _read(_change_record("CHG0001", "s1", "4", "approved", model="legacy1"),
                               _change_record("CHG0002", "s2", "7", "approved", chg_model=_v("")),
                               _change_record("CHG0003", "s3", "4", "approved"), tree=LEGACY_TREE)
    states = {n: one(get(after, ticket_dn("servicenow", n)), "ciamTicketState") for n in ("CHG0001", "CHG0002",
                                                                                          "CHG0003")}
    assert states == {"CHG0001": "closed",           # 4 Closed Incomplete on the legacy codes
                      "CHG0002": "cancelled",        # 7 Closed Skipped: the work wasn't done
                      "CHG0003": "cancelled"}        # 4 Canceled on the standard model
    assert not [n for n in imported.notices if n.startswith("change model")]
    maps, problems = instance_maps(model(tree=LEGACY_TREE)[0])
    assert problems == () and maps.legacy_states == {"-5": "new", "1": "assess", "2": "implement", "3": "closed",
                                                     "4": "closed", "7": "cancelled"}


def test_the_legacy_map_is_the_operators_and_its_problems_are_named():
    tree = (*LEGACY_TREE, _setting(LEGACY_STATES.name, "1=new, 2=implement, 9=done"))
    _, imported, after = _read(_change_record("CHG0001", "s1", "1", "approved", model="legacy1"),
                               _change_record("CHG0002", "s2", "3", "approved", model="legacy1"), tree=tree)
    assert one(get(after, ticket_dn("servicenow", "CHG0001")), "ciamTicketState") == "new"
    assert one(get(after, ticket_dn("servicenow", "CHG0002")), "ciamTicketState") is None   # 3 isn't mapped now
    assert ("servicenow-legacy-states: `9=done`: done isn't a ticket state (new, assess, authorize, scheduled, "
            "implement, review, closed, cancelled)") in imported.notices


def test_a_model_named_on_both_state_models_is_refused():
    tree = (*TREE, _setting(LEGACY_MODELS.name, NORMAL))
    d = model(tree=tree)[0]
    assert model_kind(_change_record("CHG0001", "s1", "3", "approved"), instance_maps(d)[0]) == (
        "both", f"Normal ({NORMAL})")
    _, imported, after = _read(_change_record("CHG0001", "s1", "3", "approved"), tree=tree)
    assert one(get(after, ticket_dn("servicenow", "CHG0001")), "ciamTicketState") is None
    assert (f"change model Normal ({NORMAL}) is named in both servicenow-standard-state-models and "
            "servicenow-legacy-state-models: the state of CHG0001 is kept as ServiceNow gives it (neutral state "
            "unknown)") in imported.notices


def test_an_approval_value_the_mapping_doesnt_know_is_kept_as_a_fact():
    _, imported, after = _read(_change_record("CHG0001", "s1", "-2", "not_required"),
                               _change_record("CHG0002", "s2", "-2", "approved"))
    t = get(after, ticket_dn("servicenow", "CHG0001"))
    assert one(t, "ciamTicketApproval") is None and values(t, "ciamTicketFact")[0] == "approval not_required"
    assert ("approval `not_required` of CHG0001 isn't mapped in servicenow-approval-values: approval unknown (kept as "
            "a fact)") in imported.notices
    tree = (*TREE, _setting(APPROVAL_VALUES.name, "approved=approved, not_required=not-requested"))
    _, _, after = _read(_change_record("CHG0001", "s1", "-2", "not_required"), tree=tree)
    t = get(after, ticket_dn("servicenow", "CHG0001"))
    assert one(t, "ciamTicketApproval") == "not-requested"
    assert "approval not_required" not in values(t, "ciamTicketFact")


def test_one_instance_per_record():
    d, _, after = _read(_change_record("CHG0001", "s1", "-2", "approved"))
    assert instance_hosts(after) == (HOST,) and instance_hosts(d) == ()
    other = read_changes(_export(_change_record("CHG0001", "s1", "-2", "approved"), host="gov.servicenowservices.test"),
                         after, (), AT)
    assert (other.groups, other.notices) == ((), (
        f"the record's ServiceNow tickets were read from {HOST}; this export is from gov.servicenowservices.test: one "
        "instance per record (ticket numbers are only an instance's own)",))
    assert read_changes(_export(_change_record("CHG0001", "s1", "-1", "approved")), after, (), AT).groups
    hostless = read_changes(_export(_change_record("CHG0001", "s1", "-1", "approved"), host=None), after, (), AT)
    assert (f"no instance folder (<host>/change_request/...): the tickets' addresses aren't recorded, nor is it "
            f"checked that they are {HOST}'s") in hostless.notices


def test_a_client_certificate_reads_the_instance_with_no_login():
    _, alpha, _ = model(alpha=_source(ciamCredentialScheme="client-certificate"), tree=TREE)
    assert source_problems(alpha.d, alpha, {}) == ()
    assert change_steps(alpha.d, alpha, {}, {})[0][1].credential == ("client-certificate", "fake://kv/itsm-reader",
                                                                     "opsdir.reader")


# ------------------------------------------------------------------ work tickets: drafts and read-back
TABLE = "u_ciam_remediation"
GROUP = "0123456789abcdef0123456789abcdef"
WORK_TREE = (*TREE, _setting(TICKET_TABLE.name, TABLE), _setting(TICKET_STATES.name, "1=new, 2=implement, 3=closed, "
                                                                 "4=closed, 7=cancelled"),
             _setting(TICKET_GROUPS.name, f"Platform={GROUP}, network=Network Ops"),
             _setting(TICKET_FIELDS.name, "impact=3, urgency=3, due_date=2030-01-01 00:00:00"),
             *_changes(("CHG-4", "RMD0001")))
REQUEST = TicketRequest("platform", "cn=Platform,ou=owners,dc=ciam-ops", "CIAM: 2 findings for platform (a to b)",
                        (("action", "Certificates", "Renew the signing certificate", dt.date(2026, 11, 1)),
                         ("blocker", "Network", "Open 636", None)), dt.date(2026, 11, 1), "a", "b",
                        dt.date(2026, 10, 18))


def _work_record(number, sys_id, state, **extra):
    return {"number": _v(number), "sys_id": _v(sys_id), "state": _v(state, f"label {state}"),
            "short_description": _v(f"Work {number}"), "due_date": _v("2026-11-01 23:59:59", "11/01/2026 19:59:59"),
            "work_start": _v("2026-09-20 08:00:00"), "work_end": _v(""), "assignment_group": _v(GROUP, "Platform"),
            "assigned_to": _v(""), "priority": _v("4", "4 - Low"), "impact": _v("3"), "urgency": _v("3"),
            "sys_class_name": _v(TABLE), "closed_at": _v(""), "sys_updated_on": _v("2026-09-20 08:00:00"), **extra}


def test_a_draft_is_the_table_api_create_body_for_the_teams_group():
    d = model(tree=WORK_TREE)[0]
    draft = ticket_draft(d, REQUEST)
    assert json.loads(draft.body) == {
        "short_description": REQUEST.title, "description": "\n".join(request_lines(REQUEST)),
        "assignment_group": GROUP, "due_date": "2026-11-01 23:59:59", "impact": "3", "urgency": "3"}
    assert draft.extension == "json"
    assert draft.problems == ("servicenow-ticket-fields: `due_date` is drafted from the findings: its default is left "
                              "out",)
    assert draft.how[0] == f"POST https://<instance host>/api/now/table/{TABLE}?sysparm_input_display_value=false"
    assert "--data-binary @servicenow/<team>.json" in draft.how[1] and "<access token>" in draft.how[1]
    undated = json.loads(ticket_draft(d, REQUEST._replace(do_by=None)).body)
    assert "due_date" not in undated                   # neither the findings' nor the operator's default


def test_a_draft_names_the_setting_that_keeps_it_from_being_written():
    d = model(tree=WORK_TREE)[0]
    network = ticket_draft(d, REQUEST._replace(team="network"))
    assert network.body is None and network.problems == (
        "servicenow-ticket-groups: network's group `Network Ops` isn't a sys_id (32 hex characters): drafts post raw "
        "values, so give the group's sys_id, `opsdir setting servicenow-ticket-groups '<team>=<group sys_id>, ...' "
        "--change CHG-…`", "servicenow-ticket-fields: `due_date` is drafted from the findings: its default is left out")
    nobody = ticket_draft(d, REQUEST._replace(team="Identity"))
    assert nobody.body is None and nobody.problems[0].startswith(
        "servicenow-ticket-groups names no assignment group for Identity: add `Identity=<group sys_id>` to it")
    bare = ticket_draft(model(tree=TREE)[0], REQUEST)
    assert bare.body is None and bare.how == () and bare.problems[0] == (
        "servicenow-ticket-table isn't set: name the site-approved table derived from task that work tickets are "
        "filed in, `opsdir setting servicenow-ticket-table '<table>' --change CHG-…`")
    wrong = ticket_draft(model(tree=(*TREE, _setting(TICKET_TABLE.name, "change_request")))[0], REQUEST)
    assert wrong.body is None and wrong.problems[0].startswith("servicenow-ticket-table: `change_request` isn't a "
                                                                "table work tickets can be filed in")
    assert work_table(model(tree=WORK_TREE)[0]) == (TABLE, ())


def test_a_linked_work_ticket_is_read_back_from_the_work_ticket_table():
    d, _, _ = model(tree=WORK_TREE)
    files = {**_export(_change_record("CHG0001", "s1", "-2", "approved")),
             f"{HOST}/{TABLE}/0-0.json": _answer([_work_record("RMD0001", "w1", "2"),
                                                  _work_record("RMD0099", "w9", "1")])}
    imported = read_changes(files, d, (), AT)
    after = after_import(d, imported)
    t = get(after, ticket_dn("servicenow", "RMD0001"))
    assert dict(t.attrs) == {
        "cn": ("RMD0001",), "ciamImportedAt": ("20260923090000Z",), "ciamTitle": ("Work RMD0001",),
        "ciamProviderRef": ("w1",), "ciamDocUrl": (f"https://{HOST}/api/now/table/{TABLE}/w1",),
        "ciamTicketKind": ("work",), "ciamTicketState": ("implement",), "ciamTicketNativeState": ("2 label 2",),
        "ciamTicketDue": ("20261101235959Z",), "ciamTicketWorkStart": ("20260920080000Z",),
        "ciamTicketFact": (f"assignment_group {GROUP}", "priority 4", "impact 3", "urgency 3",
                           f"sys_class_name {TABLE}", "sys_updated_on 2026-09-20 08:00:00")}
    assert is_work(t) and one(get(after, ticket_dn("servicenow", "CHG0001")), "ciamTicketKind") is None
    assert "not linked to a change record: RMD0099 (left out)" in imported.notices
    assert "linked but not in the export: CHG0002, CHG0003 (the record keeps what it last read; nothing is " \
           "removed)" in imported.notices
    assert [lk.states for lk in linked(after) if lk.number == "RMD0001"] == [(IN_STEP,)]   # no approval to compare


def test_work_ticket_states_unmapped_display_only_and_both_tables_are_named():
    d, _, _ = model(tree=WORK_TREE)
    files = {**_export(_change_record("CHG0001", "s1", "-2", "approved")),
             f"{HOST}/{TABLE}/0-0.json": _answer([_work_record("RMD0001", "w1", "-5"),
                                                  _work_record("CHG0001", "w2", "1")])}
    imported = read_changes(files, d, (), AT)
    assert ("work-ticket state `-5` of RMD0001 isn't mapped in servicenow-ticket-states: kept as ServiceNow gives it "
            "(neutral state unknown)") in imported.notices
    assert f"CHG0001: in both change_request and {TABLE}: read as the change ticket" in imported.notices
    after = after_import(d, imported)
    assert one(get(after, ticket_dn("servicenow", "RMD0001")), "ciamTicketState") is None
    assert not is_work(get(after, ticket_dn("servicenow", "CHG0001")))
    shown = _work_record("RMD0001", "w1", "2", due_date={"display_value": "11/01/2026 19:59:59"},
                         work_start=_v("09/20/2026 04:00:00"))
    hidden = read_changes({f"{HOST}/{TABLE}/0-0.json": _answer([shown])}, d, (), AT)
    assert hidden.groups == () and ("RMD0001: work_start given as display text, not raw values (their time zone is "
                                    "unknown): left out; export raw values (sysparm_display_value=false or all)"
                                    ) in hidden.notices
    unread = read_changes({f"{HOST}/{TABLE}/0-0.json": _answer([{"number": "RMD0001", "sys_id": "w1",
                                                                  "state": "2"}])}, d, (), AT)
    assert any(n.startswith(f"{TABLE}: the answers never carry short_description") for n in unread.notices)


def test_the_collector_also_reads_the_linked_numbers_from_the_work_ticket_table():
    _, alpha, _ = model(alpha=_source(), tree=WORK_TREE)
    first = change_steps(alpha.d, alpha, {}, {})
    assert [p for p, _ in first] == [f"{HOST}/change_request/0-0.json", f"{HOST}/{TABLE}/0-0.json"]
    q = parse_qs(urlsplit(first[1][1].url).query)
    assert urlsplit(first[1][1].url).path == f"/api/now/table/{TABLE}"
    assert q["sysparm_query"] == ["numberINCHG0001,CHG0002,CHG0003,RMD0001^ORDERBYsys_id"]
    assert q["sysparm_fields"] == [",".join(WORK_FIELDS)]
    TABLES[TABLE] = [_work_record("RMD0001", "w1", "3")]
    try:
        c = collect("servicenow/change-requests", COLLECTORS[0], alpha.d, alpha, _serve)
    finally:
        del TABLES[TABLE]
    assert c.problems == () and f"{HOST}/{TABLE}/0-100.json" in c.files
    after = after_import(alpha.d, read_changes(c.files, alpha.d, (), AT))
    assert one(get(after, ticket_dn("servicenow", "RMD0001")), "ciamTicketState") == "closed"
    approvals = [call for call in c.calls if "sysapproval_approver/0-0" in call.path]
    assert parse_qs(urlsplit(approvals[0].provenance[4:]).query)["sysparm_query"] == ["sysapprovalINs1^ORDERBYsys_id"]
