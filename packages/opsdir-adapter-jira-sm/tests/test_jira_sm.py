"""Jira Service Management change requests as ticket evidence: the importer jira-sm/change-requests reads the issues the
record's change records link (REST answers: issues, approval pages, the field list) into their own entries under
ou=tickets through the operator's mapping settings (statuses to neutral states, the site's change fields); the overall
approval is derived from the approval steps' own decisions; the collector reads the site read-only, one GET per
linked issue. Nothing is ever written under ou=changes."""
import datetime as dt
import json
from urllib.parse import parse_qs, urlsplit

from opsdir.connectors.collecting import collect
from opsdir.core.directory import get, one, subtree, values, within
from opsdir.domains.governance.naming import CHANGES
from opsdir.domains.governance.tickets import IN_STEP, REJECTED, UNAPPROVED, linked, ticket_dn, ticket_rows
from opsdir_adapter_jira_sm.adapter import ADAPTER
from opsdir_adapter_jira_sm.changes import (CHANGES_IMPORTER, approval_key, field_text, jira_error, jira_time,
                                            overall_approval, read_changes)
from opsdir_adapter_jira_sm.collect import (COLLECTORS, approval_view, change_steps, is_cloud, issue_view,
                                            source_problems)
from opsdir_adapter_jira_sm.mapping import (CHANGE_FIELDS, STATUS_STATES, field_refs, resolve_fields, setting_pairs,
                                            status_states)
from network_fixtures import ALPHA, entry, model
from support import after_import

AT = dt.datetime(2026, 9, 23, 9, 0, tzinfo=dt.timezone.utc)
SITE = "example-aero.atlassian.net"
FIELDS = [{"id": "summary", "name": "Summary", "custom": False},
          {"id": "customfield_10070", "name": "Planned start", "custom": True,
           "schema": {"type": "datetime", "custom": "com.atlassian.jira.plugin.system.customfieldtypes:datetime"}},
          {"id": "customfield_10071", "name": "Planned end", "custom": True},
          {"id": "customfield_10072", "name": "Actual start", "custom": True},
          {"id": "customfield_10073", "name": "Actual end", "custom": True},
          {"id": "customfield_10005", "name": "Change type", "custom": True},
          {"id": "customfield_10006", "name": "Change risk", "custom": True},
          {"id": "customfield_10090", "name": "Approvers", "custom": True},
          {"id": "customfield_10091", "name": "Approvers", "custom": True}]
STATES = "10010=assess, Awaiting CAB approval=authorize, 10012=scheduled, Implementing=implement, 10015=closed"
MAP = ("planned-start=customfield_10070, planned-end=Planned end, work-start=customfield_10072, "
       "work-end=Actual end, change-type=Change type, risk=customfield_10006")


def _setting(name, value):
    return (f"dn: cn={name},ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamObject\n"
            f"objectClass: ciamEstateSetting\ncn: {name}\nciamEstateValue: {value}\n")


def _changes(*links):
    return tuple(f"dn: cn={cn},{CHANGES}\nobjectClass: top\nobjectClass: ciamChange\ncn: {cn}\nciamTitle: {cn}\n"
                 f"ciamChangeStatus: approved\nciamTicketRef: jira-sm:{k}\nciamPlannedAt: 20260924000000Z\n"
                 for cn, k in links)


TREE = (f"dn: {CHANGES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: changes\n",
        "dn: ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: settings\n",
        _setting(STATUS_STATES.name, STATES), _setting(CHANGE_FIELDS.name, MAP),
        *_changes(("CHG-1", "ITOPS-1"), ("CHG-2", "ITOPS-2"), ("CHG-3", "ITOPS-3")))


def _issue(key, number, status_id, status_name, **extra):
    return {"id": str(number), "key": key, "self": f"https://{SITE}/rest/api/3/issue/{number}",
            "fields": {"summary": f"Change {key}", "issuetype": {"id": "10002", "name": "Change"},
                       "status": {"id": status_id, "name": status_name,
                                  "statusCategory": {"id": 4, "key": "indeterminate"}},
                       "resolution": None, "created": "2026-09-20T08:00:00.000+0000",
                       "updated": "2026-09-22T10:00:00.000+0000",
                       "customfield_10070": "2026-09-24T02:00:00.000+0000",
                       "customfield_10071": "2026-09-24T08:00:00.000+0200",
                       "customfield_10072": None, "customfield_10073": None,
                       "customfield_10005": {"id": "1", "value": "Normal"},
                       "customfield_10006": {"id": "2", "value": "High"}, **extra}}


def _step(sid, decision, *approvers, completed=None):
    return {"id": sid, "name": "CAB approval", "finalDecision": decision, "canAnswerApproval": False,
            "approvers": [{"approver": {"accountId": a, "displayName": f"Person {a}"}, "approverDecision": d}
                          for a, d in approvers],
            "createdDate": {"iso8601": "2026-09-21T10:00:00+0200", "friendly": "Monday"},
            **({"completedDate": {"iso8601": completed}} if completed else {})}


def _page(*steps, last=True, start=0):
    return json.dumps({"start": start, "limit": 50, "size": len(steps), "isLastPage": last, "values": list(steps)})


APPROVED = _page(_step("1", "approved", ("acc-1", "approved"), completed="2026-09-22T09:00:00+0000"))


def _export(*issues, approvals=None):
    return {f"{SITE}/field.json": json.dumps(FIELDS),
            **{f"{SITE}/issue/{i['key']}.json": json.dumps(i) for i in issues},
            **{f"{SITE}/approval/{k}/0.json": p for k, p in (approvals or {}).items()}}


def _read(*issues, tree=TREE, approvals=None, files=None):
    d, _, _ = model(tree=tree)
    imported = read_changes(files or _export(*issues, approvals=approvals), d, (), AT)
    return d, imported, after_import(d, imported)


def test_registered_as_an_itsm_add_on_with_its_importer_collector_and_mapping_settings():
    assert (ADAPTER.name, ADAPTER.kind, ADAPTER.applies, ADAPTER.importers, ADAPTER.collectors, ADAPTER.settings) == (
        "jira-sm", "itsm", None, (CHANGES_IMPORTER,), COLLECTORS, (STATUS_STATES, CHANGE_FIELDS))
    assert STATUS_STATES.default is None and CHANGE_FIELDS.default is None     # the operator's to say


def test_a_linked_issue_is_read_as_evidence_through_the_mapping():
    d, imported, after = _read(_issue("ITOPS-1", 10001, "10012", "Awaiting implementation"),
                               _issue("ITOPS-9", 10009, "10012", "Awaiting implementation"),
                               approvals={"ITOPS-1": APPROVED})
    t = get(after, ticket_dn("jira-sm", "ITOPS-1"))
    assert dict(t.attrs) == {
        "cn": ("ITOPS-1",), "ciamImportedAt": ("20260923090000Z",), "ciamTitle": ("Change ITOPS-1",),
        "ciamProviderRef": ("10001",), "ciamDocUrl": (f"https://{SITE}/rest/api/3/issue/10001",),
        "ciamTicketState": ("scheduled",), "ciamTicketApproval": ("approved",),
        "ciamTicketNativeState": ("10012 Awaiting implementation",), "ciamTicketChangeType": ("normal",),
        "ciamTicketPlannedStart": ("20260924020000Z",), "ciamTicketPlannedEnd": ("20260924060000Z",),
        "ciamTicketApprovalStep": ("approved 1 created 20260921080000Z completed 20260922090000Z",),
        "ciamTicketApprover": ("approved acc-1 step 1",),
        "ciamTicketFact": ("issuetype Change", "status-category indeterminate", "created 2026-09-20T08:00:00.000+0000",
                           "updated 2026-09-22T10:00:00.000+0000", "risk High")}
    assert get(after, ticket_dn("jira-sm", "ITOPS-9")) is None
    assert "not linked to a change record: ITOPS-9 (left out)" in imported.notices
    assert ("linked but not in the export: ITOPS-2, ITOPS-3 (the record keeps what it last read; nothing is removed)"
            in imported.notices)
    assert f"1 ticket(s) read from https://{SITE}" in imported.notices
    assert not any(within(g[0], CHANGES) for g in imported.groups)       # evidence never lands on a change record
    assert {e.dn: e for e in subtree(after, CHANGES)} == {e.dn: e for e in subtree(d, CHANGES)}


def test_the_overall_approval_comes_from_the_steps_decisions_never_an_approvers():
    assert overall_approval((), "scheduled") is None                         # no steps: unknown, never not-requested
    assert overall_approval(({"finalDecision": "approved"}, {"finalDecision": "declined"}), "scheduled") == "rejected"
    assert overall_approval(({"finalDecision": "approved"}, {"finalDecision": "pending"}), "closed") == "requested"
    assert overall_approval(({"finalDecision": "approved"},), "scheduled") == "approved"
    assert overall_approval(({"finalDecision": "approved"},), "authorize") is None    # a later step may still come
    assert overall_approval(({"finalDecision": "approved"},), None) is None
    pending = _page(_step("7", "pending", ("acc-1", "approved"), ("acc-2", "pending")))
    _, _, after = _read(_issue("ITOPS-2", 10002, "10011", "Awaiting CAB approval"), approvals={"ITOPS-2": pending})
    t = get(after, ticket_dn("jira-sm", "ITOPS-2"))
    assert one(t, "ciamTicketApproval") == "requested" and one(t, "ciamTicketState") == "authorize"
    assert values(t, "ciamTicketApprover") == ("approved acc-1 step 7", "pending acc-2 step 7")
    assert "Person" not in "".join(values(t, "ciamTicketApprover"))     # identifiers, never names


def test_drift_follows_from_what_was_read():
    declined = _page(_step("3", "declined", ("acc-3", "declined"), completed="2026-09-22T12:00:00+0000"))
    pending = _page(_step("4", "pending", ("acc-4", "pending")))
    _, _, after = _read(_issue("ITOPS-1", 10001, "10012", "Awaiting implementation"),
                        _issue("ITOPS-2", 10002, "10011", "Awaiting CAB approval"),
                        _issue("ITOPS-3", 10003, "10013", "Declined"),
                        approvals={"ITOPS-1": APPROVED, "ITOPS-2": pending, "ITOPS-3": declined})
    assert {one(link.change, "cn"): link.states for link in linked(after)} == {
        "CHG-1": (IN_STEP,), "CHG-2": (UNAPPROVED,), "CHG-3": (REJECTED,)}
    rows = {r[0]: r for r in ticket_rows(after)}
    assert rows["CHG-3"][4:6] == ("unknown (10013 Declined)", "rejected (steps: 1 declined)")
    assert rows["CHG-1"][5] == "approved (steps: 1 approved)"


def test_an_unmapped_status_keeps_its_state_native_and_approval_waits_on_it():
    _, imported, after = _read(_issue("ITOPS-1", 10001, "10099", "Peer review"), approvals={"ITOPS-1": APPROVED})
    t = get(after, ticket_dn("jira-sm", "ITOPS-1"))
    assert (one(t, "ciamTicketState"), one(t, "ciamTicketNativeState"), one(t, "ciamTicketApproval")) == (
        None, "10099 Peer review", None)                                 # never taken as closed, nor approved
    assert ("status 10099 Peer review isn't mapped in jira-sm-status-states: the state of ITOPS-1 is kept as Jira "
            "gives it (neutral state unknown)") in imported.notices


def test_approvals_missing_or_short_of_their_last_page_leave_the_approval_unknown():
    short = _page(_step("1", "approved", ("acc-1", "approved")), last=False)
    _, imported, after = _read(_issue("ITOPS-1", 10001, "10012", "Awaiting implementation"),
                               _issue("ITOPS-2", 10002, "10012", "Awaiting implementation"),
                               approvals={"ITOPS-1": short})
    for key in ("ITOPS-1", "ITOPS-2"):
        assert one(get(after, ticket_dn("jira-sm", key)), "ciamTicketApproval") is None
    assert ("approvals not in the export, or not to their last page, for: ITOPS-1, ITOPS-2 (overall approval "
            "unknown)") in imported.notices


def test_the_mapping_is_the_operators_and_its_problems_are_named():
    assert setting_pairs("a=b, ,c, =d, e=") == ((("a", "b"),), ("`c` isn't <name>=<value>", "`=d` isn't <name>=<value>",
                                                                  "`e=` isn't <name>=<value>"))
    tree = (*TREE[:2], _setting(STATUS_STATES.name, "10010=assess, 10010=closed, 10011=done"),
            _setting(CHANGE_FIELDS.name, "planned-start=Approvers, Work_End=customfield_1, risk=Nope"), *TREE[4:])
    d, _, _ = model(tree=tree)
    assert status_states(d) == ({"10010": "assess"}, (
        "jira-sm-status-states: `10010` is mapped more than once (the first is used)",
        "jira-sm-status-states: `10011=done`: done isn't a ticket state (new, assess, authorize, scheduled, implement, "
        "review, closed, cancelled)"))
    refs, problems = field_refs(d)
    assert refs == {"planned-start": "Approvers", "risk": "Nope"}
    assert problems == ("jira-sm-change-fields: `Work_End` isn't a role name (lowercase letters, digits and dashes)",)
    assert resolve_fields(refs, tuple(FIELDS)) == ({}, (
        "jira-sm-change-fields: planned-start: 2 fields are named `Approvers` (customfield_10090, customfield_10091): "
        "map it by id", "jira-sm-change-fields: risk: no field `Nope` in the site's field list"))
    assert resolve_fields({"a": "customfield_7", "b": "Planned start"}, None) == ({"a": "customfield_7"}, (
        "jira-sm-change-fields: b: no field `Planned start` (without the site's field list only a customfield_N id is "
        "read)",))
    _, imported, after = _read(_issue("ITOPS-1", 10001, "10010", "Planning"), tree=tree)
    t = get(after, ticket_dn("jira-sm", "ITOPS-1"))
    assert one(t, "ciamTicketPlannedStart") is None and one(t, "ciamTicketState") == "assess"
    assert ("jira-sm-change-fields maps no planned-start, planned-end, work-start, work-end field: those times aren't "
            "read (the site's fields named like them: Actual end (customfield_10073), Actual start "
            "(customfield_10072), Planned end (customfield_10071), Planned start (customfield_10070))"
            ) in imported.notices


def test_times_carry_their_offsets_and_a_date_alone_is_refused():
    assert jira_time("2026-09-24T08:00:00.000+0200") == ("20260924060000Z", None)
    assert jira_time("2026-09-24") == (None, "a date without a time (its time zone is unknown): map a date-time field")
    assert jira_time("soon") == (None, "`soon` isn't a date-time")
    _, imported, after = _read(_issue("ITOPS-1", 10001, "10012", "Awaiting implementation",
                                      customfield_10072="2026-09-24", customfield_10005={"value": "Major"}))
    t = get(after, ticket_dn("jira-sm", "ITOPS-1"))
    assert one(t, "ciamTicketWorkStart") is None and one(t, "ciamTicketChangeType") is None
    assert "change-type Major" in values(t, "ciamTicketFact")
    assert ("ITOPS-1: work-start (customfield_10072): a date without a time (its time zone is unknown): map a "
            "date-time field") in imported.notices
    assert "ITOPS-1: change-type `Major` isn't standard, normal or emergency: kept as a fact" in imported.notices


def test_field_values_become_ids_never_names():
    assert field_text({"accountId": "acc-9", "displayName": "A Person"}) == "acc-9"
    assert field_text([{"value": "Payments"}, {"value": "Crew"}]) == "Payments,Crew"
    assert field_text({"key": "JIRAUSER1", "name": "aperson"}) == "JIRAUSER1"
    assert field_text(None) == "" and field_text(3) == "3"


def test_saved_answers_errors_unknown_files_dating_and_sites_are_named():
    d, _, _ = model(tree=TREE)
    search = json.dumps({"issues": [_issue("ITOPS-1", 10001, "10012", "Awaiting implementation")], "isLast": True})
    files = {"search-1.json": search, "approval-ITOPS-1.json": APPROVED, "fields.json": json.dumps(FIELDS),
             "approval/ITOPS-2/0.json": json.dumps({"errorMessage": "You do not have permission"}),
             "issue/ITOPS-3.json": json.dumps({"errorMessages": ["Issue does not exist"], "errors": {}}),
             "notes.json": json.dumps({"hello": 1}), "readme.txt": "x"}
    imported = read_changes(files, d, (), AT)
    t = get(after_import(d, imported), ticket_dn("jira-sm", "ITOPS-1"))
    assert one(t, "ciamTicketApproval") == "approved"
    assert "approval/ITOPS-2/0.json: Jira answered an error: You do not have permission" in imported.notices
    assert "issue/ITOPS-3.json: Jira answered an error: Issue does not exist" in imported.notices
    assert ("notes.json: isn't a Jira answer (an issue, a search answer, an approval page under approval/<KEY>/ or "
            "the field list)") in imported.notices
    assert read_changes(files, d, (), None).notices == ("ticket evidence is dated: give --at (when the export was "
                                                        "taken)",)
    other = _issue("ITOPS-2", 10002, "10012", "x")
    two = {**files, "other.json": json.dumps({**other, "self": "https://other.atlassian.net/rest/api/3/issue/1"})}
    assert read_changes(two, d, (), AT).groups == ()
    assert (approval_key("x/approval/ITOPS-4/50.json"), approval_key("approval-AB_1-22-page2.json"),
            approval_key("approvals.json")) == ("ITOPS-4", "AB_1-22", None)
    assert jira_error([1]) is None and jira_error({"values": [], "errorMessage": "x"}) is None


def test_fields_the_issues_never_carry_are_named():
    issue = _issue("ITOPS-1", 10001, "10012", "Awaiting implementation")
    issue["fields"].pop("customfield_10006")
    _, imported, _ = _read(issue)
    assert ("the issues never carry customfield_10006 (risk) (a field the reader can't see, or not on the change "
            "screens)") in imported.notices


def _source(url=f"https://{SITE}", **extra):
    return (entry(ALPHA, "itsm", "ciamCollectionSource", ciamBindingRole="itsm",
                  ciamImporter="jira-sm/change-requests", ciamSourceRef=url, ciamCredentialRole="itsm-reader",
                  ciamLoginName="opsdir.reader@example-aero.test", **extra),
            entry(ALPHA, "itsm-reader", "ciamSecretRef", ciamBindingRole="itsm-reader",
                  ciamRefUri="fake://kv/itsm-reader"))


ISSUES = {"ITOPS-1": _issue("ITOPS-1", 10001, "10012", "Awaiting implementation", secret_note="not kept",
                            customfield_10006={"value": "High", "self": "https://x", "emailAddress": "a@b"})}
STEPS = {"ITOPS-1": [_step(str(i), "approved", ("acc-1", "approved")) for i in range(1, 4)]}


def _serve(request):
    url = urlsplit(request.url)
    q = parse_qs(url.query)
    if url.path.endswith("/field"):
        return json.dumps(FIELDS), None
    if "/approval" in url.path:
        key, start, limit = url.path.split("/")[-2], int(q["start"][0]), 2
        steps = STEPS.get(key, [])[start:start + limit]
        return json.dumps({"start": start, "limit": limit, "size": len(steps), "values": steps,
                           "isLastPage": start + limit >= len(STEPS.get(key, []))}), None
    key = url.path.rsplit("/", 1)[1]
    return (json.dumps(ISSUES[key]), None) if key in ISSUES else (None, None)       # 404: absent


def test_the_collector_reads_the_field_list_then_each_linked_issue_then_its_approval_pages():
    _, alpha, _ = model(alpha=_source(), tree=TREE)
    first = change_steps(alpha.d, alpha, {}, {})
    assert [p for p, _ in first] == [f"{SITE}/field.json"]
    assert first[0][1].url == f"https://{SITE}/rest/api/3/field"
    assert first[0][1].credential == ("basic", "fake://kv/itsm-reader", "opsdir.reader@example-aero.test")
    second = change_steps(alpha.d, alpha, {f"{SITE}/field.json": json.dumps(FIELDS)}, {})
    issue = dict(second)[f"{SITE}/issue/ITOPS-2.json"]
    assert issue.url == (f"https://{SITE}/rest/api/3/issue/ITOPS-2?fields=summary,status,resolution,issuetype,created,"
                         "updated,customfield_10005,customfield_10006,customfield_10070,customfield_10071,"
                         "customfield_10072,customfield_10073")
    assert issue.absent == (404,)
    c = collect("jira-sm/change-requests", COLLECTORS[0], alpha.d, alpha, _serve)
    assert c.problems == ()
    assert sorted(c.files) == [f"{SITE}/approval/ITOPS-1/0.json", f"{SITE}/approval/ITOPS-1/2.json",
                               f"{SITE}/field.json", f"{SITE}/issue/ITOPS-1.json"]
    kept = "".join(c.files.values())
    assert "secret_note" not in kept and "emailAddress" not in kept and "Person acc-1" not in kept
    after = after_import(alpha.d, read_changes(c.files, alpha.d, (), AT))
    t = get(after, ticket_dn("jira-sm", "ITOPS-1"))
    assert one(t, "ciamTicketApproval") == "approved" and len(values(t, "ciamTicketApprovalStep")) == 3
    assert "risk High" in values(t, "ciamTicketFact")


def test_data_center_and_the_gateway_are_told_apart_by_the_url():
    assert is_cloud(f"https://{SITE}") and is_cloud("https://ops.atlassian-us-gov-mod.net")
    assert is_cloud("https://api.atlassian.com/ex/jira/1234-abcd") and not is_cloud("https://jira.example-aero.test")
    _, dc, _ = model(alpha=_source("https://jira.example-aero.test/", ciamCredentialScheme="bearer"), tree=TREE)
    steps = dict(change_steps(dc.d, dc, {"jira.example-aero.test/field.json": json.dumps(FIELDS),
                                         "jira.example-aero.test/issue/ITOPS-1.json": json.dumps(ISSUES["ITOPS-1"])},
                              {}))
    assert steps["jira.example-aero.test/field.json"].url == "https://jira.example-aero.test/rest/api/2/field"
    assert steps["jira.example-aero.test/approval/ITOPS-1/0.json"].url == (
        "https://jira.example-aero.test/rest/servicedeskapi/request/ITOPS-1/approval?start=0&limit=50")
    assert steps["jira.example-aero.test/field.json"].credential[0] == "bearer"


def test_projections_keep_only_what_the_importer_reads():
    view = issue_view(("status",))({"id": "1", "key": "A-1", "self": "s", "expand": "x",
                                    "fields": {"status": {"id": "3", "name": "Open", "iconUrl": "u",
                                                          "statusCategory": {"key": "new", "colorName": "blue"}},
                                               "description": "secret"}})
    assert view == {"id": "1", "key": "A-1", "self": "s",
                    "fields": {"status": {"id": "3", "name": "Open", "statusCategory": {"key": "new"}}}}
    page = approval_view({"start": 0, "isLastPage": True, "_links": {}, "values": [
        {"id": "1", "name": "CAB", "finalDecision": "approved", "createdDate": {"iso8601": "t", "friendly": "f"},
         "approvers": [{"approver": {"key": "JIRAUSER1", "name": "aperson", "displayName": "A"},
                        "approverDecision": "approved"}]}]})
    assert page == {"start": 0, "isLastPage": True, "values": [
        {"id": "1", "finalDecision": "approved", "createdDate": {"iso8601": "t"},
         "approvers": [{"approver": {"key": "JIRAUSER1"}, "approverDecision": "approved"}]}]}


def test_a_scheme_the_site_isnt_read_with_here_is_refused_with_why():
    _, alpha, _ = model(alpha=_source(ciamCredentialScheme="token"), tree=TREE)
    assert source_problems(alpha.d, alpha, {}) == (
        "collection source `itsm`: credential scheme `token`: the site is read with basic (an account's email and API "
        "token, or a Data Center user's password) or bearer (a Data Center personal access token, or an OAuth or "
        "scoped token minted outside opsdir)",)
    assert change_steps(alpha.d, alpha, {}, {}) == ()
