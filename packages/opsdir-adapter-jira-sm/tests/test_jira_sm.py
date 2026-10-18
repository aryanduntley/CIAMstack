"""Jira Service Management change requests as ticket evidence: the importer jira-sm/change-requests reads the issues the
record's change records link (REST answers: issues, approval pages, the field list) into their own entries under
ou=tickets through the operator's mapping settings (statuses to neutral states, the site's change fields); the overall
approval is derived from the approval steps' own decisions; the collector reads the site read-only, one GET per
linked issue. Nothing is ever written under ou=changes."""
import datetime as dt
import json
from urllib.parse import parse_qs, urlsplit

from opsdir.connectors.collecting import collect
from opsdir.connectors.handoff import handoff_files
from opsdir.core.contract import TicketRequest
from opsdir.core.directory import get, one, subtree, values, within
from opsdir.domains.governance.naming import CHANGES
from opsdir.domains.governance.tickets import IN_STEP, REJECTED, UNAPPROVED, linked, ticket_dn, ticket_rows
from opsdir_adapter_jira_sm.adapter import ADAPTER
from opsdir_adapter_jira_sm.changes import (CHANGES_IMPORTER, approval_key, field_text, jira_error, jira_time,
                                            overall_approval, read_changes)
from opsdir_adapter_jira_sm.collect import (COLLECTORS, approval_view, change_steps, is_cloud, issue_view,
                                            source_problems)
from opsdir_adapter_jira_sm.drafts import (FIELDS as TICKET_FIELDS, PROJECTS, SETTINGS as DRAFT_SETTINGS,
                                           SITE as TICKET_SITE,
                                           TEAM_FIELD, adf_description, field_value, ticket_draft, wiki_description)
from opsdir_adapter_jira_sm.mapping import (CHANGE_FIELDS, ISSUE_TYPE, STATUS_STATES, field_refs, resolve_fields,
                                            setting_pairs, status_states)
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
    assert (ADAPTER.name, ADAPTER.kind, ADAPTER.applies, ADAPTER.importers, ADAPTER.collectors, ADAPTER.settings,
            ADAPTER.ticket_draft) == ("jira-sm", "itsm", None, (CHANGES_IMPORTER,), COLLECTORS,
                                      (STATUS_STATES, CHANGE_FIELDS, ISSUE_TYPE, *DRAFT_SETTINGS), ticket_draft)
    assert all(s.default is None for s in ADAPTER.settings)                     # the operator's to say


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
                         "updated,duedate,customfield_10005,customfield_10006,customfield_10070,customfield_10071,"
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


# ------------------------------------------------------------------ work-ticket drafts and their read-back (task 612)
AS_OF = dt.date(2026, 10, 18)
ITEMS = (("blocker", "Network", "Open 636 to the directory", None),
         ("action", "Certificates", "Renew the [signing] certificate *now*", dt.date(2026, 11, 1)),
         ("action", "Allowlist", "Ask the partner to add 10.0.0.0/24", dt.date(2026, 10, 25)))
REQUEST = TicketRequest("Platform", "cn=Platform,ou=owners,dc=ciam-ops",
                        "CIAM: 3 findings for Platform (aws/prod to azure/prod)", ITEMS, dt.date(2026, 10, 25),
                        "aws/prod", "azure/prod", AS_OF)
DRAFTING = {TICKET_SITE.name: f"https://{SITE}/", PROJECTS.name: "platform=CIAM/value:Identity, network=NET",
            TEAM_FIELD.name: "customfield_10100", ISSUE_TYPE.name: "10002",
            TICKET_FIELDS.name: "priority=id:3, labels=list:ciam|remediation"}


def _drafting(**settings):
    given = {**DRAFTING, **settings}
    return model(tree=(*TREE, *(_setting(k, v) for k, v in given.items() if v is not None)))[0]


def test_a_cloud_draft_is_a_task_issue_with_an_adf_description():
    t = ticket_draft(_drafting(), REQUEST)
    assert t.problems == () and t.extension == "json"
    fields = json.loads(t.body)["fields"]
    assert {k: v for k, v in fields.items() if k != "description"} == {
        "project": {"key": "CIAM"}, "issuetype": {"id": "10002"}, "customfield_10100": {"value": "Identity"},
        "summary": "CIAM: 3 findings for Platform (aws/prod to azure/prod)", "duedate": "2026-10-25",
        "priority": {"id": "3"}, "labels": ["ciam", "remediation"]}
    doc = fields["description"]
    assert (doc["type"], doc["version"]) == ("doc", 1)
    assert [b["type"] for b in doc["content"]] == ["paragraph", "heading", "bulletList", "paragraph"]
    items = [i["content"][0]["content"][0]["text"] for i in doc["content"][2]["content"]]
    assert items == ["[action] Allowlist: Ask the partner to add 10.0.0.0/24 (do by 2026-10-25)",
                     "[action] Certificates: Renew the [signing] certificate *now* (do by 2026-11-01)",
                     "[blocker] Network: Open 636 to the directory"]
    assert t.how[0] == f"POST https://{SITE}/rest/api/3/issue (Jira Cloud, REST v3: the description is ADF)"
    assert t.how[1] == (f"curl --request POST 'https://{SITE}/rest/api/3/issue' --user '<email>:<api-token>' "
                        "--header 'Accept: application/json' --header 'Content-Type: application/json' "
                        "--data-binary @jira-sm/<team>.json")
    assert "Bearer" not in t.body and "token" not in t.body                 # never a credential in a draft


def test_a_data_center_draft_has_a_wiki_description_and_a_pat_curl():
    d = _drafting(**{TICKET_SITE.name: "https://jira.example-aero.test/jira", ISSUE_TYPE.name: "CIAM=10105, NET=10002",
                     TEAM_FIELD.name: "components", PROJECTS.name: "Platform=CIAM/names:IAM|Directory"})
    t = ticket_draft(d, REQUEST)
    fields = json.loads(t.body)["fields"]
    assert (fields["issuetype"], fields["components"]) == ({"id": "10105"}, [{"name": "IAM"}, {"name": "Directory"}])
    assert fields["description"].split("\n\n")[1].splitlines() == [
        "h2. Findings",
        "* \\[action\\] Allowlist: Ask the partner to add 10.0.0.0/24 (do by 2026-10-25)",
        "* \\[action\\] Certificates: Renew the \\[signing\\] certificate \\*now\\* (do by 2026-11-01)",
        "* \\[blocker\\] Network: Open 636 to the directory"]
    assert t.how[0].startswith("POST https://jira.example-aero.test/jira/rest/api/2/issue (Jira Data Center")
    assert "--header 'Authorization: Bearer <personal-access-token>'" in t.how[1]


def test_the_gateway_and_government_cloud_say_how_they_are_reached():
    gateway = ticket_draft(_drafting(**{TICKET_SITE.name: "https://api.atlassian.com/ex/jira/1234-abcd"}), REQUEST)
    assert "--header 'Authorization: Bearer <access-token>'" in gateway.how[1]
    assert "description" in json.loads(gateway.body)["fields"]
    gov = ticket_draft(_drafting(**{TICKET_SITE.name: "https://ops.atlassian-us-gov-mod.net"}), REQUEST)
    assert isinstance(json.loads(gov.body)["fields"]["description"], dict)          # Cloud: ADF
    assert any("api.atlassian-us-gov-mod.com/ex/jira/<cloudId>" in h and "unconfirmed" in h for h in gov.how)


def test_what_keeps_a_draft_from_being_written_names_the_setting_to_give():
    none = ticket_draft(_drafting(**{k: None for k in DRAFTING}), REQUEST)
    assert none.body is None and none.how == ()
    assert none.problems == (
        "no jira-sm-ticket-site: the base URL of the Jira site the tickets are filed on (`opsdir setting "
        "jira-sm-ticket-site https://<site>.atlassian.net --change <id>`)",
        "jira-sm-ticket-projects names no project for Platform (`opsdir setting jira-sm-ticket-projects '<team>="
        "<project key>[/<team field value>], ...' --change <id>`, every team in one value)")
    no_type = ticket_draft(_drafting(**{ISSUE_TYPE.name: "NET=10002"}), REQUEST)
    assert no_type.body is None and no_type.how and no_type.problems[0].startswith(
        "jira-sm-ticket-issue-type names no issue type for project CIAM (its Task type's id, from GET "
        "/rest/api/3/issue/createmeta/CIAM/issuetypes")
    no_field = ticket_draft(_drafting(**{TEAM_FIELD.name: None}), REQUEST)
    assert no_field.body is None and no_field.problems == (
        "Platform's value in jira-sm-ticket-projects needs its field: `opsdir setting jira-sm-ticket-team-field "
        "customfield_<n> --change <id>`",)
    bad = ticket_draft(_drafting(**{TICKET_SITE.name: "atlassian.net", PROJECTS.name: "Platform=ciam"}), REQUEST)
    assert bad.body is None and "jira-sm-ticket-site: `atlassian.net` isn't a site's base URL" in bad.problems[0]
    assert "jira-sm-ticket-projects: `Platform=ciam`: ciam isn't a project key" in bad.problems


def test_defaults_the_draft_sets_itself_or_cant_read_are_named_and_left_out():
    t = ticket_draft(_drafting(**{TICKET_FIELDS.name: "summary=x, Story Points=3, customfield_7=number:x, "
                                                      "customfield_8=number:5, environment=text:id:9"}), REQUEST)
    fields = json.loads(t.body)["fields"]
    assert (fields["summary"], fields["customfield_8"], fields["environment"]) == (REQUEST.title, 5, "id:9")
    assert "customfield_7" not in fields
    assert t.problems == ("jira-sm-ticket-fields: `Story Points` isn't a field id (customfield_N, or a system field's "
                          "id)", "jira-sm-ticket-fields: `summary` is set by the draft itself (left out)",
                          "jira-sm-ticket-fields: customfield_7: `number:x`: `x` isn't a number")
    assert "duedate" not in json.loads(ticket_draft(_drafting(), REQUEST._replace(do_by=None)).body)["fields"]


def test_field_values_take_their_shape_and_text_stays_text():
    assert [field_value(v)[0] for v in ("High", "id:3", "values:a|b", "list:x| y", "number:2.5", "https://x",
                                        "accountId:5b10")] == [
        "High", {"id": "3"}, [{"value": "a"}, {"value": "b"}], ["x", "y"], 2.5, "https://x", {"accountId": "5b10"}]
    lines = ("Intro", "", "- one", "- two", "", "Closing")
    assert [b["type"] for b in adf_description(lines)["content"]] == ["paragraph", "heading", "bulletList",
                                                                      "paragraph"]
    assert wiki_description(lines) == "Intro\n\nh2. Findings\n* one\n* two\n\nClosing"


def test_handed_off_drafts_are_written_per_team_with_how_to_file_them():
    d = _drafting()
    plan = type("Plan", (), {})()
    plan.src, plan.dst = type("S", (), {"label": "aws/prod"})(), type("S", (), {"label": "azure/prod"})()
    plan.as_of, plan.blockers = AS_OF, (("Network", "Open 636 to the directory", "network"),)
    plan.actions = (("Certificates", "Renew the signing certificate", "Platform", dt.date(2026, 11, 1)),
                    ("Docs", "Write the runbook", "ops", None))
    files = handoff_files(d, plan, (ADAPTER,))
    assert sorted(files) == ["tickets/README.md", "tickets/jira-sm/Platform.json", "tickets/jira-sm/network.json"]
    assert json.loads(files["tickets/jira-sm/network.json"])["fields"]["project"] == {"key": "NET"}
    readme = files["tickets/README.md"]
    assert "- **not complete for ops**: jira-sm-ticket-projects names no project for ops" in readme
    assert f"    POST https://{SITE}/rest/api/3/issue (Jira Cloud, REST v3: the description is ADF)" in readme


WORK_TREE = (*TREE, _setting(ISSUE_TYPE.name, "10003"),
             _setting(STATUS_STATES.name, f"{STATES}, To Do=new, In Progress=implement, Done=closed"),
             *_changes(("CHG-4", "CIAM-7")))


def _task(key, number, status_name, duedate="2026-10-25"):
    return {"id": str(number), "key": key, "self": f"https://{SITE}/rest/api/3/issue/{number}",
            "fields": {"summary": f"CIAM: findings {key}", "issuetype": {"id": "10003", "name": "Task"},
                       "status": {"id": "3", "name": status_name, "statusCategory": {"key": "indeterminate"}},
                       "resolution": None, "created": "2026-10-18T08:00:00.000+0000",
                       "updated": "2026-10-19T08:00:00.000+0000", "duedate": duedate}}


def test_a_linked_task_issue_is_read_back_as_a_work_ticket_without_approval():
    d, imported, after = _read(_task("CIAM-7", 20007, "In Progress"),
                               _issue("ITOPS-1", 10001, "10012", "Awaiting implementation"),
                               tree=WORK_TREE, approvals={"ITOPS-1": APPROVED})
    t = get(after, ticket_dn("jira-sm", "CIAM-7"))
    assert dict(t.attrs) == {
        "cn": ("CIAM-7",), "ciamImportedAt": ("20260923090000Z",), "ciamTitle": ("CIAM: findings CIAM-7",),
        "ciamProviderRef": ("20007",), "ciamDocUrl": (f"https://{SITE}/rest/api/3/issue/20007",),
        "ciamTicketState": ("implement",), "ciamTicketNativeState": ("3 In Progress",),
        "ciamTicketKind": ("work",), "ciamTicketDue": ("20261025000000Z",),
        "ciamTicketFact": ("issuetype Task", "status-category indeterminate", "created 2026-10-18T08:00:00.000+0000",
                           "updated 2026-10-19T08:00:00.000+0000")}
    change = get(after, ticket_dn("jira-sm", "ITOPS-1"))
    assert one(change, "ciamTicketApproval") == "approved" and one(change, "ciamTicketKind") is None
    assert f"2 ticket(s) read (1 work) from https://{SITE}" in imported.notices
    assert not any("CIAM-7" in n and "approvals" in n for n in imported.notices)    # a work ticket has none to read


def test_a_work_tickets_due_day_must_be_a_day():
    _, imported, after = _read(_task("CIAM-7", 20007, "To Do", duedate="25/10/2026"), tree=WORK_TREE)
    assert one(get(after, ticket_dn("jira-sm", "CIAM-7")), "ciamTicketDue") is None
    assert "CIAM-7: duedate `25/10/2026` isn't a day (YYYY-MM-DD)" in imported.notices


def test_the_collector_asks_no_approvals_of_a_work_ticket():
    _, alpha, _ = model(alpha=_source(), tree=WORK_TREE)
    done = {f"{SITE}/field.json": json.dumps(FIELDS), f"{SITE}/issue/ITOPS-1.json": json.dumps(ISSUES["ITOPS-1"]),
            f"{SITE}/issue/CIAM-7.json": json.dumps(_task("CIAM-7", 7, "To Do"))}
    paths = [p for p, _ in change_steps(alpha.d, alpha, done, {})]
    assert f"{SITE}/approval/ITOPS-1/0.json" in paths and not any("approval/CIAM-7" in p for p in paths)


def test_the_work_issue_type_is_one_id_or_one_per_project():
    from opsdir_adapter_jira_sm.mapping import issue_types
    assert issue_types(_drafting(**{ISSUE_TYPE.name: "10002"})) == ({"*": "10002"}, ())
    assert issue_types(_drafting(**{ISSUE_TYPE.name: "CIAM=10105, net=1, OPS=x"})) == (
        {"CIAM": "10105"}, ("jira-sm-ticket-issue-type: `net=1` isn't <project key>=<issue type id>",
                            "jira-sm-ticket-issue-type: `OPS=x` isn't <project key>=<issue type id>"))
    assert issue_types(_drafting(**{ISSUE_TYPE.name: "Task"}))[1] == (
        "jira-sm-ticket-issue-type: `Task` isn't an issue type id, or <project key>=<issue type id>, ...",)

