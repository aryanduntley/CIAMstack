"""BMC Helix ITSM / Remedy change requests as ticket evidence: the importer bmc-helix/change-requests reads the changes
the record's change records link (AR System REST answers of CHG:Infrastructure Change and AP:Detail-Signature) into
their own entries under ou=tickets; statuses go through bmc-helix-status-states (BMC's documented list by default);
the overall approval is rejected with the status Rejected, else derived from the approval requests' signatures; the
collector reads the server read-only with an AR-JWT or bearer token minted outside opsdir. Nothing is ever written
under ou=changes."""
import datetime as dt
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, unquote, urlsplit

from opsdir.connectors.collecting import collect
from opsdir.connectors.handoff import handoff_files
from opsdir.core.contract import TicketRequest
from opsdir.core.directory import get, one, subtree, values, within
from opsdir.domains.governance.naming import CHANGES
from opsdir.domains.governance.tickets import (AFTER_READ, IN_STEP, OUTSIDE_WINDOW, REJECTED, UNAPPROVED, linked,
                                               ticket_dn, ticket_rows, ticket_state_map)
from opsdir_adapter_bmc_helix.adapter import ADAPTER
from opsdir_adapter_bmc_helix.changes import (CHANGES_IMPORTER, approval_key, ar_error, read_changes, signatures_of,
                                              steps_of)
from opsdir_adapter_bmc_helix.collect import COLLECTORS, change_steps, entries_view, source_problems
from opsdir_adapter_bmc_helix.drafts import HOW, TICKET_FIELDS, TICKET_GROUPS, team_groups, ticket_draft
from opsdir_adapter_bmc_helix.states import (STATUS_STATES, WORK_ORDER_STATES, change_type, overall_approval,
                                             step_decision)
from opsdir_adapter_bmc_helix.workorders import is_work_order
from network_fixtures import ALPHA, entry, model
from support import after_import

AT = dt.datetime(2026, 9, 23, 9, 0, tzinfo=dt.timezone.utc)
HOST = "example-aero-restapi.onbmc.com"
CHANGE_URL = f"https://{HOST}/api/arsys/v1/entry/CHG%3AInfrastructure%20Change"


def _setting(name, value):
    return (f"dn: cn={name},ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamObject\n"
            f"objectClass: ciamEstateSetting\ncn: {name}\nciamEstateValue: {value}\n")


def _changes(*links):
    return tuple(f"dn: cn={cn},{CHANGES}\nobjectClass: top\nobjectClass: ciamChange\ncn: {cn}\nciamTitle: {cn}\n"
                 f"ciamChangeStatus: approved\nciamTicketRef: bmc-helix:{n}\nciamPlannedAt: 20260924000000Z\n"
                 for cn, n in links)


BASE = (f"dn: {CHANGES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: changes\n",
        "dn: ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: settings\n")
TREE = (*BASE, *_changes(("CHG-1", "CRQ000000000001"), ("CHG-2", "CRQ000000000002"), ("CHG-3", "CRQ000000000003")))


def _change(n, rid, status, timing="Normal", **extra):
    return {"values": {"Infrastructure Change ID": n, "Request ID": rid, "Description": f"Change {n}",
                       "Change Request Status": status, "Status Reason": None, "Change Type": "Change",
                       "Change Timing": timing, "Scheduled Start Date": "2026-09-24T02:00:00.000+0000",
                       "Scheduled End Date": "2026-09-24T08:00:00.000+0200", "Actual Start Date": None,
                       "Actual End Date": None, "Risk Level": "Risk Level 2", "Impact": "3-Moderate/Limited",
                       "Urgency": "4-Low", "Priority": "Low", "Last Modified Date": "2026-09-22T10:00:00.000+0000",
                       **extra},
            "_links": {"self": [{"href": f"{CHANGE_URL}/{rid}"}]}}


def _sig(sid, request, aid, status, who="jcab", phase="Business Approval", application="CHG:Infrastructure Change"):
    return {"values": {"Detail-Sig-Id": sid, "Approval ID": aid, "Request": request, "Application": application,
                       "Approval Status": status, "Approvers": who, "Approver Signature": who if status in (
                           "Approved", "Rejected") else None, "Phase": phase,
                       "Create-Date-Sig": "2026-09-21T10:00:00.000+0200",
                       "Modified-Date-Sig": "2026-09-22T09:00:00.000+0000"}}


def _page(*sigs, more=False):
    return json.dumps({"entries": list(sigs), "_links": {"self": [{"href": "x"}],
                                                         **({"next": [{"href": "y"}]} if more else {})}})


APPROVED = _page(_sig("S1", "000000000000101", "AP1", "Approved"))


def _export(*changes, approvals=None):
    return {**{f"{HOST}/change/{c['values']['Infrastructure Change ID']}.json": json.dumps({"entries": [c]})
               for c in changes},
            **{f"{HOST}/approval/{n}/0.json": p for n, p in (approvals or {}).items()}}


def _read(*changes, tree=TREE, approvals=None, files=None):
    d, _, _ = model(tree=tree)
    imported = read_changes(files or _export(*changes, approvals=approvals), d, (), AT)
    return d, imported, after_import(d, imported)


def test_registered_as_an_itsm_add_on_with_its_importer_collector_and_status_setting():
    assert (ADAPTER.name, ADAPTER.kind, ADAPTER.applies, ADAPTER.importers, ADAPTER.collectors, ADAPTER.settings) == (
        "bmc-helix", "itsm", None, (CHANGES_IMPORTER,), COLLECTORS,
        (STATUS_STATES, WORK_ORDER_STATES, TICKET_GROUPS, TICKET_FIELDS))
    assert ADAPTER.ticket_draft is ticket_draft
    assert (TICKET_GROUPS.default, TICKET_FIELDS.default) == (None, None)           # site-specific: no default
    d, _, _ = model(tree=TREE)
    states, problems = ticket_state_map(d, STATUS_STATES)          # BMC's documented list, by default
    assert problems == () and len(states) == 11
    assert "Pending" not in states and "Rejected" not in states
    work, problems = ticket_state_map(d, WORK_ORDER_STATES)        # BMC's documented work-order list, by default
    assert problems == () and len(work) == 7 and work["In Progress"] == "implement"
    assert "Pending" not in work and "Rejected" not in work


def test_a_linked_change_is_read_as_evidence():
    d, imported, after = _read(_change("CRQ000000000001", "000000000000101", "Scheduled"),
                               _change("CRQ000000000009", "000000000000109", "Scheduled"),
                               approvals={"CRQ000000000001": APPROVED})
    t = get(after, ticket_dn("bmc-helix", "CRQ000000000001"))
    assert dict(t.attrs) == {
        "cn": ("CRQ000000000001",), "ciamImportedAt": ("20260923090000Z",), "ciamTitle": ("Change CRQ000000000001",),
        "ciamProviderRef": ("000000000000101",), "ciamDocUrl": (f"{CHANGE_URL}/000000000000101",),
        "ciamTicketState": ("scheduled",), "ciamTicketApproval": ("approved",), "ciamTicketNativeState": ("Scheduled",),
        "ciamTicketChangeType": ("normal",), "ciamTicketPlannedStart": ("20260924020000Z",),
        "ciamTicketPlannedEnd": ("20260924060000Z",),
        "ciamTicketApprovalStep": ("approved AP1 created 20260921080000Z",),
        "ciamTicketApprover": ("approved jcab step AP1 updated 20260922090000Z phase Business Approval",),
        "ciamTicketFact": ("change-type Change", "risk-level Risk Level 2", "impact 3-Moderate/Limited",
                           "urgency 4-Low", "priority Low", "last-modified 2026-09-22T10:00:00.000+0000")}
    assert get(after, ticket_dn("bmc-helix", "CRQ000000000009")) is None
    assert "not linked to a change record: CRQ000000000009 (left out)" in imported.notices
    assert ("linked but not in the export: CRQ000000000002, CRQ000000000003 (the record keeps what it last read; "
            "nothing is removed)") in imported.notices
    assert f"1 ticket(s) read from {HOST}" in imported.notices
    assert not any(within(g[0], CHANGES) for g in imported.groups)       # evidence never lands on a change record
    assert {e.dn: e for e in subtree(after, CHANGES)} == {e.dn: e for e in subtree(d, CHANGES)}


def test_signature_statuses_decide_steps_and_the_status_rejected_decides_the_approval():
    assert step_decision(("Approved", "Rejected", "Pending")) == "declined"
    assert step_decision(("Approved", "Hold")) == "pending" and step_decision(("More Information",)) == "pending"
    assert step_decision(("Approved", "Closed", "Cancelled")) == "approved"      # One Must Sign closes the others
    assert step_decision(("Cancelled", "Error")) is None
    assert overall_approval("Rejected", (), None) == "rejected"                    # the status alone says it
    assert overall_approval("Scheduled", ("approved", "pending"), "scheduled") == "requested"
    assert overall_approval("Scheduled For Approval", ("approved",), "authorize") is None   # a later phase may come
    assert overall_approval("Scheduled", (), "scheduled") is None                  # no signatures: unknown
    assert (change_type("Emergency"), change_type("Standard"), change_type("Expedited")) == ("emergency", "standard",
                                                                                              None)


def test_drift_follows_from_what_was_read():
    pending = _page(_sig("S2", "000000000000102", "AP2", "Approved", who="jmgr", phase="Review"),
                    _sig("S3", "CRQ000000000002", "AP3", "Pending", who="jcab;kcab"))
    rejected = _page(_sig("S4", "000000000000103", "AP4", "Rejected"))
    _, _, after = _read(_change("CRQ000000000001", "000000000000101", "Scheduled"),
                        _change("CRQ000000000002", "000000000000102", "Scheduled For Approval"),
                        _change("CRQ000000000003", "000000000000103", "Rejected",
                                **{"Status Reason": "Schedule Conflicts"}),
                        approvals={"CRQ000000000001": APPROVED, "CRQ000000000002": pending,
                                   "CRQ000000000003": rejected})
    assert {one(link.change, "cn"): link.states for link in linked(after)} == {
        "CHG-1": (IN_STEP,), "CHG-2": (UNAPPROVED,), "CHG-3": (REJECTED,)}
    t = get(after, ticket_dn("bmc-helix", "CRQ000000000002"))
    assert values(t, "ciamTicketApprovalStep") == ("approved AP2 created 20260921080000Z",
                                                   "pending AP3 created 20260921080000Z")
    assert "pending jcab;kcab step AP3 updated 20260922090000Z phase Business Approval" in values(
        t, "ciamTicketApprover")
    rows = {r[0]: r for r in ticket_rows(after)}
    assert rows["CHG-3"][4:6] == ("unknown (Rejected)", "rejected (steps: 1 declined)")
    assert "status-reason Schedule Conflicts" in values(get(after, ticket_dn("bmc-helix", "CRQ000000000003")),
                                                        "ciamTicketFact")


def test_work_outside_the_planned_window_and_classes_that_arent_a_change_type():
    _, imported, after = _read(_change("CRQ000000000001", "000000000000101", "Implementation In Progress",
                                       timing="Expedited", **{"Actual Start Date": "2026-09-24T01:30:00.000+0000",
                                                              "Actual End Date": "2026-09-24"}),
                               approvals={"CRQ000000000001": APPROVED})
    t = get(after, ticket_dn("bmc-helix", "CRQ000000000001"))
    assert (one(t, "ciamTicketWorkStart"), one(t, "ciamTicketWorkEnd"), one(t, "ciamTicketChangeType")) == (
        "20260924013000Z", None, None)
    assert "change-timing Expedited" in values(t, "ciamTicketFact")
    # read before the work it reports began: evidence from after the read (governance.tickets after-read)
    assert {one(link.change, "cn"): link.states for link in linked(after)}["CHG-1"] == (OUTSIDE_WINDOW, AFTER_READ)
    assert ("CRQ000000000001: Actual End Date: a date without a time (its time zone is unknown)" in imported.notices)
    assert ("CRQ000000000001: Change Timing `Expedited` isn't Emergency, Normal or Standard: kept as a fact"
            in imported.notices)


def test_statuses_the_setting_doesnt_map_stay_native_and_the_setting_can_be_overridden():
    _, imported, after = _read(_change("CRQ000000000001", "000000000000101", "Pending"),
                               approvals={"CRQ000000000001": APPROVED})
    t = get(after, ticket_dn("bmc-helix", "CRQ000000000001"))
    assert (one(t, "ciamTicketState"), one(t, "ciamTicketNativeState"), one(t, "ciamTicketApproval")) == (
        None, "Pending", None)                                       # never taken as closed, nor approved
    assert ("status Pending isn't mapped in bmc-helix-status-states: the state of CRQ000000000001 is kept as BMC "
            "gives it (neutral state unknown)") in imported.notices
    tree = (*TREE, _setting(STATUS_STATES.name, "Awaiting CAB=authorize, Scheduled=scheduled, Done=finished"))
    _, imported, after = _read(_change("CRQ000000000001", "000000000000101", "Awaiting CAB"), tree=tree)
    assert one(get(after, ticket_dn("bmc-helix", "CRQ000000000001")), "ciamTicketState") == "authorize"
    assert ("bmc-helix-status-states: `Done=finished`: finished isn't a ticket state (new, assess, authorize, "
            "scheduled, implement, review, closed, cancelled)") in imported.notices


def test_signatures_belong_by_request_and_application_and_need_their_last_page():
    change = _change("CRQ000000000001", "000000000000101", "Scheduled")["values"]
    sigs = [_sig("S1", "000000000000101", "AP1", "Approved")["values"],
            _sig("S1", "000000000000101", "AP1", "Approved")["values"],          # the same row on two pages
            _sig("S2", "CRQ000000000001", "AP1", "Closed")["values"],
            _sig("S3", "000000000000101", "AP9", "Pending", application="HPD:Help Desk")["values"],
            _sig("S4", "000000000000999", "AP8", "Pending")["values"]]
    mine, other = signatures_of(change, sigs)
    assert [s["Detail-Sig-Id"] for s in mine] == ["S1", "S2"] and [s["Detail-Sig-Id"] for s in other] == ["S3"]
    assert steps_of(mine) == (("AP1", "approved", "20260921080000Z"),)
    short = _page(_sig("S1", "000000000000101", "AP1", "Approved"), more=True)
    _, imported, after = _read(_change("CRQ000000000001", "000000000000101", "Scheduled"),
                               _change("CRQ000000000002", "000000000000102", "Rejected"),
                               approvals={"CRQ000000000001": short})
    assert one(get(after, ticket_dn("bmc-helix", "CRQ000000000001")), "ciamTicketApproval") is None
    assert one(get(after, ticket_dn("bmc-helix", "CRQ000000000002")), "ciamTicketApproval") == "rejected"
    assert ("approval signatures not in the export, or not to their last page, for: CRQ000000000001, "
            "CRQ000000000002 (overall approval unknown unless the status is Rejected)") in imported.notices
    void = _page(_sig("S5", "000000000000101", "AP5", "Cancelled"),
                 _sig("S6", "000000000000101", "AP6", "Pending", application="HPD:Help Desk"))
    _, imported, after = _read(_change("CRQ000000000001", "000000000000101", "Scheduled"),
                               approvals={"CRQ000000000001": void})
    t = get(after, ticket_dn("bmc-helix", "CRQ000000000001"))
    assert values(t, "ciamTicketApprovalStep") == () and one(t, "ciamTicketApproval") is None
    assert values(t, "ciamTicketApprover") == ("cancelled jcab step AP5 updated 20260922090000Z phase Business "
                                               "Approval",)
    assert ("CRQ000000000001: approval AP5 has only cancelled, closed or errored signatures: not a step"
            in imported.notices)
    assert "signatures of another application left out: CRQ000000000001 (HPD:Help Desk)" in imported.notices


def test_saved_answers_errors_unknown_files_dating_duplicates_and_servers_are_named():
    d, _, _ = model(tree=TREE)
    files = {"crq-1.json": json.dumps(_change("CRQ000000000001", "000000000000101", "Scheduled")),
             "approval-CRQ000000000001.json": APPROVED,
             "approval/CRQ000000000002/0.json": json.dumps([{"messageType": "ERROR", "messageNumber": 302,
                                                             "messageText": "Entry does not exist in database"}]),
             "notes.json": json.dumps({"hello": 1}), "readme.txt": "x"}
    imported = read_changes(files, d, (), AT)
    assert one(get(after_import(d, imported), ticket_dn("bmc-helix", "CRQ000000000001")),
               "ciamTicketApproval") == "approved"
    assert ("approval/CRQ000000000002/0.json: AR System answered an error: 302 Entry does not exist in database"
            in imported.notices)
    assert ("notes.json: isn't an AR System entry answer (a change of CHG:Infrastructure Change, a work order of "
            "WOI:WorkOrderInterface or signatures of AP:Detail-Signature)") in imported.notices
    assert read_changes(files, d, (), None).notices == ("ticket evidence is dated: give --at (when the export was "
                                                        "taken)",)
    twice = {**files, "crq-1b.json": json.dumps(_change("CRQ000000000001", "000000000000777", "Draft"))}
    assert read_changes(twice, d, (), AT).groups == ()
    other = _change("CRQ000000000002", "000000000000102", "Draft")
    other["_links"]["self"][0]["href"] = "https://remedy.example-aero.test:8008/api/arsys/v1/entry/x/1"
    assert read_changes({**files, "other.json": json.dumps(other)}, d, (), AT).groups == ()
    assert (approval_key("h/approval/CRQ000000000004/100.json"), approval_key("approval-CRQ000000000004-2.json"),
            approval_key("approvals.json")) == ("CRQ000000000004", "CRQ000000000004", None)
    assert ar_error([1]) is None and ar_error({"entries": []}) is None


def _source(url=f"https://{HOST}", scheme="token"):
    return (entry(ALPHA, "itsm", "ciamCollectionSource", ciamBindingRole="itsm",
                  ciamImporter="bmc-helix/change-requests", ciamSourceRef=url, ciamCredentialRole="itsm-reader",
                  ciamCredentialScheme=scheme),
            entry(ALPHA, "itsm-reader", "ciamSecretRef", ciamBindingRole="itsm-reader",
                  ciamRefUri="fake://kv/itsm-reader"))


SERVED = {"CRQ000000000001": _change("CRQ000000000001", "000000000000101", "Scheduled",
                                     **{"Detailed Description": "not kept"})}
SIGNED = {"000000000000101": [_sig(f"S{i}", "000000000000101", f"AP{i}", "Approved") for i in range(1, 4)]}


def _serve(request):
    url = urlsplit(request.url)
    q = parse_qs(url.query)
    if unquote(url.path).endswith("AP:Detail-Signature"):
        rid = q["q"][0].split('"')[1]
        offset, limit = int(q["offset"][0]), 2                       # the server pages by 2, whatever was asked
        rows = SIGNED.get(rid, [])
        return json.dumps({"entries": rows[offset:offset + limit],
                           "_links": {"next": [{"href": "n"}]} if offset + limit < len(rows) else {}}), None
    number = q["q"][0].split('"')[1]
    return json.dumps({"entries": [SERVED[number]] if number in SERVED else []}), None


def test_the_collector_reads_each_linked_change_then_its_signature_pages_with_an_ar_jwt():
    _, alpha, _ = model(alpha=_source(), tree=TREE)
    first = change_steps(alpha.d, alpha, {}, {})
    assert [p for p, _ in first] == [f"{HOST}/change/CRQ000000000001.json", f"{HOST}/change/CRQ000000000002.json",
                                     f"{HOST}/change/CRQ000000000003.json"]
    call = first[0][1]
    assert call.url.startswith(f"{CHANGE_URL}?q=%27Infrastructure%20Change%20ID%27%20%3D%20%22CRQ000000000001%22"
                               "&fields=values(Infrastructure%20Change%20ID,Request%20ID,")
    assert call.url.endswith("&limit=2&offset=0")
    assert call.credential == ("api-key", "fake://kv/itsm-reader", None, "Authorization", "AR-JWT ")
    c = collect("bmc-helix/change-requests", COLLECTORS[0], alpha.d, alpha, _serve)
    assert c.problems == ()
    assert sorted(c.files) == [f"{HOST}/approval/CRQ000000000001/0.json", f"{HOST}/approval/CRQ000000000001/2.json",
                               f"{HOST}/change/CRQ000000000001.json", f"{HOST}/change/CRQ000000000002.json",
                               f"{HOST}/change/CRQ000000000003.json"]
    assert "not kept" not in "".join(c.files.values())
    after = after_import(alpha.d, read_changes(c.files, alpha.d, (), AT))
    t = get(after, ticket_dn("bmc-helix", "CRQ000000000001"))
    assert one(t, "ciamTicketApproval") == "approved" and len(values(t, "ciamTicketApprovalStep")) == 3
    signatures = dict(change_steps(alpha.d, alpha, c.files, {}))[f"{HOST}/approval/CRQ000000000001/0.json"]
    assert "%28%27Request%27%20%3D%20%22000000000000101%22%20OR%20%27Request%27%20%3D%20%22CRQ000000000001%22%29" \
        in signatures.url


def test_a_bearer_token_is_taken_and_a_password_is_refused_with_why():
    _, onprem, _ = model(alpha=_source("https://remedy.example-aero.test:8008/", "bearer"), tree=TREE)
    steps = change_steps(onprem.d, onprem, {}, {})
    assert steps[0][1].credential == ("bearer", "fake://kv/itsm-reader", None)
    assert steps[0][0] == "remedy.example-aero.test/change/CRQ000000000001.json"
    _, alpha, _ = model(alpha=_source(scheme="basic"), tree=TREE)
    assert source_problems(alpha.d, alpha, {}) == (
        "collection source `itsm`: credential scheme `basic`: the server is read with token (the JWT AR System's "
        "logon, POST /api/jwt/login, returns: sent as AR-JWT) or bearer (a BMC Helix SSO OAuth access token), "
        "obtained outside opsdir",)
    assert change_steps(alpha.d, alpha, {}, {}) == ()


def test_projections_keep_only_what_the_importer_reads():
    view = json.loads(entries_view(("Request ID",))(json.dumps(
        {"entries": [{"values": {"Request ID": "1", "Detailed Description": "secret"},
                      "_links": {"self": [{"href": "s"}], "other": [{"href": "o"}]}}],
         "_links": {"self": [{"href": "x"}], "next": [{"href": "n"}]}})))
    assert view == {"entries": [{"values": {"Request ID": "1"}, "_links": {"self": [{"href": "s"}]}}],
                    "_links": {"next": [{"href": "n"}]}}
    error = json.dumps([{"messageType": "ERROR", "messageText": "no"}])
    assert entries_view(("x",))(error) == error and entries_view(("x",))("<html>") == "<html>"


# ------------------------------------------------------------------ work orders: drafts and read-back
AS_OF = dt.date(2026, 10, 18)
GROUPS = "Platform=Example Company/Identity Services/Identity Platform, network=Example Company/Network/Edge"
FIELDS = ("First Name=Ops, Last Name=Reader, Customer First Name=CIAM, Customer Last Name=Owner, "
          "Company=Example Company, Customer Company=Example Company, Location Company=Example Company")


def _request(team="Platform", items=(("action", "Certificates", "Renew the signing certificate",
                                      dt.date(2026, 11, 1)),), do_by=dt.date(2026, 11, 1)):
    return TicketRequest(team, f"cn={team},ou=owners,dc=ciam-ops", f"CIAM: 1 finding for {team} (aws/prod to "
                         "azure/prod)", items, do_by, "aws/prod", "azure/prod", AS_OF)


def _drafting(groups=GROUPS, fields=FIELDS):
    d, _, _ = model(tree=(*TREE, *((_setting(TICKET_GROUPS.name, groups),) if groups else ()),
                          *((_setting(TICKET_FIELDS.name, fields),) if fields else ())))
    return d


def test_a_team_s_findings_are_drafted_as_a_work_order_create_body():
    draft = ticket_draft(_drafting(), _request())
    assert (draft.extension, draft.problems, draft.how) == ("json", (), HOW)
    assert json.loads(draft.body) == {"values": {
        "First Name": "Ops", "Last Name": "Reader", "Customer First Name": "CIAM", "Customer Last Name": "Owner",
        "Company": "Example Company", "Customer Company": "Example Company", "Location Company": "Example Company",
        "z1D_Action": "CREATE", "Summary": "CIAM: 1 finding for Platform (aws/prod to azure/prod)",
        "Detailed Description": (
            "Findings of the CIAMstack plan from aws/prod to azure/prod (as of 2026-10-18) that Platform owns.\n\n"
            "- [action] Certificates: Renew the signing certificate (do by 2026-11-01)\n\n"
            "Link this ticket on the opsdir change that does the work (ciamTicketRef), so its state is read back."),
        "Status": "Assigned", "Support Company": "Example Company", "Support Organization": "Identity Services",
        "Support Group Name": "Identity Platform", "Priority": "Medium",
        "Scheduled End Date": "2026-11-01T23:59:59.000+0000"}}
    assert HOW[0] == "POST https://<ar-rest-host>/api/arsys/v1/entry/WOI%3AWorkOrderInterface_Create"
    assert "Authorization: AR-JWT <jwt>" in HOW[1] and "Detailed Decription" not in draft.body


def test_a_blocker_raises_the_priority_a_given_one_wins_and_owned_fields_stay_opsdir_s():
    blocker = _request("PLATFORM", (("blocker", "Network", "Open 636", None),), None)
    values = json.loads(ticket_draft(_drafting(), blocker).body)["values"]
    assert (values["Priority"], values["Support Group Name"], "Scheduled End Date" in values) == (
        "High", "Identity Platform", False)                       # a team by name, any case; no do-by, no date
    given = ticket_draft(_drafting(fields=f"{FIELDS}, Priority=Low, Status=Closed, Work Order Type=General"),
                         blocker)
    values = json.loads(given.body)["values"]
    assert (values["Priority"], values["Status"], values["Work Order Type"]) == ("Low", "Assigned", "General")
    assert given.problems == ("bmc-helix-ticket-fields: `Status` is set by opsdir: left out",)
    wrong = ticket_draft(_drafting(fields=f"{FIELDS}, Priority=Urgent"), blocker)
    assert json.loads(wrong.body)["values"]["Priority"] == "High"
    assert wrong.problems == ("bmc-helix-ticket-fields: Priority `Urgent` isn't Critical, High, Medium, Low: High "
                              "is used",)


def test_no_draft_without_the_team_s_group_or_the_foundation_fields_and_the_problem_says_how():
    unmapped = ticket_draft(_drafting(), _request("security"))
    assert unmapped.body is None and unmapped.how == HOW
    assert unmapped.problems == (
        "bmc-helix-ticket-groups gives no support group for security: add "
        "`security=<company>/<organization>/<group>` to it, `opsdir setting bmc-helix-ticket-groups "
        "'<team>=<company>/<organization>/<group>, ...' --change <id>`",)
    bare = ticket_draft(_drafting(groups=None, fields="First Name=Ops"), _request())
    assert bare.body is None and len(bare.problems) == 2
    assert bare.problems[1].startswith("bmc-helix-ticket-fields doesn't give Last Name, Customer First Name, "
                                       "Customer Last Name, Company, Customer Company, Location Company")
    assert "`opsdir setting bmc-helix-ticket-fields 'First Name=<value>, " in bare.problems[1]
    groups, problems = team_groups(_drafting(groups="Platform=Example Company/Identity Services, bad"))
    assert groups == {} and problems == (
        "bmc-helix-ticket-groups: `bad` isn't <name>=<value>",
        "bmc-helix-ticket-groups: `Platform=Example Company/Identity Services` isn't "
        "<team>=<company>/<organization>/<group>")


def test_the_hand_off_writes_the_drafts_and_says_what_is_missing():
    plan = SimpleNamespace(src=SimpleNamespace(label="aws/prod"), dst=SimpleNamespace(label="azure/prod"),
                           as_of=AS_OF, blockers=(("Network", "Open 636", "security"),),
                           actions=(("Certificates", "Renew", "Platform", dt.date(2026, 11, 1)),))
    files = handoff_files(_drafting(), plan, (ADAPTER,))
    assert sorted(files) == ["tickets/README.md", "tickets/bmc-helix/Platform.json"]
    assert "**not complete for security**: bmc-helix-ticket-groups gives no support group" in files[
        "tickets/README.md"]
    assert "AR-JWT <jwt>" in files["tickets/README.md"] and "AR-JWT" not in files["tickets/bmc-helix/Platform.json"]


WORK_URL = f"https://{HOST}/api/arsys/v1/entry/WOI%3AWorkOrderInterface"
WORK_TREE = (*BASE, *_changes(("CHG-1", "CRQ000000000001"), ("CHG-4", "WO0000000000401")))


def _work_order(n, rid, status, **extra):
    return {"values": {"Work Order ID": n, "Request ID": rid, "Description": "CIAM: 1 finding for Platform",
                       "Status": status, "Status Reason": None, "Priority": "Medium", "Work Order Type": "General",
                       "Scheduled Start Date": "2026-09-23T00:00:00.000+0000",
                       "Scheduled End Date": "2026-11-01T23:59:59.000+0000", "Actual Start Date": None,
                       "Actual End Date": None, "Last Modified Date": "2026-09-22T10:00:00.000+0000", **extra},
            "_links": {"self": [{"href": f"{WORK_URL}/{rid}"}]}}


def test_a_linked_work_order_is_read_back_as_a_work_ticket():
    assert is_work_order("WO0000000000401") and not is_work_order("CRQ000000000001")
    files = {f"{HOST}/workorder/WO0000000000401.json": json.dumps(
        {"entries": [_work_order("WO0000000000401", "000000000000401", "In Progress")]}),
        "wo-9.json": json.dumps(_work_order("WO0000000000409", "000000000000409", "Assigned"))}
    d, imported, after = _read(tree=WORK_TREE, files=files)
    t = get(after, ticket_dn("bmc-helix", "WO0000000000401"))
    assert dict(t.attrs) == {
        "cn": ("WO0000000000401",), "ciamImportedAt": ("20260923090000Z",),
        "ciamTitle": ("CIAM: 1 finding for Platform",), "ciamProviderRef": ("000000000000401",),
        "ciamDocUrl": (f"{WORK_URL}/000000000000401",), "ciamTicketKind": ("work",),
        "ciamTicketState": ("implement",), "ciamTicketNativeState": ("In Progress",),
        "ciamTicketPlannedStart": ("20260923000000Z",), "ciamTicketPlannedEnd": ("20261101235959Z",),
        "ciamTicketDue": ("20261101235959Z",),
        "ciamTicketFact": ("priority Medium", "work-order-type General",
                           "last-modified 2026-09-22T10:00:00.000+0000")}
    assert "not linked to a change record: WO0000000000409 (left out)" in imported.notices
    assert ("linked but not in the export: CRQ000000000001 (the record keeps what it last read; nothing is removed)"
            in imported.notices)
    states = {(x.number, x.states) for x in linked(after)}
    assert ("WO0000000000401", (IN_STEP,)) in states                   # a work ticket has no approval to compare


def test_an_unmapped_work_order_status_is_kept_native_and_named():
    files = {"wo.json": json.dumps(_work_order("WO0000000000401", "000000000000401", "Pending"))}
    _, imported, after = _read(tree=WORK_TREE, files=files)
    t = get(after, ticket_dn("bmc-helix", "WO0000000000401"))
    assert (one(t, "ciamTicketState"), one(t, "ciamTicketNativeState")) == (None, "Pending")
    assert ("status Pending isn't mapped in bmc-helix-work-order-states: the state of WO0000000000401 is kept as BMC "
            "gives it (neutral state unknown)") in imported.notices
    cancelled = {"wo.json": json.dumps(_work_order("WO0000000000401", "000000000000401", "Cancelled"))}
    _, _, after = _read(tree=WORK_TREE, files=cancelled)
    assert [x.states for x in linked(after) if x.number == "WO0000000000401"] == [("cancelled",)]


SERVED_WORK = {"WO0000000000401": _work_order("WO0000000000401", "000000000000401", "Completed",
                                              **{"Detailed Description": "not kept"})}


def _serve_work(request):
    if unquote(urlsplit(request.url).path).endswith("WOI:WorkOrderInterface"):
        number = parse_qs(urlsplit(request.url).query)["q"][0].split('"')[1]
        return json.dumps({"entries": [SERVED_WORK[number]] if number in SERVED_WORK else []}), None
    return _serve(request)


def test_the_collector_reads_a_linked_work_order_once_without_approvals():
    _, alpha, _ = model(alpha=_source(), tree=WORK_TREE)
    first = dict(change_steps(alpha.d, alpha, {}, {}))
    assert sorted(first) == [f"{HOST}/change/CRQ000000000001.json", f"{HOST}/workorder/WO0000000000401.json"]
    call = first[f"{HOST}/workorder/WO0000000000401.json"]
    assert call.url.startswith(f"{WORK_URL}?q=%27Work%20Order%20ID%27%20%3D%20%22WO0000000000401%22"
                               "&fields=values(Work%20Order%20ID,Request%20ID,Description,Status,")
    assert call.url.endswith("&limit=2&offset=0")
    assert call.credential == ("api-key", "fake://kv/itsm-reader", None, "Authorization", "AR-JWT ")
    c = collect("bmc-helix/change-requests", COLLECTORS[0], alpha.d, alpha, _serve_work)
    assert c.problems == () and not any("approval/WO" in p for p in c.files)
    assert "not kept" not in "".join(c.files.values())
    after = after_import(alpha.d, read_changes(c.files, alpha.d, (), AT))
    t = get(after, ticket_dn("bmc-helix", "WO0000000000401"))
    assert (one(t, "ciamTicketKind"), one(t, "ciamTicketState")) == ("work", "review")
