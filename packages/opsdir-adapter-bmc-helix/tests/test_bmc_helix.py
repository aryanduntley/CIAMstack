"""BMC Helix ITSM / Remedy change requests as ticket evidence: the importer bmc-helix/change-requests reads the changes
the record's change records link (AR System REST answers of CHG:Infrastructure Change and AP:Detail-Signature) into
their own entries under ou=tickets; statuses go through bmc-helix-status-states (BMC's documented list by default);
the overall approval is rejected with the status Rejected, else derived from the approval requests' signatures; the
collector reads the server read-only with an AR-JWT or bearer token minted outside opsdir. Nothing is ever written
under ou=changes."""
import datetime as dt
import json
from urllib.parse import parse_qs, unquote, urlsplit

from opsdir.connectors.collecting import collect
from opsdir.core.directory import get, one, subtree, values, within
from opsdir.domains.governance.naming import CHANGES
from opsdir.domains.governance.tickets import (AFTER_READ, IN_STEP, OUTSIDE_WINDOW, REJECTED, UNAPPROVED, linked,
                                               ticket_dn, ticket_rows, ticket_state_map)
from opsdir_adapter_bmc_helix.adapter import ADAPTER
from opsdir_adapter_bmc_helix.changes import (CHANGES_IMPORTER, approval_key, ar_error, read_changes, signatures_of,
                                              steps_of)
from opsdir_adapter_bmc_helix.collect import COLLECTORS, change_steps, entries_view, source_problems
from opsdir_adapter_bmc_helix.states import STATUS_STATES, change_type, overall_approval, step_decision
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
        "bmc-helix", "itsm", None, (CHANGES_IMPORTER,), COLLECTORS, (STATUS_STATES,))
    d, _, _ = model(tree=TREE)
    states, problems = ticket_state_map(d, STATUS_STATES)          # BMC's documented list, by default
    assert problems == () and len(states) == 11
    assert "Pending" not in states and "Rejected" not in states


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
    assert ("notes.json: isn't an AR System entry answer (a change of CHG:Infrastructure Change or signatures of "
            "AP:Detail-Signature)") in imported.notices
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
