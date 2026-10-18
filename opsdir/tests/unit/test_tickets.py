"""ITSM ticket evidence: change records linked to their tickets (ciamTicketRef), the tickets as an ITSM add-on's
importer read them (ciamTicket under ou=tickets), and the drift between the two. The planner's check is silent while
no ticket was read; a ticket ITSM says was rejected or cancelled while the record approves the change blocks; other
drift is an action for the change's owner (else the operator). Evidence never touches a change record."""
import datetime as dt

from opsdir.core.contract import PlanContext
from opsdir.core.directory import one, values, within
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.governance.domain import DOMAIN
from opsdir.domains.governance.naming import CHANGES, TICKETS
from opsdir.core.contract import Setting
from opsdir.domains.governance.schema import TICKET_APPROVALS
from opsdir.domains.governance.tickets import (AFTER_READ, APPLIED_OUTSIDE, AREA, BLOCKING, CANCELLED, CLOSED_PENDING,
                                               IN_STEP, LIVE_REJECTED, NOT_IMPORTED, OUTSIDE_WINDOW, REJECTED,
                                               TICKET_HEADERS, UNAPPROVED, WINDOW_DIFFERS, after_read,
                                               applied_outside_window, check_tickets, drift_states, finding_text,
                                               linked, linked_numbers, ticket_dn, ticket_entry, ticket_group,
                                               ticket_map, ticket_refs, ticket_rows, ticket_state_map)
import mini_estate
from support import REGISTRY, build_directory

AS_OF = dt.date(2026, 10, 1)
OPS = "cn=ops,ou=owners,dc=ciam-ops"


def _change(cn, status, ref=None, planned=None, **attrs):
    return (f"dn: cn={cn},{CHANGES}\nobjectClass: top\nobjectClass: ciamChange\ncn: {cn}\nciamTitle: Work {cn}\n"
            f"ciamChangeStatus: {status}\n" + (f"ciamTicketRef: {ref}\n" if ref else "")
            + (f"ciamPlannedAt: {planned}\n" if planned else "")
            + "".join(f"{k}: {v}\n" for k, v in attrs.items()))


def _ticket(number, adapter="snow", read="20260923090000Z", **attrs):
    return (f"dn: {ticket_dn(adapter, number)}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamTicket\n"
            f"cn: {number}\nciamImportedAt: {read}\n"
            + "".join(f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,))))


BASE = (
    "dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
    f"dn: {OPS}\nobjectClass: top\nobjectClass: ciamParty\ncn: ops\nciamOwnerKind: team\n",
    "dn: cn=acme,ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: acme\nciamOwnerKind: operator\n",
    f"dn: {CHANGES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: changes\n",
)
CONTAINERS = (f"dn: {TICKETS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: tickets\n",
              f"dn: ou=snow,{TICKETS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: snow\n")
WINDOW = {"ciamTicketPlannedStart": "20260924020000Z", "ciamTicketPlannedEnd": "20260924060000Z"}
CHANGES_LINKED = (
    _change("CHG-1", "approved", "snow:C1", "20260924000000Z"),
    _change("CHG-2", "approved", "snow:C2", "20260924000000Z", ciamOwner=OPS),
    _change("CHG-3", "applied", "snow:C3", "20260924000000Z"),
    _change("CHG-4", "approved", "snow:C4", "20260924000000Z"),
    _change("CHG-5", "approved", "snow:C5", "20260924000000Z"),
    _change("CHG-6", "rejected", "snow:C6"),
    _change("CHG-7", "approved", "snow:C7", "20260920000000Z"),
    _change("CHG-8", "applied", "snow:C8", "20260924000000Z"),
    _change("CHG-9", "approved", "snow:C9"),
    _change("CHG-10", "approved", "jira:IAM-1"),
    _change("CHG-11", "approved"),
)
TICKETS_READ = (
    _ticket("C1", ciamTicketState="scheduled", ciamTicketApproval="approved", **WINDOW),
    _ticket("C2", ciamTicketState="authorize", ciamTicketApproval="rejected", **WINDOW),
    _ticket("C3", ciamTicketState="cancelled", ciamTicketApproval="approved", **WINDOW),
    # one approver approved, but the change's own approval is still requested: approval is never judged from rows
    _ticket("C4", ciamTicketState="authorize", ciamTicketApproval="requested",
            ciamTicketApprover="approved a1b2 updated 20260921100000Z", **WINDOW),
    _ticket("C5", ciamTicketState="closed", ciamTicketApproval="approved", **WINDOW),
    _ticket("C6", ciamTicketState="scheduled", ciamTicketApproval="approved"),
    _ticket("C7", ciamTicketState="scheduled", ciamTicketApproval="approved", **WINDOW),
    _ticket("C8", read="20260925000000Z", ciamTicketState="closed", ciamTicketApproval="approved",
            ciamTicketWorkStart="20260924013000Z",
            ciamTicketWorkEnd="20260924050000Z", **WINDOW),
)


def _d(*records):
    return build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *BASE, *records)))))


def _check(d, writes=None):
    return check_tickets(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, AS_OF, {}, {},
                                     (), writes))


def _states(d):
    return {one(link.change, "cn"): link.states for link in linked(d)}


def test_the_governance_domain_checks_and_reports_tickets():
    assert check_tickets in DOMAIN.checks and "tickets" in DOMAIN.reports
    assert DOMAIN.reports["tickets"].writes            # the runner gives it the record's writes from history


def test_a_change_names_its_ticket_as_adapter_and_number():
    d = _d(*CHANGES_LINKED)
    assert [ticket_refs(link.change)[0] for link in linked(d)][:2] == [("snow", "C1"), ("jira", "IAM-1")]
    assert linked_numbers(d, "snow") == ("C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9")
    assert linked_numbers(d, "jira") == ("IAM-1",)


def test_the_check_is_silent_while_no_ticket_was_read():
    found = _check(_d(*CHANGES_LINKED))
    assert (found.blockers, found.actions, found.ok) == ((), (), ())


def test_each_drift_state_is_kept_apart():
    states = _states(_d(*CHANGES_LINKED, *CONTAINERS, *TICKETS_READ))
    assert states == {"CHG-1": (IN_STEP,), "CHG-2": (REJECTED,), "CHG-3": (CANCELLED,), "CHG-4": (UNAPPROVED,),
                      "CHG-5": (CLOSED_PENDING,), "CHG-6": (LIVE_REJECTED,), "CHG-7": (WINDOW_DIFFERS,),
                      "CHG-8": (OUTSIDE_WINDOW,), "CHG-9": (NOT_IMPORTED,),
                      "CHG-10": ()}       # no jira ticket read at all: nothing to compare yet


def test_rejected_and_cancelled_block_and_the_rest_are_actions_for_the_owner_else_the_operator():
    d = _d(*CHANGES_LINKED, *CONTAINERS, *TICKETS_READ)
    found = _check(d)
    links = {one(link.change, "cn"): link for link in linked(d)}
    assert found.blockers == ((AREA, finding_text(links["CHG-2"], REJECTED), "ops"),
                              (AREA, finding_text(links["CHG-3"], CANCELLED), "acme"))
    assert [(a[1], a[2], a[3]) for a in found.actions] == [
        (finding_text(links[c], s), "acme", None) for c, s in (("CHG-4", UNAPPROVED), ("CHG-5", CLOSED_PENDING),
                                                                ("CHG-6", LIVE_REJECTED), ("CHG-7", WINDOW_DIFFERS),
                                                                ("CHG-8", OUTSIDE_WINDOW), ("CHG-9", NOT_IMPORTED))]
    assert len(found.ok) == 1 and "CHG-1" in found.ok[0] and "ITSM says scheduled" in found.ok[0]
    assert not found.fixes                                              # a change's status is a person's


def test_the_texts_say_what_itsm_says_never_that_the_ticket_approves():
    d = _d(*CHANGES_LINKED, *CONTAINERS, *TICKETS_READ)
    links = {one(link.change, "cn"): link for link in linked(d)}
    assert finding_text(links["CHG-2"], REJECTED).startswith(
        "Change `CHG-2` (Work CHG-2) is approved in the record, but ITSM says its ticket snow:C2 (read 2026-09-23) "
        "was **rejected**")
    assert "approval of its ticket snow:C4 (read 2026-09-23) is requested" in finding_text(links["CHG-4"], UNAPPROVED)
    assert "2026-09-24 02:00Z to 2026-09-24 06:00Z" in finding_text(links["CHG-7"], WINDOW_DIFFERS)
    assert "ran 2026-09-24 01:30Z to 2026-09-24 05:00Z" in finding_text(links["CHG-8"], OUTSIDE_WINDOW)
    assert set(BLOCKING) == {REJECTED, CANCELLED}


def test_the_planned_day_is_compared_with_the_window_days_in_utc():
    d = _d(_change("CHG-1", "approved", "snow:C1", "20260924235900Z"), _change("CHG-2", "approved", "snow:C2",
                                                                                 "20260925000000Z"),
           *CONTAINERS, _ticket("C1", ciamTicketApproval="approved", **WINDOW),
           _ticket("C2", ciamTicketApproval="approved", ciamTicketPlannedStart="20260924020000Z"))
    assert _states(d) == {"CHG-1": (IN_STEP,), "CHG-2": (IN_STEP,)}     # same day; an open end


def test_drift_combines_when_several_hold():
    d = _d(_change("CHG-1", "approved", "snow:C1", "20260930000000Z"), *CONTAINERS,
           _ticket("C1", ciamTicketApproval="not-requested", ciamTicketState="closed", **WINDOW))
    assert drift_states(linked(d)[0].change, linked(d)[0].ticket) == (UNAPPROVED, CLOSED_PENDING, WINDOW_DIFFERS)


def test_an_unknown_state_or_approval_raises_nothing_from_it():
    d = _d(_change("CHG-1", "approved", "snow:C1"), *CONTAINERS, _ticket("C1", ciamTicketNativeState="9 Custom"))
    assert _states(d) == {"CHG-1": (IN_STEP,)}


def test_a_ticket_entry_is_its_own_group_under_ou_tickets_and_keeps_what_the_record_adds():
    d = _d(*CONTAINERS, _ticket("C1", ciamOwner=OPS, ciamTicketState="new"))
    e = ticket_entry(d, "snow", "C1", "20260924000000Z",
                     {"ciamTicketState": "scheduled", "ciamTicketApproval": None,
                      "ciamTicketFact": ("type normal", "close_code successful"), "ciamChangeStatus": "approved"})
    assert e.dn == f"cn=C1,ou=snow,{TICKETS}" and not within(e.dn, CHANGES)
    assert values(e, "ciamOwner") == (OPS,) and one(e, "ciamTicketState") == "scheduled"
    assert values(e, "ciamTicketFact") == ("type normal", "close_code successful")
    assert "ciamTicketApproval" not in e.attrs and "ciamChangeStatus" not in e.attrs   # only ticket attributes
    assert ticket_group(e) == (e.dn, (e,))


def test_the_report_lists_every_linked_change():
    d = _d(*CHANGES_LINKED, *CONTAINERS, *TICKETS_READ[:1],
           _ticket("C2", ciamTicketState="authorize", ciamTicketApproval="rejected",
                   ciamTicketNativeState="-3 Authorize", **WINDOW))
    rows = ticket_rows(d)
    assert len(rows[0]) == len(TICKET_HEADERS)
    assert rows[0] == ("CHG-1", "approved", "2026-09-24", "snow:C1", "scheduled", "approved",
                      "2026-09-24 02:00Z to 2026-09-24 06:00Z", "", "", "2026-09-23", IN_STEP)
    assert rows[1][3:6] == ("jira:IAM-1", "", "")
    assert rows[1][-1] == NOT_IMPORTED
    assert rows[2][4:6] == ("authorize (-3 Authorize)", "rejected") and rows[2][-1] == REJECTED


def _utc(*parts):
    return dt.datetime(*parts, tzinfo=dt.timezone.utc)


def test_the_records_own_writes_are_compared_with_the_planned_window():
    d = _d(*CHANGES_LINKED[:1], *CONTAINERS, TICKETS_READ[0])
    t = linked(d)[0].ticket
    inside = (_utc(2026, 9, 24, 2), _utc(2026, 9, 24, 6), 3)
    assert applied_outside_window(t, inside) is None and applied_outside_window(t, None) is None
    assert applied_outside_window(t, (_utc(2026, 9, 24, 1, 59), _utc(2026, 9, 24, 3), 2)) == "before"
    assert applied_outside_window(t, (_utc(2026, 9, 24, 3), _utc(2026, 9, 24, 6, 1), 2)) == "after"
    assert applied_outside_window(t, (_utc(2026, 9, 23), _utc(2026, 9, 25), 2)) == "before and after"
    assert _states(d) == {"CHG-1": (IN_STEP,)}                                  # writes not read: nothing said
    writes = {"CHG-1": (_utc(2026, 10, 17, 9), _utc(2026, 10, 17, 9, 5), 4)}
    assert linked(d, writes)[0].states == (APPLIED_OUTSIDE,)
    assert linked(d, {"CHG-1": inside})[0].states == (IN_STEP,)


def test_an_open_window_end_is_never_crossed():
    d = _d(*CHANGES_LINKED[:1], *CONTAINERS, _ticket("C1", ciamTicketState="scheduled", ciamTicketApproval="approved",
                                                     ciamTicketPlannedStart="20260924020000Z"))
    assert applied_outside_window(linked(d)[0].ticket, (_utc(2026, 9, 24, 3), _utc(2099, 1, 1), 1)) is None


def test_writes_outside_the_window_are_an_action_naming_only_the_window():
    d = _d(*CHANGES_LINKED[:1], *CONTAINERS, TICKETS_READ[0])
    writes = {"CHG-1": (_utc(2026, 10, 17, 9, 7), _utc(2026, 10, 17, 9, 8), 2)}
    found = _check(d, writes)
    assert not found.blockers and not found.ok and len(found.actions) == 1
    text = found.actions[0][1]
    assert text == ("Change `CHG-1` (Work CHG-1): the record's writes under it landed after the planned window ITSM "
                    "gives its ticket snow:C1 (read 2026-09-23) (2026-09-24 02:00Z to 2026-09-24 06:00Z, as the "
                    "record's history says): review what was written outside the window, or have the ticket's "
                    "window corrected.")
    assert "2026-10-17" not in text                                     # never the write times: they're wall-clock
    row = ticket_rows(d, None, writes)[0]
    assert row[TICKET_HEADERS.index("applied")] == "2026-10-17 09:07Z to 2026-10-17 09:08Z"
    assert row[-1] == APPLIED_OUTSIDE


def test_times_after_the_read_are_evidence_from_the_future():
    t = _ticket("C1", ciamTicketState="closed", ciamTicketApproval="approved", **WINDOW,
                ciamTicketWorkStart="20260924021000Z", ciamTicketWorkEnd="20260923080000Z",
                ciamTicketApprovalStep=("approved 41 created 20260918090000Z completed 20260923100000Z",
                                        "pending 42 created ?"),
                ciamTicketApprover=("approved a1b2 updated 20260923091500Z",
                                    "approved jdoe step 7 updated 20260922000000Z phase Review board",
                                    "approved JIRAUSER1 step 9"))
    d = _d(_change("CHG-1", "approved", "snow:C1", "20260924000000Z"), *CONTAINERS, t)
    ticket = linked(d)[0].ticket
    assert after_read(ticket) == (("approver record a1b2 updated", "20260923091500Z"),
                                  ("approval step 41 completed", "20260923100000Z"),
                                  ("work started", "20260924021000Z"))
    assert linked(d)[0].states == (CLOSED_PENDING, AFTER_READ)
    text = finding_text(linked(d)[0], AFTER_READ)
    assert text.startswith("Change `CHG-1` (Work CHG-1): its ticket snow:C1 was read as of 2026-09-23 09:00Z, but "
                           "ITSM says of it: approver record a1b2 updated 2026-09-23 09:15Z; approval step 41 "
                           "completed 2026-09-23 10:00Z; work started 2026-09-24 02:10Z.")
    assert AFTER_READ in [s for link in linked(d) for s in link.states]
    assert any("Evidence from after the read" in a[1] for a in _check(d).actions)


def test_planned_times_after_the_read_are_fine():
    d = _d(_change("CHG-1", "approved", "snow:C1", "20260924000000Z"), *CONTAINERS,
           _ticket("C1", ciamTicketState="scheduled", ciamTicketApproval="approved", **WINDOW))
    assert after_read(linked(d)[0].ticket) == () and _states(d) == {"CHG-1": (IN_STEP,)}


SETTING = Setting("snow-approvals", "string", "not requested=not-requested, approved=approved", "test")


def test_a_mapping_setting_maps_to_the_values_it_allows():
    d = _d()
    assert ticket_map(d, SETTING, TICKET_APPROVALS, "a ticket approval") == (
        {"not requested": "not-requested", "approved": "approved"}, ())
    bad = SETTING._replace(default="approved=approved, approved=rejected, skipped=done, odd")
    mapping, problems = ticket_map(d, bad, TICKET_APPROVALS, "a ticket approval")
    assert mapping == {"approved": "approved"}
    assert problems == ("snow-approvals: `odd` isn't <name>=<value>",
                        "snow-approvals: `approved` is mapped more than once (the first is used)",
                        "snow-approvals: `skipped=done`: done isn't a ticket approval (not-requested, requested, "
                        "approved, rejected)")
    states = SETTING._replace(default="Open=assess, Done=finished")
    assert ticket_state_map(d, states)[0] == {"Open": "assess"}


def test_a_change_names_its_change_ticket_and_the_work_ticket_it_was_handed_over_by():
    change = _change("CHG-20", "approved", "snow:C1", "20260924000000Z") + "ciamTicketRef: snow:W1\n"
    work = _ticket("W1", ciamTicketKind="work", ciamTicketState="cancelled", ciamTicketDue="20261101000000Z")
    d = _d(*CONTAINERS, change, TICKETS_READ[0], work)
    links = {link.number: link.states for link in linked(d)}
    assert links == {"C1": (IN_STEP,), "W1": (CANCELLED,)}       # no approval to compare on a work ticket
    found = _check(d)
    assert not found.blockers                                       # a cancelled work ticket is an action
    assert [a[1] for a in found.actions] == [
        "Change `CHG-20` (Work CHG-20) is approved in the record, but ITSM says its ticket snow:W1 (read 2026-09-23), "
        "a work ticket, "
        "was **cancelled**: the work handed over by it was withdrawn. Confirm the change is still wanted, or correct "
        "the record."]
    assert linked_numbers(d, "snow") == ("C1", "W1")
