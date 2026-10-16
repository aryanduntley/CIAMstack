"""ITSM ticket evidence: change records linked to the tickets their change management tracks them by, and what each
ticket said when an ITSM add-on's importer last read it, compared with the record. Pure.

A change names its ticket in ciamTicketRef as <adapter>:<number> (servicenow:CHG0030101): the operator's link. The
add-on's importer reads the tickets the record links into their own entries (ciamTicket at cn=<number>,ou=<adapter>,
ou=tickets): the ticket's state in neutral terms (when the add-on knows the ticket's state model), its overall
approval, its planned and actual (work) windows, its approval records and other fields as the system gave them, all
EVIDENCE. Nothing here, and nothing an importer writes, is under ou=changes: a ticket never changes a change's status
or approver, and never authorizes a write (the store accepts a write only under an approved change record).

Each linked change is in one or more of these drift states, kept apart because each asks something different:

  in-step           the ticket agrees with the record
  not-imported      the ticket hasn't been read (not exported, or the reader may not see it), while the record holds
                    tickets read from the same system
  rejected          the record approves the change (approved or applied); ITSM says the ticket's approval was rejected
  cancelled         the record approves the change; ITSM says the ticket was cancelled
  unapproved        the record approves the change; ITSM says approval is still requested or was never requested
  closed-pending    ITSM says the ticket is closed (or cancelled, for a proposed change) while the record has the
                    change still proposed or approved: the record doesn't say what happened
  live-but-rejected the record rejected the change; ITSM says the ticket is approved, scheduled or being implemented
  window-differs    the day the record plans the change (ciamPlannedAt, UTC) is outside the ticket's planned window's
                    days
  outside-window    ITSM says the work ran outside the ticket's own planned window (actual start before its planned
                    start, or actual end after its planned end; exact UTC times, no tolerance)

The planner's check is silent while the record holds no ticket at all (nothing read yet: a plan is as before);
rejected and cancelled are blockers (the record holds an approval its change management refused or withdrew), the
others actions for the change's owner (else the operator). A ticket's approval is never judged from its approval
records (one approved approver doesn't approve a change; no records doesn't mean none was needed): only from the
overall approval the system reports. No fix is offered: a change's status is a person's.
"""
from typing import NamedTuple

from ...core.directory import (children, get, gtime_at, gtime_date, make_entry, merged_attrs, one, rdn_of, rdn_value,
                               subtree)
from ...core.findings import findings, owner_label
from .naming import CHANGES, TICKETS
from .parties import operator_label

AREA = "Change tickets"
TICKET_CLASS = "ciamTicket"
TICKET_ATTRS = ("cn", "ciamImportedAt", "ciamTitle", "ciamProviderRef", "ciamDocUrl", "ciamTicketState",
                "ciamTicketApproval", "ciamTicketNativeState", "ciamTicketPlannedStart", "ciamTicketPlannedEnd",
                "ciamTicketWorkStart", "ciamTicketWorkEnd", "ciamTicketApprover", "ciamTicketFact")
TICKET_HEADERS = ("change", "status", "planned", "ticket", "state", "approval", "planned window", "work window",
                  "read at", "drift")
IN_STEP, NOT_IMPORTED, REJECTED, CANCELLED, UNAPPROVED, CLOSED_PENDING, LIVE_REJECTED, WINDOW_DIFFERS, \
    OUTSIDE_WINDOW = ("in-step", "not-imported", "rejected", "cancelled", "unapproved", "closed-pending",
                      "live-but-rejected", "window-differs", "outside-window")
BLOCKING = (REJECTED, CANCELLED)
APPROVING = ("approved", "applied")          # record statuses that let the change's writes in
PENDING = ("proposed", "approved")           # record statuses that don't say what happened yet
LIVE = ("scheduled", "implement")            # ticket states of work still to happen or happening

# A linked change compared with its ticket: the change, the adapter and number it names, the ticket as last read (None:
# not read) and its drift states (none: nothing to compare yet, the system's tickets were never read).
Linked = NamedTuple("Linked", [("change", object), ("adapter", str), ("number", str), ("ticket", object),
                               ("states", tuple)])


# ------------------------------------------------------------------ links and where tickets are kept
def ticket_ref(change):
    """(adapter, number) a change's ciamTicketRef names, or None (none, or not <adapter>:<number>)."""
    adapter, _, number = (one(change, "ciamTicketRef") or "").partition(":")
    return (adapter, number) if adapter and number else None


def adapter_dn(adapter):
    """The branch holding the tickets one ITSM add-on read."""
    return f"ou={adapter},{TICKETS}"


def ticket_dn(adapter, number):
    """Where a ticket an ITSM add-on read is kept."""
    return f"cn={number},{adapter_dn(adapter)}"


def linked_changes(d):
    """Every change record naming a ticket, by name."""
    return tuple(sorted((c for c in children(d, CHANGES, "ciamChange") if ticket_ref(c)), key=rdn_value))


def linked_numbers(d, adapter):
    """The ticket numbers the record's changes name for one ITSM add-on, each once, in change order."""
    return tuple(dict.fromkeys(ticket_ref(c)[1] for c in linked_changes(d) if ticket_ref(c)[0] == adapter))


def tickets(d):
    """Every ticket the record holds (as last read)."""
    return tuple(subtree(d, TICKETS, TICKET_CLASS))


# ------------------------------------------------------------------ what importers write
def ticket_entry(d, adapter, number, at, facts):
    """A ticket's entry as read at `at` (GeneralizedTime): facts {attribute of TICKET_ATTRS: value, or a tuple for a
    multi-valued one; None: the system didn't say}; what the record adds to the entry (owners) kept."""
    dn = ticket_dn(adapter, number)
    owned = {"cn": (number,), "ciamImportedAt": (at,),
             **{k: (v if isinstance(v, tuple) else (v,)) for k, v in facts.items()
                if k in TICKET_ATTRS and k not in ("cn", "ciamImportedAt")}}
    return make_entry(dn, ("top", "ciamObject", TICKET_CLASS), merged_attrs(get(d, dn), owned, TICKET_ATTRS))


def ticket_group(entry):
    """The import group of one ticket: its own entry, replacing only it (an export never removes another ticket)."""
    return entry.dn, (entry,)


# ------------------------------------------------------------------ comparison
def _day(e, attr):
    v = one(e, attr)
    return gtime_date(v) if v else None


def _at(e, attr):
    v = one(e, attr)
    return gtime_at(v) if v else None


def window_differs(change, ticket):
    """Whether the day the record plans the change is outside the days of the ticket's planned window (either end the
    ticket doesn't give is open)."""
    planned = _day(change, "ciamPlannedAt")
    start, end = _day(ticket, "ciamTicketPlannedStart"), _day(ticket, "ciamTicketPlannedEnd")
    return planned is not None and (start is not None or end is not None) and \
        ((start is not None and planned < start) or (end is not None and planned > end))


def outside_window(ticket):
    """Whether ITSM says the work ran outside the ticket's own planned window: it started before the planned start or
    ended after the planned end."""
    start, end = _at(ticket, "ciamTicketPlannedStart"), _at(ticket, "ciamTicketPlannedEnd")
    began, ended = _at(ticket, "ciamTicketWorkStart"), _at(ticket, "ciamTicketWorkEnd")
    return (start is not None and began is not None and began < start) or \
        (end is not None and ended is not None and ended > end)


def drift_states(change, ticket):
    """The drift states of a change against its ticket as read (IN_STEP alone when they agree)."""
    status, state, approval = (one(change, "ciamChangeStatus"), one(ticket, "ciamTicketState"),
                               one(ticket, "ciamTicketApproval"))
    found = (*((REJECTED,) if status in APPROVING and approval == "rejected" else ()),
             *((CANCELLED,) if status in APPROVING and state == "cancelled" else ()),
             *((UNAPPROVED,) if status in APPROVING and approval in ("requested", "not-requested") else ()),
             *((CLOSED_PENDING,) if (state == "closed" and status in PENDING) or
               (state == "cancelled" and status == "proposed") else ()),
             *((LIVE_REJECTED,) if status == "rejected" and (approval == "approved" or state in LIVE) else ()),
             *((WINDOW_DIFFERS,) if window_differs(change, ticket) else ()),
             *((OUTSIDE_WINDOW,) if outside_window(ticket) else ()))
    return found or (IN_STEP,)


def linked(d):
    """Every linked change compared with its ticket (Linked), by change name."""
    read = {rdn_of(t.dn.split(",", 1)[1]) for t in tickets(d)}       # the systems whose tickets were read

    def compare(c):
        adapter, number = ticket_ref(c)
        t = get(d, ticket_dn(adapter, number))
        states = drift_states(c, t) if t is not None else ((NOT_IMPORTED,) if adapter in read else ())
        return Linked(c, adapter, number, t, states)
    return tuple(compare(c) for c in linked_changes(d))


# ------------------------------------------------------------------ words
def _when(gt):
    return f"{gt[:4]}-{gt[4:6]}-{gt[6:8]} {gt[8:10]}:{gt[10:12]}Z" if gt else "?"


def _window(t, start, end):
    s, e = one(t, start), one(t, end)
    return f"{_when(s)} to {_when(e)}" if s or e else ""


def _owner(d, change):
    """Who answers for a linked change: its owners, else the party operating the platform."""
    if change.attrs.get("ciamOwner"):
        return owner_label(d, change)
    return operator_label(d)


def _change(link):
    return f"Change `{rdn_value(link.change)}` ({one(link.change, 'ciamTitle')})"


def _ticket(link):
    read = one(link.ticket, "ciamImportedAt") if link.ticket is not None else None
    return f"its ticket {link.adapter}:{link.number}" + (f" (read {_when(read)[:10]})" if read else "")


def _approval(t):
    return (one(t, "ciamTicketApproval") or "unknown").replace("-", " ")


def finding_text(link, state):
    """What one drift state of a linked change says, in words ('ITSM says': evidence, never the record's approval)."""
    if state == NOT_IMPORTED:
        return (f"{_change(link)} names ticket {link.adapter}:{link.number}, but no import has read it (it wasn't in "
                "the export, or the reader can't see it: an ITSM answer can be cut short by its access rules): "
                "include it in the next read.")
    status, t = one(link.change, "ciamChangeStatus"), link.ticket
    head = f"{_change(link)} is {status} in the record"
    texts = {
        REJECTED: f"{head}, but ITSM says {_ticket(link)} was **rejected**: the record holds an approval its change "
                  "management refused. Reconcile them before the move (a ticket never changes the record's status).",
        CANCELLED: f"{head}, but ITSM says {_ticket(link)} was **cancelled**: the record holds an approval for "
                   "work its change management withdrew. Reconcile them before the move (a ticket never changes the "
                   "record's status).",
        UNAPPROVED: f"{head}, but ITSM says the approval of {_ticket(link)} is {_approval(t)}: have it approved in "
                    "ITSM, or correct the record.",
        CLOSED_PENDING: f"{head}, but ITSM says {_ticket(link)} is {one(t, 'ciamTicketState')}: record what "
                        "happened (applied or rejected), or reopen the ticket.",
        LIVE_REJECTED: f"{head}, but ITSM says {_ticket(link)} is still "
                       f"{one(t, 'ciamTicketState') or 'open'} (approval {_approval(t)}): withdraw the ticket, or "
                       "correct the record.",
        WINDOW_DIFFERS: f"{_change(link)} is planned for {_when(one(link.change, 'ciamPlannedAt'))[:10]} in the "
                        f"record, but ITSM says {_ticket(link)} plans it for "
                        f"{_window(t, 'ciamTicketPlannedStart', 'ciamTicketPlannedEnd')}: align the dates.",
        OUTSIDE_WINDOW: f"{_change(link)}: ITSM says the work on {_ticket(link)} "
                        f"ran {_window(t, 'ciamTicketWorkStart', 'ciamTicketWorkEnd')}, outside its planned window "
                        f"{_window(t, 'ciamTicketPlannedStart', 'ciamTicketPlannedEnd')}: review the work done "
                        "outside the window.",
    }
    return texts[state]


def check_tickets(ctx):
    """Blockers for linked changes whose ticket ITSM says was rejected or cancelled while the record approves them,
    actions for the other drift, the changes in step as fine; nothing while the record holds no ticket."""
    if not tickets(ctx.d):
        return findings()
    links = linked(ctx.d)
    raised = [(s, link) for link in links for s in link.states if s != IN_STEP]
    return findings(
        blockers=[(AREA, finding_text(link, s), _owner(ctx.d, link.change)) for s, link in raised if s in BLOCKING],
        actions=[(AREA, finding_text(link, s), _owner(ctx.d, link.change), None) for s, link in raised
                 if s not in BLOCKING],
        ok=[f"{_change(link)} agrees with {_ticket(link)}: {one(link.change, 'ciamChangeStatus')}; ITSM says "
            f"{one(link.ticket, 'ciamTicketState') or 'state unknown'}, approval {_approval(link.ticket)}"
            for link in links if link.states == (IN_STEP,)])


def ticket_rows(d, dn=None):
    """One row per linked change: its status and planned day in the record, the ticket, what ITSM said of it (state,
    with the system's own; overall approval; planned and work windows; when it was read) and its drift."""
    def row(link):
        t = link.ticket
        native = f" ({one(t, 'ciamTicketNativeState')})" if t is not None and one(t, "ciamTicketNativeState") else ""
        state = f"{one(t, 'ciamTicketState') or 'unknown'}{native}" if t is not None else ""
        return (rdn_value(link.change), one(link.change, "ciamChangeStatus"),
                _when(one(link.change, "ciamPlannedAt"))[:10] if one(link.change, "ciamPlannedAt") else "",
                f"{link.adapter}:{link.number}", state, _approval(t) if t is not None else "",
                _window(t, "ciamTicketPlannedStart", "ciamTicketPlannedEnd") if t is not None else "",
                _window(t, "ciamTicketWorkStart", "ciamTicketWorkEnd") if t is not None else "",
                _when(one(t, "ciamImportedAt"))[:10] if t is not None else "",
                ", ".join(link.states or (NOT_IMPORTED,)))
    return [row(link) for link in linked(d)]
