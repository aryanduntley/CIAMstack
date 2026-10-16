"""What a BMC Helix ITSM / Remedy change ticket's own values mean in neutral terms (the user's decisions, task 556):
its Change Request Status as a ticket state, through the estate setting bmc-helix-status-states whose default is
BMC's documented status list (an operator overrides it for a tenant that customised the list); its Change Timing as a
change type; and its approval signatures' statuses as approval steps' decisions. Pure.

BMC Helix ITSM returns an enum as its string value (never its number or a label), so the map is keyed by the status
text. Pending (on hold, from any phase) and Rejected have no neutral state: Rejected is the change's approval
(overall_approval). Of Change Timing, Emergency, Normal and Standard are the neutral change types; Expedited, Latent
and No Impact aren't one (they're kept as facts)."""
from opsdir.core.contract import Setting
from opsdir.domains.governance.schema import TICKET_CHANGE_TYPES, TICKET_STATES
from opsdir.domains.governance.tickets import derived_approval

DEFAULT_STATES = ("Draft=new, Request For Authorization=authorize, Request For Change=assess, Planning In "
                  "Progress=assess, Scheduled For Review=assess, Scheduled For Approval=authorize, "
                  "Scheduled=scheduled, Implementation In Progress=implement, Completed=review, Closed=closed, "
                  "Cancelled=cancelled")
STATUS_STATES = Setting("bmc-helix-status-states", "string", DEFAULT_STATES,
                        "What each Change Request Status of the BMC Helix ITSM change tickets means, as "
                        f"comma-separated <status>=<state> ({', '.join(TICKET_STATES)}); the default is BMC's "
                        "documented list (Pending and Rejected have no state): change it only for a tenant whose "
                        "list was customised")
REJECTED = "Rejected"                                   # the status a rejected approval puts a change in
# An approval signature's status (AP:Detail-Signature 'Approval Status') as its step's decision: a step is declined
# when any signature is, else pending when any waits, else approved when any approved (One Must Sign closes the
# others); Cancelled, Error and Closed decide nothing.
SIGNATURE_DECISIONS = {"Rejected": "declined", "Pending": "pending", "Hold": "pending", "More Information": "pending",
                       "Approved": "approved"}
PRECEDENCE = ("declined", "pending", "approved")


def change_type(timing):
    """The neutral change type of a Change Timing value (Emergency, Normal, Standard), or None."""
    text = str(timing or "").strip().lower()
    return text if text in TICKET_CHANGE_TYPES else None


def step_decision(statuses):
    """An approval step's decision (declined, pending, approved) from its signatures' statuses, or None when they
    decide nothing (only Cancelled, Error or Closed)."""
    found = {SIGNATURE_DECISIONS.get(str(s or "")) for s in statuses}
    return next((d for d in PRECEDENCE if d in found), None)


def overall_approval(status, decisions, state):
    """The ticket's overall approval: rejected when its status is Rejected, else derived from its steps' decisions
    (None: the steps weren't read, or don't decide it)."""
    return "rejected" if status == REJECTED else derived_approval(decisions, state)
