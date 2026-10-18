"""BMC Helix ITSM work orders read back (decision 3415): the work tickets a team's findings were handed over by
(drafts.py), linked on the change that does the work as ciamTicketRef bmc-helix:<Work Order ID>, read by
bmc-helix/change-requests (changes.py) and collected (collect.py) with the change tickets, as WORK tickets
(ciamTicketKind work): evidence of the hand-off, with no approval to compare. Pure.

A linked number is a work order when it starts with WO (BMC's Work Order ID prefix, WO0000000000123); any other is a
change. Work orders are read from WOI:WorkOrderInterface, the query interface BMC documents for integrations, qualified
by Work Order ID, with the fields its query mappings name (the task 612 research): the base form WOI:WorkOrder's
REST names, and its assignee-side support group fields, weren't confirmed, so neither is read.

What a work order says:
  ciamTicketKind          work
  ciamTicketState         its Status in neutral terms, by bmc-helix-work-order-states (states.py): a status the
                          setting doesn't map (Pending, Rejected, a customised one) is kept native only
  ciamTicketNativeState   the Status as BMC gives it
  planned / work window   Scheduled Start Date and Scheduled End Date, Actual Start Date and Actual End Date (the
                          schedule fields work orders and changes share, WINDOW), read as UTC
  ciamTicketDue           Scheduled End Date: when BMC expects the work done
  ciamTicketFact          status-reason, priority, work-order-type and last-modified, as BMC gives them
  ciamProviderRef         the entry's Request ID; ciamDocUrl its REST self link; ciamTitle its Description (the
                          work order's summary on the interface)"""
from opsdir.core.directory import iso_date_time
from opsdir.domains.governance.tickets import WORK

WORK_ORDER_FORM = "WOI:WorkOrderInterface"
WO_NUMBER, WO_PREFIX = "Work Order ID", "WO"
# the schedule fields work orders and change tickets share, as the ticket attributes they are read into
WINDOW = (("Scheduled Start Date", "ciamTicketPlannedStart"), ("Scheduled End Date", "ciamTicketPlannedEnd"),
          ("Actual Start Date", "ciamTicketWorkStart"), ("Actual End Date", "ciamTicketWorkEnd"))
WO_FACTS = (("Status Reason", "status-reason"), ("Priority", "priority"), ("Work Order Type", "work-order-type"),
            ("Last Modified Date", "last-modified"))
WO_FIELDS = (WO_NUMBER, "Request ID", "Description", "Status", *(f for f, _ in WINDOW), *(f for f, _ in WO_FACTS))


def is_work_order(number):
    """Whether a linked bmc-helix number names a work order (it starts with WO), not a change."""
    return str(number or "").startswith(WO_PREFIX)


def _text(v):
    return "" if v is None else str(v)


def window_times(values):
    """{ticket attribute: (GeneralizedTime or None, why not or None)} of an entry's schedule fields (WINDOW): a field
    not given is (None, None)."""
    return {attr: iso_date_time(values[f]) if values.get(f) not in (None, "") else (None, None) for f, attr in WINDOW}


def work_order_facts(values, url, states):
    """({ticket attribute: value}, problems) of one work order's values; url: its REST self link (None: not given);
    states: {Status: neutral state}."""
    number, status = _text(values.get(WO_NUMBER)), _text(values.get("Status"))
    times = window_times(values)
    facts = tuple((slug, _text(values.get(f))) for f, slug in WO_FACTS)
    return ({"ciamTitle": _text(values.get("Description")) or None,
             "ciamProviderRef": _text(values.get("Request ID")) or None,
             "ciamDocUrl": url,
             "ciamTicketKind": WORK,
             "ciamTicketState": states.get(status),
             "ciamTicketNativeState": status or None,
             **{attr: times[attr][0] for _, attr in WINDOW},
             "ciamTicketDue": times["ciamTicketPlannedEnd"][0],
             "ciamTicketFact": tuple(f"{k} {x}" for k, x in facts if x) or None},
            tuple(f"{number}: {f}: {why}" for f, attr in WINDOW for why in (times[attr][1],) if why))
