"""How long a destination keeps what it is sent (logs, audit records, security findings), as the reports and checks read
it from ciamRetentionDays, and the reports' yes/no for a recorded switch. Shared by the observability and estate
domains. Pure."""
from ...core.directory import one

INDEFINITE = 0                     # ciamRetentionDays of a destination that never expires what it keeps


def retention_days(b):
    """How many days binding b keeps what it is sent (ciamRetentionDays; INDEFINITE: forever), or None when b is None
    or records none."""
    v = one(b, "ciamRetentionDays") if b is not None else None
    return int(v) if v is not None else None


def longest_retention(days):
    """The longest of several retentions (retention_days values): INDEFINITE when any keeps forever, else the most
    days; None when none is recorded."""
    known = [d for d in days if d is not None]
    return INDEFINITE if INDEFINITE in known else max(known) if known else None


def yes_no(e, attr):
    """A report's cell for a boolean attribute of entry e: 'yes' (TRUE), 'no' (FALSE), '' when not recorded."""
    v = one(e, attr)
    return "yes" if v == "TRUE" else "no" if v == "FALSE" else ""
