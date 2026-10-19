"""Change records (ciamChange under ou=changes): every write to the record names one, and the store accepts a write
only under one that is approved. Its lifecycle is proposed -> approved -> applied, or rejected. The store sets who
wrote it (ciamAuthor, the database login that created it) and who approved it (ciamApprovedBy, the login that moved it
to approved), and refuses an approval by its own author while approval-separation is on, an approval by someone who
isn't a recorded person once people are recorded, and applied from anything but approved. Where the approvals-required
setting asks for more than one approver, each approval is recorded (ciamApprovals) and the change stays proposed until
its records' environments have theirs (migration 0015). Here: the records that create a change and move it along that
lifecycle, and how many approvals it needs. Pure."""
from ...core.changeset import new_entry, set_values
from ...core.directory import get, norm_dn, one, values
from ...core.interchange.ldif import LdifRecord, parse, write_records
from ...core.naming import env_label
from ...core.settings import setting_pairs, setting_value
from .imports import environment_of_scope
from .naming import CHANGES
from .settings import APPROVALS_REQUIRED

PROPOSED, APPROVED, APPLIED, REJECTED = "proposed", "approved", "applied", "rejected"
NEXT = {APPROVED: (PROPOSED, REJECTED), REJECTED: (PROPOSED, APPROVED), APPLIED: (APPROVED,)}   # target: from


def change_dn(change_id):
    """The DN of a change record."""
    return f"cn={change_id},{CHANGES}"


def change_record(d, change_id):
    """A change record's entry, or None."""
    return get(d, change_dn(change_id))


def new_change(d, change_id, title, ticket=None):
    """The record creating a proposed change; ValueError when it exists or the record has no ou=changes yet (the
    initial load makes it). Its author is set by the store."""
    if change_record(d, change_id) is not None:
        raise ValueError(f"change {change_id} already exists")
    if get(d, CHANGES) is None:
        raise ValueError("the record has no ou=changes yet: the initial load (opsdir load) makes it")
    return (new_entry(change_dn(change_id), ("top", "ciamChange"),
                      {"cn": (change_id,), "ciamTitle": (title,), "ciamChangeStatus": (PROPOSED,),
                       **({"ciamTicketRef": (ticket,)} if ticket else {})}),)


def proposal_record(change_id, title, records):
    """The record of a proposed change holding the LDIF change records it applies once a person approves it
    (ciamChangeRecords): what a fix, an edit or an AI proposes. ValueError when there is nothing to apply."""
    if not records:
        raise ValueError(f"{change_id} would change nothing in the record")
    return LdifRecord(change_dn(change_id), "add", {
        "objectClass": ("top", "ciamChange"), "cn": (change_id,), "ciamTitle": (title,),
        "ciamChangeStatus": (PROPOSED,), "ciamChangeRecords": (write_records(records),)}, ())


def status_change(d, change_id, status):
    """The record moving a change to status (approved, rejected or applied); ValueError when there is no such change
    or it can't move there from where it is. Who approved is set by the store."""
    change = change_record(d, change_id)
    if change is None:
        raise ValueError(f"no change {change_id}")
    held = one(change, "ciamChangeStatus")
    if held not in NEXT[status]:
        raise ValueError(f"change {change_id} is {held}: it can't become {status} (only from "
                         f"{' or '.join(NEXT[status])})")
    return set_values(change, "ciamChangeStatus", (status,))


def required_approvals(d, env):
    """How many approvals an environment ('cloud/env', '' for what lies in none) needs under the approvals-required
    setting: its own number, else the '*' one, else 1 (as the store reads it; malformed parts left out)."""
    pairs = dict(reversed(setting_pairs(setting_value(d, APPROVALS_REQUIRED))[0]))
    wanted = {k.lower(): v for k, v in pairs.items()}
    text = wanted.get(env.lower()) if env else None
    text = text if text is not None else wanted.get("*", "1")
    return int(text) if text.isdigit() and text != "0" else 1


def _record_env(record):
    env = environment_of_scope(norm_dn(record.dn))
    return env_label(env) if env else ""


def approvals_needed(d, change):
    """How many approvals a change needs: the most its proposed records' environments need ('*' when it proposes
    nothing)."""
    records = tuple(r for text in values(change, "ciamChangeRecords") for r in parse(text))
    return max((required_approvals(d, _record_env(r)) for r in records), default=required_approvals(d, ""))


def approvers(change):
    """The people who approved a change, in order (ciamApprovals, else its approver from before tiers)."""
    return tuple(values(change, "ciamApprovals")) or tuple(values(change, "ciamApprovedBy"))


def change_lines(change, needed=1):
    """A change record in lines: status, title, author, approver, the approvals so far when more than one is needed
    or given (needed: approvals_needed), ticket."""
    given = approvers(change)
    tally = f"{', '.join(given) or 'none yet'} ({len(given)} of {needed})" if needed > 1 or len(given) > 1 else None
    return tuple(f"{label:<10} {value}" for label, value in (
        ("change", one(change, "cn")), ("status", one(change, "ciamChangeStatus")), ("title", one(change, "ciamTitle")),
        ("author", one(change, "ciamAuthor")), ("approved", one(change, "ciamApprovedBy")), ("approvals", tally),
        ("ticket", one(change, "ciamTicketRef"))) if value)
