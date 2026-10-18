"""Change records (ciamChange under ou=changes): every write to the record names one, and the store accepts a write
only under one that is approved. Its lifecycle is proposed -> approved -> applied, or rejected. The store sets who
wrote it (ciamAuthor, the database login that created it) and who approved it (ciamApprovedBy, the login that moved it
to approved), and refuses an approval by its own author while approval-separation is on, an approval by someone who
isn't a recorded person once people are recorded, and applied from anything but approved. Here: the records that
create a change and move it along that lifecycle. Pure."""
from ...core.changeset import new_entry, set_values
from ...core.directory import get, one
from .naming import CHANGES

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


def change_lines(change):
    """A change record in lines: status, title, author, approver, ticket."""
    return tuple(f"{label:<10} {value}" for label, value in (
        ("change", one(change, "cn")), ("status", one(change, "ciamChangeStatus")), ("title", one(change, "ciamTitle")),
        ("author", one(change, "ciamAuthor")), ("approved", one(change, "ciamApprovedBy")),
        ("ticket", one(change, "ciamTicketRef"))) if value)
