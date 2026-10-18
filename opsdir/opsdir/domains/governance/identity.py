"""The record's own identity: which organization or company it belongs to (its org code), its identifier (a UUID
made when the identity is first set) and the group it belongs to (its parent's org code), in one entry, cn=record
below the root. Each company keeps its own record; the identity tells them apart, is carried in exports and evidence,
and is what lets two companies' records be combined after a merger. The org code and identifier are fixed once set
(the store refuses changing them, and refuses removing the entry); the parent and the name may change, as when a
company leaves its group. Once a record has an identity, its change records are named with the org code as prefix
(<org>-...), so their names stay unique across companies; the store enforces it for new change records. Pure."""
import re
from typing import NamedTuple

from ...core.changeset import delete_values, new_entry, set_values
from ...core.directory import get, one
from ...core.naming import SUFFIX
from .schema import ORG_CODE, UUID

IDENTITY_DN = f"cn=record,{SUFFIX}"
IDENTITY_CLASS = "ciamRecordIdentity"
MAX_CODE = 32

Identity = NamedTuple("Identity", [("org", str), ("record_id", str), ("parent", str), ("name", str)])


def record_identity(d):
    """The record's Identity, or None when it has none yet."""
    e = get(d, IDENTITY_DN)
    if e is None or IDENTITY_CLASS not in e.classes:
        return None
    return Identity(one(e, "ciamOrgCode"), one(e, "ciamRecordId"), one(e, "ciamParentOrgCode"),
                    one(e, "description"))


def code_problem(code, what="org code"):
    """Why a text isn't a valid org code, or None."""
    if len(code) > MAX_CODE:
        return f"{what} {code!r} is longer than {MAX_CODE} characters"
    if not re.fullmatch(ORG_CODE, code):
        return f"{what} {code!r} isn't lowercase letters and digits joined by single hyphens, starting with a letter"
    return None


def _value(e, attr, value):
    """The modify record giving an attribute a value (removing it for ""), or None when it holds it or value is None
    (left as it is)."""
    held = one(e, attr)
    if value is None or (value or None) == held:
        return None
    return set_values(e, attr, (value,)) if value else delete_values(e, attr, (held,))


def identity_changes(d, org, record_id, parent=None, name=None):
    """The change records giving the record its identity, or updating its parent and name (None leaves one as it is,
    "" removes it); none when it already holds them. ValueError for an invalid code, or an org code other than the one
    the record already has (fixed once set); record_id is used only when the identity is new."""
    problems = [p for p in (code_problem(org), parent and code_problem(parent, "parent org code")) if p]
    if parent == org:
        problems.append(f"parent org code {parent!r} is the record's own org code")
    if problems:
        raise ValueError("; ".join(problems))
    held = record_identity(d)
    if held is None:
        if not re.fullmatch(UUID, record_id):
            raise ValueError(f"record id {record_id!r} isn't a lowercase UUID")
        return (new_entry(IDENTITY_DN, ("top", IDENTITY_CLASS),
                          {"cn": ("record",), "ciamOrgCode": (org,), "ciamRecordId": (record_id,),
                           **({"ciamParentOrgCode": (parent,)} if parent else {}),
                           **({"description": (name,)} if name else {})}),)
    if held.org != org:
        raise ValueError(f"the record's org code is {held.org!r}, fixed once set; it can't become {org!r}")
    e = get(d, IDENTITY_DN)
    return tuple(r for r in (_value(e, "ciamParentOrgCode", parent), _value(e, "description", name)) if r)


def change_name_problem(identity, name):
    """Why a new change record can't have this name under the record's identity, or None (any name before the record
    has an identity)."""
    if identity is None or name.lower().startswith(f"{identity.org}-"):
        return None
    return f"change {name!r} isn't named {identity.org}-...: this record's change records start with its org code"


def identity_line(identity):
    """The record's identity in one line (exports carry it as a comment), or None without one."""
    if identity is None:
        return None
    group = f" in {identity.parent}" if identity.parent else ""
    return f"record {identity.org} {identity.record_id}{group}"
