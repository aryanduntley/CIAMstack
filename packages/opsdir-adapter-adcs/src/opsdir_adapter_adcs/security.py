"""Who a certificate template's access rights let enroll, read from its nTSecurityDescriptor: the binary self-relative
security descriptor (MS-DTYP 2.4.6) the directory returns when asked for the owner, group and DACL with the SD flags
control (1.2.840.113556.1.4.801, flags 7; collect.py). Pure, metadata only.

The DACL's ACEs are walked in their stored order (MS-ADTS 5.1.3.3.4; never re-sorted): an ACE marked inherit-only
(0x08) doesn't apply to the template itself. A trustee is granted Enroll by an access-allowed ACE (0x00) or
access-allowed object ACE (0x05) with GENERIC_ALL (0x10000000), full control (0xF01FF), or the control-access right
(0x100) with no object type (every extended right) or the Certificate-Enrollment extended right
(0e10c968-78fb-11d2-90d4-00c04f79dc55); the Certificate-AutoEnrollment right alone isn't Enroll. A deny ACE (0x01,
0x06) for the same right and trustee met first stops that trustee's grant; another group the requester belongs to may
deny it too, which the descriptor can't say: the enrollees are those the template grants, a candidate reading.

Broad trustees (this adapter's reading of the published ESC research, which names no single list): Everyone S-1-1-0,
Authenticated Users S-1-5-11, Anonymous Logon S-1-5-7, BUILTIN\\Users S-1-5-32-545, and a domain's Domain Users (-513),
Domain Guests (-514) and Domain Computers (-515; any user who may join a computer holds one). A descriptor that can't
be read, or whose DACL holds ACE types other than these four (callback or conditional ACEs), leaves who may enroll
unknown; an absent DACL (a NULL DACL grants everyone everything) counts as Everyone.
"""
from typing import NamedTuple
from uuid import UUID

ALLOWED, DENIED, ALLOWED_OBJECT, DENIED_OBJECT = 0x00, 0x01, 0x05, 0x06
INHERIT_ONLY = 0x08
OBJECT_TYPE_PRESENT, INHERITED_OBJECT_TYPE_PRESENT = 0x1, 0x2
CONTROL_ACCESS, GENERIC_ALL, FULL_CONTROL = 0x100, 0x10000000, 0xF01FF
DACL_PRESENT = 0x0004
ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
BROAD, RESTRICTED, UNKNOWN = "broad", "restricted", "unknown"
EVERYONE = "S-1-1-0"
WELL_KNOWN = {EVERYONE: "Everyone", "S-1-5-7": "Anonymous Logon", "S-1-5-9": "Enterprise Domain Controllers",
              "S-1-5-11": "Authenticated Users", "S-1-5-18": "Local System", "S-1-5-32-544": "Administrators",
              "S-1-5-32-545": "Users"}
DOMAIN_RIDS = {512: "Domain Admins", 513: "Domain Users", 514: "Domain Guests", 515: "Domain Computers",
               516: "Domain Controllers", 517: "Cert Publishers", 518: "Schema Admins", 519: "Enterprise Admins"}
BROAD_SIDS = frozenset((EVERYONE, "S-1-5-7", "S-1-5-11", "S-1-5-32-545"))
BROAD_RIDS = frozenset((513, 514, 515))

# One ACE of a DACL: its type, flags, access mask, the object type GUID it is scoped to (None: none) and its trustee.
Ace = NamedTuple("Ace", [("type", int), ("flags", int), ("mask", int), ("object_type", object), ("sid", str)])


def _u16(raw, at):
    return int.from_bytes(raw[at:at + 2], "little")


def _u32(raw, at):
    return int.from_bytes(raw[at:at + 4], "little")


def sid_text(raw):
    """The string form (S-1-<authority>-<sub>...) of a binary SID (MS-DTYP 2.4.2.2) at the start of raw, or None
    when raw is too short for the count it states."""
    if len(raw) < 8:
        return None
    count = raw[1]
    if len(raw) < 8 + 4 * count:
        return None
    subs = (_u32(raw, 8 + 4 * i) for i in range(count))
    return "-".join(("S", str(raw[0]), str(int.from_bytes(raw[2:8], "big")), *map(str, subs)))


def _domain_rid(sid):
    """The RID of a domain-relative SID (S-1-5-21-<three domain parts>-<RID>), else None."""
    parts = sid.split("-")
    return int(parts[7]) if len(parts) == 8 and parts[1:4] == ["1", "5", "21"] else None


def principal_label(sid):
    """A trustee as the record names it: its SID with its well-known name when it has one."""
    name = WELL_KNOWN.get(sid) or DOMAIN_RIDS.get(_domain_rid(sid))
    return f"{sid} ({name})" if name else sid


def is_broad(sid):
    """Whether a trustee is a broad group (BROAD_SIDS, or a domain's users, guests or computers)."""
    return sid in BROAD_SIDS or _domain_rid(sid) in BROAD_RIDS


def _ace(raw, at):
    """(Ace or None for a type this reader doesn't judge, its size) of the ACE at offset at, or (None, 0) when it
    can't be read."""
    if at + 8 > len(raw):
        return None, 0
    kind, flags, size = raw[at], raw[at + 1], _u16(raw, at + 2)
    if size < 8 or at + size > len(raw):
        return None, 0
    if kind in (ALLOWED, DENIED):
        sid = sid_text(raw[at + 8:at + size])
        return (Ace(kind, flags, _u32(raw, at + 4), None, sid) if sid else None), size if sid else 0
    if kind in (ALLOWED_OBJECT, DENIED_OBJECT):
        present = _u32(raw, at + 8)
        start = at + 12 + 16 * bool(present & OBJECT_TYPE_PRESENT) + 16 * bool(present & INHERITED_OBJECT_TYPE_PRESENT)
        object_type = str(UUID(bytes_le=bytes(raw[at + 12:at + 28]))) if present & OBJECT_TYPE_PRESENT else None
        sid = sid_text(raw[start:at + size]) if start < at + size else None
        return (Ace(kind, flags, _u32(raw, at + 4), object_type, sid) if sid else None), size if sid else 0
    return None, size


def dacl_aces(sd):
    """(aces, problem) of a self-relative security descriptor's DACL: its ACEs in stored order, None for a NULL
    DACL (no DACL: everyone is granted everything), and a problem (the descriptor can't be read, or holds ACE types
    this reader doesn't judge) or None."""
    if not isinstance(sd, bytes) or len(sd) < 20 or sd[0] != 1:
        return (), "isn't a security descriptor"
    control, offset = _u16(sd, 2), _u32(sd, 16)
    if not control & DACL_PRESENT or offset == 0:
        return None, None
    if offset + 8 > len(sd):
        return (), "its DACL lies outside it"
    return _walk(sd, offset + 8, _u16(sd, offset + 4), ())


def _walk(sd, at, left, read):
    """(aces, problem) of the left ACEs from offset at, after those read."""
    if left == 0:
        return read, None
    ace, size = _ace(sd, at)
    if size == 0:
        return (), "an ACE can't be read"
    if ace is None:
        return (), (f"its DACL holds an ACE of type {sd[at]:#04x} (a callback or conditional ACE) this reader "
                    "doesn't judge")
    return _walk(sd, at + size, left - 1, (*read, ace))


def _enroll(ace):
    """Whether an ACE's right covers Enroll."""
    return bool(ace.mask & GENERIC_ALL or ace.mask & FULL_CONTROL == FULL_CONTROL
                or (ace.mask & CONTROL_ACCESS and ace.object_type in (None, ENROLL)))


def enrollees(sd):
    """(trustees, scope, problem) of a template's nTSecurityDescriptor (bytes, or None when the export holds none):
    the trustees its DACL grants Enroll (labelled, in ACE order), broad when one is a broad group, else restricted;
    unknown with why when the descriptor is missing or can't be judged."""
    if sd is None:
        return (), UNKNOWN, None
    aces, problem = dacl_aces(sd)
    if problem:
        return (), UNKNOWN, problem
    if aces is None:
        return (principal_label(EVERYONE),), BROAD, None
    applying = tuple(a for a in aces if not a.flags & INHERIT_ONLY and _enroll(a))
    first = {a.sid: a.type for a in reversed(applying)}        # the first ACE met for each trustee decides
    granted = tuple(sid for sid in dict.fromkeys(a.sid for a in applying) if first[sid] in (ALLOWED, ALLOWED_OBJECT))
    return (tuple(principal_label(s) for s in granted), BROAD if any(map(is_broad, granted)) else RESTRICTED, None)
