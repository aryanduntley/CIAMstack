"""Parties (ciamParty under ou=owners): how one is named in correspondence, and the one operating the platform. Pure."""
from ...core.directory import children, make_entry, one, rdn_value
from .naming import OWNERS


def display_name(e):
    """How a party is named in correspondence: its display name, else its RDN."""
    return one(e, "ciamDisplayName") or rdn_value(e)


def party_entry(name, kind="team", display=None, mail=None):
    """The entry of a party under ou=owners: its kind (team, partner, vendor, operator), how it is named in
    correspondence and its mail when given."""
    return make_entry(f"cn={name},{OWNERS}", ("top", "ciamParty"), {
        "cn": (name,), "ciamOwnerKind": (kind,), **({"ciamDisplayName": (display,)} if display else {}),
        **({"mail": (mail,)} if mail else {})})


def operator(d):
    """The party that operates the platform (ciamOwnerKind operator), if the directory records one."""
    return next((p for p in children(d, OWNERS, "ciamParty") if one(p, "ciamOwnerKind") == "operator"), None)


def operator_label(d):
    """How a finding names the party operating the platform as its owner: its RDN, or **NO OWNER** when the record
    names none."""
    op = operator(d)
    return rdn_value(op) if op is not None else "**NO OWNER**"
