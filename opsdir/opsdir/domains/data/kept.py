"""What a move keeps of a data service: the fixes giving the target's binding what the source's has. Shared by the
managed database and object store checks. Pure."""
from ...core.changeset import set_values
from ...core.directory import one, values
from ...core.environment import of_class
from ...core.findings import Fix, choice_fix


def carry_fix(key, area, title, s, t, attrs, manual, risks=()):
    """The Fix giving the target's binding t the source's (s) values of attrs."""
    return Fix(key, area, title, tuple(set_values(t, a, values(s, a)) for a in attrs), tuple(manual), tuple(risks))


def key_choice_fix(m, key, area, title, t, manual):
    """The Fix encrypting the target's binding t with one of environment m's keys (a choice by key role), or None
    when m binds no key."""
    keys = sorted({one(k, "ciamBindingRole") for k in of_class(m, "ciamKeyRef")})
    return choice_fix(key, area, title, t, "ciamEncryptedByRole", [(k, f"key `{k}`", ()) for k in keys], manual)
