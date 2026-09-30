"""The user directory's schema as the record describes it: every recorded attribute type and object class, and where
its definition comes from (a standard every compliant server knows, or a definition in the record). A directory can
be built from the record only when nothing is left undefined."""
from typing import NamedTuple

from ...core.directory import children, one
from ...core.findings import findings, owner_label
from ...core.ldap_schema import standard_attribute, standard_class
from .naming import USER_SCHEMA

USER_SCHEMA_HEADERS = ("kind", "name", "origin", "oid", "problem")
DEFINED = "defined in the record"

# One recorded attribute or class: its entry, kind (attribute | class), where its definition comes from, its OID,
# and what is wrong with it (None when it can be built).
Described = NamedTuple("Described", [("entry", object), ("kind", str), ("name", str), ("origin", str),
                                     ("oid", str), ("problem", str)])


def _attribute(e):
    name, oid = one(e, "ciamLdapName"), one(e, "ciamLdapOid")
    std = standard_attribute(name)
    if std:
        clash = oid and oid != std.oid
        return Described(e, "attribute", name, std.standard, oid or std.oid,
                         f"redefines standard {std.name} ({std.oid})" if clash else None)
    missing = [a for a in ("ciamLdapOid", "ciamLdapSyntax") if not one(e, a)]
    return Described(e, "attribute", name, DEFINED if not missing else "undefined", oid,
                     f"not standard; needs {', '.join(missing)}" if missing else None)


def _superior_problem(sup, recorded):
    if not sup or standard_class(sup) or sup.lower() in recorded:
        return None
    return f"superclass {sup} is neither standard nor recorded"


def _class(e, recorded):
    name, oid = one(e, "ciamLdapName"), one(e, "ciamLdapOid")
    std = standard_class(name)
    if std:
        clash = oid and oid != std.oid
        return Described(e, "class", name, std.standard, oid or std.oid,
                         f"redefines standard {std.name} ({std.oid})" if clash else None)
    problem = "not standard; needs ciamLdapOid" if not oid else _superior_problem(one(e, "ciamLdapSuperior"), recorded)
    return Described(e, "class", name, DEFINED if oid else "undefined", oid, problem)


def described(d):
    """Every recorded user-directory attribute, then every class, in DN order."""
    classes = children(d, USER_SCHEMA, "ciamUserObjectClass")
    recorded = {one(c, "ciamLdapName").lower() for c in classes}
    return (*(_attribute(e) for e in children(d, USER_SCHEMA, "ciamUserAttribute")),
            *(_class(e, recorded) for e in classes))


def attribute_records(d):
    """{lowercase LDAP name: user-schema record} of every attribute the record describes."""
    return {one(e, "ciamLdapName").lower(): e for e in children(d, USER_SCHEMA, "ciamUserAttribute")
            if one(e, "ciamLdapName")}


def defined_attributes(d):
    """Recorded attributes whose definition the record supplies (what a server must be given)."""
    return tuple(x.entry for x in described(d) if x.kind == "attribute" and x.origin == DEFINED and not x.problem)


def defined_classes(d):
    """Recorded object classes whose definition the record supplies."""
    return tuple(x.entry for x in described(d) if x.kind == "class" and x.origin == DEFINED and not x.problem)


def user_schema_rows(d, dn=None):
    """Report rows: kind, name, origin, OID, problem."""
    return [(x.kind, x.name, x.origin, x.oid or "", x.problem or "") for x in described(d)]


def check_user_schema(ctx):
    """Every attribute and class the user directory uses must be standard or defined in the record, or the target
    directory can't be built from it."""
    xs = described(ctx.d)
    bad = [x for x in xs if x.problem]
    if bad:
        return findings(blockers=[("Schema", f"User-directory {x.kind} `{x.name}`: {x.problem}. The target directory "
                                   "can't be built from the record.", owner_label(ctx.d, x.entry)) for x in bad])
    standard = sum(1 for x in xs if x.origin != DEFINED)
    return findings(ok=[f"Every user-directory attribute and object class is standard ({standard}) or defined in "
                        f"the record ({len(xs) - standard})."])
