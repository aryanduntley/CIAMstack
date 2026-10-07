"""Principals and the permission sets they hold: the report, and the planner's checks on them. Pure.

A principal names the binding role of its identity (ciamIdentityRole), so each environment gives it its own role,
managed identity or service account; the core role check already names a role the source binds and the target
doesn't. Here: an identity no environment binds, a principal nobody owns, an access review that is overdue, and a
break-glass account that couldn't be used today (no credential, no procedure, never or long ago tested).
"""
from ...core.directory import children, date_of, follow_all, one, rdn_value, values
from ...core.environment import bound_nowhere
from ...core.findings import findings, owner_label, responsible
from ...core.settings import setting_value
from .naming import PERMISSION_SETS, PRINCIPALS
from .settings import REVIEW_DAYS, TEST_DAYS

PRINCIPAL_HEADERS = ("principal", "kind", "identity role", "server role", "permission sets", "permits", "conditions",
                     "owner", "reviewed", "to check")


def permission_sets(d):
    return children(d, PERMISSION_SETS, "ciamPermissionSet")


def principals(d):
    return children(d, PRINCIPALS, "ciamPrincipal")


def permits(d, p):
    """Everything a principal's permission sets allow, as 'verb role' (sorted, once each)."""
    return tuple(sorted({x for s in follow_all(d, p, "ciamHoldsSet") if s is not None
                         for x in values(s, "ciamPermits")}))


def to_check(d, p, as_of):
    """What an operator should look at for one principal, as short phrases."""
    reviewed, tested = date_of(p, "ciamReviewedOn"), date_of(p, "ciamLastTested")
    every = int(one(p, "ciamReviewIntervalDays") or setting_value(d, REVIEW_DAYS))
    glass = one(p, "ciamPrincipalKind") == "break-glass"
    checks = (("no owner", not values(p, "ciamOwner")),
              ("never reviewed", reviewed is None),
              (f"review overdue (last {reviewed}, every {every} days)" if reviewed else "",
               bool(reviewed) and (as_of - reviewed).days > every),
              ("no permission set", not values(p, "ciamHoldsSet") and not glass),
              ("break-glass: no credential role", glass and not one(p, "ciamUsesRole")),
              ("break-glass: no procedure", glass and not one(p, "ciamRunbookRef")),
              ("break-glass: never tested", glass and tested is None),
              (f"break-glass: last tested {tested}" if tested else "",
               glass and bool(tested) and (as_of - tested).days > setting_value(d, TEST_DAYS)))
    return tuple(text for text, applies in checks if applies)


def principal_rows(d, dn=None, as_of=None):
    """One row per principal: what it acts as, what it may do, who owns it, when it was reviewed, what to check."""
    return [(rdn_value(p), one(p, "ciamPrincipalKind"), one(p, "ciamIdentityRole"), one(p, "ciamTargetRole") or "",
             ", ".join(rdn_value(s) for s in follow_all(d, p, "ciamHoldsSet") if s is not None),
             ", ".join(permits(d, p)), ", ".join(values(p, "ciamCondition")),
             owner_label(d, p) if values(p, "ciamOwner") else "", str(date_of(p, "ciamReviewedOn") or ""),
             "; ".join(to_check(d, p, as_of)) if as_of else "")
            for p in principals(d)]


def check_principals(ctx):
    """A principal whose identity neither environment binds is a blocker (nothing to act as after the move); every
    other point to check about a principal is an action for its owner."""
    blockers, actions = [], []
    for p in principals(ctx.d):
        name, owner = rdn_value(p), responsible(ctx.d, p, ctx.src.env)
        if bound_nowhere((one(p, "ciamIdentityRole"),), ctx.src, ctx.dst):
            blockers.append(("Access", f"Principal `{name}` acts as role `{one(p, 'ciamIdentityRole')}`, which neither "
                                       f"{ctx.src.label} nor {ctx.dst.label} binds: record the identity each "
                                       "environment gives it.", owner))
        actions.extend(("Access", f"Principal `{name}`: {point}.", owner, None) for point in to_check(ctx.d, p,
                                                                                                     ctx.as_of))
    return findings(blockers=blockers, actions=actions)
