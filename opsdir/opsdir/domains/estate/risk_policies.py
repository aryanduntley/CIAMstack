"""Risk-based sign-in policies: what a threat-detection service watching identity enforces when a sign-in or a user is
judged risky, as the record states it on the service (ciamSecurityService). Pure.

A policy is '<sign-in|user> <level>+: <grant>' (ciamRiskPolicy, several per service): from that level of a sign-in's
or the user's risk up, ask for another factor (mfa), a password change, or refuse access (block). Whom the service's
policies cover is the record's to say (ciamPolicyCovers: identity bindings' roles, users or groups, or all-users), as
is whom they leave out (ciamPolicyExcludes: the break-glass accounts, so a policy never locks everyone out); a policy
names no one by default. They only report what they would do unless the record says enforced (ciamPolicyMode).

A cloud renders the policies only when they are complete: at least one policy, whom it covers, every role it names an
identity binding (a user or group) of the environment. What keeps them from being rendered is named (problems), never
guessed.
"""
import re
from collections import namedtuple

from ...core.directory import one, values
from ...core.environment import of_class
from .naming import ALL_USERS, POLICY_MODES, RISK_POLICY, USER_RISK_GRANTS

IDENTITY = "ciamIdentityBinding"
PEOPLE = ("user", "group")              # the identity kinds a sign-in policy can cover or leave out
REPORT_ONLY = POLICY_MODES[0]
# One risk-based policy: whose risk (sign-in, user), the least level it applies at, what it requires then
RiskPolicy = namedtuple("RiskPolicy", ("subject", "level", "grant"))
# Whom a service's policies cover and leave out: all_users, the identity bindings covered and excluded, and the roles
# named that are no user or group binding of the environment (unknown)
PolicyScope = namedtuple("PolicyScope", ("all_users", "covered", "excluded", "unknown"))
_POLICY = re.compile(RISK_POLICY)


def risk_policies(service):
    """The risk-based policies a security service states (ciamRiskPolicy), in the record's order."""
    return tuple(RiskPolicy(*m.groups()) for v in values(service, "ciamRiskPolicy") for m in (_POLICY.match(v),) if m)


def policy_mode(service):
    """Whether a service's risk policies are enforced or only report (report-only when the record doesn't say)."""
    return one(service, "ciamPolicyMode") or REPORT_ONLY


def _people(m):
    return {one(b, "ciamBindingRole"): b for b in of_class(m, IDENTITY)
            if one(b, "ciamIdentityKind") in PEOPLE and one(b, "ciamBindingRole")}


def policy_scope(m, service):
    """Whom environment m's security service's risk policies cover and leave out (PolicyScope): all_users when it
    covers all-users; the identity bindings (users, groups) its roles name; roles naming none (unknown)."""
    people = _people(m)
    covers, excludes = values(service, "ciamPolicyCovers"), values(service, "ciamPolicyExcludes")
    named = [r for r in (*covers, *excludes) if r != ALL_USERS]
    return PolicyScope(ALL_USERS in covers, tuple(people[r] for r in covers if r in people),
                       tuple(people[r] for r in excludes if r in people),
                       tuple(dict.fromkeys(r for r in named if r not in people)))


def policy_problems(m, service):
    """What keeps a security service's risk policies from being rendered in environment m (empty when they can be):
    policies on a service that doesn't watch identity, policies covering no one, roles that name no user or group,
    policy fields with no policy, a grant that answers a user's risk only on a sign-in's (password-change,
    risk-remediation). Also, as advice that doesn't stop the render, a policy covering every user with no
    one left out (no break-glass account)."""
    policies, scope = risk_policies(service), policy_scope(m, service)
    name = one(service, "cn")
    watches = one(service, "ciamSecurityKind") == "threat-detection" and \
        "identity" in values(service, "ciamSecurityCoverage")
    fields = any(values(service, a) for a in ("ciamPolicyCovers", "ciamPolicyExcludes", "ciamPolicyMode"))
    return tuple(p for p, bad in (
        (f"{name}: risk policies on a service that doesn't watch identity (threat-detection covering identity)",
         policies and not watches),
        (f"{name}: risk policies cover no one: set ciamPolicyCovers (identity roles, or {ALL_USERS})",
         policies and not values(service, "ciamPolicyCovers")),
        (f"{name}: ciamPolicyCovers/ciamPolicyExcludes name no user or group identity of the environment: "
         f"{', '.join(scope.unknown)}", bool(scope.unknown)),
        (f"{name}: whom risk policies cover is recorded but no policy (ciamRiskPolicy)", fields and not policies),
        *((f"{name}: '{p.subject} {p.level}+: {p.grant}': {p.grant} answers a user's risk only (user {p.level}+)",
           True) for p in policies if p.grant in USER_RISK_GRANTS and p.subject != "user"))
        if bad)


def policy_advice(m, service):
    """Advice on complete risk policies that doesn't stop their render: a policy covering every user with no one left
    out could lock out the break-glass accounts."""
    scope = policy_scope(m, service)
    return ((f"{one(service, 'cn')}: risk policies cover {ALL_USERS} and leave no one out: exclude the break-glass "
             "accounts (ciamPolicyExcludes) so a policy can't lock everyone out",)
            if risk_policies(service) and scope.all_users and not values(service, "ciamPolicyExcludes") else ())


def renders(m, service):
    """Whether environment m's security service has risk policies a cloud renders: some, and nothing in the way."""
    return bool(risk_policies(service)) and not policy_problems(m, service)
