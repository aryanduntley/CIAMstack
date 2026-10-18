"""Permissions: which actions of the catalog (ACTIONS) people may do over which areas, as governed grants
(ciamGrant under ou=grants, each giving actions to people or teams, limited to environments and to what given teams own
or keep). The record's policy (policy_for) is the function the operations layer asks before every operation
(governance.authorization); every front end shares it.

- No grant recorded: every action is allowed (a single-team install, the showcase: behaviour unchanged).
- Otherwise: administration (init, upgrade, the initial load) is left to the database's own privileges; every other
  action needs the requester to be a recorded person; reading is open to every recorded person (the record holds no
  secret values); any other action needs a grant of it, held by the person or a team of theirs, whose environments
  include the area's (none listed: all) and whose owners include the team the area is scoped to (none listed: all; a
  grant limited to owners covers only an area scoped to one of them).
Pure."""
from ...core.changeset import new_entry, set_values
from ...core.directory import children, get, one, values
from .naming import GRANTS
from .people import person_dn, team_dn, teams_of
from .schema import ACTIONS

GRANT_CLASS = "ciamGrant"
OPEN, ADMIN = "read", "admin"


def grants(d):
    """Every recorded grant's entry."""
    return children(d, GRANTS, GRANT_CLASS)


def grant_dn(name):
    """The DN of a grant."""
    return f"cn={name},{GRANTS}"


def _grantee_dn(d, name):
    return person_dn(name) if get(d, person_dn(name)) is not None else team_dn(name)


def grant_changes(d, name, actions, grantees, environments=(), owners=()):
    """The change records recording a grant (ou=grants added when missing) or replacing its actions, grantees and
    limits; ValueError for an action outside the catalog, a grantee that is no recorded person or team, or an owner
    that is no recorded team."""
    unknown = [a for a in actions if a not in ACTIONS]
    nobody = [g for g in grantees if get(d, _grantee_dn(d, g)) is None]
    no_team = [o for o in owners if get(d, team_dn(o)) is None]
    if unknown or nobody or no_team or not actions or not grantees:
        raise ValueError("; ".join([*(f"{a} isn't an action ({', '.join(ACTIONS)})" for a in unknown),
                                    *(f"{g} is no recorded person (ou=people) or team (ou=owners)" for g in nobody),
                                    *(f"no team {o} (ou=owners)" for o in no_team),
                                    *(["a grant gives at least one action"] if not actions else []),
                                    *(["a grant is for at least one person or team"] if not grantees else [])]))
    attrs = {"ciamGrantAction": tuple(actions), "ciamGrantee": tuple(_grantee_dn(d, g) for g in grantees),
             "ciamGrantEnvironment": tuple(environments), "ciamGrantOwner": tuple(team_dn(o) for o in owners)}
    e = get(d, grant_dn(name))
    if e is None:
        branch = () if get(d, GRANTS) is not None else (new_entry(GRANTS, ("top", "organizationalUnit"),
                                                                  {"ou": ("grants",)}),)
        return (*branch, new_entry(grant_dn(name), ("top", GRANT_CLASS),
                                   {"cn": (name,), **{k: v for k, v in attrs.items() if v}}))
    return tuple(set_values(e, k, v) for k, v in attrs.items() if tuple(values(e, k)) != v)


def _covers(g, area):
    envs, owners = values(g, "ciamGrantEnvironment"), {o.lower() for o in values(g, "ciamGrantOwner")}
    if envs and area.environment not in envs:
        return False
    if not owners:
        return True
    return (area.scope is not None and area.scope.kind == "keeper"
            and any(v.lower() in owners for v in area.scope.value))


def holds(d, login, action, area):
    """Whether a recorded person holds a grant of the action covering the area (theirs, or a team of theirs)."""
    mine = {person_dn(login).lower(), *(team_dn(t).lower() for t in teams_of(d, login))}
    return any(action in values(g, "ciamGrantAction") and mine & {x.lower() for x in values(g, "ciamGrantee")}
               and _covers(g, area) for g in grants(d))


def policy_for(d):
    """The record's policy, (requester, action, area) -> None when allowed, else why not (governance.authorization)."""
    if not grants(d):
        return lambda requester, action, area: None
    def policy(requester, action, area):                                        # noqa: E306
        if action == ADMIN:
            return None
        if get(d, person_dn(requester)) is None:
            return "they aren't a recorded person (ou=people)"
        if action == OPEN or holds(d, requester, action, area):
            return None
        return f"no grant gives them {action} there (opsdir report grants)"
    return policy


GRANT_HEADERS = ("grant", "actions", "to", "environments", "owners")


def grant_rows(d, dn=None):
    """The grants report: each grant's actions, people and teams, and limits (dn unused: every grant)."""
    rdn = lambda dn: dn.split(",", 1)[0].split("=", 1)[1]                       # noqa: E731
    return tuple((one(g, "cn"), ", ".join(values(g, "ciamGrantAction")),
                  ", ".join(rdn(x) for x in values(g, "ciamGrantee")),
                  ", ".join(values(g, "ciamGrantEnvironment")) or "all",
                  ", ".join(rdn(x) for x in values(g, "ciamGrantOwner")) or "all")
                 for g in sorted(grants(d), key=lambda g: one(g, "cn")))
