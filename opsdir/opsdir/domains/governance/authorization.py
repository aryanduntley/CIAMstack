"""Authorization: whether a requester may do an action over an area, asked once by the operations layer before an
operation runs, for every front end (decisions 2727, 2728). 5.7 builds the hook; the rule (people, teams, the action
catalog and its grants) is milestone 7.7's, plugged in as a policy instead of a second check. Pure.

A policy is a function (requester, action, area) -> None when it allows, else why it refuses. allow_all, today's
default, allows every requester, so a single-team install keeps its behaviour."""
from typing import NamedTuple, Optional

from ...core.environment import ENVIRONMENT, Scope

# What an operation acts on, as asked (the record isn't loaded yet): an environment's label, the slice of it
# (core.environment.Scope) and, for a migration, the environment it moves from.
Area = NamedTuple("Area", [("environment", str), ("scope", Scope), ("source", Optional[str])])
Area.__new__.__defaults__ = (ENVIRONMENT, None)


def allow_all(requester, action, area):
    """The default policy: every requester may do every action over every area."""
    return None


def area_text(area):
    """An area in words, for a refusal: 'target/prod', 'target/prod (keeper cn=net,...)', 'target/prod (from
    source/prod)'."""
    sliced = area.scope is not None and area.scope.kind != "environment"
    return (area.environment + (f" ({area.scope.kind} {', '.join(area.scope.value)})" if sliced else "")
            + (f" (from {area.source})" if area.source else ""))


def refusal(policy, requester, action, area):
    """Why policy refuses requester the action over area, as a message naming all three; None when it allows."""
    why = policy(requester, action, area)
    return None if why is None else f"{requester} may not {action} {area_text(area)}: {why}"
