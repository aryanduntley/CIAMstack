"""The people who work on the record (ciamPerson under ou=people), each named by their own database login, so the
store knows who wrote and who approved each change from the session itself. A person belongs to teams (ciamMemberOf ->
ciamParty under ou=owners). Once people are recorded, only a recorded person approves a change (the store enforces
it); with none recorded (a single-team install, the showcase) any login may, though never its own change while
approval-separation is on. Pure."""
from ...core.changeset import new_entry, set_values
from ...core.directory import children, get, one, values
from ...core.naming import role_name_problem
from .naming import OWNERS, PEOPLE

PERSON_CLASS = "ciamPerson"


def person_dn(login):
    """The DN of a person's entry."""
    return f"cn={login},{PEOPLE}"


def people(d):
    """Every recorded person's entry."""
    return children(d, PEOPLE, PERSON_CLASS)


def team_dn(team):
    """The DN of a team (ciamParty under ou=owners) by its name."""
    return f"cn={team},{OWNERS}"


def teams_of(d, login):
    """The names of the teams a person belongs to (none when not recorded)."""
    e = get(d, person_dn(login))
    return tuple(t.split(",", 1)[0].split("=", 1)[1] for t in values(e, "ciamMemberOf")) if e is not None else ()


def person_changes(d, login, name=None, mail=None, teams=None):
    """The change records recording a person, or updating their name, mail and teams (None leaves one as it is);
    ValueError for a login that isn't a plain database role name or a team that isn't recorded."""
    problem = role_name_problem(login, "login")
    unknown = [t for t in teams or () if get(d, team_dn(t)) is None]
    if problem or unknown:
        raise ValueError("; ".join([*([problem] if problem else []),
                                    *(f"no team {t} (ou=owners)" for t in unknown)]))
    attrs = {"ciamDisplayName": name, "mail": mail,
             "ciamMemberOf": None if teams is None else tuple(team_dn(t) for t in teams)}
    e = get(d, person_dn(login))
    if e is None:
        branch = () if get(d, PEOPLE) is not None else (new_entry(PEOPLE, ("top", "organizationalUnit"),
                                                                  {"ou": ("people",)}),)
        return (*branch, new_entry(person_dn(login), ("top", PERSON_CLASS),
                                   {"cn": (login,), **{k: (v,) if isinstance(v, str) else v
                                                       for k, v in attrs.items() if v}}))
    return tuple(set_values(e, k, (v,) if isinstance(v, str) else v) for k, v in attrs.items()
                 if v is not None and tuple(values(e, k)) != ((v,) if isinstance(v, str) else tuple(v)))


def person_lines(d, login):
    """A recorded person in lines: login, name, mail, teams; None when not recorded."""
    e = get(d, person_dn(login))
    if e is None:
        return None
    return tuple(f"{label:<6} {value}" for label, value in (
        ("login", login), ("name", one(e, "ciamDisplayName")), ("mail", one(e, "mail")),
        ("teams", ", ".join(teams_of(d, login)))) if value)
