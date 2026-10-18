"""The people who work on the record (ciamPerson under ou=people), each named by their own database login, so the
store knows who wrote and who approved each change from the session itself. A person belongs to teams (ciamMemberOf ->
ciamParty under ou=owners). Once people are recorded, only a recorded person approves a change (the store enforces
it); with none recorded (a single-team install, the showcase) any login may, though never its own change while
approval-separation is on. A person signing in to the HTTP API is found by how the company's identity provider names
them (ciamIdpSubject: '<issuer> <subject>', a token's iss and sub claims); the API server, under the login the
api-login setting names, then acts for their login. Pure."""
from urllib.parse import urlsplit

from ...core.changeset import new_entry, set_values
from ...core.directory import children, get, one, values
from ...core.naming import role_name_problem
from .naming import OWNERS, PEOPLE

PERSON_CLASS = "ciamPerson"
SUBJECT_ATTR = "ciamIdpSubject"


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


def subject_problem(text):
    """Why a text can't be an identity-provider subject ('<issuer> <subject>': exactly two space-separated parts, the
    issuer an https URL), or None."""
    parts = (text or "").split(" ")
    if len(parts) != 2 or not all(parts):
        return f"identity-provider subject {text!r} isn't '<issuer> <subject>' (two parts, one space)"
    url = urlsplit(parts[0])
    return None if url.scheme == "https" and url.hostname else \
        f"identity-provider subject {text!r}: the issuer {parts[0]!r} isn't an https URL"


def _holders(d, subject):
    return tuple(one(e, "cn") for e in people(d) if subject in values(e, SUBJECT_ATTR))


def person_for_subject(d, issuer, subject):
    """The login (cn) of the person the identity provider names (their ciamIdpSubject '<issuer> <subject>', the
    issuer and subject compared exactly), or None, also when more than one person holds it (person_changes refuses
    that; a record edited by hand could still)."""
    found = _holders(d, f"{issuer} {subject}")
    return found[0] if len(found) == 1 else None


def person_changes(d, login, name=None, mail=None, teams=None, subjects=None):
    """The change records recording a person, or updating their name, mail, teams and identity-provider subjects
    ('<issuer> <subject>'; None leaves one as it is); ValueError for a login that isn't a plain database role name, a
    team that isn't recorded, or a subject that is malformed or names another person."""
    problems = [p for p in (role_name_problem(login, "login"), *(subject_problem(s) for s in subjects or ())) if p]
    problems += [f"identity-provider subject {s!r} already names {', '.join(held)}" for s in subjects or ()
                 for held in (tuple(h for h in _holders(d, s) if h != login),) if held]
    unknown = [t for t in teams or () if get(d, team_dn(t)) is None]
    if problems or unknown:
        raise ValueError("; ".join([*problems, *(f"no team {t} (ou=owners)" for t in unknown)]))
    attrs = {"ciamDisplayName": name, "mail": mail,
             "ciamMemberOf": None if teams is None else tuple(team_dn(t) for t in teams),
             SUBJECT_ATTR: None if subjects is None else tuple(subjects)}
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
    """A recorded person in lines: login, name, mail, teams, identity-provider subjects; None when not recorded."""
    e = get(d, person_dn(login))
    if e is None:
        return None
    return tuple(f"{label:<6} {value}" for label, value in (
        ("login", login), ("name", one(e, "ciamDisplayName")), ("mail", one(e, "mail")),
        ("teams", ", ".join(teams_of(d, login))), *(("idp", s) for s in values(e, SUBJECT_ATTR))) if value)
