"""Change records and people, pure (domains.governance changes and people): the records that create and move a
change, who belongs to which team, how the identity provider names a person, and the role script's peer logins,
per-person roles and the API login."""
import pytest

from opsdir import cli
from opsdir.core.directory import make_directory
from opsdir.core.interchange.ldif import parse
from opsdir.domains.governance.changes import change_lines, new_change, status_change
from opsdir.domains.governance.people import person_changes, person_for_subject, person_lines, teams_of
from opsdir.store.roles import db_roles_sql

BASE = """dn: ou=changes,dc=ciam-ops
objectClass: organizationalUnit
ou: changes

dn: cn=CHG-1,ou=changes,dc=ciam-ops
objectClass: ciamChange
cn: CHG-1
ciamTitle: A change
ciamChangeStatus: proposed
ciamAuthor: alice

dn: cn=platform,ou=owners,dc=ciam-ops
objectClass: ciamParty
cn: platform

dn: cn=network,ou=owners,dc=ciam-ops
objectClass: ciamParty
cn: network
"""


def directory(text=BASE):
    rows = [(r.dn, tuple(r.attrs.get("objectClass", ())), {k: v for k, v in r.attrs.items() if k != "objectClass"})
            for r in parse(text)]
    return make_directory((), {}, rows)


def test_a_new_change_is_proposed_and_names_its_ticket():
    (record,) = new_change(directory(), "CHG-2", "Open LDAPS", "servicenow:CHG0030101")
    assert record.attrs["ciamChangeStatus"] == ("proposed",) and record.attrs["ciamTicketRef"] == (
        "servicenow:CHG0030101",)
    assert "ciamAuthor" not in record.attrs                               # the store sets it
    with pytest.raises(ValueError, match="CHG-1 already exists"):
        new_change(directory(), "CHG-1", "Again")
    with pytest.raises(ValueError, match="no ou=changes yet"):
        new_change(directory(""), "CHG-2", "Open LDAPS")


def test_a_change_moves_along_its_lifecycle_only():
    assert status_change(directory(), "CHG-1", "approved").mods == (("replace", "ciamChangeStatus", ("approved",)),)
    with pytest.raises(ValueError, match="is proposed: it can't become applied"):
        status_change(directory(), "CHG-1", "applied")
    with pytest.raises(ValueError, match="no change CHG-9"):
        status_change(directory(), "CHG-9", "approved")


def test_a_change_in_lines():
    (e,) = [x for x in directory().entries.values() if x.dn.startswith("cn=CHG-1")]
    assert change_lines(e) == ("change     CHG-1", "status     proposed", "title      A change", "author     alice")


def test_a_person_and_their_teams():
    records = person_changes(directory(), "alice", "Alice", "alice@example.com", ("platform", "network"))
    assert [r.dn for r in records] == ["ou=people,dc=ciam-ops", "cn=alice,ou=people,dc=ciam-ops"]
    d = directory(BASE + "\n" + "\n".join(
        f"dn: {r.dn}\n" + "".join(f"{k}: {v}\n" for k, vs in r.attrs.items() for v in vs) for r in records))
    assert teams_of(d, "alice") == ("platform", "network") and teams_of(d, "bob") == ()
    assert person_lines(d, "alice") == ("login  alice", "name   Alice", "mail   alice@example.com",
                                        "teams  platform, network")
    assert person_changes(d, "alice", teams=("platform",))[0].mods == (
        ("replace", "ciamMemberOf", ("cn=platform,ou=owners,dc=ciam-ops",)),)
    assert person_changes(d, "alice", name="Alice") == ()


def test_bad_logins_and_unknown_teams_are_refused():
    with pytest.raises(ValueError, match="login name 'Alice Smith'.*no team security"):
        person_changes(directory(), "Alice Smith", teams=("security",))


def test_the_role_script_for_people_signing_in_over_ssh():
    script = db_roles_sql("opsdir_owner", "opsdir_migrate", "opsdir_app", "opsdir", "peer", ("alice", "bob"))
    assert "create role alice login in role opsdir_app;" in script.splitlines()
    assert "--   local opsdir bob peer" in script.splitlines()
    assert not any("hostssl" in line for line in script.splitlines())
    with pytest.raises(ValueError, match="person name 'Bob'"):
        db_roles_sql("o", "m", "r", "d", "peer", ("Bob",))


def test_the_role_script_for_the_api_server():
    lines = db_roles_sql("opsdir_owner", "opsdir_migrate", "opsdir_app", "opsdir", "certificate",
                         api="opsdir_api").splitlines()
    for line in ("create role opsdir_api login in role opsdir_app;", "grant connect on database opsdir to opsdir_api;",
                 "--   opsdir setting api-login opsdir_api --change CHG-...",
                 "-- Only the API server holds its credentials.", "--   hostssl opsdir opsdir_api 0.0.0.0/0 cert"):
        assert line in lines, line
    assert "opsdir_api" not in db_roles_sql("opsdir_owner", "opsdir_migrate", "opsdir_app", "opsdir")
    with pytest.raises(ValueError, match="API login name 'API'"):
        db_roles_sql("o", "m", "r", "d", api="API")
    with pytest.raises(ValueError, match="the API login 'r' must be a role of its own"):
        db_roles_sql("o", "m", "r", "d", api="r")
    assert cli.parser().parse_args(["db-roles", "--api-login", "opsdir_api"]).api_login == "opsdir_api"


ISSUER = "https://login.example.com/tenant"


def with_people(*records):
    return directory(BASE + "\n" + "\n".join(
        f"dn: {r.dn}\n" + "".join(f"{k}: {v}\n" for k, vs in r.attrs.items() for v in vs) for r in records))


def test_a_person_is_found_by_how_the_identity_provider_names_them():
    d = with_people(*person_changes(directory(), "alice", subjects=(f"{ISSUER} 00u1abc", "https://idp.test/ x-9")))
    assert person_for_subject(d, ISSUER, "00u1abc") == "alice"
    assert person_for_subject(d, "https://idp.test/", "x-9") == "alice"
    assert person_for_subject(d, ISSUER + "/", "00u1abc") is None              # the issuer exactly
    assert person_for_subject(d, ISSUER, "00U1ABC") is None                    # the subject exactly
    assert person_for_subject(directory(), ISSUER, "00u1abc") is None
    assert person_lines(d, "alice") == ("login  alice", f"idp    {ISSUER} 00u1abc", "idp    https://idp.test/ x-9")
    assert person_changes(d, "alice", subjects=(f"{ISSUER} 00u1abc",))[0].mods == (
        ("replace", "ciamIdpSubject", (f"{ISSUER} 00u1abc",)),)
    assert person_changes(d, "alice", subjects=(f"{ISSUER} 00u1abc", "https://idp.test/ x-9")) == ()
    assert person_changes(d, "alice", name="Alice")[0].mods == (("replace", "ciamDisplayName", ("Alice",)),)


HELD_TWICE = BASE + f"""
dn: ou=people,dc=ciam-ops
objectClass: organizationalUnit
ou: people

dn: cn=alice,ou=people,dc=ciam-ops
objectClass: ciamPerson
cn: alice
ciamIdpSubject: {ISSUER} 00u1abc

dn: cn=bob,ou=people,dc=ciam-ops
objectClass: ciamPerson
cn: bob
ciamIdpSubject: {ISSUER} 00u1abc
"""


def test_a_subject_names_one_person():
    d = with_people(*person_changes(directory(), "alice", subjects=(f"{ISSUER} 00u1abc",)))
    with pytest.raises(ValueError, match="already names alice"):
        person_changes(d, "bob", subjects=(f"{ISSUER} 00u1abc",))
    assert person_for_subject(directory(HELD_TWICE), ISSUER, "00u1abc") is None     # held twice (by hand): nobody


@pytest.mark.parametrize("subject, message", [
    ("00u1abc", "isn't '<issuer> <subject>'"),
    (f"{ISSUER}  00u1abc", "isn't '<issuer> <subject>'"),
    (f"{ISSUER} 00u1abc extra", "isn't '<issuer> <subject>'"),
    ("http://login.example.com 00u1abc", "the issuer 'http://login.example.com' isn't an https URL"),
    ("login.example.com 00u1abc", "isn't an https URL"),
    ("https:// 00u1abc", "isn't an https URL")])
def test_malformed_subjects_are_refused(subject, message):
    with pytest.raises(ValueError, match=message):
        person_changes(directory(), "alice", subjects=(subject,))


def test_the_person_command_takes_repeatable_subjects():
    a = cli.parser().parse_args(["person", "alice", "--idp-subject", f"{ISSUER} 1", "--idp-subject", f"{ISSUER} 2"])
    assert a.idp_subject == [f"{ISSUER} 1", f"{ISSUER} 2"]
    assert cli.parser().parse_args(["person", "alice"]).idp_subject is None
