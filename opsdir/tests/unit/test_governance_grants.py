"""Permissions, pure (domains.governance.grants): the record's policy with no grants, then with grants for people and
teams, limited to environments and to what teams own or keep; and the grant records."""
import pytest

from opsdir import cli
from opsdir.core.directory import make_directory
from opsdir.core.environment import ENVIRONMENT, Scope
from opsdir.core.interchange.ldif import parse
from opsdir.domains.governance.authorization import Area
from opsdir.domains.governance.grants import grant_changes, grant_rows, policy_for
from opsdir.domains.governance.schema import ACTIONS

PEOPLE = """dn: cn=platform,ou=owners,dc=ciam-ops
objectClass: ciamParty
cn: platform

dn: cn=network,ou=owners,dc=ciam-ops
objectClass: ciamParty
cn: network

dn: cn=alice,ou=people,dc=ciam-ops
objectClass: ciamPerson
cn: alice
ciamMemberOf: cn=platform,ou=owners,dc=ciam-ops

dn: cn=bob,ou=people,dc=ciam-ops
objectClass: ciamPerson
cn: bob
"""
GRANTS = """
dn: cn=platform-render,ou=grants,dc=ciam-ops
objectClass: ciamGrant
cn: platform-render
ciamGrantAction: render
ciamGrantAction: plan
ciamGrantee: cn=platform,ou=owners,dc=ciam-ops
ciamGrantEnvironment: target/prod

dn: cn=bob-network,ou=grants,dc=ciam-ops
objectClass: ciamGrant
cn: bob-network
ciamGrantAction: apply
ciamGrantee: cn=bob,ou=people,dc=ciam-ops
ciamGrantOwner: cn=network,ou=owners,dc=ciam-ops
"""


def directory(text):
    rows = [(r.dn, tuple(r.attrs.get("objectClass", ())), {k: v for k, v in r.attrs.items() if k != "objectClass"})
            for r in parse(text)]
    return make_directory((), {}, rows)


def test_with_no_grants_everything_is_allowed():
    policy = policy_for(directory(PEOPLE))
    assert policy("anyone", "apply", Area("")) is None and policy("alice", "approve", Area("target/prod")) is None


def test_reads_are_open_to_people_and_administration_to_the_database():
    policy = policy_for(directory(PEOPLE + GRANTS))
    assert policy("bob", "read", Area("")) is None
    assert policy("stranger", "admin", Area("")) is None
    assert policy("stranger", "read", Area("")) == "they aren't a recorded person (ou=people)"


def test_a_team_grant_limited_to_an_environment():
    policy = policy_for(directory(PEOPLE + GRANTS))
    assert policy("alice", "render", Area("target/prod")) is None               # through the platform team
    assert policy("alice", "plan", Area("target/prod", ENVIRONMENT, "source/prod")) is None
    assert "no grant gives them render there" in policy("alice", "render", Area("source/prod"))
    assert "no grant gives them apply there" in policy("alice", "apply", Area("target/prod"))
    assert policy("bob", "render", Area("target/prod"))                         # not in the team


def test_a_grant_limited_to_owners_covers_only_their_scoped_areas():
    policy = policy_for(directory(PEOPLE + GRANTS))
    keeper = Scope("keeper", ("cn=network,ou=owners,dc=ciam-ops",))
    assert policy("bob", "apply", Area("target/prod", keeper)) is None
    assert policy("bob", "apply", Area("target/prod"))                          # the whole environment: not his
    assert policy("bob", "apply", Area("target/prod", Scope("keeper", ("cn=platform,ou=owners,dc=ciam-ops",))))


def test_grant_records_and_report():
    d = directory(PEOPLE)
    records = grant_changes(d, "net", ("apply", "plan"), ("bob", "network"), ("target/prod",), ("network",))
    assert [r.dn for r in records] == ["ou=grants,dc=ciam-ops", "cn=net,ou=grants,dc=ciam-ops"]
    assert records[1].attrs["ciamGrantee"] == ("cn=bob,ou=people,dc=ciam-ops", "cn=network,ou=owners,dc=ciam-ops")
    with pytest.raises(ValueError, match="fly isn't an action.*carol is no recorded person.*no team security"):
        grant_changes(d, "bad", ("fly",), ("carol",), (), ("security",))
    assert grant_rows(directory(PEOPLE + GRANTS)) == (
        ("bob-network", "apply", "bob", "all", "network"),
        ("platform-render", "render, plan", "platform", "target/prod", "all"))


def test_every_command_is_an_action_of_the_catalog():
    mapped = {*cli.FIXED_ACTIONS, *cli.WHEN_CHANGED, "fix", "change", "onboard", "edit"}
    assert set(cli.COMMANDS) - cli.NO_DATABASE <= mapped, set(cli.COMMANDS) - cli.NO_DATABASE - mapped
    assert {*cli.FIXED_ACTIONS.values(), *cli.WHEN_CHANGED.values(), *cli.FIX_ACTIONS.values(),
            *cli.CHANGE_ACTIONS.values(), *cli.ONBOARD_ACTIONS.values()} <= set(ACTIONS)


@pytest.mark.parametrize("argv, action, environment", [
    (["render", "target/prod"], "render", "target/prod"),
    (["plan", "source/prod", "target/prod"], "plan", "target/prod"),
    (["modify", "--change", "CHG-1", "x.ldif"], "apply", ""),
    (["setting", "deployment", "production"], "read", ""),
    (["setting", "deployment", "production", "--change", "CHG-1"], "settings", ""),
    (["fix", "propose", "a/b", "c/d", "k", "--change", "CHG-2"], "propose", "c/d"),
    (["change", "approve", "CHG-2"], "approve", ""),
    (["upgrade"], "admin", "")])
def test_commands_and_their_areas(argv, action, environment):
    a = cli.parser().parse_args(argv)
    assert (cli.command_action(a), cli.command_area(a).environment) == (action, environment)
