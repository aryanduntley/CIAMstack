"""Permissions against Postgres: the command check the CLI and every front end ask (operations.authorize_command),
with the record's own grants, as the session's login."""
from datetime import date

import pytest

from opsdir import operations as ops
from opsdir.core.environment import ENVIRONMENT, Scope
from opsdir.core.interchange.ldif import parse
from opsdir.domains.governance.authorization import Area
from opsdir.store import postgres as db

pytestmark = pytest.mark.integration

BASE = """dn: dc=ciam-ops
objectClass: top
objectClass: domain
dc: ciam-ops

dn: ou=changes,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: changes

dn: cn=CHG-1,ou=changes,dc=ciam-ops
objectClass: top
objectClass: ciamChange
cn: CHG-1
ciamTitle: People and grants
ciamChangeStatus: approved

dn: ou=owners,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: owners

dn: cn=platform,ou=owners,dc=ciam-ops
objectClass: top
objectClass: ciamParty
cn: platform
ciamOwnerKind: team
"""


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    ops.init(c)
    ops.load(c, parse(BASE))
    yield c
    c.close()


def login(conn):
    return conn.execute("select session_user").fetchone()[0]


def record(conn, preview):
    ops.apply_preview(conn, preview, "CHG-1")


def test_without_grants_every_command_is_allowed(conn):
    ops.authorize_command(conn, "apply", Area(""))
    ops.authorize_command(conn, "render", Area("target/prod"), claimed="someone-else")      # --as is a label


def test_once_grants_exist_people_need_one(conn):
    record(conn, ops.preview_person(conn, login(conn), "The Tester", teams=("platform",)))
    record(conn, ops.preview_grant(conn, "platform-render", ("render",), ("platform",), ("target/prod",)))
    ops.authorize_command(conn, "render", Area("target/prod"))                               # through the team
    ops.authorize_command(conn, "read", Area(""))
    ops.authorize_command(conn, "admin", Area(""))
    with pytest.raises(SystemExit, match=f"{login(conn)} may not render source/prod: no grant gives them render"):
        ops.authorize_command(conn, "render", Area("source/prod"))
    with pytest.raises(SystemExit, match="may not apply"):
        ops.authorize_command(conn, "apply", Area(""))
    with pytest.raises(SystemExit, match="once people are recorded, the requester is the login"):
        ops.authorize_command(conn, "render", Area("target/prod"), claimed="someone-else")
    keeper = Scope("keeper", ("cn=platform,ou=owners,dc=ciam-ops",))
    ops.authorize_command(conn, "render", Area("target/prod", keeper))                       # unlimited by owner
    with pytest.raises(SystemExit, match="may not apply target/prod: no grant"):
        ops.authorize_command(conn, "apply", Area("target/prod", ENVIRONMENT))
    rows = ops.report(conn, "grants", None, None)
    assert rows.rows == (("platform-render", "render", "platform", "target/prod", "all"),)


def test_a_login_that_isnt_a_recorded_person_is_refused_once_grants_exist(conn):
    record(conn, ops.preview_person(conn, "someone_else"))
    record(conn, ops.preview_grant(conn, "all", ("render",), ("someone_else",)))
    with pytest.raises(SystemExit, match="they aren't a recorded person"):
        ops.authorize_command(conn, "read", Area(""))


def test_my_area_on_reports_and_my_open_items(conn):
    question = ("dn: ou=unknowns,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
                "ou: unknowns\n\ndn: cn=q1,ou=unknowns,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
                "objectClass: ciamUnknown\ncn: q1\nciamQuestion: Which CA signs partner certificates?\n"
                "ciamOwner: cn=platform,ou=owners,dc=ciam-ops\n")
    ops.modify(conn, parse(question), "CHG-1")
    with pytest.raises(SystemExit, match="isn't a recorded person"):
        ops.my_report(conn, "unknowns")
    record(conn, ops.preview_person(conn, login(conn), "The Tester", teams=("platform",)))
    rows, note = ops.my_report(conn, "unknowns")
    assert [r[0] for r in rows.rows] == ["q1"] and note is None
    assert ops.my_report(conn, "grants")[1] is None                  # owners column: none of mine yet
    assert dict(ops.mine(conn))["open unknowns of platform"] == ("q1  Which CA signs partner certificates?",)
    q1 = "cn=q1,ou=unknowns,dc=ciam-ops"
    owners = {s.name: s.rows for s in ops.application(conn, q1, date(2026, 10, 18), mine=True).sections}["owners"]
    assert [r[2] for r in owners] == ["platform"]


def test_my_area_needs_a_recorded_person(conn):
    with pytest.raises(SystemExit, match="isn't a recorded person"):
        ops.application(conn, "cn=platform,ou=owners,dc=ciam-ops", date(2026, 10, 18), mine=True)
    with pytest.raises(SystemExit, match="isn't a recorded person"):
        ops.fixes(conn, "source/prod", "target/prod", date(2026, 10, 18), mine=True)
