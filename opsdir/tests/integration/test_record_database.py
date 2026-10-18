"""The record's own database against Postgres: a local connection is accepted and reports the options libpq applied
(never the password), and the deployment setting takes development or production."""
import pytest
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from opsdir import operations as ops
from opsdir.connectors.registry import store_parts
from opsdir.core.interchange.ldif import parse
from opsdir.store import migrations, postgres as db

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
ciamTitle: Settings
ciamChangeStatus: approved
"""


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    migrations.init(c, *store_parts())
    db.load_records(c, parse(BASE))
    yield c
    c.close()


def test_a_local_connection_is_accepted_and_reports_its_options(conn):
    assert db.connection_problem(conn) is None
    options = db.effective_options(conn)
    assert options["host"] and "password" not in options


def test_the_deployment_setting_takes_development_or_production(conn):
    ops.apply_preview(conn, ops.preview_setting(conn, "deployment", "production"), "CHG-1")
    with pytest.raises(ValueError, match="isn't one of development, production"):
        ops.preview_setting(conn, "deployment", "prod")


def test_the_posture_of_the_test_connection(conn):
    rows, failures = ops.posture(conn)
    checks = {check: status for check, status, _ in rows.rows}
    assert checks["schema"] == "ok" and checks["server version"] == "ok" and failures == 0
    ops.apply_preview(conn, ops.preview_setting(conn, "deployment", "production"), "CHG-1")
    checks = {check: status for check, status, _ in ops.posture(conn)[0].rows}
    assert checks["development defaults"] == "fail" and checks["record identity"] == "fail"


def test_a_given_password_signs_in_as_a_token_would(dsn):
    params = conninfo_to_dict(dsn)
    password = params.pop("password", None)
    with db.connect(make_conninfo(**params), password) as c:
        assert c.execute("select 1").fetchone() == (1,) and c.pgconn.used_password == bool(password)
