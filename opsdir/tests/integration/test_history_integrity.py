"""History rows come only from entry writes, against Postgres with one login (the test database's, which owns the
schema): the store adds a row for every entry write and sets who and when itself, and refuses a row added any other
way, even inside a statement that also writes an entry. (The runtime login's missing right to add rows at all:
test_record_roles.py, on a scratch server.)"""
import psycopg
import pytest

from opsdir import operations as ops
from opsdir.core.interchange.ldif import parse
from opsdir.store import postgres as db

pytestmark = pytest.mark.integration

BASE = """dn: dc=ciam-ops
objectClass: top
objectClass: domain
dc: ciam-ops
"""

ADDED = ("insert into opsdir.entry_history (dn, op, change_id, db_user, at) "
         "values ('dc=ciam-ops', 'update', 'CHG-9', 'someone_else', '2020-01-01')")


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    ops.init(c)
    ops.load(c, parse(BASE))
    yield c
    c.close()


def test_an_entry_write_adds_its_row_with_the_store_s_own_who_and_when(conn):
    login = conn.execute("select session_user").fetchone()[0]
    rows = conn.execute("select db_user, change_id, at > now() - interval '1 hour' from opsdir.entry_history "
                        "where dn = 'dc=ciam-ops'").fetchall()
    assert rows == [(login, "BOOTSTRAP", True)]


def test_a_row_added_any_other_way_is_refused(conn):
    with pytest.raises(psycopg.errors.RaiseException, match="history rows are written only by the store"):
        conn.execute(ADDED)
    conn.rollback()
    with pytest.raises(psycopg.errors.RaiseException, match="history rows are written only by the store"):
        with conn.transaction():                          # an entry write the store accepts, with a row beside it
            conn.execute("set local opsdir.change_id = 'BOOTSTRAP'")
            conn.execute(f"with forged as ({ADDED} returning id) "
                         "update opsdir.entry set attrs = attrs where dn_norm = 'dc=ciam-ops'")
    assert conn.execute("select count(*) from opsdir.entry_history where db_user = 'someone_else'").fetchone() == (0,)
