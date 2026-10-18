"""Who asks (store.postgres requester): the person a front end serving many people acts for in a context, else the
connection's own login; the store is told the person inside each write transaction (migration 0013 decides whether
to trust it)."""
import threading
from types import SimpleNamespace

import pytest

from opsdir.store import postgres as db


def fake_conn(login, executed):
    """A stand-in connection answering `select session_user` and recording every statement."""
    def execute(sql, params=None):
        executed.append((sql, params))
        return SimpleNamespace(fetchone=lambda: (login,))
    return SimpleNamespace(execute=execute)


def test_the_requester_is_the_login_unless_a_person_is_named():
    conn = fake_conn("opsdir_api", [])
    assert db.REQUESTER.get() is None and db.requester(conn) == "opsdir_api"
    with db.requesting("alice") as who:
        assert who == "alice" and db.requester(conn) == "alice"
        with db.requesting("bob"):
            assert db.requester(conn) == "bob"
        assert db.requester(conn) == "alice"
    assert db.REQUESTER.get() is None and db.requester(conn) == "opsdir_api"


def test_the_person_is_restored_after_an_error():
    with pytest.raises(RuntimeError):
        with db.requesting("alice"):
            raise RuntimeError("boom")
    assert db.REQUESTER.get() is None


def test_each_thread_has_its_own_requester():
    seen = {}
    with db.requesting("alice"):
        t = threading.Thread(target=lambda: seen.update(other=db.REQUESTER.get()))
        t.start()
        t.join()
    assert seen == {"other": None}


def test_a_write_transaction_names_the_person_only_when_one_is_set():
    executed = []
    db._begin_change(fake_conn("x", executed), "CHG-1")
    assert executed == [("select set_config('opsdir.change_id', %s, true)", ("CHG-1",))]
    executed.clear()
    with db.requesting("alice"):
        db._begin_change(fake_conn("x", executed), "CHG-1")
    assert executed == [("select set_config('opsdir.change_id', %s, true)", ("CHG-1",)),
                        ("select set_config('opsdir.requester', %s, true)", ("alice",))]
