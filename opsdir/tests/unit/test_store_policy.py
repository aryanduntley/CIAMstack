"""How the record's database may be reached (store.policy): local and loopback servers as they are, off-host ones
only with verified TLS or a weaker mode the operator named; and the oldest server the store accepts, refused before
upgrade touches anything."""
from types import SimpleNamespace

import pytest

from opsdir.core.contract import DbTarget
from opsdir.store import migrations
from opsdir.store.policy import db_target, is_local, tls_problem, version_problem


@pytest.mark.parametrize("host", [None, "", "/var/run/postgresql", "@abstract", "localhost", "127.0.0.1", "127.0.0.2",
                                  "::1", "localhost,/tmp"])
def test_local_hosts(host):
    assert is_local(host)


@pytest.mark.parametrize("host", ["db.example.internal", "10.0.0.5", "localhost,db.example.internal"])
def test_off_host(host):
    assert not is_local(host)


def test_a_local_server_needs_no_tls():
    assert tls_problem("localhost", "disable", None, False) is None


def test_an_off_host_server_needs_verified_tls():
    assert tls_problem("db.example.internal", "verify-full", "/etc/ca.pem", True) is None
    assert tls_problem("db.example.internal", "prefer", "system", True) is None        # system implies verify-full
    problem = tls_problem("db.example.internal", "require", None, True)
    assert "reached with sslmode=require" in problem and "OPSDIR_DB_TLS=require" in problem
    assert "reached without TLS" in tls_problem("db.example.internal", "prefer", None, False)


def test_a_weaker_mode_is_accepted_only_when_named():
    assert tls_problem("db.example.internal", "require", None, True, allowed="require") is None
    assert tls_problem("db.example.internal", "require", None, True, allowed="verify-ca")       # not the mode used
    assert tls_problem("db.example.internal", "disable", None, False, allowed="disable") is None
    assert tls_problem("db.example.internal", "prefer", None, False, allowed="prefer")          # no TLS after all


def test_server_versions():
    assert version_problem(170009) is None and version_problem(180006) is None
    assert version_problem(160015) == "the record's database runs PostgreSQL 16; the store needs 17 or later"


def test_upgrade_refuses_an_old_server_before_touching_it():
    old = SimpleNamespace(info=SimpleNamespace(server_version=150019))       # nothing else is ever called on it
    with pytest.raises(SystemExit, match="runs PostgreSQL 15; the store needs 17"):
        migrations.upgrade(old, (), (), None, (), (), ())


def test_the_target_a_connection_string_reaches():
    assert db_target("host=a.example,b.example port=6432 user=app dbname=rec", {}) == DbTarget("a.example", 6432,
                                                                                            "app", "rec")
    assert db_target("dbname=rec", {"PGHOST": "h", "PGPORT": "5433", "PGUSER": "u"}) == DbTarget("h", 5433, "u", "rec")
    assert db_target("", {"PGUSER": "u"}) == DbTarget("", 5432, "u", "u")
