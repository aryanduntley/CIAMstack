"""Upgrading a store that holds the showcase: data, references, history and vocabulary survive or are defended."""
import psycopg
import pytest

from opsdir.connectors.registry import schema_sync, store_parts
from opsdir.store import migrations, postgres as db
from showcase_support import APPROVED, DATA

pytestmark = pytest.mark.integration

PROBE_SQL = "create table opsdir.probe (id int primary key);"


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    yield c
    c.close()


@pytest.fixture(scope="module")
def parts():
    return store_parts()


@pytest.fixture(scope="module")
def probe(parts):
    """A new migration numbered after the shipped ones, as the next release would add it."""
    return migrations.migration(f"{len(parts[0]) + 1:04d}_probe.sql", PROBE_SQL)


def _counts(conn):
    return conn.execute("select (select count(*) from opsdir.entry), (select count(*) from opsdir.entry_history),"
                        " (select count(*) from opsdir.entry_ref), (select count(*) from opsdir.v_unowned)").fetchone()


def _loaded(conn, parts):
    """A store with the synthetic estate and the approved changes, as the demo leaves it."""
    migrations.init(conn, *parts)
    db.load_ldif(conn, sorted(DATA.glob("*.ldif")), schema_sync=schema_sync())
    for change_id, path in APPROVED:
        db.apply_changes(conn, path, change_id)


def test_upgrade_keeps_entries_references_and_history(conn, parts, probe):
    _loaded(conn, parts)
    before = _counts(conn)
    assert before[1] > before[0]                                     # bootstrap + two approved changes
    shipped, *rest = parts
    assert migrations.upgrade(conn, (*shipped, probe), *rest) == (probe,)
    assert _counts(conn) == before
    assert conn.execute("select to_regclass('opsdir.probe') is not null").fetchone()[0]
    assert migrations.current_version(conn) == probe.version


def test_definitions_are_reapplied(conn, parts):
    _loaded(conn, parts)
    unowned = _counts(conn)[3]
    conn.execute("drop view opsdir.v_unowned")
    migrations.upgrade(conn, *parts)
    assert _counts(conn)[3] == unowned


def test_a_value_no_installed_part_defines_is_rejected(conn, parts, tmp_path):
    _loaded(conn, parts)
    change = tmp_path / "bad-provider.ldif"
    change.write_text("dn: cloud=source,ou=environments,dc=ciam-ops\nchangetype: modify\n"
                      "replace: ciamCloudProvider\nciamCloudProvider: nosuchcloud\n-\n")
    with pytest.raises(psycopg.Error, match="not registered by any installed domain or adapter"):
        db.apply_changes(conn, change, APPROVED[0][0])


def test_removing_an_adapter_whose_values_are_in_use_is_refused(conn, parts):
    _loaded(conn, parts)
    *rest, vocab = parts
    without_aws = tuple(row for row in vocab if row[2] != "aws")
    with pytest.raises(SystemExit, match="is an adapter missing"):
        migrations.upgrade(conn, *rest, without_aws)
    assert conn.execute("select count(*) from opsdir.vocabulary").fetchone()[0] == len(vocab)   # rolled back
