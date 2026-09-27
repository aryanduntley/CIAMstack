"""Creating and upgrading the store with versioned migrations, against Postgres."""
import psycopg
import pytest

from opsdir.connectors.registry import schema_fragments, store_parts
from opsdir.core.standard import CORE, fragment_counts, schema_ldif
from opsdir.store import migrations, postgres as db
from support import APPROVED, DATA

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
    db.load_ldif(conn, sorted(DATA.glob("*.ldif")))
    for change_id, path in APPROVED:
        db.apply_changes(conn, path, change_id)


def test_fresh_database_gets_every_migration_then_nothing(conn, parts):
    conn.execute("drop schema if exists opsdir cascade")
    shipped = parts[0]
    assert migrations.upgrade(conn, *parts) == shipped
    assert migrations.upgrade(conn, *parts) == ()
    assert migrations.current_version(conn) == shipped[-1].version
    n_attrs, n_classes = fragment_counts(schema_fragments())
    assert db.registry_counts(conn) == (n_attrs + 6, n_classes + 3)   # + standard LDAP definitions


def test_upgrade_keeps_entries_references_and_history(conn, parts, probe):
    _loaded(conn, parts)
    before = _counts(conn)
    assert before[1] > before[0]                                     # bootstrap + two approved changes
    shipped, *rest = parts
    assert migrations.upgrade(conn, (*shipped, probe), *rest) == (probe,)
    assert _counts(conn) == before
    assert conn.execute("select to_regclass('opsdir.probe') is not null").fetchone()[0]
    assert migrations.current_version(conn) == probe.version


def test_edited_applied_migration_is_refused_and_nothing_changes(conn, parts):
    migrations.init(conn, *parts)
    shipped, *rest = parts
    edited = (shipped[0]._replace(checksum="0" * 64), *shipped[1:])
    with pytest.raises(SystemExit, match="edited"):
        migrations.upgrade(conn, edited, *rest)
    assert migrations.upgrade(conn, *parts) == ()


def test_database_newer_than_the_code_is_refused(conn, parts, probe):
    shipped, *rest = parts
    migrations.init(conn, (*shipped, probe), *rest)
    with pytest.raises(SystemExit, match=f"doesn't know: {migrations.label(probe)}"):
        migrations.upgrade(conn, *parts)


def test_schema_from_before_versioning_is_refused(conn, parts):
    conn.execute("drop schema if exists opsdir cascade")
    conn.execute("create schema opsdir; create table opsdir.entry (id int)")
    with pytest.raises(SystemExit, match="before versioned migrations"):
        migrations.upgrade(conn, *parts)
    migrations.init(conn, *parts)                                   # init rebuilds it
    assert migrations.current_version(conn) >= 1


def test_definitions_are_reapplied(conn, parts):
    _loaded(conn, parts)
    unowned = _counts(conn)[3]
    conn.execute("drop view opsdir.v_unowned")
    migrations.upgrade(conn, *parts)
    assert _counts(conn)[3] == unowned


def test_removing_a_published_definition_is_refused(conn, parts):
    migrations.init(conn, *parts)
    shipped, definitions, _, schemes, _ = parts
    with pytest.raises(SystemExit, match="missing from the published schema"):
        migrations.upgrade(conn, shipped, definitions, schema_ldif((CORE,)), schemes, ())


def test_init_matches_the_cli_and_leaves_a_versioned_store(conn, parts):
    migrations.init(conn, *parts)
    assert conn.execute("select name from opsdir.schema_migration order by version").fetchall() == \
        [(m.name,) for m in parts[0]]
    assert conn.execute("select count(*) from opsdir.suffix").fetchone()[0] == 1
    assert conn.execute("select count(*) from opsdir.ref_scheme").fetchone()[0] == len(parts[3])


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
