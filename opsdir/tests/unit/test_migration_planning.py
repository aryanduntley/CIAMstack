"""Planning schema migrations (pure): which migrations run, and which databases are refused."""
import hashlib

import pytest

from opsdir.store.migrations import (MIGRATIONS, UPSERT_ATTRIBUTE_TYPE, in_sequence, label, migration, pending,
                                     read_migrations, removed_definitions)

M1, M2, M3 = (migration(f"000{v}_step_{v}.sql", f"select {v};") for v in (1, 2, 3))


def applied(*migrations):
    return tuple((m.version, m.name, m.checksum) for m in migrations)


def test_migration_reads_version_name_and_checksum_from_file():
    m = migration("0012_add_owner_index.sql", "create index x on t(y);")
    assert (m.version, m.name, label(m)) == (12, "add_owner_index", "0012_add_owner_index")
    assert m.checksum == hashlib.sha256(b"create index x on t(y);").hexdigest()


@pytest.mark.parametrize("name", ["1_core.sql", "0001-core.sql", "0001_Core.sql", "0001_core.txt"])
def test_badly_named_migration_files_are_refused(name):
    with pytest.raises(SystemExit):
        migration(name, "")


def test_sequence_must_run_from_one_without_gaps_or_repeats():
    assert in_sequence((M3, M1, M2)) == (M1, M2, M3)
    for broken in ((M2, M3), (M1, M3), (M1, M1._replace(name="again"))):
        with pytest.raises(SystemExit):
            in_sequence(broken)


@pytest.mark.parametrize("done, expected", [((), (M1, M2, M3)), ((M1,), (M2, M3)), ((M1, M2, M3), ())])
def test_pending_is_what_the_database_has_not_applied(done, expected):
    assert pending(applied(*done), (M1, M2, M3)) == expected


def test_edited_applied_migration_is_refused():
    with pytest.raises(SystemExit, match="edited: 0001_step_1"):
        pending(applied(M1), (M1._replace(checksum="other"), M2))


def test_migration_the_code_does_not_have_is_refused():
    with pytest.raises(SystemExit, match="doesn't know: 0003_step_3"):
        pending(applied(M1, M2, M3), (M1, M2))


def test_gap_in_the_applied_migrations_is_refused():
    with pytest.raises(SystemExit, match="older than"):
        pending(applied(M1, M3), (M1, M2, M3))


def test_removed_definitions():
    ats, ocs = [{"name": "cn"}, {"name": "ciamOwner"}], [{"name": "top"}]
    assert removed_definitions(["cn", "ciamOwner"], ["top"], ats, ocs) == ((), ())
    assert removed_definitions(["cn", "ciamGone"], ["top", "ciamOldClass"], ats, ocs) == (("ciamGone",), ("ciamOldClass",))


def test_registry_upsert_updates_every_column_but_the_name():
    assert "on conflict (name) do update set oid = excluded.oid" in UPSERT_ATTRIBUTE_TYPE
    assert "name = excluded.name" not in UPSERT_ATTRIBUTE_TYPE


def test_shipped_migrations_are_in_sequence():
    shipped = read_migrations()
    assert label(shipped[0]) == "0001_core"
    assert [m.version for m in shipped] == list(range(1, len(shipped) + 1))
    assert len(shipped) == len(list(MIGRATIONS.glob("*")))      # nothing else lives in the directory
