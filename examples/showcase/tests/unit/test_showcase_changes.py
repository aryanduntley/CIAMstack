"""Change sets on the showcase: before -> after is exactly the approved changes, and applies back exactly."""
from opsdir.core.changeset import diff
from opsdir.core.interchange.export import export_text
from opsdir.core.interchange.ldif import parse, write_records
from opsdir.core.naming import SUFFIX
from opsdir.store.postgres import read_ldif_files
from opsdir.core.directory import norm_dn
from showcase_support import DATA, approved_attributes, approved_targets, import_records
from support import build_directory, schema_for


def test_the_showcase_changes_are_exactly_the_approved_ones(estate):
    records = diff(estate["before"], estate["after"])
    assert {norm_dn(r.dn): r.changetype for r in records} == approved_targets()
    assert all({attr for _, attr, _ in r.mods} == approved_attributes(r.dn) for r in records
               if r.changetype == "modify")


def test_applying_a_change_set_to_its_base_gives_the_other_snapshot(estate):
    records = read_ldif_files(sorted(DATA.glob("*.ldif")))
    schema = schema_for(records)
    rebuilt = build_directory(schema, records, (*import_records(schema, records),
                                                *parse(write_records(diff(estate["before"], estate["after"])))))
    assert export_text(rebuilt, SUFFIX) == export_text(estate["after"], SUFFIX)
