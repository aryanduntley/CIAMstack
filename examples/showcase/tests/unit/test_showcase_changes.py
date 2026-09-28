"""Change sets on the showcase: before -> after is exactly the approved changes, and applies back exactly."""
from opsdir.core.changeset import diff
from opsdir.core.interchange.export import export_text
from opsdir.core.interchange.ldif import parse, write_records
from opsdir.core.naming import SUFFIX
from opsdir.store.postgres import read_ldif_files
from showcase_support import DATA
from support import build_directory, schema_for


def test_the_showcase_changes_are_exactly_the_two_approved_ones(estate):
    records = diff(estate["before"], estate["after"])
    assert [(r.changetype, r.dn.split(",")[0]) for r in records] == [("add", "cn=fw-mro-batch"), ("modify", "cn=svc-ldaps")]
    assert {attr for _, attr, _ in records[1].mods} == {"ciamFqdn", "ciamDnsZone", "ciamChangeRef"}


def test_applying_a_change_set_to_its_base_gives_the_other_snapshot(estate):
    records = read_ldif_files(sorted(DATA.glob("*.ldif")))
    rebuilt = build_directory(schema_for(records), records, parse(write_records(diff(estate["before"], estate["after"]))))
    assert export_text(rebuilt, SUFFIX) == export_text(estate["after"], SUFFIX)
