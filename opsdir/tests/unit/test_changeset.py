"""Change sets between directory snapshots: what changed, in an order the store can apply, and exact round trips."""
from opsdir.cli import export_text
from opsdir.core.changeset import diff, entry_mods
from opsdir.core.directory import make_directory
from opsdir.core.interchange.ldif import LdifRecord, parse, write_records
from opsdir.core.naming import SUFFIX
from opsdir.store.postgres import read_ldif_files
from support import DATA, SCHEMA, build_directory

TYPES = (("cn", "string", "meta"), ("ou", "string", "meta"), ("description", "string", "meta"))
CLASSES = (("top", None), ("organizationalUnit", "top"), ("ciamThing", "top"), ("ciamOther", "top"))


def d(*entries):
    return make_directory(TYPES, CLASSES, entries)


ROOT = ("dc=x", ["top"], {})
OU = ("ou=a,dc=x", ["top", "organizationalUnit"], {"ou": ["a"]})
LEAF = ("cn=l,ou=a,dc=x", ["top", "ciamThing"], {"cn": ["l"], "description": ["one"]})


def test_equal_snapshots_have_no_changes():
    assert diff(d(ROOT, OU, LEAF), d(ROOT, OU, LEAF)) == ()


def test_adds_come_parents_first_and_deletes_children_first():
    added = diff(d(ROOT), d(ROOT, OU, LEAF))
    assert [(r.changetype, r.dn) for r in added] == [("add", "ou=a,dc=x"), ("add", "cn=l,ou=a,dc=x")]
    assert added[1].attrs == {"objectClass": ("top", "ciamThing"), "cn": ("l",), "description": ("one",)}
    removed = diff(d(ROOT, OU, LEAF), d(ROOT))
    assert [(r.changetype, r.dn) for r in removed] == [("delete", "cn=l,ou=a,dc=x"), ("delete", "ou=a,dc=x")]


def test_modifies_replace_changed_and_delete_removed_attributes():
    new_leaf = ("cn=l,ou=a,dc=x", ["top", "ciamOther"], {"cn": ["l"]})
    (r,) = diff(d(ROOT, OU, LEAF), d(ROOT, OU, new_leaf))
    assert r == LdifRecord("cn=l,ou=a,dc=x", "modify", {},
                           (("replace", "objectClass", ("top", "ciamOther")), ("delete", "description", ())))


def test_entry_mods_is_empty_for_equal_entries():
    e = d(ROOT, OU, LEAF).entries["cn=l,ou=a,dc=x"]
    assert entry_mods(e, e) == ()


def test_change_records_round_trip_through_ldif():
    records = (*diff(d(ROOT), d(ROOT, OU, LEAF)), *diff(d(ROOT, OU, LEAF), d(ROOT, OU)),
               *diff(d(ROOT, OU, LEAF), d(ROOT, OU, ("cn=l,ou=a,dc=x", ["top", "ciamThing"], {"cn": ["l"]}))))
    assert tuple(parse(write_records(records))) == records


def test_the_showcase_changes_are_exactly_the_two_approved_ones(estate):
    records = diff(estate["before"], estate["after"])
    assert [(r.changetype, r.dn.split(",")[0]) for r in records] == [("add", "cn=fw-mro-batch"), ("modify", "cn=svc-ldaps")]
    assert {attr for _, attr, _ in records[1].mods} == {"ciamFqdn", "ciamDnsZone", "ciamChangeRef"}


def test_applying_a_change_set_to_its_base_gives_the_other_snapshot(estate):
    rebuilt = build_directory(SCHEMA.read_text(), read_ldif_files(sorted(DATA.glob("*.ldif"))),
                              parse(write_records(diff(estate["before"], estate["after"]))))
    assert export_text(rebuilt, SUFFIX) == export_text(estate["after"], SUFFIX)
