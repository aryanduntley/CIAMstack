"""Importing a product's export (in memory, with the fake adapter's importer): the importer is found by name, what
it yields becomes change records (containers only when missing; each imported subtree made exactly what the import
says, entries it keeps unchanged), secret material is withheld, and entries outside what it imports are refused."""
import datetime as dt

import pytest

from opsdir.connectors.importing import import_changes, importer_named, preview_import
from opsdir.core.contract import Imported
from opsdir.core.directory import make_entry
import mini_estate
from mini_estate import FAKE, FAKE_IMPORTER

SSO = "cn=sso,ou=identity-services,dc=ciam-ops"


def changes(files, d=None):
    records, notices = preview_import(d or mini_estate.directory(), "fake-cloud", files, (FAKE,))
    return [(r.changetype, r.dn) for r in records], notices


def test_the_importer_is_found_by_adapter_and_name():
    assert importer_named("fake-cloud", (FAKE,)) == (FAKE, FAKE_IMPORTER)
    assert importer_named("fake-cloud/services", (FAKE,)) == (FAKE, FAKE_IMPORTER)
    with pytest.raises(SystemExit, match="name one of fake-cloud's importers: services"):
        importer_named("fake-cloud/other", (FAKE,))
    with pytest.raises(SystemExit, match=r"installed importers: fake-cloud/services"):
        importer_named("nothing", (FAKE,))


def test_new_entries_are_added_and_existing_ones_changed_only_where_the_export_differs():
    recs, notices = changes({"services/sso.url": "https://sso.example.test\n", "services/api.url": "https://api.test"})
    assert recs == [("add", "cn=api,ou=identity-services,dc=ciam-ops")] and notices == ()   # sso: unchanged
    recs, _ = changes({"services/sso.url": "https://login.example.test"})
    assert recs == [("modify", SSO)]


def test_a_missing_container_is_added_first():
    d = mini_estate.directory()
    bare = d._replace(entries={k: v for k, v in d.entries.items() if "identity-services" not in k})
    recs, _ = changes({"services/api.url": "https://api.test"}, bare)
    assert recs == [("add", "ou=identity-services,dc=ciam-ops"), ("add", "cn=api,ou=identity-services,dc=ciam-ops")]


def test_what_the_import_no_longer_holds_under_its_scope_is_deleted():
    d = mini_estate.directory()
    child = make_entry(f"cn=old,{SSO}", ("top", "organizationalUnit"), {"ou": ("old",)})
    with_child = d._replace(entries={**d.entries, child.norm: child})
    group = Imported((), ((SSO, (d.entries[child.norm.split(",", 1)[1]],)),), ())
    assert [(r.changetype, r.dn) for r in import_changes(with_child, group)] == [("delete", child.dn)]


def test_secret_material_is_withheld_and_said():
    recs, notices = changes({"services/leak.url": "https://user:hunter2@sso.example.test"})
    assert recs == [] and notices == ("leak: withheld (looks like secret material)",)


def test_an_entry_outside_the_imported_scope_is_refused():
    stray = make_entry("cn=x,ou=owners,dc=ciam-ops", ("top", "ciamParty"), {"cn": ("x",)})
    with pytest.raises(SystemExit, match="outside what it imports: cn=x,ou=owners,dc=ciam-ops"):
        import_changes(mini_estate.directory(), Imported((), ((SSO, (stray,)),), ()))


def test_the_importer_is_told_when_the_import_runs():
    at = dt.datetime(2026, 9, 30, 14, 15, tzinfo=dt.timezone.utc)
    clock = FAKE_IMPORTER._replace(read=lambda files, d, patterns, when: Imported((), (), (f"at {when:%Y%m%d%H%M%SZ}",)))
    adapter = FAKE._replace(importers=(clock,))
    assert preview_import(mini_estate.directory(), "fake-cloud", {}, (adapter,), at=at)[1] == ("at 20260930141500Z",)
