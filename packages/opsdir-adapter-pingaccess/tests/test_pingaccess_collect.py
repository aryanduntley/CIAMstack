"""PingAccess collector and the configuration export: the Admin API read collection by collection from the
collection source's admin node (GET with X-XSRF-Header, an Auditor's Basic credentials or a bearer token from the
reference the record names, the CA it names as trust anchor), page by page, then each application's resources, and
never the export, backups or agent and engine configuration; what it collects imports like the saved responses; a
saved export imports to the same record with its encryption material dropped."""
import json
from pathlib import Path
from urllib.parse import urlsplit

from opsdir.connectors.collecting import collect
from opsdir_adapter_pingaccess.adapter import ADAPTER
from opsdir_adapter_pingaccess.api import API, PAGE_SIZE, XSRF
from opsdir_adapter_pingaccess.collect import COLLECTORS, api_steps, pages, source_problems
from opsdir_adapter_pingaccess.importer import read_admin_api, read_export
from opsdir.domains.governance.collection import collection_sources
from network_fixtures import ALPHA, entry, model

TESTS = Path(__file__).resolve().parent
ADMIN_API, EXPORT = TESTS / "admin-api", TESTS / "export"
SOURCE = dict(ciamBindingRole="collect-pa", ciamImporter="pingaccess/admin-api",
              ciamSourceRef="https://pa-admin.example.test:9000", ciamCredentialRole="pa-auditor",
              ciamLoginName="opsdir-auditor", ciamCaRole="pa-ca")
BOUND = (entry(ALPHA, "pa-auditor", "ciamSecretRef", ciamBindingRole="pa-auditor", ciamRefUri="fake://kv/pa-auditor"),
         entry(ALPHA, "pa-ca", "ciamSecretRef", ciamBindingRole="pa-ca", ciamRefUri="fake://kv/pa-ca"))


def files_of(root):
    return {p.relative_to(root).as_posix(): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


SAVED = files_of(ADMIN_API)


def _alpha(*bindings):
    _, alpha, _ = model(alpha=bindings)
    return alpha


def answer(call):
    """The fixture's response to a GET, by its path (a page past the first: empty; an unknown collection: none)."""
    parts = urlsplit(call.url)
    path = parts.path[len(API) + 1:]
    page = dict(q.split("=") for q in parts.query.split("&")) if parts.query else {}
    saved = SAVED.get(f"{path}/page-{page['page']}.json" if page else f"{path}.json")
    if saved is None and page.get("page", "1") != "1":
        return json.dumps({"items": []}), None
    return saved, None


def test_the_admin_api_read_with_the_recorded_credential_and_imported_like_the_saved_responses():
    assert [c.importer for c in ADAPTER.collectors] == ["admin-api"]
    m = _alpha(entry(ALPHA, "pa-admin", "ciamCollectionSource", **SOURCE), *BOUND)
    first = api_steps(m.d, m, {}, {})
    assert first[0][0] == "version.json"
    assert {c.headers for _, c in first} == {XSRF}
    assert {c.credential for _, c in first} == {("basic", "fake://kv/pa-auditor", "opsdir-auditor")}
    assert {c.ca for _, c in first} == {"fake://kv/pa-ca"} and {c.absent for _, c in first} == {(404,)}
    urls = [c.url for _, c in first]
    assert f"https://pa-admin.example.test:9000{API}/sites?page=1&numberPerPage={PAGE_SIZE}" in urls
    assert not any("/config" in u or "backup" in u or u.endswith("/resources") for u in urls)
    c = collect("pingaccess/admin-api", COLLECTORS[0], m.d, m, answer)
    assert c.problems == ()
    assert "applications/1/resources/page-1.json" in c.files
    assert read_admin_api(c.files, m.d, ()).groups == read_admin_api(SAVED, m.d, ()).groups


def test_pages_continue_while_full_and_stop_on_a_repeated_page():
    m = _alpha(entry(ALPHA, "pa-admin", "ciamCollectionSource", **SOURCE), *BOUND)
    (s,) = collection_sources(m, "pingaccess/admin-api")
    full = json.dumps({"items": [{"id": n} for n in range(PAGE_SIZE)]})
    other = json.dumps({"items": [{"id": n + PAGE_SIZE} for n in range(PAGE_SIZE)]})
    assert [p for p, _ in pages(s, {}, "rules")] == ["rules/page-1.json"]
    assert [p for p, _ in pages(s, {"rules/page-1.json": full}, "rules")] == ["rules/page-1.json",
                                                                               "rules/page-2.json"]
    assert len(pages(s, {"rules/page-1.json": full, "rules/page-2.json": other}, "rules")) == 3
    assert len(pages(s, {"rules/page-1.json": full, "rules/page-2.json": full}, "rules")) == 2   # paging ignored


def test_unbound_roles_and_other_schemes_stop_it_with_the_reason():
    m = _alpha(entry(ALPHA, "pa-admin", "ciamCollectionSource", **SOURCE))
    assert api_steps(m.d, m, {}, {}) == ()
    assert source_problems(m.d, m, {}) == (
        "collection source `pa-admin`: role `pa-auditor` (its credential) isn't bound in alpha/prod",
        "collection source `pa-admin`: role `pa-ca` (its trust anchor) isn't bound in alpha/prod")
    keyed = _alpha(entry(ALPHA, "pa-admin", "ciamCollectionSource", **SOURCE, ciamCredentialScheme="api-key"), *BOUND)
    assert source_problems(keyed.d, keyed, {}) == (
        "collection source `pa-admin`: credential scheme `api-key`: PingAccess's Admin API takes basic or bearer",)
    bearer = _alpha(entry(ALPHA, "pa-admin", "ciamCollectionSource", **SOURCE, ciamCredentialScheme="bearer"), *BOUND)
    assert api_steps(bearer.d, bearer, {}, {})[0][1].credential[0] == "bearer"


def test_a_saved_export_imports_the_same_record_and_drops_its_encryption_material():
    d = _alpha()
    exported = read_export(files_of(EXPORT), d.d, ())
    read = read_admin_api({p: t for p, t in SAVED.items() if not p.startswith("engines/")}, d.d, ())
    assert exported.groups == read.groups                     # the export holds no engines
    assert "pa-export.json: the export's encryptionKey (its encryption material) dropped, never stored" in \
        exported.notices
    assert "pa-export.json: the export's masterKeys (its encryption material) dropped, never stored" in \
        exported.notices
    assert "pa-export.json: section licenseFeatures is no collection this adapter reads, not imported" in \
        exported.notices
    text = json.dumps([dict(e.attrs) for _, es in exported.groups for e in es])
    assert "bWFzdGVyLWtleS1jaXBoZXJ0ZXh0" not in text and "cG9ydGFibGUtZXhwb3J0LWtleQ" not in text
