"""CyberArk account inventory: the importer cyberark/accounts reads the PVWA API's account listings into the record's
secret-store inventory, metadata only (a value-bearing field is never read, only named), each safe complete,
incomplete or denied; rotation only from a CPM change that worked; the collector pages each safe the record's
references name with a session token, keeping only metadata; references reconcile through the adapter's locator."""
import datetime as dt
import json
from urllib.parse import parse_qs, urlsplit

from opsdir.connectors.collecting import collect
from opsdir.core.directory import get, one, values
from opsdir.domains.pki.inventory import MISSING, PRESENT, inventories, reconcile, record_references
from opsdir_adapter_cyberark.adapter import ADAPTER
from opsdir_adapter_cyberark.collect import COLLECTORS, account_steps, next_offset, source_problems
from opsdir_adapter_cyberark.inventory import (ACCOUNTS_IMPORTER, account_facts, locate, metadata_only,
                                               read_accounts)
from network_fixtures import ALPHA, entry, model
from support import after_import

AT = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.timezone.utc)
INV = "ou=cyberark,ou=secret-inventory,dc=ciam-ops"
DB = {"id": "12_3", "safeName": "CIAM-Prod", "name": "db-admin", "platformId": "WinDomain", "userName": "dba",
      "secret": "hunter2-never-read", "createdTime": 1756684800,
      "secretManagement": {"automaticManagementEnabled": True, "status": "success", "lastModifiedTime": 1758672000,
                           "lastVerifiedTime": 1758758400}}
MANUAL = {"id": "12_4", "safeName": "CIAM-Prod", "name": "bigip", "categoryModificationTime": "2026-09-01T00:00:00Z",
          "secretManagement": {"automaticManagementEnabled": False, "manualManagementReason": "Owned by networking",
                               "status": "failure", "lastModifiedTime": 1758672000}}


def page(accounts, count):
    return json.dumps({"value": accounts, "count": count})


def _source(**extra):
    return (entry(ALPHA, "pvwa", "ciamCollectionSource", ciamBindingRole="pvwa", ciamImporter="cyberark/accounts",
                  ciamSourceRef="https://pvwa.example.test/", ciamCredentialRole="pvwa-session",
                  ciamCredentialScheme="token", **extra),
            entry(ALPHA, "pvwa-session", "ciamSecretRef", ciamBindingRole="pvwa-session",
                  ciamRefUri="fake://kv/pvwa-session"),
            entry(ALPHA, "db", "ciamSecretRef", ciamBindingRole="db", ciamRefUri="cyberark://ops/CIAM-Prod/db-admin",
                  ciamCopyRef="cyberark://ops/CIAM-DR/db-admin"))


def test_registered_with_its_importer_collector_and_locator():
    assert ADAPTER.importers == (ACCOUNTS_IMPORTER,) and ADAPTER.collectors == COLLECTORS
    assert ADAPTER.inventory_locator["cyberark"] is locate
    assert locate("ops/CIAM-Prod/db-admin") == ("CIAM-Prod", "db-admin") and locate("ops/CIAM-Prod") is None


def test_a_safe_listed_whole_is_complete_and_only_metadata_is_read():
    d, _, _ = model()
    imported = read_accounts({"accounts/CIAM-Prod.json": page([DB, MANUAL], 2)}, d, (), AT)
    after = after_import(d, imported)
    inv = get(after, f"cn=CIAM-Prod,{INV}")
    assert (one(inv, "ciamInventoryState"), one(inv, "ciamInventoryAt")) == ("complete", "20260930120000Z")
    db = get(after, f"cn=db-admin,cn=CIAM-Prod,{INV}")
    assert dict(db.attrs) == {"cn": ("db-admin",), "ciamRotationManaged": ("TRUE",), "ciamRotationStatus": ("success",),
                              "ciamLastRotated": ("20250924000000Z",), "ciamLastVerified": ("20250925000000Z",)}
    assert not any("hunter2" in v for e in after.entries.values() for vs in e.attrs.values() for v in vs)
    assert "CIAM-Prod: account `db-admin` carries secret: not read (metadata only)" in imported.notices


def test_rotation_only_from_a_cpm_change_that_worked():
    facts = account_facts(MANUAL)
    assert facts["ciamLastRotated"] is None and facts["ciamRotationStatus"] == "failure"
    assert (facts["ciamRotationManaged"], facts["ciamManualReason"], facts["ciamStoreModified"]) == (
        "FALSE", "Owned by networking", "20260901000000Z")
    in_process = account_facts({"secretManagement": {"status": "inProcess", "lastModifiedDateTime": 1758672000}})
    assert (in_process["ciamRotationStatus"], in_process["ciamLastRotated"]) == ("in-progress", None)
    millis = account_facts({"secretManagement": {"status": "Success", "lastModifiedTime": 1758672000000}})
    assert millis["ciamLastRotated"] == "20250924000000Z"


def test_short_pages_no_count_and_error_answers_are_kept_apart():
    d, _, _ = model()
    after = after_import(d, read_accounts({
        "accounts/CIAM-Prod/0.json": page([DB], 3), "accounts/CIAM-Prod/1.json": page([MANUAL], 3),
        "accounts/CIAM-Dev.json": json.dumps({"value": [DB | {"safeName": "CIAM-Dev"}]}),
        "accounts/CIAM-HR.json": json.dumps({"ErrorCode": "PASWS012E", "ErrorMessage": "Safe not found or no access"}),
        "accounts/CIAM-QA.json": "<html>gateway timeout</html>"}, d, (), AT))
    state = {c: (one(e, "ciamInventoryState"), values(e, "ciamInventoryProblem"))
             for c, e in ((c, get(after, f"cn={c},{INV}")) for c in ("CIAM-Prod", "CIAM-Dev", "CIAM-HR", "CIAM-QA"))}
    assert state == {"CIAM-Prod": ("incomplete", ("2 of 3 accounts listed",)),
                     "CIAM-Dev": ("incomplete", ("the listing gives no count, so it can't be shown complete",)),
                     "CIAM-HR": ("denied", ("PASWS012E: Safe not found or no access",)),
                     "CIAM-QA": ("incomplete", ("accounts/CIAM-QA.json isn't an account listing",
                                                "the listing gives no count, so it can't be shown complete"))}


def test_an_inventory_is_dated():
    d, _, _ = model()
    assert read_accounts({"accounts/X.json": page([], 0)}, d, ()).notices == (
        "an inventory is dated: give --at (when the listing was taken)",)


def test_references_reconcile_through_the_adapters_locator():
    d, _, _ = model(alpha=_source())
    after = after_import(d, read_accounts({"accounts/CIAM-Prod.json": page([DB], 1),
                                           "accounts/CIAM-DR.json": page([], 0)}, d, (), AT))
    held = inventories(after)
    assert [(r.uri, reconcile(after, r, held).state)
            for r in record_references(after, ADAPTER.inventory_locator)] == [
        ("cyberark://ops/CIAM-Prod/db-admin", PRESENT), ("cyberark://ops/CIAM-DR/db-admin", MISSING)]


def _answer(request):
    q = parse_qs(urlsplit(request.url).query)
    safe, offset = q["filter"][0].split(" eq ", 1)[1], int(q["offset"][0])
    accounts = {"CIAM-Prod": [DB, MANUAL, DB | {"id": "12_5", "name": "svc"}], "CIAM-DR": []}[safe]
    return page(accounts[offset:offset + 2], len(accounts)), None


def test_the_collector_pages_each_safe_the_references_name_with_a_session_token_keeping_only_metadata():
    _, alpha, _ = model(alpha=_source())
    first = account_steps(alpha.d, alpha, {}, {"inventory_container": "CIAM-Extra"})
    assert [p for p, _ in first] == ["accounts/CIAM-Prod/0.json", "accounts/CIAM-DR/0.json",
                                     "accounts/CIAM-Extra/0.json"]
    req = first[0][1]
    assert req.url == ("https://pvwa.example.test/PasswordVault/API/Accounts?filter=safeName%20eq%20CIAM-Prod"
                       "&limit=1000&offset=0")
    assert req.credential == ("token", "fake://kv/pvwa-session", None)
    c = collect("cyberark/accounts", COLLECTORS[0], alpha.d, alpha, _answer)
    assert c.problems == () and sorted(c.files) == ["accounts/CIAM-DR/0.json", "accounts/CIAM-Prod/0.json",
                                                    "accounts/CIAM-Prod/2.json"]
    assert "hunter2" not in "".join(c.files.values()) and "userName" not in c.files["accounts/CIAM-Prod/0.json"]
    after = after_import(alpha.d, read_accounts(c.files, alpha.d, (), AT))
    assert one(get(after, f"cn=CIAM-Prod,{INV}"), "ciamInventoryState") == "complete"


def test_paging_stops_when_the_count_is_reached_or_the_page_isnt_a_listing():
    assert next_offset(page([DB, DB], 5), 0) == 2 and next_offset(page([DB], 3), 2) is None
    assert next_offset("<html/>", 0) is None and next_offset(page([], 3), 0) is None
    assert metadata_only("<html/>") == "<html/>"


def test_a_password_scheme_is_refused_with_why():
    _, alpha, _ = model(alpha=_source()[1:] + (
        entry(ALPHA, "pvwa", "ciamCollectionSource", ciamBindingRole="pvwa", ciamImporter="cyberark/accounts",
              ciamSourceRef="https://pvwa.example.test", ciamCredentialRole="pvwa-session", ciamLoginName="reader"),))
    assert source_problems(alpha.d, alpha, {}) == (
        "collection source `pvwa`: credential scheme `basic`: the PVWA API takes a session token (token) or a "
        "Privilege Cloud access token (bearer)",)
    assert account_steps(alpha.d, alpha, {}, {}) == ()
