"""Vault KV inventory: the importer hashicorp-vault/kv-metadata reads the CLI's listings and KV 2 metadata into the
record's secret-store inventory, metadata only: a mount complete, incomplete (a folder unlisted, a path without
metadata) or denied; a deleted or destroyed current version recorded deleted; updated_time never taken for rotation;
KV 1 listing only. The collector walks each mount the references name from its root (or a prefix) with the operator's
own Vault login, the store's address its only setting."""
import datetime as dt
import json

from opsdir.core.directory import get, one, values
from opsdir.domains.pki.inventory import DELETED, MISSING, PRESENT, inventories, reconcile, record_references
from opsdir_adapter_hashicorp_vault.adapter import ADAPTER
from opsdir_adapter_hashicorp_vault.collect import COLLECTORS, kv_steps, roots
from opsdir_adapter_hashicorp_vault.inventory import (KV_METADATA_IMPORTER, listing_path, locate, metadata_only,
                                                      metadata_path, read_kv_metadata)
from network_fixtures import ALPHA, entry, model
from support import after_import

AT = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.timezone.utc)
INV = "ou=vault,ou=secret-inventory,dc=ciam-ops"


def meta(updated, deletion="", destroyed=False):
    """`vault kv metadata get -format=json` output as the CLI prints it (who changed it included)."""
    return json.dumps({"request_id": "r", "data": {
        "created_time": "2026-01-01T00:00:00.1Z", "updated_time": updated, "current_version": 2, "oldest_version": 0,
        "custom_metadata": {"owner": "ops"}, "last_updated_by": {"actor": "token", "client_id": "abc"},
        "versions": {"1": {"created_time": "2026-01-01T00:00:00Z", "deletion_time": "", "destroyed": False},
                     "2": {"created_time": updated, "deletion_time": deletion, "destroyed": destroyed}}}})


EXPORT = {listing_path("secret", ""): json.dumps(["app", "ciam/"]),
          listing_path("secret", "ciam/"): json.dumps(["db", "old", "gone"]),
          metadata_path("secret", "app"): meta("2026-09-01T10:00:00.656588175Z"),
          metadata_path("secret", "ciam/db"): meta("2026-09-02T10:00:00Z"),
          metadata_path("secret", "ciam/old"): meta("2026-03-01T00:00:00Z", deletion="2026-09-29T00:00:00Z"),
          metadata_path("secret", "ciam/gone"): meta("2026-03-01T00:00:00Z", destroyed=True)}


def _source():
    return (entry(ALPHA, "vault", "ciamSecretStore", ciamBindingRole="vault", ciamRefScheme="vault",
                  ciamStoreEndpoint="https://vault.example.test:8200"),
            entry(ALPHA, "db", "ciamSecretRef", ciamBindingRole="db", ciamRefUri="vault://secret/ciam/db",
                  ciamCopyRef=("vault://secret/ciam/old", "vault://secret/ciam/new")))


def test_registered_with_its_importer_collector_and_locator():
    assert ADAPTER.importers[0] == KV_METADATA_IMPORTER and ADAPTER.collectors[:1] == COLLECTORS
    assert ADAPTER.inventory_locator["vault"] is locate
    assert locate("secret/ciam/db") == ("secret", "ciam/db") and locate("transit") is None


def test_a_mount_listed_whole_with_its_metadata_is_complete():
    d, _, _ = model()
    after = after_import(d, read_kv_metadata(EXPORT, d, (), AT))
    inv = get(after, f"cn=secret,{INV}")
    assert (one(inv, "ciamInventoryState"), values(inv, "ciamInventoryPrefix")) == ("complete", ())
    assert dict(get(after, f"cn=ciam/db,cn=secret,{INV}").attrs) == {
        "cn": ("ciam/db",), "ciamObjectState": ("active",), "ciamStoreModified": ("20260902100000Z",)}
    states = {one(e, "cn"): one(e, "ciamObjectState") for e in after.entries.values()
              if "ciamSecretObject" in e.classes}
    assert states == {"app": "active", "ciam/db": "active", "ciam/old": "deleted", "ciam/gone": "deleted"}
    assert not any("ops" == v or "abc" == v for e in after.entries.values() for vs in e.attrs.values() for v in vs)


def test_a_deletion_scheduled_after_the_inventory_isnt_a_deletion_yet():
    d, _, _ = model()
    later = {**EXPORT,
             metadata_path("secret", "ciam/old"): meta("2026-03-01T00:00:00Z", deletion="2026-12-01T00:00:00Z")}
    after = after_import(d, read_kv_metadata(later, d, (), AT))
    assert one(get(after, f"cn=ciam/old,cn=secret,{INV}"), "ciamObjectState") == "active"


def test_unlisted_folders_missing_metadata_and_refusals_are_kept_apart():
    d, _, _ = model()
    partial = {k: v for k, v in EXPORT.items()
               if k not in (listing_path("secret", "ciam/"), metadata_path("secret", "app"))}
    refused = {listing_path("hr", ""): "Code: 403. Errors:\n\n* permission denied\n"}
    after = after_import(d, read_kv_metadata({**partial, **refused}, d, (), AT))
    assert [(one(get(after, f"cn={m},{INV}"), "ciamInventoryState"), values(get(after, f"cn={m},{INV}"),
                                                                           "ciamInventoryProblem"))
            for m in ("secret", "hr")] == [
        ("incomplete", ("1 folder(s) not listed: ciam/", "1 path(s) without metadata")),
        ("denied", ("listing / refused: permission denied",))]


def test_a_prefix_listed_alone_is_the_inventorys_prefix_and_kv1_is_listing_only():
    d, _, _ = model()
    after = after_import(d, read_kv_metadata({listing_path("kv", "team/"): json.dumps(["a", "b"])}, d, (), AT))
    inv = get(after, f"cn=kv,{INV}")
    assert (one(inv, "ciamInventoryState"), values(inv, "ciamInventoryPrefix")) == ("complete", ("team/",))
    assert dict(get(after, f"cn=team/a,cn=kv,{INV}").attrs) == {"cn": ("team/a",)}


def test_references_reconcile_and_metadata_is_trimmed():
    d, _, _ = model(alpha=_source())
    after = after_import(d, read_kv_metadata(EXPORT, d, (), AT))
    held = inventories(after)
    assert [(r.uri, reconcile(after, r, held).state) for r in record_references(after, ADAPTER.inventory_locator)] == [
        ("vault://secret/ciam/db", PRESENT), ("vault://secret/ciam/old", DELETED), ("vault://secret/ciam/new", MISSING)]
    kept = json.loads(metadata_only(EXPORT[metadata_path("secret", "app")]))
    assert "custom_metadata" not in kept["data"] and "last_updated_by" not in kept["data"]
    assert metadata_only("not json") == "not json"


def test_the_collector_walks_each_mount_from_its_root_with_the_stores_address():
    _, alpha, _ = model(alpha=_source())
    first = kv_steps(alpha.d, alpha, {}, {"inventory_container": "kv/team"})
    assert [(p, c.argv, c.env) for p, c in first] == [
        ("list/secret/_keys.json", ("vault", "kv", "list", "-format=json", "-mount=secret", ""),
         (("VAULT_ADDR", "https://vault.example.test:8200"),)),
        ("list/kv/team/_keys.json", ("vault", "kv", "list", "-format=json", "-mount=kv", "team/"),
         (("VAULT_ADDR", "https://vault.example.test:8200"),))]
    done = {"list/secret/_keys.json": EXPORT[listing_path("secret", "")],
            "list/secret/ciam/_keys.json": json.dumps(["db"])}
    assert [p for p, _ in kv_steps(alpha.d, alpha, done, {})] == [
        "list/secret/_keys.json", "list/secret/ciam/_keys.json", "metadata/secret/ciam/db.json",
        "metadata/secret/app.json"]
    (_, call), = [(p, c) for p, c in kv_steps(alpha.d, alpha, done, {}) if p == "metadata/secret/app.json"]
    assert call.argv == ("vault", "kv", "metadata", "get", "-format=json", "-mount=secret", "app")
    assert call.keep is metadata_only


def test_a_kv1_store_is_listed_without_metadata_calls():
    _, alpha, _ = model(alpha=(entry(ALPHA, "vault", "ciamSecretStore", ciamBindingRole="vault", ciamRefScheme="vault",
                                     ciamStoreKvVersion="1"),
                               entry(ALPHA, "db", "ciamSecretRef", ciamBindingRole="db",
                                     ciamRefUri="vault://secret/ciam/db")))
    done = {"list/secret/_keys.json": json.dumps(["app"])}
    assert [(p, c.env) for p, c in kv_steps(alpha.d, alpha, done, {})] == [("list/secret/_keys.json", ())]


def test_containers_given_as_a_mount_or_a_prefix():
    assert roots(("secret", "kv/team", "kv/a/b/", "/x")) == (("secret", ""), ("kv", "team/"), ("kv", "a/b/"))
