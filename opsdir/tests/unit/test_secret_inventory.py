"""Secret-store inventories reconciled with the record's references (domains/pki/inventory and
connectors/secret_inventory): each reference's state kept apart (present, deleted, confirmed missing, listing
incomplete, store refused, not inventoried), copies too, rotation only from a timestamp meaning rotation, the objects
nothing references; the planner's findings on the target, the report, and the `token` and `api-key` credential
schemes collectors send session tokens and API keys with."""
import datetime as dt

from opsdir import live
from opsdir.connectors.reports import catalogue
from opsdir.connectors.secret_inventory import inventory_locators, secret_inventory_check
from opsdir.core.contract import Imported, PlanContext
from opsdir.core.directory import gtime, ou_entry
from opsdir.core.environment import env_model
from opsdir.domains.pki.inventory import (AREA, CONTAINER_OPTION, DELETED, INACCESSIBLE, INCOMPLETE, MISSING,
                                          NOT_INVENTORIED, PRESENT, UNREFERENCED, inventories, inventory_entry,
                                          inventory_findings, inventory_group, inventory_rows, object_entry,
                                          reconcile, record_references, wanted_containers)
from opsdir.domains.pki.naming import SECRET_INVENTORY, inventory_scheme_dn
import mini_estate
from support import after_import

AS_OF = dt.date(2026, 10, 1)
AT = gtime(dt.datetime(2026, 9, 30, 12, 0))
LOCATORS = {"fake": lambda rest: tuple(rest.split("/", 1)) if "/" in rest else None}
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"


def _record(beta=None, containers=(), **credential):
    """The mini estate with the credential signing-key bound in alpha (fake://secrets/alpha/signing) and beta (beta's
    binding attributes given), and the container inventories given: ((container, state, {object: facts}, extra
    inventory keyword arguments), ...)."""
    d = mini_estate.directory(mini_estate.credential_changes(alpha={}, beta=beta or {}, **credential))
    groups = tuple(inventory_group(inventory_entry(d, "fake", c, AT, state, **kw),
                                   tuple(object_entry(d, "fake", c, name, facts) for name, facts in objs.items()))
                   for c, state, objs, kw in containers)
    return after_import(d, Imported((ou_entry(SECRET_INVENTORY), ou_entry(inventory_scheme_dn("fake"))), groups,
                                    ())) if groups else d


def _plan(d):
    ctx = PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, AS_OF, {}, {}, ())
    return inventory_findings(ctx, LOCATORS)


def _states(d):
    held = inventories(d)
    return {(r.ref.uri, r.ref.attr): r.state for r in (reconcile(d, x, held) for x in record_references(d, LOCATORS))}


def test_each_reference_state_is_kept_apart():
    d = _record(beta={"ciamCopyRef": ("fake://vault-b/signing", "fake://gone/signing")},
                containers=(("secrets", "complete", {"alpha/signing": {}}, {}),
                            ("vault-b", "denied", {}, {"problems": ("403 on listing",)}),
                            ("gone", "incomplete", {}, {"problems": ("12 of 40 accounts listed",)})))
    assert _states(d) == {("fake://secrets/alpha/signing", "ciamRefUri"): PRESENT,
                          ("fake://secrets/beta/signing", "ciamRefUri"): MISSING,
                          ("fake://vault-b/signing", "ciamCopyRef"): INACCESSIBLE,
                          ("fake://gone/signing", "ciamCopyRef"): INCOMPLETE}


def test_a_deleted_object_and_a_container_never_inventoried():
    d = _record(beta={"ciamCopyRef": "fake://elsewhere/signing"},
                containers=(("secrets", "complete", {"alpha/signing": {"ciamObjectState": "disabled"},
                                                     "beta/signing": {"ciamObjectState": "active"}}, {}),))
    assert _states(d) == {("fake://secrets/alpha/signing", "ciamRefUri"): DELETED,
                          ("fake://secrets/beta/signing", "ciamRefUri"): PRESENT,
                          ("fake://elsewhere/signing", "ciamCopyRef"): NOT_INVENTORIED}


def test_a_reference_outside_the_prefixes_listed_is_not_inventoried():
    d = _record(containers=(("secrets", "complete", {"alpha/signing": {}}, {"prefixes": ("alpha/",)}),))
    assert _states(d)[("fake://secrets/beta/signing", "ciamRefUri")] == NOT_INVENTORIED


def test_the_planner_says_nothing_when_no_inventory_of_the_targets_schemes_is_held():
    assert _plan(_record()) == _plan(_record())._replace(blockers=(), actions=(), ok=())


def test_missing_and_deleted_objects_block_and_unconfirmed_ones_are_actions():
    d = _record(beta={"ciamCopyRef": ("fake://vault-b/signing", "fake://elsewhere/x")},
                containers=(("secrets", "complete", {"alpha/signing": {}}, {}),
                            ("vault-b", "denied", {}, {"problems": ("403 on listing",)})))
    found = _plan(d)
    assert found.blockers == ((AREA, "beta/prod references `signing-key` (fake://secrets/beta/signing), but secrets's "
                                     "inventory of 2026-09-30 is complete and holds no `beta/signing`: whatever reads "
                                     "it fails. Create it in the store, or correct the reference.", "**NO OWNER**"),)
    assert [a[1].split(": ", 1)[1] for a in found.actions] == [
        "the store refused to list vault-b (403 on listing): grant the inventory's reader list access to it and "
        "collect again.",
        "elsewhere isn't inventoried: collect its inventory (`opsdir collect`, --inventory-container), or record "
        "why not."]
    assert all(a[1].startswith("beta/prod references `signing-key` (a copy at fake://") for a in found.actions)


def test_a_copy_missing_from_its_store_blocks_because_rotation_wouldnt_update_it():
    d = _record(beta={"ciamCopyRef": "fake://vault-b/signing"},
                containers=(("secrets", "complete", {"alpha/signing": {}, "beta/signing": {}}, {}),
                            ("vault-b", "complete", {}, {})))
    assert [b[1] for b in _plan(d).blockers] == [
        "beta/prod references `signing-key` (a copy at fake://vault-b/signing), but vault-b's inventory of 2026-09-30 "
        "is complete and holds no `signing`: the copy rotating the material must update isn't there. Create it in the "
        "store, or correct the reference."]


def test_rotation_is_judged_only_from_a_rotation_timestamp_on_the_references_own_location():
    rotated = {"ciamLastRotated": "20260601000000Z", "ciamRotationStatus": "failure", "ciamRotationManaged": "FALSE",
               "ciamManualReason": "Disabled by the vault administrator"}
    d = _record(beta={"ciamAutoRotate": "TRUE"},
                containers=(("secrets", "complete", {"beta/signing": rotated, "alpha/signing": {}}, {}),))
    assert [a[1] for a in _plan(d).actions] == [
        "beta/prod: `signing-key` (fake://secrets/beta/signing): rotation overdue: last rotated 2026-06-01, due "
        "2026-08-30 (every 90 days).",
        "beta/prod: `signing-key` (fake://secrets/beta/signing): the store's last rotation failed.",
        "beta/prod: `signing-key` (fake://secrets/beta/signing): the binding says its store rotates it, but the store "
        "doesn't manage it (Disabled by the vault administrator)."]
    modified_only = {"ciamStoreModified": "20250101000000Z"}       # a write, not a rotation: never overdue
    d = _record(containers=(("secrets", "complete", {"beta/signing": modified_only, "alpha/signing": {}}, {}),))
    assert _plan(d).actions == () and _plan(d).ok == (
        "1 secret reference(s) of beta/prod found in their stores' inventories.",
        "Rotation in secrets (fake) isn't observable from its inventory: the store's metadata doesn't say when "
        "material rotated.")


def test_objects_nothing_references_in_the_targets_containers_are_one_action_each_container():
    d = _record(containers=(("secrets", "complete", {"alpha/signing": {}, "beta/signing": {}, "old/admin": {},
                                                     "old/bind": {}}, {}),
                            ("unused", "complete", {"x": {}}, {})))
    assert [a[1] for a in _plan(d).actions] == [
        "secrets (fake) holds 2 object(s) no reference in the record names: `old/admin`, `old/bind`. Reference what "
        "is in use, or remove the rest from the store."]


def test_the_report_lists_every_placed_reference_then_the_unreferenced_objects():
    d = _record(beta={"ciamCopyRef": "fake://vault-b/signing"},
                containers=(("secrets", "complete", {"alpha/signing": {"ciamLastRotated": "20260901000000Z",
                                                                       "ciamRotationManaged": "TRUE",
                                                                       "ciamRotationStatus": "success"},
                                                     "spare": {}}, {}),))
    assert inventory_rows(d, LOCATORS, AS_OF) == [
        ("alpha/prod", "signing-key", "fake://secrets/alpha/signing", "fake: secrets", PRESENT, "2026-09-30",
         "2026-09-01", "2026-11-30", "managed, success", ""),
        ("beta/prod", "signing-key", "fake://secrets/beta/signing", "fake: secrets", MISSING, "2026-09-30", "", "", "",
         ""),
        ("beta/prod", "signing-key", "fake://vault-b/signing (copy)", "fake: vault-b", NOT_INVENTORIED, "", "", "",
         "", ""),
        ("", "", "spare", "fake: secrets", UNREFERENCED, "2026-09-30", "", "", "", "")]


def test_the_containers_to_inventory_are_those_references_name_then_the_operators():
    d = _record(beta={"ciamCopyRef": "fake://vault-b/signing"})
    assert wanted_containers(d, "fake", LOCATORS["fake"], " extra, secrets ,") == ("secrets", "vault-b", "extra")
    assert CONTAINER_OPTION.flag == "--inventory-container"


def test_the_planner_and_the_report_catalogue_use_the_installed_adapters_locators():
    check = secret_inventory_check(())
    assert check.__name__ == "check_secret_inventory" and inventory_locators(()) == {}
    assert "secret-inventory" in catalogue()


def test_a_token_credential_is_sent_as_the_whole_authorization_header():
    assert live._authorization(("token", "vault://pvwa/session", None), "8f1e-session") == {
        "Authorization": "8f1e-session"}
    assert live._authorization(("bearer", "x", None), "t") == {"Authorization": "Bearer t"}


def test_an_api_key_is_sent_alone_in_the_header_the_request_names():
    assert live._authorization(("api-key", "vault://fw/key", None, "X-PAN-KEY"), "LUFRPT1-key") == {
        "X-PAN-KEY": "LUFRPT1-key"}
