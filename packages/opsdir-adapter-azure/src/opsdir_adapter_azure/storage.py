"""Azure: the object stores (blob containers, azblob://<account>/<container>) an environment uses, rendered as Terraform
and read back. Pure.

Versioning, public access, the customer-managed key, lifecycle management and object replication are the storage
account's settings, not the container's: the stack renders an account (with every described container in it) when it
keeps those containers. A container someone else keeps (ciamManagedBy) is theirs and so is its account: a comment names
the keeper and what to ask them for. A container the record only references is left alone (its account a data source
where an identity's grant needs it).

Rendered into the stack's main.tf, per account the stack keeps:
  azurerm_storage_account: Standard, zone-redundant (ZRS), TLS 1.2, HTTPS only, nested items public only when nothing
  blocks it, blob versioning (and the change feed object replication needs), the user-assigned identity its key needs
  azurerm_storage_account_customer_managed_key: the key of its containers' key role (customer_key)
  azurerm_storage_management_policy: a rule per container with lifecycle rules (cool, cold, archive tiers and delete,
  for base blobs and for versions)
  per container: azurerm_storage_container (private; metadata role and managedby, what the importers read it back by),
  an immutability policy (locked for compliance, unlocked for governance; its days), object replication to its
  replica (the destination account an input)
  import blocks for the account and the container when the container's provider ref (its ARM ID) is recorded

Read back from (azurerm type, attributes) pairs, Terraform state as it is or the CLI and ARM templates normalized to
it (cli_storage.py): each container with what its account, immutability policy, management policy and object
replication say (and the tags of its account: a container has metadata, not tags). A setting no source reports is
left as the record has it.
"""
from itertools import groupby

from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import of_class
from opsdir.core.inventory import of_types, resource
from opsdir.domains.data.storage import (LifecycleRule, depth_summary, has_depth, kept_store, lifecycle_rules,
                                         lifecycle_value)
from opsdir.domains.network.plumbing import adopted
from opsdir.domains.network.stack import kept_by, owned
from opsdir_format_terraform.hcl import Block, block, import_block, ref, tf_name
from .arm_ids import arm_segment
from .cli_storage import BASE, VERSION
from .cmk import customer_key, key_ref
from .identities import LOC, RG
from .network import binding_tags
from .account import tagged

_TIERS = {"cool": "tierToCool", "cold": "tierToCold", "archive": "tierToArchive", "delete": "delete"}
_FROM_BASE = {tf: neutral for neutral, cli in _TIERS.items() for c, tf in BASE if c == cli}
_FROM_VERSION = {tf: neutral for neutral, cli in _TIERS.items() for c, tf in VERSION if c == cli}


def container_of(uri):
    """(account, container) of an azblob:// storage reference, else None."""
    if not (uri or "").startswith("azblob://"):
        return None
    account, _, container = uri[len("azblob://"):].partition("/")
    return (account, container.split("/", 1)[0]) if account and container else None


def kept_containers(m):
    """Environment m's object stores in blob containers whose settings the stack renders: described by the record,
    kept by the stack."""
    return tuple(b for b in of_class(m, "ciamObjectStore")
                 if container_of(one(b, "ciamStorageRef")) and kept_store(b))


# ------------------------------------------------------------------ render
def _any(stores, attr, value):
    return any(one(b, attr) == value for b in stores)


def _account(m, account, stores):
    n = tf_name(account)
    keyed = next((b for b in stores if one(b, "ciamEncryptedByRole")), None)
    k = customer_key(m, keyed, f"{n}_storage") if keyed is not None else None
    replicated = any(container_of(one(b, "ciamStorageReplicaRef")) for b in stores)
    versioning = _any(stores, "ciamStorageVersioning", "TRUE") or replicated
    public = None if not any(one(b, "ciamStoragePublicBlocked") for b in stores) else \
        not _any(stores, "ciamStoragePublicBlocked", "TRUE")
    keys = {one(b, "ciamEncryptedByRole") for b in stores if one(b, "ciamEncryptedByRole")}
    managed = [(b, rules) for b in stores for rules in (lifecycle_rules(b),) if rules]
    first = next((b for b in stores if adopted(b)), None)
    return (*((f"# storage account {account}: its containers name keys {', '.join(sorted(keys))}; an account has one "
               f"key: {one(keyed, 'ciamEncryptedByRole')} is used",) if len(keys) > 1 else ()),
            *((k.blocks if k is not None else ())),
            block("resource", ["azurerm_storage_account", n], [
                ("name", account), ("resource_group_name", RG), ("location", LOC), ("account_tier", "Standard"),
                ("account_replication_type", "ZRS"), ("min_tls_version", "TLS1_2"),
                ("https_traffic_only_enabled", True),
                *((("allow_nested_items_to_be_public", public),) if public is not None else ()),
                ("blob_properties", Block((("versioning_enabled", versioning),
                                           *((("change_feed_enabled", True),) if replicated else ())))),
                *((("identity", Block((("type", "UserAssigned"), ("identity_ids", [ref(f"{k.identity}.id")])))),)
                  if k is not None and k.identity else ((k.note,) if k is not None and k.note else ())),
                ("tags", tagged(m, {"ManagedBy": "opsdir"}))]),
            *((block("resource", ["azurerm_storage_account_customer_managed_key", n], [
                ("storage_account_id", ref(f"azurerm_storage_account.{n}.id")),
                ("key_vault_id", ref(f"{k.key}.key_vault_id")), ("key_name", ref(f"{k.key}.name")),
                ("user_assigned_identity_id", ref(f"{k.identity}.id")), ("depends_on", [ref(k.grant)])]),)
              if k is not None and k.identity else ()),
            *((block("resource", ["azurerm_storage_management_policy", n], [
                ("storage_account_id", ref(f"azurerm_storage_account.{n}.id")),
                *(("rule", Block(_rule(b, rules))) for b, rules in managed)]),) if managed else ()),
            *((import_block(f"azurerm_storage_account.{n}", one(first, "ciamProviderRef").split("/blobServices/")[0]),)
              if first is not None else ()))


def _rule(b, rules):
    container = container_of(one(b, "ciamStorageRef"))[1]

    def actions(noncurrent, names):
        mine = {r.action: r.days for r in reversed(rules) if r.noncurrent == noncurrent}
        return tuple((tf, mine[neutral]) for neutral, cli in _TIERS.items() if neutral in mine
                     for c, tf in names if c == cli)
    base, versions = actions(False, BASE), actions(True, VERSION)
    return (("name", f"ciam-{container}"), ("enabled", True),
            ("filters", Block((("blob_types", ["blockBlob"]), ("prefix_match", [f"{container}/"])))),
            ("actions", Block((*((("base_blob", Block(base)),) if base else ()),
                               *((("version", Block(versions)),) if versions else ())))))


def _container(b):
    account, container = container_of(one(b, "ciamStorageRef"))
    n, a = tf_name(rdn_value(b)), tf_name(account)
    mode, days = one(b, "ciamStorageImmutability"), one(b, "ciamStorageLockDays")
    replica = container_of(one(b, "ciamStorageReplicaRef"))
    destination = f"{n}_replica_account_id"
    return (block("resource", ["azurerm_storage_container", n], [
                ("name", container), ("storage_account_id", ref(f"azurerm_storage_account.{a}.id")),
                ("container_access_type", "private"),
                ("metadata", {"role": one(b, "ciamBindingRole"), "managedby": "opsdir"})]),
            *((block("resource", ["azurerm_storage_container_immutability_policy", n], [
                ("storage_container_resource_manager_id", ref(f"azurerm_storage_container.{n}.resource_manager_id")),
                ("immutability_period_in_days", int(days or 1)), ("protected_append_writes_enabled", False),
                ("locked", mode == "compliance")]),) if mode in ("governance", "compliance") else ()),
            *((f"# {rdn_value(b)}: its replica {one(b, 'ciamStorageReplicaRef')} isn't a blob container: replication "
               "not rendered",) if one(b, "ciamStorageReplicaRef") and not replica else ()),
            *((block("variable", [destination], [("type", ref("string")), ("description", (
                f"The ID of storage account {replica[0]}, which container {container} is copied to"))]),
               block("resource", ["azurerm_storage_object_replication", n], [
                   ("source_storage_account_id", ref(f"azurerm_storage_account.{a}.id")),
                   ("destination_storage_account_id", ref(f"var.{destination}")),
                   ("rules", Block((("source_container_name", ref(f"azurerm_storage_container.{n}.name")),
                                    ("destination_container_name", replica[1]))))])) if replica else ()),
            *((import_block(f"azurerm_storage_container.{n}", one(b, "ciamProviderRef")),) if adopted(b) else ()))


def render_object_stores(m):
    """HCL for environment m's object stores in blob containers the record describes: comments naming who keeps the
    others and what to ask them for, then each account the stack keeps with its containers."""
    described = [b for b in of_class(m, "ciamObjectStore") if container_of(one(b, "ciamStorageRef")) and has_depth(b)]
    kept = sorted(kept_containers(m), key=lambda b: (container_of(one(b, "ciamStorageRef")), b.dn))
    return (*(f"# Object store '{rdn_value(b)}' (role {one(b, 'ciamBindingRole')}) "
              f"is kept by {kept_by(m, b)}, with its "
              f"storage account: not rendered here. Ask them for: {depth_summary(b)}" for b in described
              if not owned(b)),
            *(x for account, stores in groupby(kept, key=lambda b: container_of(one(b, "ciamStorageRef"))[0])
              for group in (tuple(stores),)
              for x in (*_account(m, account, group), *(y for b in group for y in _container(b)))))


# ------------------------------------------------------------------ read back
def _first(v):
    return v[0] if isinstance(v, list) and v else v if isinstance(v, dict) else {}


def _metadata_role(a):
    """A container's role from its metadata (keys role or bindingrole, any case): containers carry metadata, not
    tags."""
    meta = {k.lower(): v for k, v in (a.get("metadata") or {}).items()}
    return meta.get("role") or meta.get("bindingrole")


def _low(x):
    return (x or "").lower()


def _account_of(a):
    return a.get("storage_account_name") or arm_segment(a.get("storage_account_id") or a.get("id"), "storageAccounts")


def _name_of(account_ref):
    """An account's name from its ID (or the name itself, as or-policy lists may give it)."""
    return arm_segment(account_ref, "storageAccounts") or account_ref


def _lifecycle(policy, container):
    """The neutral lifecycle values a management policy's enabled rules give a container (a rule with no prefix, or
    one matching the container, applies)."""
    out = []
    for r in policy.get("rule") or ():
        prefixes = _first(r.get("filters")).get("prefix_match") or []
        if r.get("enabled") is False or (prefixes and not any(
                p.split("/", 1)[0] == container for p in prefixes)):
            continue
        acts = _first(r.get("actions"))
        out += [LifecycleRule(False, int(d), _FROM_BASE[k]) for k, d in _first(acts.get("base_blob")).items()
                if k in _FROM_BASE and d is not None]
        out += [LifecycleRule(True, int(d), _FROM_VERSION[k]) for k, d in _first(acts.get("version")).items()
                if k in _FROM_VERSION and d is not None]
    return sorted(dict.fromkeys(lifecycle_value(r) for r in out))


def _key_url(account, cmks):
    cmk = cmks.get(_low(account.get("id"))) or {}
    url = _first(account.get("customer_managed_key")).get("key_vault_key_id") or cmk.get("key_vault_key_id")
    if not url and cmk.get("key_name") and arm_segment(cmk.get("key_vault_id"), "vaults"):
        url = f"https://{arm_segment(cmk['key_vault_id'], 'vaults')}.vault.azure.net/keys/{cmk['key_name']}"
    return url


def object_store_resources(pairs):
    """Storage resources of (azurerm type, attributes) pairs: blob containers, with what their account, immutability
    policy, management policy and object replication say."""
    accounts = {_low(a.get("name")): a for a in of_types(pairs, "azurerm_storage_account") if a.get("name")}
    cmks = {_low(c.get("storage_account_id")): c
            for c in of_types(pairs, "azurerm_storage_account_customer_managed_key")}
    locks = {_low(p.get("storage_container_resource_manager_id")): p
             for p in of_types(pairs, "azurerm_storage_container_immutability_policy")}
    policies = {_low(_name_of(p.get("storage_account_id"))): p
                for p in of_types(pairs, "azurerm_storage_management_policy")}
    copies = [(o, r) for o in of_types(pairs, "azurerm_storage_object_replication") for r in o.get("rules") or ()]

    def one_container(c):
        account, name = _account_of(c), c.get("name")
        a = accounts.get(_low(account))
        lock = locks.get(_low(c.get("resource_manager_id") or c.get("id")))
        props = _first((a or {}).get("blob_properties"))
        copy = next(((o, r) for o, r in copies if r.get("source_container_name") == name
                     and _low(_name_of(o.get("source_storage_account_id"))) == _low(account)), None)
        public = (a or {}).get("allow_nested_items_to_be_public")
        return resource("storage", c.get("id") or f"{account}/{name}", {
            "ciamStorageRef": f"azblob://{account}/{name}",
            "ciamStorageVersioning": ("TRUE" if props.get("versioning_enabled") else "FALSE") if props else None,
            "ciamStoragePublicBlocked": ("FALSE" if public else "TRUE") if public is not None else None,
            "ciamStorageImmutability": ("compliance" if lock.get("locked") else "governance") if lock else None,
            "ciamStorageLockDays": lock.get("immutability_period_in_days") if lock else None,
            "ciamStorageLifecycle": _lifecycle(policies[_low(account)], name) if _low(account) in policies else None,
            "ciamStorageReplicaRef": f"azblob://{_name_of(copy[0].get('destination_storage_account_id'))}/"
                                     f"{copy[1].get('destination_container_name')}" if copy else None},
            links={"ciamEncryptedByRole": key_ref(_key_url(a, cmks)) if a else None},
            name=name, role=_metadata_role(c),
            tags=(a["tags"] or {}) if a and "tags" in a else None)   # a container has metadata; its account tags
    return tuple(one_container(c) for c in of_types(pairs, "azurerm_storage_container")
                 if _account_of(c) and c.get("name"))
