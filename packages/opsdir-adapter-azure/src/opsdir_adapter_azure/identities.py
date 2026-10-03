"""The managed identities and role assignments Azure renderers share: role assignments from the Azure permission
table (opsdir_adapter_azure.access) at the narrowest scope (the secret or key in its vault, Key Vault's RBAC model; the
storage container; the resource a provider ref names), the data sources those scopes need, and notes for what can't be
granted. The platform's Terraform (workloads, terraform.py) and the landing zone's (deployers, operator groups,
landing.py) use them. Pure.
"""
import re

from opsdir.core.directory import one
from opsdir.core.environment import of_class
from opsdir_format_terraform.hcl import block, ref, tf_name

RG = ref("data.azurerm_resource_group.main.name")
LOC = ref("data.azurerm_resource_group.main.location")


def scope(b):
    """(the narrowest scope a role assignment on a binding's resource takes, the data source it needs or None)."""
    uri, storage = one(b, "ciamRefUri", ""), one(b, "ciamStorageRef", "")
    if uri.startswith(("azkv://", "azkv-key://")):
        vault, _, rest = uri.split("://", 1)[1].partition("/")
        child = "keys" if uri.startswith("azkv-key://") else "secrets"
        return (f"${{data.azurerm_key_vault.{tf_name(vault)}.id}}/{child}/{rest.split('/')[-1]}",
                ("azurerm_key_vault", vault))
    if storage.startswith("azblob://"):
        account, _, container = storage[9:].partition("/")
        return (f"${{data.azurerm_storage_account.{tf_name(account)}.id}}/blobServices/default/containers/{container}",
                ("azurerm_storage_account", account))
    return one(b, "ciamProviderRef"), None


def notes(w):
    return tuple(f"# NOTE: principal {w.principal}: {note}" for note in w.notes)


def assignments(w, principal_id):
    """One role assignment per permit, at the narrowest scope, to a principal (an identity's, a group's object id)."""
    n = tf_name(w.identity_role)
    return tuple(block("resource", ["azurerm_role_assignment", f"{n}_{tf_name(permit)}"], [
        ("scope", scope(b)[0]), ("role_definition_name", role_of(row, b)), ("principal_id", principal_id)])
        for permit, b, row in w.grants)


def managed_identity(w):
    return block("resource", ["azurerm_user_assigned_identity", tf_name(w.identity_role)], [
        ("name", w.name), ("resource_group_name", RG), ("location", LOC),
        ("tags", {"Principal": w.principal, "Role": w.identity_role, "ManagedBy": "opsdir"})])


def identity(m, w):
    """A workload principal's user-assigned managed identity and its role assignments."""
    n = tf_name(w.identity_role)
    return (*notes(w), managed_identity(w),
            *assignments(w, ref(f"azurerm_user_assigned_identity.{n}.principal_id")))


def role_of(row, b):
    """The role a row grants: its first alternative, or for an Event Grid topic the Event Grid one."""
    alternatives = row.needs[0]
    grid = re.search(r"/providers/Microsoft\.EventGrid/", one(b, "ciamProviderRef", ""), re.IGNORECASE)
    return next((r for r in alternatives if r.startswith("EventGrid")), alternatives[0]) if grid else alternatives[0]


def scope_data(m, identities, standalone=False):
    """Data sources the role assignments' scopes need: in the platform's Terraform, those the secrets' vault checks
    don't declare already; in a standalone root (the landing zone), all of them."""
    declared = set() if standalone else {("azurerm_key_vault", one(b, "ciamRefUri").split("://", 1)[1].split("/", 1)[0])
                                         for b in of_class(m, "ciamSecretRef")}
    needed = dict.fromkeys(need for w in identities for _, b, _ in w.grants for _, need in (scope(b),) if need)
    return tuple(block("data", [kind, tf_name(name)], [("name", name), ("resource_group_name", RG)])
                 for kind, name in needed if (kind, name) not in declared)
