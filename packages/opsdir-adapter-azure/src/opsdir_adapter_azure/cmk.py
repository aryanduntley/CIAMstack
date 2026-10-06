"""Azure: Key Vault references of a binding's roles and the customer-managed key that encrypts a data service (a
database server, a storage account), shared by their renders and read-backs. Pure.

  role_uri        the reference URI a binding's role is bound to (a secret's azkv://, a key's azkv-key://), or a comment
                  when the environment doesn't bind it
  vault_object    (vault, name) of such a URI
  customer_key    the key's vault and key data sources, a user-assigned identity and its Key Vault Crypto Service
                  Encryption User grant on the key: what a service needs to encrypt with it
  key_ref         the azkv-key:// reference of a Key Vault key URL, as a read-back links it to its key binding
"""
from typing import NamedTuple

from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import UNBOUND, bound
from opsdir_format_terraform.hcl import block, ref
from .identities import LOC, RG
from .network import binding_tags

CMK_ROLE = "Key Vault Crypto Service Encryption User"
# A data service's customer-managed key: blocks (data sources, the identity, its grant), the addresses of the
# identity, the key data source and the grant to refer to (None when there is no key to use), and note: a body comment
# ('#', text) when the key role is unbound, else None.
CustomerKey = NamedTuple("CustomerKey", [("blocks", tuple), ("identity", str), ("key", str), ("grant", str),
                                         ("note", tuple)])


def vault_object(uri):
    """(vault, name) of an azkv:// or azkv-key:// reference (azkv://<vault>/<name>, azkv-key://<vault>/keys/<name>)."""
    vault, _, rest = uri.split("://", 1)[1].partition("/")
    return vault, rest.rsplit("/", 1)[-1]


def role_uri(m, role, what):
    """(the role's reference URI, None) when m binds it, (None, a comment) when it doesn't, (None, None) for no role."""
    if not role:
        return None, None
    uri = bound(m, role, "ciamRefUri")
    return (None, ("#", f"{uri}: no {what} binding for role {role} in this environment")) \
        if uri.startswith(UNBOUND) else (uri, None)


def customer_key(m, b, n):
    """The CustomerKey of binding b's key role (ciamEncryptedByRole), its blocks named after n."""
    uri, note = role_uri(m, one(b, "ciamEncryptedByRole"), "key")
    if uri is None:
        return CustomerKey((), None, None, None, note)
    vault, name = vault_object(uri)
    ident = f"azurerm_user_assigned_identity.{n}_cmk"
    return CustomerKey(
        (block("data", ["azurerm_key_vault", f"{n}_cmk"], [("name", vault), ("resource_group_name", RG)]),
         block("data", ["azurerm_key_vault_key", f"{n}_cmk"], [
             ("name", name), ("key_vault_id", ref(f"data.azurerm_key_vault.{n}_cmk.id"))]),
         block("resource", ["azurerm_user_assigned_identity", f"{n}_cmk"], [
             ("name", f"id-{rdn_value(b)}-cmk"), ("location", LOC), ("resource_group_name", RG),
             ("tags", binding_tags(b))]),
         block("resource", ["azurerm_role_assignment", f"{n}_cmk"], [
             ("scope", ref(f"data.azurerm_key_vault_key.{n}_cmk.resource_versionless_id")),
             ("role_definition_name", CMK_ROLE), ("principal_id", ref(f"{ident}.principal_id"))])),
        ident, f"data.azurerm_key_vault_key.{n}_cmk", f"azurerm_role_assignment.{n}_cmk", None)


def key_ref(url):
    """The key reference of a Key Vault key URL (https://<vault>.vault.azure.net/keys/<name>[/<version>])."""
    host, _, path = (url or "").partition("://")[2].partition("/")
    parts = path.split("/")
    return f"azkv-key://{host.split('.')[0].lower()}/keys/{parts[1]}" if len(parts) > 1 and parts[0] == "keys" \
        else None
