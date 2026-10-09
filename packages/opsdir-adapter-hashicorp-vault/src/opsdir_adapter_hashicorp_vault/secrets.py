"""Vault secrets: vault:// references resolved at run time with the Vault CLI, and the Vault token forms the store
refuses."""
from opsdir.core.contract import SecretPattern
from opsdir.core.directory import one
from opsdir.core.interchange import jinja

# Vault token forms the store refuses (SPEC R4): service, batch and recovery tokens
SECRET_PATTERNS = (
    SecretPattern("vault-token", r"(^|[^A-Za-z0-9])hv[sbr]\.[A-Za-z0-9_-]{20,}", "A HashiCorp Vault token"),
)



def kv_command(rest):
    return f"vault kv get -field=value '{rest}'"


def kv_lookup(m, store, rest):
    """The Ansible lookup reading a vault:// secret's `value` field at run time (community.hashi_vault vault_kv2_get
    or vault_kv1_get, by the store's ciamStoreKvVersion: 2 when not recorded): the reference's first segment is the
    mount, the rest the path; the address from the store's ciamStoreEndpoint when recorded, the token and auth from
    the controller's Vault settings. None for a reference with no path under its mount (its resolver command then)."""
    version = (one(store, "ciamStoreKvVersion") if store is not None else None) or "2"
    if "/" not in rest:
        return None
    mount, path = rest.split("/", 1)
    url = {"url": one(store, "ciamStoreEndpoint")} if store is not None and one(store, "ciamStoreEndpoint") else {}
    return f"{jinja.lookup(f'community.hashi_vault.vault_kv{version}_get', path, engine_mount_point=mount, **url)}" \
           ".secret.value"
