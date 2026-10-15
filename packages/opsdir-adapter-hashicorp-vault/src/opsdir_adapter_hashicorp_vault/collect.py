"""Vault collector (`opsdir collect`, core.contract Collector): the KV listings and metadata hashicorp-vault/kv-metadata
reads, read-only and metadata only. Pure: the core runs the commands.

The Vault CLI runs under the operator's own Vault login (VAULT_TOKEN, or the CLI's token helper), as resolving a
vault:// reference does; opsdir passes only the address, the environment's vault secret store's ciamStoreEndpoint
(VAULT_ADDR, when recorded). The mounts listed are those the record's vault:// references name (in every environment),
plus the operator's --inventory-container ones (a mount, or mount/prefix/ to list only under a prefix):
  vault kv list -format=json -mount=<mount> <prefix>     every prefix, from the root (or the prefix given) down
  vault kv metadata get -format=json -mount=<mount> <path>    every path, unless the store records KV version 1
each saved as the importer reads it (inventory.listing_path, metadata_path), the metadata trimmed to what the importer
reads (inventory.metadata_only). The token needs only: list on <mount>/metadata, list and read on <mount>/metadata/*,
and nothing on <mount>/data/* (README); the -mount flag needs the Vault CLI 1.11 or later."""
import json

from opsdir.core.contract import Collector, Command
from opsdir.core.directory import one
from opsdir.domains.pki.credentials import secret_store
from opsdir.domains.pki.inventory import CONTAINER_OPTION, wanted_containers
from .inventory import SCHEME, listing_path, locate, metadata_only, metadata_path


def roots(containers):
    """((mount, prefix), ...) to list first: a container is a mount (its root) or mount/prefix/."""
    def split(c):
        mount, _, prefix = c.partition("/")
        return mount, (prefix.rstrip("/") + "/") if prefix.strip("/") else ""
    return tuple(dict.fromkeys(split(c) for c in containers if c.partition("/")[0]))


def _list(mount, prefix, env):
    return Command(("vault", "kv", "list", "-format=json", f"-mount={mount}", prefix), env=env)


def _metadata(mount, path, env):
    return Command(("vault", "kv", "metadata", "get", "-format=json", f"-mount={mount}", path), env=env,
                   keep=metadata_only)


def _keys(text):
    try:
        doc = json.loads(text or "")
    except ValueError:
        return ()
    return tuple(k for k in doc if isinstance(k, str)) if isinstance(doc, list) else ()


def kv_steps(d, m, done, options):
    """Each mount's listings, from its roots down through the folders each listing names, and (KV 2) each path's
    metadata."""
    store = secret_store(m, SCHEME) if m is not None else None
    endpoint = one(store, "ciamStoreEndpoint") if store is not None else None
    env = (("VAULT_ADDR", endpoint),) if endpoint else ()
    v1 = store is not None and one(store, "ciamStoreKvVersion") == "1"
    def walk(mount, prefix):
        keys = _keys(done.get(listing_path(mount, prefix)))
        return ((listing_path(mount, prefix), _list(mount, prefix, env)),
                *(c for k in keys if k.endswith("/") for c in walk(mount, prefix + k)),
                *(() if v1 else ((metadata_path(mount, prefix + k), _metadata(mount, prefix + k, env))
                                 for k in keys if not k.endswith("/"))))
    containers = wanted_containers(d, SCHEME, locate, options.get("inventory_container"))
    return tuple({path: call for mount, prefix in roots(containers) for path, call in walk(mount, prefix)}.items())


COLLECTORS = (Collector("kv-metadata", "environment", kv_steps, options=(CONTAINER_OPTION,)),)
