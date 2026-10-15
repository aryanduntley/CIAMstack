# opsdir-adapter-hashicorp-vault

opsdir adapter for HashiCorp Vault: `vault://` secret references. A secret-store adapter: it owns the `vault://` reference scheme, resolves it with the Vault CLI at run time, tells configuration management (Ansible) and the Kubernetes renderers how to read it, refuses Vault tokens anywhere in the record, and inventories its key/value mounts (metadata only) so the record's references can be reconciled with what Vault holds. The secret value never reaches the database or a rendered file.

**Applies to** any environment whose bindings reference `vault://` secrets (kind `secret-store`). It renders nothing for an environment (`applies` is always false); its scheme resolves wherever a binding uses it, declared in a stack or not.

**Depends on** `opsdir`. Resolving needs the Vault CLI (`vault`) on the machine running `opsdir`, signed in with the operator's own token and `VAULT_ADDR`; Ansible runs need the `community.hashi_vault` collection (pinned by opsdir-adapter-ansible); Kubernetes delivery needs the External Secrets Operator or the Secrets Store CSI driver with Vault's CSI provider in the cluster, and Vault's Kubernetes auth.

## What it renders

Nothing of its own. It supplies how `vault://` references are read to the adapters that render:

### Configuration management

opsdir-adapter-ansible reads `vault://` references at run time with `community.hashi_vault.vault_kv2_get` (or `vault_kv1_get` when the environment's Vault store records `ciamStoreKvVersion: 1`), `.secret.value`: the reference's first segment is the KV mount (`engine_mount_point`), the rest the path; `url` from the store's `ciamStoreEndpoint` when recorded; token and auth from the controller's Vault settings (`ansible_lookup`, `kv_lookup`). A reference with no path under its mount has no lookup: Ansible pipes the resolver command instead.

### Kubernetes workloads

The `kubernetes` adapter asks this one how `vault://` references reach a cluster (`kubernetes.py`, `SECRET_DELIVERY`). What a reference doesn't say comes from the environment's secret store for the scheme (`ciamSecretStore` with `ciamRefScheme: vault`):

| From the record | Rendered as |
|---|---|
| the store's `ciamStoreEndpoint` | the Vault address: ESO `server`, CSI `vaultAddress`; `UNBOUND:vault-address` when not recorded |
| the store's `ciamStoreAuthRole` | the Kubernetes auth role: ESO `auth.kubernetes.role`, CSI `roleName`; `UNBOUND:vault-role` when not recorded |
| the store's `ciamStoreAuthMount` | the Kubernetes auth mount: ESO `auth.kubernetes.mountPath`, CSI `vaultKubernetesMountPath`; default `kubernetes` |
| the store's `ciamStoreKvVersion` | the engine version: ESO `version` `v1`/`v2`; CSI `secretPath` `<mount>/data/<path>` for KV 2, the reference as is for KV 1; default 2 |
| the reference `vault://<mount>/<path>` | **External Secrets Operator**: a SecretStore per mount (one store serves one mount) with provider `vault` (`path` the mount, Kubernetes auth as the workload's service account, `serviceAccountRef`); `remoteRef` `key` the path under the mount, `property: value`. **Secrets Store CSI driver** (provider `vault`): each secret's `objectName`, `secretPath` and `secretKey: value` |

`opsdir/scripts/validate-csi-sync.sh` runs this delivery for real on a local kind cluster (Vault in dev mode, its CSI provider, Kubernetes auth bound to the sync pod's service account).

## References and secret patterns it owns

| Scheme | Form | Resolved |
|---|---|---|
| `vault` | `vault://<mount>/<path>`: a secret in a key/value engine, read as its field `value` | at run time: `vault kv get -field=value '<mount>/<path>'` |

The store refuses Vault tokens anywhere in the record (SPEC R4, secret pattern `vault-token`): service, batch and recovery tokens (`hvs.`, `hvb.`, `hvr.` followed by 20 or more token characters).

No vocabulary, schema, required roles or planner checks of its own. The secret store binding's attributes (`ciamStoreEndpoint`, `ciamStoreAuthRole`, `ciamStoreAuthMount`, `ciamStoreKvVersion`) are the core `pki` domain's.

## KV inventory (importer `hashicorp-vault/kv-metadata`, metadata only)

What a key/value mount holds, read into the record's secret-store inventory (`ou=vault,ou=secret-inventory`: one `ciamSecretInventory` per mount, a `ciamSecretObject` per path; the core `pki` domain's classes). The core reconciles every `vault://` reference (a secret reference's `ciamRefUri` and each `ciamCopyRef`) with it through this adapter's locator (`vault://<mount>/<path>` → mount, path): present, deleted, confirmed missing, listing incomplete, refused, or not inventoried; and the paths nothing references. `opsdir plan` blocks on a reference confirmed missing or deleted in the target and gives the rest as actions; `opsdir report secret-inventory` lists them all (opsdir/README.md, Secret-store inventories).

**Collect** (`opsdir collect --adapter hashicorp-vault/kv-metadata --env CLOUD/ENV`) runs the Vault CLI under the operator's own Vault login (`VAULT_TOKEN` or the token helper, as resolving does); opsdir passes only `VAULT_ADDR`, from the environment's vault store's `ciamStoreEndpoint` when recorded. The mounts listed are those the record's `vault://` references name, plus `--inventory-container` (comma-separated: a mount, or `mount/prefix/` to list only under a prefix):

| Call | Saved as |
|---|---|
| `vault kv list -format=json -mount=<mount> <prefix>`, from the root (or the prefix given) down through every folder a listing names | `list/<mount>/<prefix>_keys.json` (the root: `list/<mount>/_keys.json`) |
| `vault kv metadata get -format=json -mount=<mount> <path>` for every path (not when the store records `ciamStoreKvVersion: 1`) | `metadata/<mount>/<path>.json`, trimmed to the times, versions and deletion facts the importer reads (custom metadata and who changed it are dropped before anything sees them) |

**Least privilege**: the token needs only this policy (for the mount `secret`), and never `read` on `<mount>/data/*`:

```hcl
path "secret/metadata" {
  capabilities = ["list"]
}
path "secret/metadata/*" {
  capabilities = ["list", "read"]
}
```

The `-mount` flag needs the **Vault CLI 1.11 or later** (tested with 2.2.0, the version `opsdir/scripts/fetch-tools.sh` pins); the server must serve KV version 2 for metadata (KV 1 is listed only).

**Import** (`opsdir import --change CHG-… --at YYYYMMDDhhmmssZ hashicorp-vault/kv-metadata DIR`, or what `opsdir collect` collected): a mount is complete when every folder its listings name was listed and every path has its metadata; otherwise incomplete, with why. A listing Vault refused (`permission denied`) records the mount as denied. The prefixes listed first become the inventory's `ciamInventoryPrefix` (none when the root was listed). A path whose current version is destroyed, or deleted by the time the inventory was taken, is `deleted`; `updated_time` is `ciamStoreModified`, **never rotation** (a KV write doesn't prove the material rotated), so KV objects carry no rotation facts and the planner says once per mount that rotation isn't observable. A mount without any metadata is a KV 1 store's: its paths are recorded with no facts.

## Known limits

- **Not run against a live Vault server** beyond the local dev-mode Vault in `validate-csi-sync.sh`; Vault Enterprise namespaces aren't modelled.
- Only key/value engines (KV 1 and 2), and only a secret's field `value`: a secret kept under other field names, or in another engine (database, PKI, transit), isn't read.
- The CLI resolver takes the address and token from the operator's environment (`VAULT_ADDR`, the token helper), not from the store binding.
- **KV inventory**: KV engines only. A mount is the reference's first path segment, as for resolving (a nested mount path such as `kv/team` isn't told apart). An empty mount or prefix makes `vault kv list -format=json` exit 2 with no error text, so its collection is recorded as failed. Rotation isn't observable from KV metadata; database secrets engine static roles report their last rotation only with the password, so they aren't inventoried. Vault Enterprise namespaces (`X-Vault-Namespace`) aren't passed.

## Tests

`tests/test_hashicorp_vault.py`: registration through the entry point, never rendering for an environment, resolving `vault://` references through the registry. `tests/test_vault_kubernetes.py`: External Secrets reading the `value` field under the mount, CSI reading the KV 2 data path. `tests/test_vault_inventory.py`: the KV inventory (complete, deleted and destroyed paths, a scheduled deletion, unlisted folders, missing metadata, refusals, prefixes, KV 1, reconciliation, the collector's walk and the store's address). `tests/test_vault_live.py` (marker `vault`, skipped without `tools/bin/vault`): a local dev server, a token with only the policy above runs the collector's own commands, the importer reads them, and the same token is refused the secret's data. The Ansible lookups (KV 2 and KV 1, the store's endpoint) are tested in opsdir-adapter-ansible (`tests/test_ansible_inventory.py`).

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-hashicorp-vault/tests` (add `-m vault` for the live test).

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `hashicorp-vault`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
