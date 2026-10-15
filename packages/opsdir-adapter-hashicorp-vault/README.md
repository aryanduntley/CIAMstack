# opsdir-adapter-hashicorp-vault

opsdir adapter for HashiCorp Vault: `vault://` secret references. A secret-store adapter: it owns the `vault://` reference scheme, resolves it with the Vault CLI at run time, tells configuration management (Ansible) and the Kubernetes renderers how to read it, and refuses Vault tokens anywhere in the record. The secret value never reaches the database or a rendered file.

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

No vocabulary, schema, importers, required roles or planner checks. The secret store binding's attributes (`ciamStoreEndpoint`, `ciamStoreAuthRole`, `ciamStoreAuthMount`, `ciamStoreKvVersion`) are the core `pki` domain's.

## Known limits

- **Not run against a live Vault server** beyond the local dev-mode Vault in `validate-csi-sync.sh`; Vault Enterprise namespaces aren't modelled.
- Only key/value engines (KV 1 and 2), and only a secret's field `value`: a secret kept under other field names, or in another engine (database, PKI, transit), isn't read.
- The CLI resolver takes the address and token from the operator's environment (`VAULT_ADDR`, the token helper), not from the store binding.

## Tests

`tests/test_hashicorp_vault.py`: registration through the entry point, never rendering for an environment, resolving `vault://` references through the registry. `tests/test_vault_kubernetes.py`: External Secrets reading the `value` field under the mount, CSI reading the KV 2 data path. The Ansible lookups (KV 2 and KV 1, the store's endpoint) are tested in opsdir-adapter-ansible (`tests/test_ansible_inventory.py`).

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-hashicorp-vault/tests`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `hashicorp-vault`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
