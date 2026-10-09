# opsdir-adapter-hashicorp-vault

opsdir adapter for HashiCorp Vault: vault:// secret references.

A secret-store adapter: owns the `vault://` reference scheme and resolves it with the Vault CLI at run time. The secret value never reaches the database or a rendered file.

A reference is `vault://<mount>/<path>` in a key/value engine, read as the field `value`.

## Kubernetes workloads

The `kubernetes` adapter asks this one how `vault://` references reach a cluster (`kubernetes.py`). What a reference doesn't say comes from the environment's secret store for the scheme (`ciamSecretStore` with `ciamRefScheme: vault`): the Vault address (`ciamStoreEndpoint`), the Kubernetes auth role (`ciamStoreAuthRole`) and mount (`ciamStoreAuthMount`, default `kubernetes`), and the engine version (`ciamStoreKvVersion`, default 2). An address or role the record doesn't hold is written `UNBOUND:vault-address` / `UNBOUND:vault-role`.

- **External Secrets Operator**: a SecretStore per mount with provider `vault` (`server`, `path` the mount, `version` `v2`, Kubernetes auth as the workload's service account); `remoteRef` the path under the mount and `property: value`.
- **Secrets Store CSI driver** (Vault provider, provider `vault`): `vaultAddress`, `roleName`, `vaultKubernetesMountPath`, each secret's `secretPath` (`<mount>/data/<path>` for KV 2) and `secretKey: value`.

Tests: `tests/test_vault_kubernetes.py`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `hashicorp-vault`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
