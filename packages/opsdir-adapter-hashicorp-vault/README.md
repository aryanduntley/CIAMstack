# opsdir-adapter-hashicorp-vault

opsdir adapter for HashiCorp Vault: `vault://` secret references, and Vault's PKI secrets engine. A secret-store adapter: it owns the `vault://` reference scheme, resolves it with the Vault CLI at run time, tells configuration management (Ansible) and the Kubernetes renderers how to read it, refuses Vault tokens anywhere in the record, and inventories its key/value mounts (metadata only) so the record's references can be reconciled with what Vault holds. It also reads each PKI mount a collection source names into the record's PKI (the core `pki` domain): the mount's CA, its revocation endpoints, its roles as that CA's own certificate templates and the certificates it keeps, metadata only. The secret value never reaches the database or a rendered file, nor does any private key.

**Applies to** any environment whose bindings reference `vault://` secrets (kind `secret-store`). It renders nothing for an environment (`applies` is always false); its scheme resolves wherever a binding uses it, declared in a stack or not. Its PKI inventory applies only where an environment declares a collection source for `hashicorp-vault/pki` (or an operator imports an export): a Vault used only as a secret store is never read for PKI.

**Depends on** `opsdir` and `opsdir-adapter-x509` (its CA-neutral `certificate_facts`, which reads the PKI mounts' public certificates with the `cryptography` library). Resolving needs the Vault CLI (`vault`) on the machine running `opsdir`, signed in with the operator's own token and `VAULT_ADDR`; Ansible runs need the `community.hashi_vault` collection (pinned by opsdir-adapter-ansible); Kubernetes delivery needs the External Secrets Operator or the Secrets Store CSI driver with Vault's CSI provider in the cluster, and Vault's Kubernetes auth.

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

## PKI inventory (importer `hashicorp-vault/pki`, metadata only)

Each Vault PKI mount read into the record's PKI (the core `pki` domain, opsdir/README.md, Certification authorities and issued certificates): one mount is one certification authority. The core reconciles the record's certificates with what the mount keeps (present, revoked, superseded, confirmed missing, ...), judges the CA's roles as certificate templates (template risk) and observes the endpoints (`opsdir-adapter-x509`); this adapter only reads.

**Into the record:**

| From Vault | Recorded as |
|---|---|
| the mount | a `ciamCertAuthority` under `ou=certificate-authorities`, cn the **default issuer's subject common name** (its certificate's CN, as an AD CS CA's is; the mount's name when no default issuer's certificate was read), `ciamProviderRef` the mount, `ciamTemplateName` its roles. The operator's `ciamCaCertificate` and owners are kept |
| the default issuer's AIA URLs (`issuer/<id>`: `crl_distribution_points`, `delta_crl_distribution_points`, `ocsp_servers`, `issuing_certificates`) when it sets any, else the mount's (`config/urls`) | its revocation endpoints (`ciamRevocationEndpoint`, cn `crl-<n>`, `delta-crl-<n>`, `ocsp-<n>`, `ca-issuers-<n>`). With templating on (`enable_aia_url_templating` / `enable_templating`), `{{issuer_id}}` is the default issuer's id and `{{cluster_path}}` / `{{cluster_aia_path}}` come from `config/cluster`; a variable left unfilled keeps Vault's template (`description`) and is named in a notice |
| each role (`roles/<name>`) | a `ciamCertTemplate` that is **this CA's own** (`ciamTemplateAuthority`: the CA; cn `<CA>/<role>`): `ciamMaxValidityDays` the role's `max_ttl` in days, rounded up (`0`, the mount's maximum, isn't recorded); `ciamExtendedKeyUsage` from `server_flag`, `client_flag`, `code_signing_flag`, `email_protection_flag`, the `ext_key_usage` names (Go's `ExtKeyUsage` names, an unknown one left out with a notice) and `ext_key_usage_oids`; `ciamSubjectFromRequest` TRUE unless every name the role allows is templated from the requester's identity (`allowed_domains_template` with only `{{identity...}}` domains, not `allow_any_name`); `ciamApprovalRequired` FALSE and `ciamRequiredSignatures` 0 (Vault has neither); `ciamEnrollee` / `ciamEnrollmentScope` from the ACL policies (below). The CA's roles replace the templates the record holds as its own; a role no longer there leaves the record, one not read keeps its template; templates other CAs or a directory own (AD CS's) are never touched, and an AD CS template import keeps these |
| the certificates the mount keeps (`certs`, each `cert/<serial>`) | a `ciamCertInventory` (cn the CA, `ciamProviderRef` the mount) with a `ciamIssuedCertificate` per certificate (cn its serial as Vault lists it, colon-separated): `ciamSerialNumber` (lowercase hex), `ciamFingerprint` (SHA-256), `ciamSubject`, `ciamNotBefore`, `ciamNotAfter` from the public PEM (opsdir-adapter-x509's `certificate_facts`); revoked: `ciamRevokedAt` (`revocation_time_rfc3339`) and `ciamRevocationReason` `unspecified` (Vault records no reason). No template or requester: Vault records neither per certificate. The root CA's own certificate is listed by its mount and kept |

**Complete** means complete for the certificates Vault keeps. The inventory is **incomplete**, with why, when a listed certificate wasn't read or isn't a certificate, when the certificate listing is missing (Vault answers an empty listing with 404, so a mount that keeps none reads as incomplete), when a role has `no_store` (it keeps none of what it issues: nothing it issued can be confirmed missing) or a role wasn't read; **denied** when the listing was refused (`permission denied`). Notices name auto-tidy removing expired certificates from the store (`config/auto-tidy` `tidy_cert_store`: they leave the inventory after its `safety_buffer`), CRL or OCSP building disabled (`config/crl`), and the policies that may `sign-verbatim` (signing any request whatever the roles allow).

**Who may request from a role** (`policies.py`): the ACL policies (`sys/policies/acl`) granting `create` or `update` on `<mount>/issue/<role>` or `<mount>/sign/<role>` (directly or through `issuer/<ref>/`), each policy judged alone the way Vault picks the rule for a path (the most specific matching path by Vault's priority rules; `deny` there wins; `+` one segment, a trailing `*` any rest, a templated `{{identity...}}` segment any one segment; HCL or JSON; the legacy `policy = "write"` form too). Recorded as `policy <name>`; **broad** when `default` grants it (every token holds `default` unless created without it), **restricted** otherwise; `root` isn't counted. When the policies weren't read (not collected, or refused) or one couldn't be parsed, the scope is **unknown** with a notice. Who holds the other policies (auth methods' roles, entities, groups) isn't read.

**Collect** (`opsdir collect --adapter hashicorp-vault/pki --env CLOUD/ENV`, `pki_collect.py`) reads each mount an environment's collection source names, with Vault's HTTP API, GETs only (a listing is a GET with `?list=true`), each answer trimmed to what the importer reads before anything sees it:

```ldif
dn: cn=collect-pki,ou=bindings,env=ENV,cloud=CLOUD,ou=environments,dc=ciam-ops
objectClass: ciamCollectionSource
ciamBindingRole: collect-pki
ciamImporter: hashicorp-vault/pki
ciamSourceRef: https://vault.example.test:8200/pki
ciamCredentialRole: pki-reader
ciamCredentialScheme: api-key
ciamCaRole: vault-ca
```

One source per mount (`ciamSourceRef` `https://<vault>:<port>/<mount>`); the token is the reference the `pki-reader` role binds, resolved when collecting and never stored, sent as `X-Vault-Token` (`api-key`) or `Authorization: Bearer` (`bearer`); `ciamCaRole` the CA certificate Vault's listener is trusted by (else the system's trust store).

| Call | Saved as (under `pki/<mount>/`) |
|---|---|
| `GET <mount>/issuers?list=true`, then `issuer/<id>` | `issuers.json`, `issuers/<id>.json` (id, name, key id, certificate, AIA URLs) |
| `GET <mount>/roles?list=true`, then `roles/<role>` | `roles.json`, `roles/<role>.json` (the fields above, `no_store`, `issuer_ref`) |
| `GET <mount>/certs?list=true`, then `cert/<serial>` | `certs.json`, `certs/<serial, - for :>.json` (certificate, revocation time and reason, issuer id; never a key: Vault keeps none) |
| `GET <mount>/config/urls`, `issuers`, `cluster`, `crl`, `auto-tidy` | `config/<name>.json` |
| `GET sys/policies/acl?list=true`, then `sys/policies/acl/<name>` | `policies.json`, `policies/<name>.json` (optional) |

An empty listing and a configuration this Vault doesn't have (404) are nothing to read; the policies are nothing to read when refused too (403). Any other refusal fails the collection. A collection makes at most the core's 2000 calls: a mount keeping more certificates is exported with the script below.

**Least privilege**: the token needs only this policy (for the mount `pki`); the last two paths are optional (without them who may request from the roles is unknown). Nothing on `issue`, `sign`, `revoke`, `tidy` or key paths. `cert/<serial>`, `ca` and `crl` are public in Vault anyway.

```hcl
path "pki/issuers" { capabilities = ["list"] }
path "pki/issuer/+" { capabilities = ["read"] }
path "pki/roles" { capabilities = ["list"] }
path "pki/roles/+" { capabilities = ["read"] }
path "pki/certs" { capabilities = ["list"] }
path "pki/cert/+" { capabilities = ["read"] }
path "pki/config/urls" { capabilities = ["read"] }
path "pki/config/issuers" { capabilities = ["read"] }
path "pki/config/cluster" { capabilities = ["read"] }
path "pki/config/crl" { capabilities = ["read"] }
path "pki/config/auto-tidy" { capabilities = ["read"] }
# optional: who may request from each role
path "sys/policies/acl" { capabilities = ["list"] }
path "sys/policies/acl/+" { capabilities = ["read"] }
```

**Export script** (`scripts/export-vault-pki.sh MOUNT OUTDIR`): the same files with the Vault CLI under the operator's own login (`VAULT_ADDR`, `VAULT_TOKEN` or the token helper), one `vault read -format=json` per item (a listing the CLI's bare array), for a mount too large for one collection or a host `opsdir` doesn't run on; the policies are left out when refused.

**Import** (`opsdir import --change CHG-… --at YYYYMMDDhhmmssZ hashicorp-vault/pki DIR`, or what `opsdir collect` collected): every `pki/<mount>/issuers.json` in `DIR` is one mount; `--at` dates the inventory (when the mount was read).

## Known limits

- **Not run against a production Vault**: the KV and PKI inventories run against a local dev-mode Vault (2.2.0, the pinned CLI) in the live tests, and resolving in `validate-csi-sync.sh`; Vault Enterprise namespaces aren't modelled.
- Resolving reads only key/value engines (KV 1 and 2), and only a secret's field `value`: a secret kept under other field names, or in another engine (database, transit), isn't read. PKI mounts are inventoried, never resolved.
- The CLI resolver takes the address and token from the operator's environment (`VAULT_ADDR`, the token helper), not from the store binding.
- **KV inventory**: KV engines only. A mount is the reference's first path segment, as for resolving (a nested mount path such as `kv/team` isn't told apart). An empty mount or prefix makes `vault kv list -format=json` exit 2 with no error text, so its collection is recorded as failed. Rotation isn't observable from KV metadata; database secrets engine static roles report their last rotation only with the password, so they aren't inventoried. Vault Enterprise namespaces (`X-Vault-Namespace`) aren't passed.
- **PKI inventory**: Vault records **no revocation reason** (every revoked certificate is `unspecified`), and neither the role a certificate was issued from nor who asked for it, so issued certificates carry no template or requester: an active certificate no record certificate matches is listed as untracked in `opsdir report issued-certificates`, but the planner, which judges untracked certificates per template, never raises it; a renewal is recognized by subject alone. A role describes what it issues now, not what it issued before it was changed. Completeness covers what Vault keeps: `no_store` roles, certificates auto-tidy removed and certificates on other clusters (performance replication keeps issued certificates per cluster: collect each cluster's mount) aren't there. The certificate listing has no paging: one collection reads at most the core's 2000 calls (use `scripts/export-vault-pki.sh` beyond). Vault Enterprise **certificate metadata** (`cert-metadata`, 1.17+: the role per certificate) isn't read (deferred; its `cert_metadata` is caller-supplied and never would be), nor Enterprise namespaces (a mount in a namespace isn't addressed), unified CRL/OCSP or the batch certificate read. Who may request from a role is read from ACL policies only: who holds them (auth methods' roles, entities, groups), Sentinel RGP/EGP policies and control groups aren't read, and a policy's `allowed_parameters` / `denied_parameters` constraints aren't judged. Only the default issuer's AIA URLs are recorded (another issuer's own are not, and certificates it issued may name others). The CA is named after the default issuer's CN: rotating to an issuer with another CN names a new CA (the old one stays in the record).
- **Other CAs** aren't covered by this package: EJBCA is read by opsdir-adapter-ejbca, and Venafi / CyberArk Certificate Manager (a managed and discovered inventory, never proof a certificate wasn't issued) is follow-up work in milestone 6.2d's follow-ups.

## Tests

`tests/test_hashicorp_vault.py`: registration through the entry point, never rendering for an environment, resolving `vault://` references through the registry. `tests/test_vault_kubernetes.py`: External Secrets reading the `value` field under the mount, CSI reading the KV 2 data path. `tests/test_vault_inventory.py`: the KV inventory (complete, deleted and destroyed paths, a scheduled deletion, unlisted folders, missing metadata, refusals, prefixes, KV 1, reconciliation, the collector's walk and the store's address). `tests/test_vault_live.py` (marker `vault`, skipped without `tools/bin/vault`): a local dev server, a token with only the policy above runs the collector's own commands, the importer reads them, and the same token is refused the secret's data. `tests/test_vault_pki.py`: the PKI inventory (a mount read into its CA, endpoints with templated URLs filled or kept, roles as the CA's own templates with validity, usages, subject from the request and who may request from them, the broad client role judged by the core's template risk, revoked, superseded and present record certificates, no_store roles, unread certificates, a missing or refused listing, the CA named after the mount, AD CS template imports keeping the roles and a role gone leaving), the ACL policy reader (HCL, JSON, legacy values, priority matching, deny, templated segments, an unclosed block) and the collector (GETs only, the second round from the listings, trimmed answers, bearer tokens, a source without a mount, a Vault used only for secrets never read for PKI). `tests/test_vault_pki_live.py` (marker `vault`): a dev server's PKI mount (root CA, templated URLs, two roles, `default` granting one, three certificates, one revoked); a token with only the policy above runs the collector through the core's runner, the importer reads it (no private key in any file), the token is refused issuing; `scripts/export-vault-pki.sh` under that token writes an export the importer reads the same way, and a `no_store` role leaves the inventory incomplete. The Ansible lookups (KV 2 and KV 1, the store's endpoint) are tested in opsdir-adapter-ansible (`tests/test_ansible_inventory.py`).

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-hashicorp-vault/tests` (add `-m vault` for the live tests).

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `hashicorp-vault`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
