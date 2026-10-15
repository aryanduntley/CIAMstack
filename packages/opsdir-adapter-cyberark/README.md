# opsdir-adapter-cyberark

opsdir adapter for CyberArk, a privileged access management (PAM) vault: `cyberark://` secret references. A secret-store adapter: it owns the `cyberark://<app-id>/<safe>/<object>` reference scheme and resolves it at run time with the Credential Provider's command-line SDK (`clipasswordsdk GetPassword`), as the application `<app-id>` the vault authorizes; and it inventories the safes' accounts (metadata only) so the record's references can be reconciled with what the vault holds. The password never reaches the database or a rendered file.

**Applies to** any environment whose bindings reference `cyberark://` secrets (kind `secret-store`). It renders nothing for an environment (`applies` is always false); its scheme resolves wherever a binding uses it, declared in a stack or not. Use it where an account is vaulted in PAM: as the binding's reference, or as another copy of a secret held elsewhere (`ciamCopyRef`), so the rotation report lists the vault among the copies to update.

**Depends on** `opsdir`. Resolving needs CyberArk's Credential Provider installed on the machine running `opsdir` (or the Ansible controller), with `clipasswordsdk` on the `PATH` and the application ID authorized for the safe in the vault.

## What it renders

Nothing. Configuration management (`opsdir-adapter-ansible`) reads `cyberark://` references at run time through the same `clipasswordsdk` command (`ansible.builtin.pipe`, which fails the play when the command exits non-zero): this adapter declares no `ansible_lookup`, so Ansible falls back to the scheme's resolver command. `community.general.cyberarkpassword` runs the same SDK without a shell, but it ignores the SDK's exit status and fails only when the SDK writes to stderr, and CyberArk's documentation doesn't say that every failure is written there; so a failed read could pass as a value. `cyberark.pas` has a Credential Provider module (a task, not a lookup) and `cyberark.conjur.conjur_variable` reads Conjur, not the Credential Provider.

It declares no Kubernetes secret delivery: a Kubernetes workload reading a `cyberark://` reference is named in `secrets-required.yaml` as a Secret the operator creates (opsdir-adapter-kubernetes).

## References it owns

| Scheme | Form | Resolved |
|---|---|---|
| `cyberark` | `cyberark://<app-id>/<safe>/<object>`: an account's password in a safe | at run time: `clipasswordsdk GetPassword -p AppDescs.AppID='<app-id>' -p Query='Safe=<safe>;Object=<object>' -o Password` |

No vocabulary, schema, secret patterns, required roles or planner checks of its own.

## Account inventory (importer `cyberark/accounts`, metadata only)

What the safes hold, read from the PVWA REST API's account listing into the record's secret-store inventory (`ou=cyberark,ou=secret-inventory`: one `ciamSecretInventory` per safe, a `ciamSecretObject` per account; the core `pki` domain's classes). The core reconciles every `cyberark://` reference (a secret reference's `ciamRefUri` and each `ciamCopyRef`, such as a PAM copy of a cloud secret) with it through this adapter's locator (`cyberark://<app-id>/<safe>/<object>` → safe, object): present, deleted, confirmed missing, listing incomplete, refused, or not inventoried; and the accounts nothing references. `opsdir plan` blocks on a reference confirmed missing in the target and gives the rest as actions (with rotation overdue against the credential's `ciamRotationDays`, a failed CPM rotation, and a binding saying `ciamAutoRotate: TRUE` for an account the CPM doesn't manage); `opsdir report secret-inventory` lists them all (opsdir/README.md, Secret-store inventories).

**Collect** (`opsdir collect --adapter cyberark/accounts --env CLOUD/ENV`) reads the environment's collection source for `cyberark/accounts` (`ciamCollectionSource`: `ciamSourceRef` the PVWA's base URL, `https://<pvwa>`, or a Privilege Cloud tenant's; `ciamCredentialRole` the role of the binding referencing the session token; `ciamCaRole` its trust anchor) with `ciamCredentialScheme`:

- `token` for a self-hosted PVWA (10.4 or later): the reference holds a session token from the PVWA's logon (`POST /PasswordVault/API/Auth/{CyberArk|LDAP|RADIUS}/Logon`), which opsdir sends as the whole `Authorization` header. opsdir never logs on itself (a logon is a POST; collection makes only GETs): the operator, or their pipeline, logs on and keeps the token where the reference points, for the session.
- `bearer` for Privilege Cloud: the reference holds an Identity OAuth access token (client credentials), sent as `Authorization: Bearer`.

The safes listed are those the record's `cyberark://` references name (in every environment), plus `--inventory-container` (comma-separated safe names): `GET /PasswordVault/API/Accounts?filter=safeName eq <safe>&limit=1000&offset=<n>`, page after page while the vault's `count` says more accounts remain, each saved as `accounts/<safe>/<offset>.json` with only the metadata the importer reads (account `id`, `safeName`, `name`, `platformId`, `createdTime`, `categoryModificationTime`, and `secretManagement`'s `automaticManagementEnabled`, `manualManagementReason`, `status`, `lastModifiedTime`, `lastReconciledTime`, `lastVerifiedTime`): a value-bearing field never leaves the collector.

**Least privilege**: the reader needs the Safe permission **List accounts** on each safe it inventories, and nothing else (not Retrieve accounts, not View Safe Members). The older `/WebServices/PIMServices.svc` API isn't used (it returns the first match only).

**Import** (`opsdir import --change CHG-… --at YYYYMMDDhhmmssZ cyberark/accounts DIR`, or what `opsdir collect` collected): `accounts/<safe>.json` (one answer) or `accounts/<safe>/<offset>.json` (its pages). A safe is complete when its pages hold as many distinct accounts as the `count` says; no count, fewer accounts or a page that isn't JSON make it incomplete, with why; the API's error answer (`ErrorCode`, `ErrorMessage`) makes it denied. Per account: `ciamLastRotated` only from `secretManagement.lastModifiedTime` when its `status` is Success (a CPM change that worked); `ciamRotationStatus` (success, failure, in-progress), `ciamRotationManaged` (automatic management), `ciamManualReason`, `ciamLastVerified` and `ciamStoreModified` (`categoryModificationTime`) kept apart. Times are read as epoch seconds or milliseconds, or ISO 8601, under both of the API's names (`lastModifiedTime` and `lastModifiedDateTime`). A field that could carry a value (`secret`, a password) is never read; one present is named in a notice.

## Known limits

- **Not run against a live vault**: the command follows CyberArk's Credential Provider documentation; the tests check the command line only.
- Only the Credential Provider's password (`-o Password`); other output properties, the Central Credential Provider (REST) and Conjur aren't read.
- **Account inventory not run against a live PVWA**: it follows CyberArk's REST API documentation, whose field names (`*Time` vs `*DateTime`) and time formats (numbers vs text) differ between versions, so both are read; check them on the deployed version. The vault's `MaxDisplayedRecords` can cap a listing without saying so: completeness is proven only up to the `count` the vault reports, so set it above the largest safe's account count. Paging is sequential, one request at a time (the API's rate limits aren't documented). The Privilege Cloud token URL isn't documented here: obtain the token as CyberArk Identity documents for the tenant. The vault doesn't say when an account was deleted: a deleted account is simply not listed (confirmed missing). Delinea Secret Server isn't covered.
- **Native Ansible lookup deferred**: `cyberark://` stays on the `clipasswordsdk` pipe until `community.general.cyberarkpassword` checks the SDK's exit status upstream, or CyberArk's documentation (Credential Provider guide) confirms that every GetPassword failure writes to stderr. Then this adapter declares the lookup (`lookup('community.general.cyberarkpassword', {'appid': .., 'query': 'Safe=..;Object=..', 'output': 'Password'})[0].password`, its options as one positional dict), with a guard failing on an empty value and `AIM_CLIPASSWORDSDK_CMD` (default `/opt/CARKaim/sdk/clipasswordsdk`) documented here.

## Tests

`tests/test_cyberark.py`: registration through the entry point, never rendering for an environment, resolving vaulted passwords through the registry (the command line). `tests/test_cyberark_inventory.py`: the account inventory (a complete safe, metadata only and value-bearing fields named, rotation only from a CPM success, short pages, no count, error and non-JSON answers, an undated import, reconciliation through the locator, the collector paging each safe with a session token and keeping only metadata, a password scheme refused). The pipe fallback is tested in opsdir-adapter-ansible (`tests/test_ansible_inventory.py`).

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-cyberark/tests`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `cyberark`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
