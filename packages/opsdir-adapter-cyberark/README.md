# opsdir-adapter-cyberark

opsdir adapter for CyberArk, a privileged access management (PAM) vault: `cyberark://` secret references. A secret-store adapter: it owns the `cyberark://<app-id>/<safe>/<object>` reference scheme and resolves it at run time with the Credential Provider's command-line SDK (`clipasswordsdk GetPassword`), as the application `<app-id>` the vault authorizes. The password never reaches the database or a rendered file.

**Applies to** any environment whose bindings reference `cyberark://` secrets (kind `secret-store`). It renders nothing for an environment (`applies` is always false); its scheme resolves wherever a binding uses it, declared in a stack or not. Use it where an account is vaulted in PAM: as the binding's reference, or as another copy of a secret held elsewhere (`ciamCopyRef`), so the rotation report lists the vault among the copies to update.

**Depends on** `opsdir`. Resolving needs CyberArk's Credential Provider installed on the machine running `opsdir` (or the Ansible controller), with `clipasswordsdk` on the `PATH` and the application ID authorized for the safe in the vault.

## What it renders

Nothing. Configuration management (`opsdir-adapter-ansible`) reads `cyberark://` references at run time through the same `clipasswordsdk` command (`ansible.builtin.pipe`, which fails the play when the command exits non-zero): this adapter declares no `ansible_lookup`, so Ansible falls back to the scheme's resolver command. `community.general.cyberarkpassword` runs the same SDK without a shell, but it ignores the SDK's exit status and fails only when the SDK writes to stderr, and CyberArk's documentation doesn't say that every failure is written there; so a failed read could pass as a value. `cyberark.pas` has a Credential Provider module (a task, not a lookup) and `cyberark.conjur.conjur_variable` reads Conjur, not the Credential Provider.

It declares no Kubernetes secret delivery: a Kubernetes workload reading a `cyberark://` reference is named in `secrets-required.yaml` as a Secret the operator creates (opsdir-adapter-kubernetes).

## References it owns

| Scheme | Form | Resolved |
|---|---|---|
| `cyberark` | `cyberark://<app-id>/<safe>/<object>`: an account's password in a safe | at run time: `clipasswordsdk GetPassword -p AppDescs.AppID='<app-id>' -p Query='Safe=<safe>;Object=<object>' -o Password` |

No vocabulary, schema, secret patterns, importers, required roles or planner checks.

## Known limits

- **Not run against a live vault**: the command follows CyberArk's Credential Provider documentation; the tests check the command line only.
- Only the Credential Provider's password (`-o Password`); other output properties, the Central Credential Provider (REST) and Conjur aren't read.
- **Native Ansible lookup deferred**: `cyberark://` stays on the `clipasswordsdk` pipe until `community.general.cyberarkpassword` checks the SDK's exit status upstream, or CyberArk's documentation (Credential Provider guide) confirms that every GetPassword failure writes to stderr. Then this adapter declares the lookup (`lookup('community.general.cyberarkpassword', {'appid': .., 'query': 'Safe=..;Object=..', 'output': 'Password'})[0].password`, its options as one positional dict), with a guard failing on an empty value and `AIM_CLIPASSWORDSDK_CMD` (default `/opt/CARKaim/sdk/clipasswordsdk`) documented here.

## Tests

`tests/test_cyberark.py`: registration through the entry point, never rendering for an environment, resolving vaulted passwords through the registry (the command line). The pipe fallback is tested in opsdir-adapter-ansible (`tests/test_ansible_inventory.py`).

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-cyberark/tests`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `cyberark`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
