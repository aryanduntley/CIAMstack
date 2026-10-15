# opsdir-adapter-cyberark

opsdir adapter for CyberArk, a privileged access management (PAM) vault: cyberark:// secret references.

A secret-store adapter: owns the `cyberark://<app-id>/<safe>/<object>` reference scheme and resolves it at run time with the Credential Provider's command-line SDK (`clipasswordsdk GetPassword`), as the application `<app-id>` the vault authorizes. The password never reaches the database or a rendered file.

Configuration management (`opsdir-adapter-ansible`) reads `cyberark://` references at run time through the same `clipasswordsdk` command (`ansible.builtin.pipe`, which fails the play when the command exits non-zero). `community.general.cyberarkpassword` runs the same SDK without a shell, but it ignores the SDK's exit status and fails only when the SDK writes to stderr, and CyberArk's documentation doesn't say that every failure is written there; so a failed read could pass as a value. `cyberark.pas` has a Credential Provider module (a task, not a lookup) and `cyberark.conjur.conjur_variable` reads Conjur, not the Credential Provider.

Use it where an account is vaulted in PAM: as the binding's reference, or as another copy of a secret held elsewhere (`ciamCopyRef`), so a rotation report lists the vault too.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `cyberark`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
