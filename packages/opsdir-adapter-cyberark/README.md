# opsdir-adapter-cyberark

opsdir adapter for CyberArk, a privileged access management (PAM) vault: cyberark:// secret references.

A secret-store adapter: owns the `cyberark://<app-id>/<safe>/<object>` reference scheme and resolves it at run time with the Credential Provider's command-line SDK (`clipasswordsdk GetPassword`), as the application `<app-id>` the vault authorizes. The password never reaches the database or a rendered file.

Use it where an account is vaulted in PAM: as the binding's reference, or as another copy of a secret held elsewhere (`ciamCopyRef`), so a rotation report lists the vault too.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `cyberark`); nothing in the opsdir core changes. In this repository: `scripts/dev-install.sh`.
