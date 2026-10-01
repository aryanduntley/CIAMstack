# opsdir-adapter-hashicorp-vault

opsdir adapter for HashiCorp Vault: vault:// secret references.

A secret-store adapter: owns the `vault://` reference scheme and resolves it with the Vault CLI at run time. The secret value never reaches the database or a rendered file.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `hashicorp-vault`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
