# opsdir-adapter-pingfederate

opsdir adapter for PingFederate: SP connections, OIDC clients and IdP connections from the federation domain.

Applies to environments with federation servers whose `ciamProductVersion` is PingFederate. Renders the federation domain as environment-neutral, Admin API-shaped JSON: SP connections, OIDC clients, IdP connections.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingfederate`); nothing in the opsdir core changes. In this repository: `scripts/dev-install.sh`.
