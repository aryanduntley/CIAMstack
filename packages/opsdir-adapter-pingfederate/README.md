# opsdir-adapter-pingfederate

opsdir adapter for PingFederate: SP connections, OIDC clients and IdP connections as Admin API shaped JSON, and, on `opsdir-base-saml` and `opsdir-base-oidc`, the standard documents at PingFederate's endpoint paths.

Applies to environments with servers whose `ciamProductVersion` is PingFederate. Environment-neutral outputs:

- `pingfederate/sp-connections.json`, `oidc-clients.json`, `idp-connections.json`: the federation domain's integrations, standard values mapped to PingFederate's names (grant types, client authentication, bindings). An illustrative subset of the Admin API, not yet validated against a live `/pf-admin-api/v1`.
- `saml/sp/`, `saml/partner-idp/`: every SAML partner's metadata as recorded; `oidc/clients/`: every OIDC client's registration metadata.
- `saml/idp/<service>.xml`, `oidc/discovery/<service>.json`: the IdP metadata and OpenID provider metadata of the identity services its servers serve (`ciamTargetRole` `pf-engine` or `pf-admin`), with PingFederate's default endpoint paths (`/idp/SSO.saml2`, `/as/authorization.oauth2`, `/as/token.oauth2`, `/pf/JWKS`, ...).

## Reading PingFederate's configuration

```bash
curl -u administrator:… -H 'X-XSRF-Header: PingFederate' https://pf-admin:9999/pf-admin-api/v1/bulk/export > export/data.json
opsdir import --change CHG-… pingfederate export/        # --dry-run first to see what it would change
```

The importer `pingfederate/bulk` reads the Admin API bulk export (and this adapter's own rendered `pingfederate/*.json`, so a render reads back unchanged):

- **SP connections** become SAML service-provider integrations: entity ID, default ACS URL and binding, the claims of the attribute contract linked to the user-schema records they are fulfilled from, the certificates the connection uses (the key pair it signs with, the SP's own certificates).
- **IdP connections** become partner identity-provider integrations: entity ID, the JIT provisioning base DN, the partner's signing certificates.
- **OAuth clients** become OIDC client integrations: client ID, redirect URIs, grant types, PKCE, token endpoint authentication, restricted scopes. Where PingFederate's name stands for several standard ones (`SECRET`), the record's value is kept when it is one of them, else the standard default (`client_secret_basic`).
- **Key pairs** (`/keyPairs/signing`, `/keyPairs/sslServer`) and connection certificates become certificate facts, matched by fingerprint; facts the export doesn't give are kept.

Integrations are matched by entity ID or client ID, and keep everything the export doesn't hold (owners, criticality, populations, claim transforms, certificate links the record makes). A client or connection the record didn't have is added and named in the notices, so it gets an owner. Client secrets and data store passwords are never read. The LDAP data stores are checked against the record (the consumer PingFederate binds as; a directory reached by a server's hostname instead of a service name; connections without TLS). Adapters, access token managers, policies, JDBC data stores and where clients, grants and sessions are kept (`hivemodule.xml`: hold it with `opsdir capture`) are named, and read in a later version.

Defines the server roles `pf-engine` and `pf-admin`. Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingfederate`); nothing in the opsdir core changes. In this repository: `scripts/dev-install.sh`.
