# opsdir-adapter-pingfederate

opsdir adapter for PingFederate: SP connections, OIDC clients and IdP connections as Admin API shaped JSON, and, on `opsdir-base-saml` and `opsdir-base-oidc`, the standard documents at PingFederate's endpoint paths.

Applies to environments with servers whose `ciamProductVersion` is PingFederate (11 and 12). Environment-neutral outputs:

- `pingfederate/sp-connections.json`, `oidc-clients.json`, `idp-connections.json`: the federation domain's integrations, standard values mapped to PingFederate's names (grant types, client authentication, bindings). An illustrative subset of the Admin API, not yet validated against a live `/pf-admin-api/v1`.
- `saml/sp/`, `saml/partner-idp/`: every SAML partner's metadata as recorded; `oidc/clients/`: every OIDC client's registration metadata.
- `saml/idp/<service>.xml`, `oidc/discovery/<service>.json`: the IdP metadata and OpenID provider metadata of the identity services its servers serve (`ciamTargetRole` `pf-engine` or `pf-admin`), with PingFederate's default endpoint paths (`/idp/SSO.saml2`, `/as/authorization.oauth2`, `/as/token.oauth2`, `/pf/JWKS`, ...).

Per environment: `pingfederate/data-stores.json`, the data stores with that environment's hosts and secret references (below).

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

- **Data stores** (LDAP, JDBC, custom) become `pingfedDataStore` entries, below.

Integrations are matched by entity ID or client ID, data stores by id, and keep everything the export doesn't hold (owners, criticality, populations, claim transforms, certificate links the record makes, a data store's credential role). A client or connection the record didn't have is added and named in the notices, so it gets an owner. Client secrets and data store passwords are never read. Adapters, access token managers, policies and where clients, grants and sessions are kept (`hivemodule.xml`: hold it with `opsdir capture`) are named, and read in a later version (milestone 4.1).

## Data stores

Held under `ou=data-stores,ou=pingfederate` in this package's schema (OID arc `1.3.6.1.4.1.32473.3.4`, prefix `pingfed`), one `pingfedDataStore` per store, named by its id: its type (`pingfedStoreType`) and its settings as the Admin API writes them (`pingfedConfig`), less what differs per environment:

| What | On import | Rendered per environment (`pingfederate/data-stores.json`) |
|---|---|---|
| Hosts (an LDAP store's `hostnames`, a JDBC URL's host) | When every host is the same service name in the record (or a rendered `UNBOUND:<role>`), the store names that binding's role (`pingfedTargetRole`) and port (`pingfedPort`) and the hosts leave the settings (a JDBC URL keeps the rest: `jdbc:postgresql:///pf`). Otherwise they are kept as they are: a fixed host | The target role's service name and port, or `UNBOUND:<role>` where the environment binds none; fixed hosts as recorded |
| Credentials (`password`, and every encrypted value: `encryptedPassword`, a custom store's `encryptedValue`) | Withheld under their plain name (`/password`, `/configuration/fields/<n>/value`; `pingfedWithheld`): PingFederate encrypts them with the deployment's own master key, so they never carry over | `${secret:<ref>}` of the store's credential role (`pingfedCredentialRole`), `UNBOUND:<role>`, or `${withheld}` while no credential role is set |
| Bind account (an LDAP store's `userDN`) | Linked to the consumer record with that bind DN (`pingfedConsumer`) | Unchanged (part of the settings) |

The credential role is never guessed: an approved change sets it. The rendered file imports back unchanged. Notices name a store that binds as an account no consumer records, hosts that are a server's hostname (they change when servers are replaced or moved) or unknown to the record, a store with no single service name, an LDAP store without TLS (`useSsl` and `useStartTLS` off), and withheld credentials without a credential role.

**Planner check** (`check_data_stores`): a store with withheld credentials but no credential role, and a target or credential role the target environment doesn't bind, are blockers; a fixed host and an LDAP store without TLS are actions.

Defines the server roles `pf-engine` and `pf-admin`. Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingfederate`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
