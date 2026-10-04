# opsdir-adapter-pingfederate

opsdir adapter for PingFederate: SP connections, OIDC clients and IdP connections as Admin API shaped JSON, and, on `opsdir-base-saml` and `opsdir-base-oidc`, the standard documents at PingFederate's endpoint paths.

Applies to environments with servers whose `ciamProductVersion` is PingFederate (11 and 12). Environment-neutral outputs:

- `pingfederate/sp-connections.json`, `oidc-clients.json`, `idp-connections.json`: the federation domain's integrations, standard values mapped to PingFederate's names (grant types, client authentication, bindings). An illustrative subset of the Admin API, not yet validated against a live `/pf-admin-api/v1`.
- `saml/sp/`, `saml/partner-idp/`: every SAML partner's metadata as recorded; `oidc/clients/`: every OIDC client's registration metadata.
- `saml/idp/<service>.xml`, `oidc/discovery/<service>.json`: the IdP metadata and OpenID provider metadata of the identity services its servers serve (`ciamTargetRole` `pf-engine` or `pf-admin`), with PingFederate's default endpoint paths (`/idp/SSO.saml2`, `/as/authorization.oauth2`, `/as/token.oauth2`, `/pf/JWKS`, ...).

Per environment: `pingfederate/data-stores.json`, the data stores with that environment's hosts and secret references; the plugin instances (`password-credential-validators.json`, `idp-adapters.json`, `authentication-selectors.json`, `access-token-managers.json`, `notification-publishers.json`, `captcha-providers.json`); `cluster/discovery.xml`, the cluster's discovery; `other-resources.json`, the resources held as is (all below).

## Reading PingFederate's configuration

```bash
curl -u administrator:… -H 'X-XSRF-Header: PingFederate' https://pf-admin:9999/pf-admin-api/v1/bulk/export > export/data.json
opsdir import --change CHG-… pingfederate/bulk export/        # --dry-run first to see what it would change
```

The importer `pingfederate/bulk` reads the Admin API bulk export (and this adapter's own rendered `pingfederate/*.json`, so a render reads back unchanged):

- **SP connections** become SAML service-provider integrations: entity ID, default ACS URL and binding, the claims of the attribute contract linked to the user-schema records they are fulfilled from, the certificates the connection uses (the key pair it signs with, the SP's own certificates).
- **IdP connections** become partner identity-provider integrations: entity ID, the JIT provisioning base DN, the partner's signing certificates, and the id PingFederate knows the connection by (auxiliary class `pingfedConnection`, `pingfedConnectionId`). The integration keeps the name the record gives it; renders write the connection back under its PingFederate id.
- **OAuth clients** become OIDC client integrations: client ID, redirect URIs, grant types, PKCE, token endpoint authentication, restricted scopes. Where PingFederate's name stands for several standard ones (`SECRET`), the record's value is kept when it is one of them, else the standard default (`client_secret_basic`).
- **Key pairs** (`/keyPairs/signing`, `/keyPairs/sslServer`) and connection certificates become certificate facts, matched by fingerprint; facts the export doesn't give are kept. A key pair's certificate carries the id PingFederate knows the key pair by (auxiliary class `pingfedKeyPair`, `pingfedKeyPairId`): what token managers sign with.

- **Data stores** (LDAP, JDBC, custom) become `pingfedDataStore` entries, below.
- **Password credential validators, IdP adapters, authentication selectors, policy contracts, the default authentication policy and policy fragments** become entries too, below; so do **access token managers, OIDC policies and the authorization server's settings** (OAuth, below), and **notification publishers and CAPTCHA providers** (messaging, below).

Integrations are matched by entity ID or client ID, data stores by id, and keep everything the export doesn't hold (owners, criticality, populations, claim transforms, certificate links the record makes, a data store's credential role). A client or connection the record didn't have is added and named in the notices, so it gets an owner. Client secrets, data store passwords and plugin secrets are never read. Every other resource type of the export is held as is (below), so nothing the export holds is left out. Two importers, so name the one you mean: `pingfederate/bulk` (the bulk export) and `pingfederate/node-files` (the nodes' own files).

## Data stores

Held under `ou=data-stores,ou=pingfederate` in this package's schema (OID arc `1.3.6.1.4.1.32473.3.4`, prefix `pingfed`), one `pingfedDataStore` per store, named by its id: its type (`pingfedStoreType`) and its settings as the Admin API writes them (`pingfedConfig`), less what differs per environment:

| What | On import | Rendered per environment (`pingfederate/data-stores.json`) |
|---|---|---|
| Hosts (an LDAP store's `hostnames`, a JDBC URL's host) | When every host is the same service name in the record (or a rendered `UNBOUND:<role>`), the store names that binding's role (`pingfedTargetRole`) and port (`pingfedPort`) and the hosts leave the settings (a JDBC URL keeps the rest: `jdbc:postgresql:///pf`). Otherwise they are kept as they are: a fixed host | The target role's service name and port, or `UNBOUND:<role>` where the environment binds none; fixed hosts as recorded |
| Credentials (`password`, and every encrypted value: `encryptedPassword`, a custom store's `encryptedValue`) | Withheld under their plain name (`/password`, `/configuration/fields/<n>/value`; `pingfedWithheld`): PingFederate encrypts them with the deployment's own master key, so they never carry over | `${secret:<ref>}` of the store's credential role (`pingfedCredentialRole`), `UNBOUND:<role>`, or `${withheld}` while no credential role is set |
| Bind account (an LDAP store's `userDN`) | Linked to the consumer record with that bind DN (`pingfedConsumer`) | Unchanged (part of the settings) |

The credential role is never guessed: an approved change sets it. The rendered file imports back unchanged. Notices name a store that binds as an account no consumer records, hosts that are a server's hostname (they change when servers are replaced or moved) or unknown to the record, a store with no single service name, an LDAP store without TLS (`useSsl` and `useStartTLS` off), and withheld credentials without a credential role.

## Authentication: plugins and policies

| Admin API | Record (under `ou=pingfederate`) | Rendered |
|---|---|---|
| `/passwordCredentialValidators`, `/idp/adapters`, `/authenticationSelectors` | `pingfedPlugin` (cn: its id) under `ou=credential-validators`, `ou=idp-adapters`, `ou=authentication-selectors`: `pingfedPluginKind`, `pingfedPluginType` (its `pluginDescriptorRef`), `pingfedParent` (its `parentRef`), `pingfedUses` (the objects its settings fields name), settings | Per environment: `pingfederate/password-credential-validators.json`, `idp-adapters.json`, `authentication-selectors.json` |
| `/authenticationPolicyContracts` | `pingfedPolicyContract` (cn: its id) under `ou=policy-contracts` | `authentication-policy-contracts.json` (environment-neutral) |
| `/authenticationPolicies/default` | `pingfedAuthPolicySet` `cn=default,ou=authentication-policies` (its own settings), one `pingfedAuthPolicy` per tree below it (cn: the tree's name; `pingfedPosition`, `pingfedEnabled`, `pingfedPolicyTree`, `pingfedUses`) | `authentication-policies.json` (environment-neutral) |
| `/authenticationPolicies/fragments` | `pingfedAuthPolicy` (cn: its id) under `ou=policy-fragments` | `authentication-policy-fragments.json` (environment-neutral) |

- **References.** Objects keep the ids PingFederate names others by, and the record links them by DN (`pingfedUses`): a validator's data store (`LDAP Datastore`, `JDBC Datastore`), an HTML form adapter's validators (`Password Credential Validator Instance`), a composite adapter's adapters (`Adapter Instance`), and what a policy tree or fragment runs (IdP adapters, IdP connections, selectors, policy contracts, fragments). The field names are data (`plugins.REF_FIELDS`); a custom plugin's fields are added there. A reference neither the export nor the record has is named on import.
- **IdP connections in policies.** A tree step that authenticates through an IdP connection links to the partner integration carrying that connection's `pingfedConnectionId`: the PingFederate id, not the integration's name in the record, is the durable link, so renaming the integration doesn't break it. Exactly one integration may carry an id: one that two integrations claim resolves to neither and is named, on import and by the planner.
- **Secrets.** Every encrypted value (`encryptedValue`, `encryptedPassword`, …) and every settings field whose name says it holds a secret (`Secret Key`, `Client Secret`, `Password`) is withheld; each environment renders the reference of the instance's credential role (`pingfedCredentialRole`), `UNBOUND:<role>`, or `${withheld}` while none is set. All of an instance's secrets take that one role's reference.
- **The default policy is imported as one:** a tree the export no longer has is removed. Trees whose names can't name an entry, or that repeat another tree's name, are named and not imported.

## OAuth: token managers, OIDC policies, scopes

| Admin API | Record (under `ou=pingfederate`) | Rendered |
|---|---|---|
| `/oauth/accessTokenManagers` | `pingfedPlugin` kind `access-token-manager` under `ou=access-token-managers`, linked (`pingfedUses`) to the certificates of the key pairs a JWT manager signs with (its `Certificates` table) | Per environment: `pingfederate/access-token-managers.json` (symmetric keys and other secrets from its credential role) |
| `/oauth/openIdConnect/policies` | `pingfedOidcPolicy` (cn: its id) under `ou=oidc-policies`, linked to its token manager | `oidc-policies.json` (environment-neutral) |
| `/oauth/authServerSettings` | `pingfedSettings` `cn=oauth-auth-server,ou=settings`: the settings, with every scope it defines (common and exclusive) in `pingfedScope` | `auth-server-settings.json` (environment-neutral) |
| An OAuth client's `defaultAccessTokenManagerRef`, `oidcPolicy.policyGroup` | Its integration gains auxiliary class `pingfedClient`, linked (`pingfedUses`) to the token manager and OIDC policy | Written back into `oidc-clients.json` |

A key pair, like an IdP connection, is found by the id its certificate carries (`pingfedKeyPairId`); exactly one certificate may carry it. Not yet held: token manager attribute mappings (`/oauth/accessTokenMappings`), token exchange, an OAuth client's own token lifetimes and other settings beyond the standard registration.

## Messaging: notification publishers and CAPTCHA providers

Notification publishers (`/notificationPublishers`) and CAPTCHA providers (`/captchaProviders`) are plugin instances like the others (`pingfedPlugin` under `ou=notification-publishers` and `ou=captcha-providers`): their settings as the Admin API writes them, secrets withheld (the SMTP password, the CAPTCHA secret key), the credential role that holds them (`pingfedCredentialRole`), rendered back per environment. What they say about services outside the platform also becomes the core `messaging` domain's view of them, which the planner checks:

| From | Recorded |
|---|---|
| an SMTP notification publisher's Email Server and SMTP Port | an external service of kind `smtp-relay` (`ciamEndpointHost`, `ciamPort`), found by its host, reached from `pf-engine`, using the publisher's credential role (`ciamUsesRole`) |
| its From Address | a mail sender (`ciamSenderAddress`, `ciamSenderDomain`), found by its address, sent by that relay (`ciamSentBy`) |
| a CAPTCHA provider | an external service of kind `captcha` named `captcha-<id>`, its vendor from the plugin type (Google reCAPTCHA, hCaptcha, Cloudflare Turnstile), using the provider's credential role |

Their secrets never reach these entries. What the record adds (the domains a CAPTCHA allows, owners, a sender's sending role and bounce handling) is kept on import.

## Nodes and cluster discovery

```bash
opsdir import --change CHG-… pingfederate/node-files nodes/     # nodes/<hostname>/bin/run.properties, ...
```

One folder per node, named by the server's hostname (or its record name), holding what the node has under its install root:

| File | Recorded |
|---|---|
| `bin/run.properties` | On the server, auxiliary class `pingfedNode`: `pingfedOperationalMode` (`CLUSTERED_CONSOLE`, `CLUSTERED_ENGINE`, `STANDALONE`), `pingfedNodeTags`, `pingfedListener` (`runtime=9031`, `admin=9999`, `cluster=7600`, ...), every other setting in `pingfedConfig` (`pf.cluster.auth.pwd` and other secrets withheld, from the node's credential role) |
| `bin/jgroups.properties` (`server/default/conf/tcp.xml`) | The JGroups discovery protocol the node uses (`pingfedDiscovery`): `pf.cluster.discovery.protocol` in `jgroups.properties` (PingFederate 11.0 and later; `tcp.xml` holds `${DISCOVERY_TAG}`), else the protocol element of an upgraded install's `tcp.xml`; checked against the environment's discovery binding |
| `server/default/conf/META-INF/hivemodule.xml` | `pingfedSettings` `cn=storage,ou=settings`: which kind of store (JDBC, LDAP, XML file, ...) backs OAuth clients, persistent grants and sessions (`ClientManager`, `AccessGrantManager`, `SessionStorageManager`; verify against the target version) |

**Discovery is a binding, its protocol a choice.** How the nodes find each other differs per environment, the classic miss when moving. The environment binds role `pf-cluster-discovery`, and the protocol is data, chosen per environment: a `pingfedClusterDiscovery` binding states `pingfedDiscoveryProtocol`, with what that protocol needs (`ciamStorageRef` `s3://bucket` for `NATIVE_S3_PING`, `ciamFqdn` for `DNS_PING`, nothing for `TCPPING`). A binding that states none implies one from what it names: an `s3://` reference is `NATIVE_S3_PING` (a core `ciamObjectStore` binding, the bucket alone, works too), a DNS name `DNS_PING`. `pingfederate/cluster/jgroups.properties` renders the discovery lines of each node's `bin/jgroups.properties`: `pf.cluster.discovery.protocol` and its `pf.cluster.<PROTOCOL>.*` parameters (`NATIVE_S3_PING`: the cloud's region and the bucket; `DNS_PING`: `dns_query`; `TCPPING`: `initial_hosts` listing the environment's clustered nodes as `hostname[cluster port]`, so the list follows the record when servers are replaced or moved).

The protocols are a table in `discovery.py` (`PROTOCOLS`), one row each; a new protocol is a new row, and the values `pingfedDiscoveryProtocol` accepts (its vocabulary) are the rendered rows: `TCPPING`, `NATIVE_S3_PING`, `DNS_PING`. `AWS_PING` and `SWIFT_PING` are documented by Ping but not rendered yet. `AZURE_PING` (a community JGroups extension, `jgroups-azure`), `S3_PING` (deprecated), `KUBE_PING`, `JDBC_PING` and `FILE_PING` are not in PingFederate's documentation (clustering guide, 12.3 and 13.0): a node using one is named on import, and a target binding that implies one (an `azblob://` container) renders an `UNSUPPORTED` comment instead of lines and is a planner blocker. On Azure, choose `DNS_PING` (AKS) or `TCPPING` (VMs).

Import notices name a node whose protocol differs from its environment's binding, a protocol PingFederate doesn't support, and discovery the environment doesn't bind. **Planner check** (`check_cluster`): a cluster with no discovery recorded, and a target binding whose protocol isn't rendered or lacks what it needs, are blockers; a different protocol in the target is an action (every node's `jgroups.properties` changes); withheld node secrets need a credential role. `run.properties` itself is a config file to hold with `opsdir capture` (its values linked to bindings); the node facts are what the planner and the ports matrix read.

## Resources held as is

Every resource type of the bulk export not modeled above (`/serverSettings`, `/oauth/accessTokenMappings`, token processors and generators, local identity profiles, administrative accounts, ...) is kept item by item: `pingfedResource` (cn: the item's id; `settings` for a resource that is one object; `item-<n>` otherwise) under `ou=<type, '/' as '.'>,ou=resources,ou=pingfederate`, with `pingfedResourceType`, its settings (secrets withheld) and a credential role. A type is imported as one group: items the export no longer has are removed. Each environment renders them as `pingfederate/other-resources.json`, in the bulk export's shape, which imports back through `pingfederate/bulk` unchanged. Notice: `held as is (not modeled): <type> (<items>)`.

**Planner check** (`check_data_stores`): a store with withheld credentials but no credential role, and a target or credential role the target environment doesn't bind, are blockers; a fixed host and an LDAP store without TLS are actions. **`check_references`:** a plugin instance, policy tree, fragment or OIDC policy that names an object the record doesn't have (an IdP connection or key pair no entry, or more than one, carries the id of) (PingFederate refuses such a configuration), and a plugin instance or held resource with withheld secrets but no credential role or one the target doesn't bind, are blockers. **`check_cluster`:** clustered nodes whose discovery nobody recorded, and a target discovery binding that is neither storage nor a service name, are blockers (a source binding the target lacks is the core's binding check); a different kind of discovery in the target (S3 to a blob container) is an action; a node's withheld secrets need a credential role the target binds.

Defines the server roles `pf-engine` and `pf-admin`. Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingfederate`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
