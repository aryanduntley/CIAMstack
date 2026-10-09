# opsdir-adapter-pingfederate

opsdir adapter for PingFederate: PingFederate's configuration for each environment as validated Admin API requests, and, on `opsdir-base-saml` and `opsdir-base-oidc`, the standard documents at PingFederate's endpoint paths.

Applies to environments with servers whose `ciamProductVersion` is PingFederate (11 to 13; the Admin API specs vendored cover 12.1 to 13.1).

**Per environment: `pingfederate/admin-api/requests.json`** (`opsdir_adapter_pingfederate.admin_api`). Every object the record holds for PingFederate as one Admin API request, in the order PingFederate needs them (an object before those that name it): data stores; plugin instances (password credential validators, notification publishers, CAPTCHA providers, IdP adapters, authentication selectors, access token managers; a parent instance before those inheriting from it); policy contracts, fragments and the default authentication policy; OIDC policies and the authorization server's settings; the OAuth clients, SP connections and IdP connections of the integrations PingFederate serves; the resources held as is, last.

```json
{"pingFederate": "PingFederate 12.1.4", "adminApi": "12.1.0.4", "problems": [],
 "requests": [{"method": "PUT", "path": "/dataStores/user-directory", "createWith": "POST /dataStores", "body": {...}},
              {"method": "PUT", "path": "/oauth/authServerSettings", "body": {...}}, ...]}
```

- **Key pairs** come first: each key pair the record holds (a certificate carrying PingFederate's id for it, `pingfedKeyPairId`) is imported from where the environment keeps its key material, `POST /keyPairs/signing/import` (or `/keyPairs/sslServer/import` for a `tls-server` certificate) with `fileData` and `password` as secret references. The certificate's key role (`ciamKeyRole`) names the credential that is its key (PKI domain: `ciamMaterialFormat` `pkcs12` or `pem`, and `ciamPasswordRole`, the role of the secret holding the password that protects the file); the environment binds both roles. A key pair is imported once: PingFederate refuses an id it already has, which stays as it is. Named in `problems`, never guessed: a key pair with no key role or no credential for it (not imported), PKCS#12 material with no password role (its password `${withheld}`); PEM with none is taken as an unencrypted key. In Terraform: `pingfederate_keypairs_signing_key` / `pingfederate_keypairs_ssl_server_key` with `file_data` and `password` as sensitive variables.
- **Applying them** is the operator's pipeline's job (opsdir never writes to PingFederate): an object is a PUT to `<collection>/<id>`, and where it doesn't exist yet (the PUT answers 404) the `createWith` POST creates it; a settings object is a PUT. Apply them in order.
- **Checked** against the Admin API spec of the version the environment's PingFederate servers run (below); what the spec refuses is listed in `problems`, with the request and the JSON path. A version with no vendored spec is rendered unchecked and says so; servers on several versions are named.
- **Secrets are never values**: `${secret:<reference>}` (the reference the object's credential role, `pingfedCredentialRole`, binds in this environment), `UNBOUND:<role>`, or `${withheld}` while no credential role is set (the planner blocks on both). The pipeline puts the value in at apply time.
- **Integrations** (SP connections, IdP connections, OAuth clients) are rendered from the settings PingFederate holds for them (auxiliary class `pingfedHeldSettings`, read at import, secrets withheld), with every path the record's standard facts own replaced from the record: an SP connection's entity ID, default assertion consumer URL and binding, and its claims (the attribute contract's extended attributes and their fulfillment: a claim removed from the record is gone from every mapping; one the record can't hold, fulfilled from a value no user-schema record names, is kept as PingFederate has it); an OAuth client's client ID, redirect URIs, grant types (PingFederate's `EXTENSION`, which stands for two standard grants, kept as it is), PKCE, authentication type, scope restriction, token manager and OIDC policy; an IdP connection's id, entity ID and JIT base DN. An integration the record made itself holds nothing: it gets the record's facts and only harmless defaults (an assertion lifetime of 5 minutes either side); what the spec still requires (an IdP connection's identity mapping and JIT repository) is listed in `problems`, never invented.

**Per environment: `pingfederate/terraform/`** (`opsdir_adapter_pingfederate.terraform_target`). The same configuration as Terraform for Ping's provider (`pingidentity/pingfederate`), derived from the same requests, so both say the same thing:

- `versions.tf`: the provider pinned to the release that supports the environment's PingFederate version (the provider's own documentation: 1.10.0 for 12.2 to 13.1, 1.8.1 for 11.3 to 12.1; an older version gets no Terraform, only a comment) and its `product_version`. The admin credentials are the provider's environment variables (`PINGFEDERATE_PROVIDER_USERNAME`, `PINGFEDERATE_PROVIDER_PASSWORD`, or OAuth client credentials), never in the files.
- `variables.tf`: `pingfederate_https_host` (its default the admin endpoint of the environment's `pingfederate/bulk` collection source, when it declares one) and one sensitive variable per secret, named by its role and described by the reference the environment binds; the pipeline supplies the value at apply time. The provider has no write-only arguments: sensitive values end in the state, so keep the state encrypted.
- `main.tf`: one resource per request, converted against the provider's own schema of that release (vendored, trimmed: `specs/terraform-provider-<release>.json`, from Ping's provider under the Apache License 2.0; regenerate with `scripts/vendor-provider-schemas.py`): arguments in snake_case, the object's id in the resource's id argument (`data_store_id`, `connection_id`, ...), a discriminated object as the provider's variant (a data store of type LDAP as `ldap_data_store`, a policy action as `authn_source_policy_action`), a plugin field holding a secret among `sensitive_fields`, map keys (claim names) as they are, PingFederate's read-only `lastModified` left out. What the provider doesn't take is named in a comment on its resource; a resource type the provider has no resource for is named at the top, left to the admin-api requests. Each group of resources depends on the group before it (`depends_on`), the Admin API's order.

The renders are checked by Terraform itself: `opsdir/scripts/validate-terraform.sh` runs `fmt -check` and `validate` offline (the providers cached under `tools/`), on the showcase's renders in the tests. **Adopting an existing PingFederate** (`--target pingfederate=terraform,terraform-imports`; only when asked, since an import fails where the object doesn't exist): `pingfederate/terraform/imports.tf` holds an `import` block per resource, its id the provider's import id (the object's id; any placeholder for a settings object, as the provider documents), so the first `terraform plan` adopts what PingFederate already holds instead of creating it. The provider can't import key pairs: their resources are created only while `pingfederate_create_key_pairs` is true (the default, for a fresh PingFederate); set it to false where PingFederate already holds them, as `imports.tf` says.

Per environment also `pingfederate/cluster/jgroups.properties`, the cluster's discovery (below). Environment-neutral outputs:

- `saml/sp/`, `saml/partner-idp/`: every SAML partner's metadata as recorded; `oidc/clients/`: every OIDC client's registration metadata.
- `saml/idp/<service>.xml`, `oidc/discovery/<service>.json`: the IdP metadata and OpenID provider metadata of the identity services its servers serve (`ciamTargetRole` `pf-engine` or `pf-admin`), with PingFederate's default endpoint paths (`/idp/SSO.saml2`, `/as/authorization.oauth2`, `/as/token.oauth2`, `/pf/JWKS`, ...).

## Admin API specs (validation offline)

The Admin API spec of each supported PingFederate version (12.1, 12.2, 12.3, 13.0, 13.1) is vendored as package data
(`src/opsdir_adapter_pingfederate/specs/`): Ping's own OpenAPI documents from `pingfederate-go-client` (Apache License
2.0, `specs/NOTICE.md`), trimmed to each POST and PUT request's body schema and the schemas' validation keywords.
`opsdir_adapter_pingfederate.admin_api_spec` validates a payload against its request's schema without a PingFederate
(`$ref`/`allOf` merged, unions by discriminator or subtype, required, unknown properties refused, types, enums,
patterns, lengths, unique items; formats aren't checked) and picks the spec of an environment's version (`PingFederate
12.1.4` -> 12.1; a version with no vendored spec gets none). Regenerate from a local clone with
`scripts/vendor-admin-api-specs.py` (its docstring has the clone command); add a version by adding its tag to `TAGS`.

## Reading PingFederate's configuration

```bash
curl -u administrator:… -H 'X-XSRF-Header: PingFederate' https://pf-admin:9999/pf-admin-api/v1/bulk/export > export/data.json
opsdir import --change CHG-… pingfederate/bulk export/        # --dry-run first to see what it would change
```

The importer `pingfederate/bulk` reads the Admin API bulk export (and this adapter's own rendered `pingfederate/admin-api/requests.json`, each request's body an item of its resource type, so a render reads back unchanged). An SP connection, IdP connection or OAuth client also keeps its own settings as the Admin API writes them (`pingfedHeldSettings`: `pingfedConfig`, secrets withheld as `pingfedWithheld`, `pingfedCredentialRole`), what renders put the record's facts back into:

- **SP connections** become SAML service-provider integrations: entity ID, default ACS URL and binding, the claims of the attribute contract linked to the user-schema records they are fulfilled from, the certificates the connection uses (the key pair it signs with, the SP's own certificates).
- **IdP connections** become partner identity-provider integrations: entity ID, the JIT provisioning base DN, the partner's signing certificates, and the id PingFederate knows the connection by (auxiliary class `pingfedConnection`, `pingfedConnectionId`). The integration keeps the name the record gives it; renders write the connection back under its PingFederate id.
- **OAuth clients** become OIDC client integrations: client ID, redirect URIs, grant types, PKCE, token endpoint authentication, restricted scopes. Where PingFederate's name stands for several standard ones (`SECRET`), the record's value is kept when it is one of them, else the standard default (`client_secret_basic`).
- **Key pairs** (`/keyPairs/signing`, `/keyPairs/sslServer`) and connection certificates become certificate facts, matched by fingerprint; facts the export doesn't give are kept. A key pair's certificate carries the id PingFederate knows the key pair by (auxiliary class `pingfedKeyPair`, `pingfedKeyPairId`): what token managers sign with.

- **Data stores** (LDAP, JDBC, custom) become `pingfedDataStore` entries, below.
- **Password credential validators, IdP adapters, authentication selectors, policy contracts, the default authentication policy and policy fragments** become entries too, below; so do **access token managers, OIDC policies and the authorization server's settings** (OAuth, below), and **notification publishers and CAPTCHA providers** (messaging, below).

Integrations are matched by entity ID or client ID, data stores by id, and keep everything the export doesn't hold (owners, criticality, populations, claim transforms, certificate links the record makes, a data store's credential role). A client or connection the record didn't have is added and named in the notices, so it gets an owner. Client secrets, data store passwords and plugin secrets are never read. Every other resource type of the export is held as is (below), so nothing the export holds is left out. Two importers, so name the one you mean: `pingfederate/bulk` (the bulk export) and `pingfederate/node-files` (the nodes' own files).

## Collecting from PingFederate (`opsdir collect`)

`opsdir collect --env CLOUD/ENV --adapter pingfederate` reads the bulk export from the admin node, read-only, and
imports it like a saved `/bulk/export` (`opsdir_adapter_pingfederate.collect`). The environment declares where:

```ldif
dn: cn=pf-admin,ou=bindings,env=prod,cloud=source,ou=environments,dc=ciam-ops
objectClass: ciamCollectionSource
ciamBindingRole: collect-pf-admin
ciamImporter: pingfederate/bulk
ciamSourceRef: https://pf-admin.example.test:9999
ciamCredentialRole: pf-admin-reader        # a binding whose ciamRefUri references the password (vault://, aws-sm://, ...)
ciamLoginName: opsdir-reader
ciamCaRole: pf-admin-ca                    # a binding whose ciamRefUri references the admin port's CA certificate (PEM)
```

opsdir resolves the password and the CA certificate when collecting (held in memory, never stored) and sends `GET
/pf-admin-api/v1/bulk/export` with `X-XSRF-Header: PingFederate` and HTTP Basic credentials. Without a bound credential
or trust anchor it says which role is missing and reads nothing. Least privilege: a native admin account with the
lowest administrative role PingFederate accepts for `/bulk/export` (Ping's role table gives Auditor view-only access
yet lists the four roles for `/bulk`: confirm against your version before relying on Auditor).

## Egress through an explicit proxy

When an environment's egress passes a proxy clients must be told about (a `ciamProxy` with `ciamProxyAddress` that isn't a firewall), PingFederate needs it on every node: `bin/run.properties` keys `http.proxyHost`, `http.proxyPort`, `https.proxyHost`, `https.proxyPort` (the AWS SDK plugins, such as the SNS notification publisher, read only the `http.*` ones) and `http.nonProxyHosts` (pipe-separated: the host, the private ranges as `10.20.*`, private DNS zones as `*.zone`, the service names). Certificate revocation checking (CRL, OCSP) has its own proxy setting (Security > Certificate Revocation Checking, `/certificates/revocation/settings`), set once on the admin node. The planner compares the keys with each node's captured `run.properties` (missing or other values are actions with a fix, `opsdir fix`, that adds them to the captured file linked to the proxy's derived values, `<proxy role>#proxy:host` and so on, so every environment's file names its own proxy and an environment without one renders them empty) and names the revocation setting, which the record can't confirm.

## Data stores

Held under `ou=data-stores,ou=pingfederate` in this package's schema (OID arc `1.3.6.1.4.1.32473.3.4`, prefix `pingfed`), one `pingfedDataStore` per store, named by its id: its type (`pingfedStoreType`) and its settings as the Admin API writes them (`pingfedConfig`), less what differs per environment:

| What | On import | Rendered per environment (a `/dataStores` request) |
|---|---|---|
| Hosts (an LDAP store's `hostnames`, a JDBC URL's hosts) | When every host is the same role in the record (a service name, an external system's `ciamExternalHost`, or a rendered `UNBOUND:<role>`), the store names that role (`pingfedTargetRole`) and the hosts' common port (`pingfedPort`), and the hosts leave the settings (a JDBC URL keeps the rest: `jdbc:postgresql:///pf`). Otherwise they are kept as they are: fixed hosts | The target role's host and port, or `UNBOUND:<role>` where the environment binds none. One host is the default; an environment that binds the role several times (an external system's hosts, ordered by `ciamHostOrder`) renders every one, in that order, each with the store's port or, when the hosts don't share one, its own `ciamPort`. Fixed hosts as recorded |
| Credentials (`password`, and every encrypted value: `encryptedPassword`, a custom store's `encryptedValue`) | Withheld under their plain name (`/password`, `/configuration/fields/<n>/value`; `pingfedWithheld`): PingFederate encrypts them with the deployment's own master key, so they never carry over | `${secret:<ref>}` of the store's credential role (`pingfedCredentialRole`), `UNBOUND:<role>`, or `${withheld}` while no credential role is set |
| Bind account (an LDAP store's `userDN`) | Linked to the consumer record with that bind DN (`pingfedConsumer`) | Unchanged (part of the settings) |

The credential role is never guessed: an approved change sets it. The rendered request imports back unchanged. Notices name a store that binds as an account no consumer records, hosts that are a server's hostname (they change when servers are replaced or moved) or unknown to the record, a store with no single service name, an LDAP store without TLS (`useSsl` and `useStartTLS` off), and withheld credentials without a credential role.

## Authentication: plugins and policies

| Admin API | Record (under `ou=pingfederate`) | Rendered |
|---|---|---|
| `/passwordCredentialValidators`, `/idp/adapters`, `/authenticationSelectors` | `pingfedPlugin` (cn: its id) under `ou=credential-validators`, `ou=idp-adapters`, `ou=authentication-selectors`: `pingfedPluginKind`, `pingfedPluginType` (its `pluginDescriptorRef`), `pingfedParent` (its `parentRef`), `pingfedUses` (the objects its settings fields name), settings | Per environment: their requests |
| `/authenticationPolicyContracts` | `pingfedPolicyContract` (cn: its id) under `ou=policy-contracts` | Per environment: their requests (the same in every one) |
| `/authenticationPolicies/default` | `pingfedAuthPolicySet` `cn=default,ou=authentication-policies` (its own settings), one `pingfedAuthPolicy` per tree below it (cn: the tree's name; `pingfedPosition`, `pingfedEnabled`, `pingfedPolicyTree`, `pingfedUses`) | Per environment: `PUT /authenticationPolicies/default` |
| `/authenticationPolicies/fragments` | `pingfedAuthPolicy` (cn: its id) under `ou=policy-fragments` | Per environment: their requests |

- **References.** Objects keep the ids PingFederate names others by, and the record links them by DN (`pingfedUses`): a validator's data store (`LDAP Datastore`, `JDBC Datastore`), an HTML form adapter's validators (`Password Credential Validator Instance`), a composite adapter's adapters (`Adapter Instance`), and what a policy tree or fragment runs (IdP adapters, IdP connections, selectors, policy contracts, fragments). The field names are data (`plugins.REF_FIELDS`); a custom plugin's fields are added there. A reference neither the export nor the record has is named on import.
- **IdP connections in policies.** A tree step that authenticates through an IdP connection links to the partner integration carrying that connection's `pingfedConnectionId`: the PingFederate id, not the integration's name in the record, is the durable link, so renaming the integration doesn't break it. Exactly one integration may carry an id: one that two integrations claim resolves to neither and is named, on import and by the planner.
- **Secrets.** Every encrypted value (`encryptedValue`, `encryptedPassword`, …) and every settings field whose name says it holds a secret (`Secret Key`, `Client Secret`, `Password`) is withheld; each environment renders the reference of the instance's credential role (`pingfedCredentialRole`), `UNBOUND:<role>`, or `${withheld}` while none is set. All of an instance's secrets take that one role's reference.
- **The default policy is imported as one:** a tree the export no longer has is removed. Trees whose names can't name an entry, or that repeat another tree's name, are named and not imported.

## OAuth: token managers, OIDC policies, scopes

| Admin API | Record (under `ou=pingfederate`) | Rendered |
|---|---|---|
| `/oauth/accessTokenManagers` | `pingfedPlugin` kind `access-token-manager` under `ou=access-token-managers`, linked (`pingfedUses`) to the certificates of the key pairs a JWT manager signs with (its `Certificates` table) | Per environment: their requests (symmetric keys and other secrets from its credential role) |
| `/oauth/openIdConnect/policies` | `pingfedOidcPolicy` (cn: its id) under `ou=oidc-policies`, linked to its token manager | Per environment: their requests |
| `/oauth/authServerSettings` | `pingfedSettings` `cn=oauth-auth-server,ou=settings`: the settings, with every scope it defines (common and exclusive) in `pingfedScope` | Per environment: `PUT /oauth/authServerSettings` (secrets from its credential role) |
| An OAuth client's `defaultAccessTokenManagerRef`, `oidcPolicy.policyGroup` | Its integration gains auxiliary class `pingfedClient`, linked (`pingfedUses`) to the token manager and OIDC policy | Written back into the client's request |

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

The protocols are a table in `discovery.py` (`PROTOCOLS`), one row each; a new protocol is a new row, and the values `pingfedDiscoveryProtocol` accepts (its vocabulary) are the rendered rows: `TCPPING`, `NATIVE_S3_PING`, `DNS_PING`. `AWS_PING` and `SWIFT_PING` are documented by Ping but not rendered yet. `AZURE_PING` (a community JGroups extension, `jgroups-azure`), `S3_PING` (deprecated), `KUBE_PING`, `JDBC_PING` and `FILE_PING` are not in PingFederate's documentation (clustering guide, 12.3 and 13.0): a node using one is named on import, and a target binding that implies one (an `azblob://` container) renders an `UNSUPPORTED` comment instead of lines and is a planner blocker. On Azure, choose `DNS_PING` (AKS) or `TCPPING` (VMs). With PingFederate on Kubernetes through the ping-devops chart, the DNS name is the chart's cluster service; opsdir-adapter-ping-devops's planner check names it and offers the binding (`discovery_records` writes it with the name given).

Import notices name a node whose protocol differs from its environment's binding, a protocol PingFederate doesn't support, and discovery the environment doesn't bind. **Planner check** (`check_cluster`): a cluster with no discovery recorded, and a target binding whose protocol isn't rendered or lacks what it needs, are blockers; a different protocol in the target is an action (every node's `jgroups.properties` changes); withheld node secrets need a credential role. Each discovery blocker offers a fix (`opsdir fix`, key `discovery:<environment>`) that binds the role: one option per rendered protocol. For a source whose nodes all run one rendered protocol, the fix offers just that protocol. The fix takes the bucket (`ciamStorageRef`, `s3://…`) or the DNS name (`ciamFqdn`) as an input; the operator gives it, and it is never guessed. A binding of another class is replaced by a `pingfedClusterDiscovery` binding of the same name, and a value the new protocol doesn't use is dropped. A target that lacks a role the source binds gets the core's templated binding fix (`binding:pf-cluster-discovery`). `run.properties` itself is a config file to hold with `opsdir capture` (its values linked to bindings); the node facts are what the planner and the ports matrix read.

## Resources held as is

Every resource type of the bulk export not modeled above (`/serverSettings`, `/oauth/accessTokenMappings`, token processors and generators, local identity profiles, administrative accounts, ...) is kept item by item: `pingfedResource` (cn: the item's id; `settings` for a resource that is one object; `item-<n>` otherwise) under `ou=<type, '/' as '.'>,ou=resources,ou=pingfederate`, with `pingfedResourceType`, its settings (secrets withheld) and a credential role. A type is imported as one group: items the export no longer has are removed. Each environment renders them as requests to their own resource type's path (a PUT to `<type>/<id>`, a settings object's PUT), last, which import back through `pingfederate/bulk` unchanged. Notice: `held as is (not modeled): <type> (<items>)`.

**Planner check** (`check_data_stores`): a store with withheld credentials but no credential role, and a target or credential role the target environment doesn't bind, are blockers; a fixed host and an LDAP store without TLS are actions. A store with fixed hosts offers a fix (`external-host:data-stores/<id>`): record the host as the source's `ciamExternalHost` of a role you give, and the next import names that role instead of the host. A store listing several hosts (two domain controllers) records one binding per host under the one role, in the store's order (`ciamHostOrder`), with their own port when they don't share one; a store whose hosts are partly named already (a service name next to a server's hostname) gets no fix, so its hosts never end up under two roles. **`check_references`:** a plugin instance, policy tree, fragment or OIDC policy that names an object the record doesn't have (an IdP connection or key pair no entry, or more than one, carries the id of) (PingFederate refuses such a configuration), and a plugin instance or held resource with withheld secrets but no credential role or one the target doesn't bind, are blockers. **`check_cluster`:** clustered nodes whose discovery nobody recorded, and a target discovery binding that is neither storage nor a service name, are blockers (a source binding the target lacks is the core's binding check); a different kind of discovery in the target (S3 to a blob container) is an action; a node's withheld secrets need a credential role the target binds.

Defines the server roles `pf-engine` and `pf-admin`. Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingfederate`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
