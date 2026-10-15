# opsdir-adapter-pingfederate

opsdir adapter for PingFederate: each environment's PingFederate configuration as Admin API requests checked against its version's spec, as Terraform for Ping's provider, or, on request, as a bulk import document, plus its cluster discovery; the Admin API bulk export, the nodes' own files and the discovery file read back into the record; and, on `opsdir-base-saml` and `opsdir-base-oidc`, the standard SAML and OIDC documents at PingFederate's endpoint paths.

**Applies to** environments where PingFederate runs: a server, or a Kubernetes workload's binding, whose `ciamProductVersion` starts with `PingFederate` (`runs_product`). Supported versions `>=11,<14`; Admin API specs are vendored for 12.1, 12.2, 12.3, 13.0 and 13.1, the Terraform provider for 11.3 to 13.1. A product adapter: it defines the server roles `pf-engine` (the runtime) and `pf-admin` (the administrative console) and the identity services its servers serve (`ciamTargetRole` `pf-engine` or `pf-admin`); where it runs (servers, Kubernetes) is other adapters'. It declares its roles for the kits that deploy it, which find them by product (`Adapter.roles`: server `pf-engine` and `pf-admin`, cluster-discovery `pf-cluster-discovery`); the ping-devops kit derives its log sidecars from this adapter's log declarations through the registry.

**Depends on** `opsdir`, `opsdir-base-saml` and `opsdir-base-oidc` (the standard documents), and `opsdir-format-terraform` (HCL writing for the `terraform` target, `terraform_target.py`). Its maintenance scripts need `pyyaml` (`scripts/vendor-admin-api-specs.py`, reading Ping's OpenAPI documents) and a Terraform CLI (`scripts/vendor-provider-schemas.py`'s schema dumps). Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingfederate`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

## What it renders

`opsdir render --target pingfederate=<targets>` chooses what each environment gets: `admin-api` and `terraform` by default, `terraform-imports` (with `terraform`) and `bulk-config` only when asked (`render.TARGETS`). Choosing `terraform-imports` without `terraform` stops the render. The cluster discovery file is rendered whatever the targets.

| From the record | Rendered as (per environment) |
|---|---|
| Certificates carrying a key pair id (`pingfedKeyPairId`) and their key credential (`ciamKeyRole`) | key pair imports, first: `POST /keyPairs/signing/import`, or `/keyPairs/sslServer/import` for a `tls-server` certificate |
| Data stores (`pingfedDataStore`) | `/dataStores`, hosts from the target role's bindings |
| Plugin instances (`pingfedPlugin`): validators, notification publishers, CAPTCHA providers, IdP adapters, selectors, access token managers | their collections, in that order, a parent instance before those inheriting from it |
| Policy contracts, fragments, the default policy (`pingfedPolicyContract`, `pingfedAuthPolicy`, `pingfedAuthPolicySet`) | `/authenticationPolicyContracts`, `/authenticationPolicies/fragments`, `PUT /authenticationPolicies/default` |
| OIDC policies, the authorization server's settings (`pingfedOidcPolicy`, `pingfedSettings cn=oauth-auth-server`) | `/oauth/openIdConnect/policies`, `PUT /oauth/authServerSettings` |
| The integrations PingFederate's identity services serve (`oidc-client`, `saml2-sp`, `saml2-idp`) | `/oauth/clients`, `/idp/spConnections`, `/sp/idpConnections` |
| Resources held as is (`pingfedResource`) | their own resource type's path, last |
| The `pf-cluster-discovery` binding and the clustered nodes | `pingfederate/cluster/jgroups.properties` |

### Admin API requests (`admin-api`): `pingfederate/admin-api/requests.json`

Every object the record holds for PingFederate as one Admin API request, in the order of the table above (an object before those that name it; `admin_api.requests`):

```json
{"pingFederate": "PingFederate 13.1.3", "adminApi": "13.1", "problems": [],
 "requests": [{"method": "PUT", "path": "/dataStores/user-directory", "createWith": "POST /dataStores", "body": {...}},
              {"method": "PUT", "path": "/oauth/authServerSettings", "body": {...}}, ...]}
```

- **Applying them** is the operator's pipeline's job (opsdir never writes to PingFederate): an object is a PUT to `<collection>/<id>`, and where it doesn't exist yet (the PUT answers 404) the `createWith` POST creates it; a settings object is a PUT; a key pair is a POST import. Apply them in order. Nothing is rendered when the record holds nothing for PingFederate.
- **Key pairs** (`keypairs.py`): each certificate carrying `pingfedKeyPairId` is imported from where the environment keeps its key material, with `fileData` and `password` as secret references. The certificate's key role (`ciamKeyRole`) names the credential that is its key (PKI domain: `ciamMaterialFormat` `pkcs12` or `pem`, and `ciamPasswordRole`, the role of the secret holding the password that protects the file); the environment binds both roles. A key pair is imported once: PingFederate refuses an id it already has, which stays as it is. Named in `problems`, never guessed: a key pair with no key role or no credential for it, or material neither PKCS#12 nor PEM (not imported), PKCS#12 material with no password role (its password `${withheld}`); PEM with none is taken as an unencrypted key (an empty password).
- **Secrets are never values**: `${secret:<reference>}` (the reference the object's credential role, `pingfedCredentialRole`, binds in this environment), `UNBOUND:<role>`, or `${withheld}` while no credential role is set (the planner blocks on both). An object's withheld values all take its one credential role's reference. The pipeline puts the value in at apply time.
- **Data stores**: their hosts from the bindings of the store's target role (`pingfedTargetRole`) and its port, `UNBOUND:<role>` where the environment binds none (details under Data stores below).
- **Integrations** (`connections.py`) are rendered from the settings PingFederate holds for them (auxiliary class `pingfedHeldSettings`, read at import, secrets withheld), with every path the record's standard facts own replaced from the record, so an edit in the record wins and a removed fact leaves no trace:
  - SP connection: entity ID; the default assertion consumer endpoint's URL and binding (others kept); the attribute contract's extended attributes and their fulfillment (a claim removed from the record is gone from every mapping; one the record can't hold, fulfilled from a value no user-schema record names, is kept as PingFederate has it; a new one is fulfilled from the user directory).
  - OAuth client: client ID, redirect URIs, grant types (PingFederate's `EXTENSION`, which stands for the JWT and SAML bearer grants, kept as it is when the record names neither; PingFederate's list kept when it names the same grants), PKCE, DPoP (`requireDpop` from `ciamDpopBound`), the scope restriction, the token manager and OIDC policy (`pingfedUses`), and its authentication: PingFederate 13.1 takes several methods per client (`clientAuthentication`, one object per method), earlier versions one (the legacy `clientAuth`). From 13.1 a client gets `clientAuthentication`, every `ciamTokenAuthMethod` enabled and the methods the record dropped disabled, when the record holds that shape, lists several methods or is new; otherwise its legacy shape stays, which 13.1 still takes, so a render imports back unchanged. Before 13.1 it gets `clientAuth` of its first method (the planner names a client listing several: `check_client_auth`). Tags, secret managers and DPoP proof settings stay in the held settings.
  - IdP connection: its id (`pingfedConnectionId`), entity ID and the JIT user repository's base DN.

  An integration the record made itself holds nothing: it gets the record's facts and only harmless defaults (`SAML20`, SP-initiated SSO, an assertion lifetime of 5 minutes either side, `SAML_SUBJECT` from `uid`); what the spec still requires (an IdP connection's identity mapping and JIT repository) is listed in `problems`, never invented.
- **An SMTP notification publisher** is rendered with the sign-in its relay records, from 13.1 (`messaging.smtp_view`; see Messaging below).
- **`problems`** (`diagnostics.problems`, the same in every render): servers running other versions than the one rendered for (the first by name is used), key pairs not imported, each request body the Admin API spec of the target's version refuses (the request and the JSON path), or that no spec is vendored for the version (the requests then go unchecked), and held settings exported from another version: one line per source version naming its objects ("held settings exported from PingFederate 12.1.4.0, rendered for 13.1.3: 14 objects (...): nothing is migrated between the versions; ..."), then one line per change between the two versions (Upgrades below) that touches some of them, with what to do. Nothing is migrated: Ping documents no bulk import across versions and no migration of an export; its way to settings of a new version is to upgrade a copy (Upgrade Utility, or a configuration archive from 11.1 on) and export it again. Settings exported from a newer version than the target are named as such: nothing is dropped, the target's spec refuses what it lacks. Objects with no recorded source version (imported before versions were recorded, or written in the record) are counted, not compared.

### Terraform (`terraform`, `terraform-imports`): `pingfederate/terraform/`

The same configuration as Terraform for Ping's provider (`pingidentity/pingfederate`), converted from the same requests (`terraform_target.py`), so both say the same thing:

- `versions.tf`: the provider pinned to the release that supports the environment's PingFederate version (`PROVIDERS`: 1.10.0 for 12.2 to 13.1, 1.8.1 for 11.3 to 12.1) and its `product_version` (major.minor). A version no pinned release supports gets only a `main.tf` comment saying so (apply the admin-api requests). The admin credentials are the provider's environment variables (`PINGFEDERATE_PROVIDER_USERNAME`, `PINGFEDERATE_PROVIDER_PASSWORD`, or OAuth client credentials), never in the files.
- `variables.tf`: `pingfederate_https_host` (its default the first location of the environment's `pingfederate/bulk` collection source, when it declares one), `pingfederate_create_key_pairs` when there are key pairs, and one sensitive variable per secret, named by its role and described by the reference the environment binds (a secret no credential role supplies: `<resource>_withheld`); the pipeline supplies the values at apply time. Every argument the provider marks sensitive ends in Terraform state: keep the state encrypted.
- `main.tf`: one resource per request, converted against the provider's own schema of that release (vendored, trimmed: `specs/terraform-provider-<release>.json`, from Ping's provider under the Apache License 2.0; regenerate with `scripts/vendor-provider-schemas.py`): arguments in snake_case, the object's id in the resource's id argument (`data_store_id`, `connection_id`, ...), a discriminated object as the provider's variant (a data store of type LDAP as `ldap_data_store`), a plugin field holding a secret among `sensitive_fields`, map keys (claim names) as they are, PingFederate's read-only `lastModified` left out. What the provider doesn't take is named in a comment on its resource (`not taken by the provider: <path>`); a resource type the provider has no resource for (`RESOURCES` maps 20 Admin API types) is named at the top (`# Not managed here`), left to the admin-api requests, after a `# Problem:` line for each of the requests' `problems`. Each group of resources depends on the group before it (`depends_on`), the Admin API's order. Key pair resources (`pingfederate_keypairs_signing_key`, `pingfederate_keypairs_ssl_server_key`, `file_data` and `password` as sensitive variables) are created only while `pingfederate_create_key_pairs` is true (the default).
- **Adopting an existing PingFederate** (`--target pingfederate=terraform,terraform-imports`; only when asked, since an import fails where the object doesn't exist): `imports.tf` holds an `import` block per resource, its id the object's id (`id` for a settings object), so the first `terraform plan` adopts what PingFederate already holds instead of creating it. The provider can't import key pairs: `imports.tf` names them; set `pingfederate_create_key_pairs` to false where PingFederate already holds them.

`opsdir/scripts/validate-terraform.sh` runs `fmt -check` and `validate` offline (the providers cached under `tools/`) on the showcase's renders in the tests.

### Bulk import document (`bulk-config`, on request): `pingfederate/bulk-config/data.json`

The same requests as a bulk import document (`bulk.py`): `metadata.pfVersion` the version the environment runs as four numbers (`13.1.3` -> `13.1.3.0`; `UNBOUND:pingfederate-version` when none is recorded); each request a `SAVE` of the collection it creates in, a settings resource's path, or a key pair's kind for its import; consecutive ones of a type are one operation. It is the product profile's `instance/bulk-config/data.json` (`render.PROFILE`: `pingfederate/bulk-config/` -> `instance/bulk-config/`, captured `files/pingfederate/` -> `instance/`): the `ping-devops` adapter's `server-profile` target places it, and the bulk importer reads it back. Its requests' `problems` are `pingfederate/bulk-config-problems.json`, outside the folder the server profile takes, so neither Ping's document nor the profile holds anything of opsdir's.

### Cluster discovery: `pingfederate/cluster/jgroups.properties`

Rendered for an environment that binds `pf-cluster-discovery` or has clustered nodes (`pingfedOperationalMode` `CLUSTERED_*`): the discovery lines of each node's `bin/jgroups.properties` (`discovery.py`), `pf.cluster.discovery.protocol` and its `pf.cluster.<PROTOCOL>.*` parameters: `NATIVE_S3_PING` the cloud's region (`ciamRegion`) and the bucket, with `remove_all_data_on_view_change` and `write_data_on_find`; `DNS_PING` `dns_query`; `TCPPING` `initial_hosts` listing the environment's clustered nodes as `hostname[cluster port]` (the node's `cluster=` listener, else 7600) and `port_range=0`, so the list follows the record when servers are replaced or moved. Instead of lines: `# UNBOUND:pf-cluster-discovery` when the role isn't bound, `# UNSUPPORTED:pf-cluster-discovery` for a protocol the adapter doesn't render (an `azblob://` container implies `AZURE_PING`), `# INCOMPLETE:pf-cluster-discovery` when the binding lacks the bucket or DNS name its protocol needs.

**Discovery is a binding, its protocol a choice.** How the nodes find each other differs per environment, the classic miss when moving. The environment binds role `pf-cluster-discovery`, and the protocol is data, chosen per environment: a `pingfedClusterDiscovery` binding states `pingfedDiscoveryProtocol`, with what that protocol needs (`ciamStorageRef` `s3://bucket` for `NATIVE_S3_PING`, `ciamFqdn` for `DNS_PING`, nothing for `TCPPING`). A binding that states none implies one from what it names: an `s3://` reference is `NATIVE_S3_PING` (a core binding of another class naming the bucket works too), a DNS name `DNS_PING`; `TCPPING` is only ever stated. The protocols are a table (`discovery.PROTOCOLS`), one row each; a new protocol is a new row, and the values `pingfedDiscoveryProtocol` accepts are the rendered rows: `TCPPING`, `NATIVE_S3_PING`, `DNS_PING`. `AWS_PING` and `SWIFT_PING` are documented by Ping but not rendered yet. `AZURE_PING` (a community JGroups extension, `jgroups-azure`), `S3_PING` (deprecated), `KUBE_PING`, `JDBC_PING` and `FILE_PING` are not in PingFederate's documentation. On Azure, choose `DNS_PING` (AKS) or `TCPPING` (VMs). With PingFederate on Kubernetes through the ping-devops chart, the DNS name is the chart's cluster service; opsdir-adapter-ping-devops's planner check names it and offers the binding (`discovery.discovery_records` writes it with the name given).

### Environment-neutral

| From the record | Rendered as |
|---|---|
| SAML service providers and partner identity providers PingFederate's services serve | `saml/sp/<integration>.xml`, `saml/partner-idp/<integration>.xml` (opsdir-base-saml) |
| Its identity services with an entity ID | `saml/idp/<service>.xml`: SSO and SLO at `/idp/SSO.saml2`, `/idp/SLO.saml2` (Redirect and POST) |
| The OIDC clients they serve | `oidc/clients/<integration>.json` (opsdir-base-oidc) |
| Its identity services with an issuer | `oidc/discovery/<service>.json`: `/as/authorization.oauth2`, `/as/token.oauth2`, `/idp/userinfo.openid`, `/pf/JWKS`, `/idp/startSLO.ping` |

The paths are PingFederate's defaults.

**Not rendered:** `run.properties` (a node's settings are held as a captured file, `opsdir capture`, its values linked to bindings; the proxy check below adds keys to it), `hivemodule.xml` (recorded, not written), the license, and anything applied: opsdir never calls the Admin API with a write.

### Admin API specs (validation offline)

The Admin API spec of each version in `admin_api_spec.VERSIONS` (12.1, 12.2, 12.3, 13.0, 13.1) is vendored as package data (`src/opsdir_adapter_pingfederate/specs/admin-api-<version>.json`): Ping's own OpenAPI documents from `pingfederate-go-client` (Apache License 2.0, `specs/NOTICE.md`), each from the newest tag of its line (`scripts/vendor-admin-api-specs.py` `TAGS`: 13.1 is `v1310.0.0`, Admin API 13.1.0.5), trimmed to each POST and PUT request's body schema and the schemas' validation keywords. `admin_api_spec` validates a payload against its request's schema without a PingFederate (`$ref`/`allOf` merged, unions by `oneOf`, discriminator or subtype, required properties, unknown properties refused, types, enums, patterns, lengths, unique items; formats aren't checked) and picks the spec of an environment's version (`PingFederate 13.1.3` -> 13.1; a version with no vendored spec gets none). Regenerate from a local clone with `scripts/vendor-admin-api-specs.py` (its docstring has the clone command); add a version by adding its tag to `TAGS`. An enum value that only lists the others comma-joined (13.1's `parStatus` `"DISABLED, ENABLED, REQUIRED"`, `RegistrationConfig.executeWorkflow`) is an artefact of the generated documents and is left out when vendoring (`real_values`).

## What it reads back

Three importers, so name the one you mean: `pingfederate/bulk` (the bulk export), `pingfederate/node-files` (the nodes' own files) and `pingfederate/cluster` (an environment's cluster discovery file). Each declared round trip reads the adapter's own render back unchanged (`reads_back`: `bulk` over `pingfederate/admin-api/*.json`, `cluster` over `pingfederate/cluster/jgroups.properties`, optional since environments that don't cluster render none).

### The bulk export: `pingfederate/bulk`

```bash
curl -u administrator:… -H 'X-XSRF-Header: PingFederate' https://pf-admin:9999/pf-admin-api/v1/bulk/export > export/data.json
opsdir import --change CHG-… pingfederate/bulk export/        # --dry-run first to see what it would change
```

Reads every `.json` file given: the Admin API bulk export (`{"metadata": {"pfVersion"}, "operations": [...]}`, `SAVE` operations) and this adapter's own rendered `requests.json` (each request's body an item of its resource type; key pair imports skipped), so a render reads back unchanged (`importer.py`).

| Admin API | Recorded | Matched by |
|---|---|---|
| `/idp/spConnections` | SAML service-provider integrations (`saml2-sp`): entity ID, default ACS URL and binding, the attribute contract's claims (`ciamClaimMap` under `ou=claims`, linked to the user-schema records they are fulfilled from), the certificates the connection uses (the key pair it signs with, the SP's own signing and encryption certificates) | entity ID |
| `/sp/idpConnections` | Partner identity-provider integrations (`saml2-idp`): entity ID, the JIT provisioning base DN, the partner's signing certificates, the id PingFederate knows the connection by (auxiliary class `pingfedConnection`, `pingfedConnectionId`) | entity ID |
| `/oauth/clients` | OIDC client integrations (`oidc-client`): client ID, redirect URIs, grant types, PKCE, DPoP, token endpoint authentication (13.1's enabled `clientAuthentication` methods, else `clientAuth`), restricted scopes; the token manager and OIDC policy it names (`pingfedClient`, `pingfedUses`) | client ID |
| `/keyPairs/signing`, `/keyPairs/sslServer` | Certificate facts (fingerprint, validity, subject, issuer, SANs), carrying the key pair's id (`pingfedKeyPair`, `pingfedKeyPairId`); new ones with key role `pf-signing-key` (purpose `saml-signing`) or `sso-tls-keystore` (`tls-server`) | fingerprint |
| `/dataStores` | `pingfedDataStore` (Data stores below) | id |
| `/passwordCredentialValidators`, `/idp/adapters`, `/authenticationSelectors`, `/authenticationPolicyContracts`, `/authenticationPolicies/default`, `/authenticationPolicies/fragments` | plugin instances, contracts, policies (Authentication below) | id (a tree: its name) |
| `/oauth/accessTokenManagers`, `/oauth/openIdConnect/policies`, `/oauth/authServerSettings` | OAuth below | id |
| `/notificationPublishers`, `/captchaProviders` | Messaging below | id |
| every other resource type | `pingfedResource`, held as is (below) | id |

- **Integrations keep their own settings** as the Admin API writes them (`pingfedHeldSettings`: `pingfedConfig`, secrets withheld as `pingfedWithheld`, `pingfedCredentialRole`), what renders put the record's facts back into. They keep everything the export doesn't hold (owners, criticality, populations, claim transforms, certificate links the record makes); an integration keeps the name the record gives it, and renders write a connection back under its PingFederate id. A client or connection the record didn't have is added (served by PingFederate's identity service when there is exactly one) and named in the notices, so it gets an owner.
- **Standard names**: where PingFederate's name stands for several standard ones (`SECRET`, `CERTIFICATE`, `EXTENSION`, a binding), the record's value is kept when it is one of them, else the only one, else the standard default (`client_secret_basic` for `SECRET`, `tls_client_auth` for `CERTIFICATE`); a grant type with none of these is named, not recorded.
- **Certificates** found by fingerprint keep the facts the export doesn't give.
- **Source version**: every object holding PingFederate's settings (integrations, data stores, plugin instances, policy contracts, policies and fragments, OIDC policies, the authorization server's settings, resources held as is: `schema.HOLDERS`) records the version they were exported from (`pingfedSourceVersion`, the export's `metadata.pfVersion`), which the renders compare with the version they render for. Exports of several versions read at once record none, and say so: import each version's export on its own. Reading a render back records none either: the record's value is kept.
- **Notices** name: the export's version; claims fulfilled from values no user-schema record names (not recorded); secrets withheld without a credential role; client secrets not imported; names whose id can't name an entry; references neither the export nor the record has; resource types held as is (`held as is (not modeled): <type> (<items>)`); that where clients, grants and sessions are stored comes from the nodes' `hivemodule.xml` (`pingfederate/node-files`) when the record doesn't hold it yet; files that aren't JSON; nothing found.
- **Never read**: client secrets, data store passwords, plugin secrets and every encrypted value (withheld; `withheld.py`).

### Collecting from PingFederate (`opsdir collect`)

`opsdir collect --env CLOUD/ENV --adapter pingfederate` reads the bulk export from the admin node, read-only, and imports it like a saved `/bulk/export` (`collect.py`, collector `bulk`). The environment declares where:

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

opsdir resolves the password and the CA certificate when collecting (held in memory, never stored) and sends `GET /pf-admin-api/v1/bulk/export` to the source's first location with `X-XSRF-Header: PingFederate` and HTTP Basic credentials. Without a bound credential or trust anchor it says which role is missing and reads nothing; a credential scheme other than `basic` or `bearer` is named too. Access: Ping's role table lists the four administrative roles for `/bulk`; whether the view-only Auditor role suffices is to be confirmed against a live PingFederate (milestone 7.2) before relying on it.

An Admin API that takes OAuth 2.0 access tokens or JWTs (`pf.admin.api.authentication` `OAuth2` or, from 12.2, `JWT`, alone or with a Basic method) is read with a bearer token instead: `ciamCredentialScheme: bearer` on the collection source, and the credential role's reference holds the token, minted outside opsdir (your identity provider's client credentials grant, or a JWT your pipeline signs) and rotated there; opsdir sends `Authorization: Bearer` and no `ciamLoginName`. Collection stays read-only GETs: opsdir never requests the token itself. The bulk export still needs an identity mapped (in `oauth2.properties` or `jwt.properties`) to the administrative roles.

### Data stores

Held under `ou=data-stores,ou=pingfederate`, one `pingfedDataStore` per store, named by its id: its type (`pingfedStoreType`: LDAP, JDBC, CUSTOM) and its settings as the Admin API writes them (`pingfedConfig`), less what differs per environment (`datastores.py`):

| What | On import | Rendered per environment (a `/dataStores` request) |
|---|---|---|
| Hosts (an LDAP store's `hostnames`, a JDBC URL's hosts) | When every host is the same role in the record (a service name, an external system's `ciamExternalHost`, or a rendered `UNBOUND:<role>`), the store names that role (`pingfedTargetRole`) and the hosts' common port (`pingfedPort`), and the hosts leave the settings (a JDBC URL keeps the rest: `jdbc:postgresql:///pf`). Otherwise they are kept as they are: fixed hosts | The target role's host and port, or `UNBOUND:<role>` where the environment binds none. One host is the default; an environment that binds the role several times (an external system's hosts, ordered by `ciamHostOrder`) renders every one, in that order, each with the store's port or, when the hosts don't share one, its own `ciamPort`. Fixed hosts as recorded |
| Credentials (`password`, and every encrypted value: `encryptedPassword`, a custom store's `encryptedValue`) | Withheld under their plain name (`/password`, `/configuration/fields/<n>/value`; `pingfedWithheld`): PingFederate encrypts them with the deployment's own master key, so they never carry over | `${secret:<ref>}` of the store's credential role (`pingfedCredentialRole`), `UNBOUND:<role>`, or `${withheld}` while no credential role is set |
| Bind account (an LDAP store's `userDN`) | Linked to the consumer record with that bind DN (`pingfedConsumer`) | Unchanged (part of the settings) |

The credential role is never guessed: an approved change sets it, and an import keeps it. Notices name a store that binds as an account no consumer records, hosts that are a server's hostname (they change when servers are replaced or moved) or unknown to the record, a store with no single service name, an LDAP store without TLS (`useSsl` and `useStartTLS` off), withheld credentials without a credential role, and an id that can't name an entry (not imported). The engines' ports to a store's service name are in the ports matrix (`listeners.store_listeners`).

### Authentication: plugins and policies

| Admin API | Record (under `ou=pingfederate`) | Rendered |
|---|---|---|
| `/passwordCredentialValidators`, `/idp/adapters`, `/authenticationSelectors` | `pingfedPlugin` (cn: its id) under `ou=credential-validators`, `ou=idp-adapters`, `ou=authentication-selectors`: `pingfedPluginKind`, `pingfedPluginType` (its `pluginDescriptorRef`), `pingfedParent` (its `parentRef`), `pingfedUses` (the objects its settings fields name), settings | Per environment: their requests (secrets from its credential role) |
| `/authenticationPolicyContracts` | `pingfedPolicyContract` (cn: its id) under `ou=policy-contracts` | Their requests (the same in every environment) |
| `/authenticationPolicies/default` | `pingfedAuthPolicySet` `cn=default,ou=authentication-policies` (its own settings), one `pingfedAuthPolicy` per tree below it (cn: the tree's name; `pingfedPosition`, `pingfedEnabled`, `pingfedPolicyTree`, `pingfedUses`) | `PUT /authenticationPolicies/default`, the trees in order |
| `/authenticationPolicies/fragments` | `pingfedAuthPolicy` (cn: its id) under `ou=policy-fragments`, linked to what it runs and the contracts it takes and hands on | Their requests |

- **References.** Objects keep the ids PingFederate names others by, and the record links them by DN (`pingfedUses`): a validator's data store (`LDAP Datastore`, `JDBC Datastore`), an HTML form adapter's validators (`Password Credential Validator Instance`), a composite adapter's adapters (`Adapter Instance`), a JWT token manager's key pairs (`Certificate`), and what a policy tree or fragment runs (IdP adapters, IdP connections, selectors, policy contracts, fragments). The field names are data (`plugins.REF_FIELDS`); a custom plugin's fields are added there. A reference neither the export nor the record has is named on import.
- **IdP connections and key pairs** are found by the id they carry (`pingfedConnectionId` on the partner integration, `pingfedKeyPairId` on the certificate): that id, not the entry's name in the record, is the durable link, so renaming the integration doesn't break it. Exactly one entry may carry an id: one that two entries claim resolves to neither and is named, on import and by the planner (with a fix, `claimants:<kind>:<id>`, keeping it on the entry chosen).
- **Secrets.** Every encrypted value (`encryptedValue`, `encryptedPassword`, …) and every settings field whose name says it holds a secret (`Secret Key`, `Client Secret`, `Password`) is withheld; each environment renders the reference of the instance's credential role.
- **The default policy is imported as one:** a tree the export no longer has is removed. Trees whose names can't name an entry, or that repeat another tree's name, are named and not imported.

### OAuth: token managers, OIDC policies, scopes

| Admin API | Record (under `ou=pingfederate`) | Rendered |
|---|---|---|
| `/oauth/accessTokenManagers` | `pingfedPlugin` kind `access-token-manager` under `ou=access-token-managers`, linked (`pingfedUses`) to the certificates of the key pairs a JWT manager signs with (its `Certificates` table) | Per environment: their requests (symmetric keys and other secrets from its credential role) |
| `/oauth/openIdConnect/policies` | `pingfedOidcPolicy` (cn: its id) under `ou=oidc-policies`, linked to its token manager | Their requests |
| `/oauth/authServerSettings` | `pingfedSettings` `cn=oauth-auth-server,ou=settings`: the settings, with every scope it defines (common and exclusive) in `pingfedScope` | `PUT /oauth/authServerSettings` (secrets from its credential role) |
| An OAuth client's `defaultAccessTokenManagerRef`, `oidcPolicy.policyGroup` | Its integration gains auxiliary class `pingfedClient`, linked (`pingfedUses`) to the token manager and OIDC policy | Written back into the client's request |

Token manager attribute mappings (`/oauth/accessTokenMappings`), token processors and generators are held as is (below); an OAuth client's own token lifetimes and other settings beyond the standard registration stay in its held settings.

### Messaging: notification publishers and CAPTCHA providers

Notification publishers (`/notificationPublishers`) and CAPTCHA providers (`/captchaProviders`) are plugin instances like the others (`pingfedPlugin` under `ou=notification-publishers` and `ou=captcha-providers`): their settings, secrets withheld (the SMTP password, the CAPTCHA secret key), the credential role that holds them, rendered back per environment. What they say about services outside the platform also becomes the core `messaging` domain's view of them, which the planner checks (`messaging.py`):

| From | Recorded |
|---|---|
| an SMTP notification publisher's Email Server and SMTP Port | an external service of kind `smtp-relay` (`ciamEndpointHost`, `ciamPort`), found by its host, reached from `pf-engine`, using the publisher's credential role (`ciamUsesRole`) |
| its sign-in: Authentication Method and, for an OAuth bearer token (13.1), OAuth Authentication Method, OAuth Token Endpoint, Client ID, OAuth Scope | on the relay: `ciamSmtpAuth` (`none`, `basic`, `oauth-client-credentials`, `oauth-private-key-jwt`; a publisher from before 13.1 with a Username: `basic`), `ciamTokenEndpoint`, `ciamClientId`, `ciamScope`; the client secret is withheld like the password and comes from the same credential role |
| its From Address | a mail sender (`ciamSenderAddress`, `ciamSenderDomain`), found by its address, sent by that relay (`ciamSentBy`) |
| a CAPTCHA provider | an external service of kind `captcha` named `captcha-<id>`, its vendor from the plugin type (Google reCAPTCHA, hCaptcha, Cloudflare Turnstile), using the provider's credential role |

Their secrets never reach these entries. What the record adds (the domains a CAPTCHA allows, owners, a sender's sending role and bounce handling) is kept on import. A publisher with no Email Server records no relay, one with no From Address no sender (both named).

The relay's sign-in is the record's: for an environment running PingFederate 13.1 or later, an SMTP publisher is rendered with the authentication its relay records (`smtp_view`), so moving a relay to OAuth (Exchange Online, a cloud relay) is a change to the relay. Option values are matched by keyword, since Ping documents the admin console's labels ("Basic Authentication", "OAuth 2.0 Bearer Token", "Client Credentials", "Private Key JWT"): a held value meaning the same method is kept, any other is written as that label. A private-key JWT's signing key is PingFederate's own (its centralized key or a key pair) and stays in the publisher's settings.

### Resources held as is

Every resource type of the bulk export not modeled above (`/serverSettings`, `/oauth/accessTokenMappings`, token processors and generators, local identity profiles, administrative accounts, ...) is kept item by item (`generic.py`): `pingfedResource` (cn: the item's id; `settings` for a resource that is one object; `item-<n>` otherwise) under `ou=<type, '/' as '.'>,ou=resources,ou=pingfederate`, with `pingfedResourceType`, its settings (secrets withheld) and a credential role. A type is imported as one group: items the export no longer has are removed; an item whose name can't name an entry, or that another item shares, is named and not held. Each environment renders them as requests to their own resource type's path (a PUT to `<type>/<id>`, a settings object's PUT), last, which import back through `pingfederate/bulk` unchanged.

### The nodes' own files: `pingfederate/node-files`

```bash
opsdir import --change CHG-… pingfederate/node-files nodes/     # nodes/<hostname>/bin/run.properties, ...
```

One folder per node, named by the server's hostname (or its record name; a folder matching no `pf-engine`/`pf-admin` server is named), holding what the node has under its install root (`nodes.py`):

| File | Recorded |
|---|---|
| `bin/run.properties` | On the server, auxiliary class `pingfedNode`: `pingfedOperationalMode` (`CLUSTERED_CONSOLE`, `CLUSTERED_ENGINE`, `STANDALONE`), `pingfedNodeTags`, `pingfedListener` (`runtime=9031`, `admin=9999`, `cluster=7600`, ... from `pf.https.port`, `pf.http.port`, `pf.secondary.https.port`, `pf.admin.https.port`, `pf.cluster.bind.port`, `pf.cluster.failure.detection.bind.port`), every other setting in `pingfedConfig` (`pf.cluster.auth.pwd` and other secrets withheld, from the node's credential role) |
| `bin/jgroups.properties` (`server/default/conf/tcp.xml`) | The JGroups discovery protocol the node uses (`pingfedDiscovery`): `pf.cluster.discovery.protocol` in `jgroups.properties` (PingFederate 11.0 and later; `tcp.xml` holds `${DISCOVERY_TAG}`), else the protocol element of an upgraded install's `tcp.xml`; checked against the environment's discovery binding |
| `server/default/conf/META-INF/hivemodule.xml` | `pingfedSettings` `cn=storage,ou=settings`: which kind of store (JDBC, LDAP, Redis, XML file, ...) backs OAuth clients, persistent grants and sessions (`ClientManager`, `AccessGrantManager`, `SessionStorageManager`; verify against the target version). Nodes that differ: the first is recorded, and named |

A folder needn't hold every file: what a file it lacks would record is kept as the record has it (a folder with only `bin/jgroups.properties` sets the node's discovery protocol and leaves its mode, tags, listeners and settings alone). Notices name an unknown operational mode, files naming no protocol, a protocol PingFederate doesn't know or the adapter doesn't render, a node whose protocol differs from its environment's binding or whose environment binds none, and withheld node secrets without a credential role.

### The discovery file: `pingfederate/cluster`

```bash
opsdir import --change CHG-… pingfederate/cluster cluster/      # cluster/<cloud>/<env>/jgroups.properties
```

Reads an environment's discovery lines, the rendered `pingfederate/cluster/jgroups.properties` or a node's own `bin/jgroups.properties`, one per environment in its `<cloud>/<env>/` folder, into its `pf-cluster-discovery` binding (`discovery_import.py`). The protocol is kept when the binding already states or implies it, and stated otherwise: a `pingfedClusterDiscovery` binding, which replaces a binding of another class under its name. `NATIVE_S3_PING`'s `bucket_name` becomes the binding's `ciamStorageRef` (`s3://<bucket>`, kept as the record has it when it names that bucket, a path included); `DNS_PING`'s `dns_query` becomes its `ciamFqdn`. Everything else follows from the rest of the record (the region from the cloud, `TCPPING`'s hosts and ports from the environment's clustered nodes, the flags always written), so it is compared with what the record renders, and a difference is a notice, never a change. Named, with the binding left alone: a file naming no protocol, one PingFederate doesn't document or the adapter doesn't render, a missing bucket or DNS name, an inherited binding that disagrees (bind the role in the environment itself), settings of another protocol, a second file for the same environment, and files outside an environment's folder.

## Schema, vocabulary and secret patterns

Schema under this package's OID arc `1.3.6.1.4.1.32473.3.4` (prefix `pingfed`, `schema.py`): 24 attributes and 14 classes. Structural, each holding Admin API settings with their source version: `pingfedDataStore`, `pingfedPlugin`, `pingfedPolicyContract`, `pingfedAuthPolicySet`, `pingfedAuthPolicy`, `pingfedOidcPolicy`, `pingfedSettings`, `pingfedResource`. Auxiliary: `pingfedConnection` (an IdP connection's id), `pingfedKeyPair` (a key pair's id on its certificate), `pingfedClient` (an OAuth client's token manager and OIDC policy), `pingfedNode` (a server's `run.properties` facts and discovery protocol), `pingfedHeldSettings` (an integration's own settings). Binding: `pingfedClusterDiscovery` (role `pf-cluster-discovery`). The record's entries live under `ou=pingfederate` (`naming.py`).

Vocabulary it owns: `ciamServerRole` and `ciamTargetRole` values `pf-engine`, `pf-admin`; `pingfedDiscoveryProtocol` values `TCPPING`, `NATIVE_S3_PING`, `DNS_PING`. Secret pattern `pingfederate-obfuscated`: PingFederate's obfuscated or encrypted values (`OBF:` followed by 16 or more characters), refused by the store anywhere in the record. It owns no reference schemes.

Formats of its files: `pingfederate/admin-api/*.json`, `pingfederate/bulk-config/*.json`, `pingfederate/bulk-config-problems.json` (JSON), `pingfederate/terraform/*.tf` (HCL), `pingfederate/cluster/*.properties` (Java properties), and the bases' `saml/*.xml`, `oidc/*.json`.

## Roles, server roles and planner checks

**Required roles** (each environment running PingFederate binds them): `subnet-pf`, `pf-sso-service`, `pf-egress`, `sso-tls-keystore`, `pf-signing-key`, `pf-admin-password`. The credential roles its data stores, plugin instances and held resources name are reported to the core's role checks (`roles_used`: `checks.credential_roles`).

**Server roles** `pf-engine` and `pf-admin`:

- **Listeners** (the ports matrix, `listeners.py`): what each node's `run.properties` says (`runtime`, `runtime-http`, `runtime-secondary` for clients, `admin` for the operators), PingFederate's defaults where the record holds none (`pf-engine` 9031, `pf-admin` 9999), and on clustered nodes the cluster ports (7600, failure detection 7700) for the other nodes; plus the ports the engines reach through data stores naming a service name's role.
- **Logs** (`logs.py`, under `pingfederate/log/` unless `pf.log.dir` moves it; text): the admin node's `admin.log`, `admin-event-detail.log`, `admin-api.log`, `admin-request.log`; the engines' `runtime-request.log`, `request.log` (legacy), `runtime-api.log`, `transaction.log`, `audit.log`, `provisioner-audit.log`, `provisioner.log`, `provisioner-channel-summary.log`, `thread-pool-exhaustion-dump.log`; `server.log` and `init.log` on both.
- **Endpoints** the edge treats specially (`render.ENDPOINTS`, on `pf-engine`): sign-in (`/as/authorization.oauth2`, `/idp/SSO.saml2`), token (`/as/token.oauth2`), SAML posts (`/idp/SSO.saml2`, `/sp/ACS.saml2`), self-service password reset (`/ext/pwdreset/*`), the heartbeat (`/pf/heartbeat.ping`), and the IdP-initiated start of a SAML sign-in (`/idp/startSSO.ping?PartnerSpId=<entity>`, a synthetic check's entry point).
- **Egress through an explicit proxy** (`proxy.py`): when an environment's egress passes a proxy clients must be told about (a `ciamProxy` with `ciamProxyAddress` that isn't a firewall), PingFederate needs it on every node role it runs (servers or Kubernetes): `bin/run.properties` keys `http.proxyHost`, `http.proxyPort`, `https.proxyHost`, `https.proxyPort` (the AWS SDK plugins, such as the SNS notification publisher, read only the `http.*` ones) and `http.nonProxyHosts` (pipe-separated: the host, the private ranges as `10.20.*`, private DNS zones as `*.zone`, the service names). Certificate revocation checking (CRL, OCSP) has its own proxy setting (Security > Certificate Revocation Checking, `/certificates/revocation/settings`), set once on the admin node (on an engine when no admin node runs). The planner compares the keys with each node's captured `run.properties` (missing or other values are actions with a fix, `opsdir fix`, that adds them to the captured file linked to the proxy's derived values, `<proxy role>#proxy:host` and so on, so every environment's file names its own proxy and an environment without one renders them empty) and names the revocation setting, which the record can't confirm.

**Planner checks** (`checks.py`):

| Check | Reports | Fix offered |
|---|---|---|
| `check_data_stores` | Blockers: a store with withheld credentials but no credential role; a target or credential role the target doesn't bind. Actions: a fixed host (no target role), an LDAP store without TLS | `credential-role:data-stores/<id>` (choose the secret role); `external-host:data-stores/<id>`: record the fixed hosts as the source's `ciamExternalHost` bindings of a role you give (one per host, in the store's order, `ciamHostOrder`, with their own port when they don't share one), so the next import names that role; none when the hosts are partly named already, so they never end up under two roles |
| `check_references` | Blockers: a plugin instance, policy tree, fragment or OIDC policy naming an object the record doesn't have (or an IdP connection or key pair id no entry, or several, carry: PingFederate refuses such a configuration); a plugin instance or held resource with withheld secrets but no credential role, or one the target doesn't bind | `claimants:<kind>:<id>`; `credential-role:<branch>/<id>` |
| `check_cluster` | Blockers: clustered nodes with no discovery recorded anywhere; a target binding whose protocol the adapter doesn't render, or that lacks the bucket or DNS name its protocol needs; a node's withheld secrets with no credential role or one the target doesn't bind. Action: a different protocol in the target (every node's `jgroups.properties` changes). A source binding the target lacks is the core's binding check (`binding:pf-cluster-discovery`) | `discovery:<environment>`: binds the role, one option per rendered protocol (just the one the source's nodes all run, when it is rendered); the bucket (`ciamStorageRef`, `s3://…`) or DNS name (`ciamFqdn`) is an input the operator gives, never guessed; a binding of another class is replaced by a `pingfedClusterDiscovery` of the same name, and a value the new protocol doesn't use is dropped |
| `check_client_auth` | Action: an OAuth client listing several authentication methods when the target runs a version before 13.1 (it gets the first) | |
| `check_smtp_auth` | Action: a relay recording OAuth sign-in while the target runs a version before 13.1 (the publisher keeps what it holds there) | |
| `check_service_roles` | Action: an SMTP relay or CAPTCHA service whose credential role (`ciamUsesRole`, set at import from `pingfedCredentialRole`) isn't its plugin instance's (a change set the instance's role after the import), so the messaging check of its secret looks at the wrong role | `service-role:<service>` setting it, as a re-import would; the credential-role fix sets both in the option chosen |
| `check_jdbc_drivers` | Action, on targets running 13.1.3 or later (whose Admin API restricts JDBC drivers and URL schemes): a JDBC store whose driver class isn't one PingFederate documents as supported (the Aurora wrapper, SQL Server, Oracle thin, MySQL, PostgreSQL: `datastores.JDBC_DRIVERS`) or whose URL doesn't use its driver's scheme. Ping publishes no exact allow-list, so it isn't a blocker | |

### Upgrades during a move

A migration may upgrade the product within the supported range (PingFederate `>=11,<14`). The planner names each server role's version jump, from the oldest version the source runs to the newest the target runs, and every change below that the jump crosses (the source version lacks it, the target's has it), at its effect, when it applies to the record. A target outside the range is a blocker, a downgrade an action. From the vendor's release notes (`versions.py`, `VERSION_CHANGES`).

| Since | Change | Effect | Named when |
|---|---|---|---|
| 12.0 | conditions comparing with 'multi-value contains DN' ignore letter case | action | settings use that condition |
| 12.1 | a request naming a resource (resource indicators) fails unless an access token manager lists it in its Resource URIs | action | token managers listing no Resource URIs |
| 12.1 | a refresh grant is no longer revoked when an access token mapping's issuance criteria fail | action | access token mappings with issuance criteria |
| 12.2 | the cluster's JGroups thread pool is set in run.properties (pf.cluster.thread.pool.max.threads) | info | always |
| 12.2 | provisioning's Flag Comparison Value is compared without letter case | action | settings with a Flag Comparison Value |
| 12.3 | runtime-request.log and admin-request.log replace request.log | info | always |
| 12.3 | the Admin API spec no longer has `tokenEndpointAttributeContract.inherited` (Ping's go-client spec from 12.3.0.3; PingFederate's own handling undocumented) | action | token managers holding it |
| 12.3 | a persistent grant past its idle timeout is no longer used while its lifetime lasts | action | settings with a grant idle timeout |
| 13.0 | the Admin API's request schemas change with the release | info | always |
| 13.0 | plugins depending on Jersey 1 stop PingFederate from working | action | plugin instances of classes outside PingFederate's own packages (`com.pingidentity.`, `org.sourceid.`) |
| 13.0 | an OIDC IdP connection expecting a JARM response fails on a plain one | action | IdP connections expecting JARM |
| 13.1 | a pushed authorization request's request_uri can be used again until the PAR Reference Timeout expires | action | the authorization server's settings, PAR not disabled |
| 13.1 | the aud claim of private_key_jwt client authentication is handled differently | action | OAuth clients using private_key_jwt |
| 13.1 | custom and third-party plugins must be Jakarta-compatible versions | action | plugin instances of classes outside PingFederate's own packages |
| 13.1.2 | an IdP connection handling failures locally sends its errors to the policy's Fail branch | action | IdP connections handling failures locally |
| 13.1.3 | the Admin API validates JDBC data stores' driver class and URL | action | the record holds JDBC data stores |

The changes that touch held settings name the objects holding them, both for the planner and in the renders' `problems` when held settings come from another version (above). Not named, since no setting the record holds says whether they apply: 12.0's removal of text-message self-service password reset, 13.0's speed bump for new devices (off by default on an upgraded server, on for a new one: set it explicitly), 13.0.3's single values from the OAuth client management service (Ping's pages disagree), 13.1.2's narrower AuthN-context override. Fixes made in several maintenance lines at once are dated by the newest line only.

## Known limits

- **Not yet run against a live PingFederate.** The requests are checked against Ping's vendored specs and the Terraform by `terraform validate`; applying them, collecting from a real admin node and importing a real export are part of the testing plan (milestone 7.2).
- **The 13.1 spec is Admin API 13.1.0.5** (pingfederate-go-client `v1310.0.0`, the newest tag; there is none for 13.1.1 to 13.1.3). Open (deferred note on `scripts/vendor-admin-api-specs.py`): re-vendor 13.1 at 13.1.3 once a tag is published, and check then whether Ping's 13.1.x spec still drops `tokenEndpointAttributeContract.inherited` and keeps the comma-joined enum artefacts.
- **SMTP sign-in option values are unverified.** Ping documents only the admin console's labels, so `messaging.smtp_auth` matches by keyword and `smtp_view` writes the label when the held value means another method. Open (deferred note on `messaging.py`): confirm against a live 13.1 export and replace `LABELS` with the stored values if they differ.
- **Unchecked versions**: 11.x and 12.0 have no vendored spec (their requests are rendered unchecked, and say so); before 11.3 there is no Terraform provider release (only a comment). `pingfederate_version` takes the first server's or workload's version by name; others are named in `problems`.
- **Discovery protocols** rendered: `TCPPING`, `NATIVE_S3_PING`, `DNS_PING`. `AWS_PING` and `SWIFT_PING` are documented by Ping but not rendered.
- **Not modeled** (held as is, rendered back unchanged, checked only for their secrets): server settings, access token mappings, token processors and generators, local identity profiles, administrative accounts and every other resource type the export holds.
- **One credential role per object**: all of an object's withheld secrets take that role's reference.
- **The admin account's least privilege** for `/bulk/export` (whether Auditor suffices) is unconfirmed.
- **`hivemodule.xml` service points** (`ClientManager`, `AccessGrantManager`, `SessionStorageManager`) and the plugin fields naming other objects (`REF_FIELDS`) are PingFederate's own as documented; verify them against the target version.

## Tests

`tests/` (unit unless marked): `test_pingfederate.py` (registration, applies, server roles, the neutral SAML and OIDC documents at PingFederate's paths, standard values mapped to its API names); `test_pingfederate_admin_api.py` (request order, PUT creatable by POST, the spec check, the record's facts winning over held settings, a removed claim gone everywhere, what the record can't say kept, new integrations' defaults and what is missing named, key pairs imported first); `test_admin_api_spec.py` (every vendored version loads with the requests the renderer makes, wrong, unknown and missing properties named with their path, discriminators and subtypes, the version mapping, the vendored specs' source and license); `test_pingfederate_terraform.py` (the provider release by version, resources with secrets as variables, no secret value in the root, only the targets chosen, import blocks only when asked); `test_pingfederate_held_versions.py` (held settings from older and newer versions named with the changes touching them, objects with no source counted, the same problems in Terraform and bulk, each release change's objects); `test_pingfederate_import.py` (integrations merged with the record's, new ones named, no secret read, every resource read, a re-import changing nothing, the render reading back, fingerprints, kept certificate facts, source versions); `test_pingfederate_datastores.py` (import, hosts as roles and fixed hosts, withheld credentials, per-environment render and read-back, the planner's findings and fixes, several hosts in order, the 13.1.3 JDBC check, roles used); `test_pingfederate_authentication.py` (plugins and policies linked, withheld secrets, tree order and removal, render and read-back, IdP connection ids and claimants); `test_pingfederate_oauth.py` (token managers, OIDC policies, scopes, client links, 13.1 multi-method clients and DPoP, legacy clients, the planner's findings); `test_pingfederate_messaging.py` (relay, sender and CAPTCHA service, secrets kept out, SMTP OAuth sign-in recorded and rendered, the service-role check and fix); `test_pingfederate_nodes.py` (node files, storage, notices, discovery render per protocol, TCPPING hosts, unsupported protocols, the cluster check and its fixes, the discovery file read back and compared); `test_pingfederate_resources.py` (held as is, render, read-back, removal, the credential-role blocker); `test_pingfederate_listeners.py`, `test_pingfederate_proxy.py`, `test_pingfederate_collect.py` (Basic and bearer collection, an unbound credential). `tests/bulk-export/data.json` is the sample export.

`test_pingfederate_store.py` (marker `integration`, Postgres via `OPSDIR_TEST_DSN`): a bulk export imported under an approved change, the store accepting every integration, claim and certificate, no secret in it, a re-import changing nothing. Full renders are exercised by the showcase's golden outputs, and the showcase's Terraform by `terraform validate` (marker `terraform`).

```bash
opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-pingfederate/tests
opsdir/.venv/bin/python -m pytest -m integration packages/opsdir-adapter-pingfederate/tests
```
