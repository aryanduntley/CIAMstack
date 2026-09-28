# opsdir: an LDAP-model standard for platform configuration

**Status:** draft 0.4 (2026-09-28), Aryan Duntley. Reference implementation in this folder.

*0.2: the schema is composed from per-domain fragments with pinned OIDs (§2.1); reference schemes, required roles and renderers come from adapters (§3.2, §7, §8); owners and the operator are data (§5).*
*0.3: one standard LDAP catalogue for both LDAP layers (§2.2); the user directory's schema is recorded (§6); the platform's own identity services and the federation protocols' standard vocabulary (§5); declaration-only adapters and standard bases (§8).*
*0.4: package-owned fragments under their own OID arcs (§2.1); custom fields and record types defined in the record itself (§2.3); value rules (§3.2); file formats and supported product versions are data (§8, §9).*

## 1. Purpose

A platform's configuration is usually spread across infrastructure-as-code files, CLI batch files, admin consoles, spreadsheets and people's heads. **opsdir** puts it in a directory instead: one tree of typed, schema-checked, cross-referenced entries. Working configuration (infrastructure code, product configuration, setup scripts) is **generated** from that tree by adapters.

Consequences:
- **A change is a directory entry,** made under an approved change record. Files are re-rendered, never hand-edited.
- **A migration is a read.** The same databases are rendered for a different environment. Only that environment's *bindings* are new.
- **Questions become queries:** blast radius, expiry, drift, who can read what, which external allowlists hold our addresses.

The first domain is a CIAM platform (directory, federation, PKI and the infrastructure they run on), but nothing in the model is specific to it or to any product.

## 2. Information model (inherited from LDAP)

opsdir uses the LDAP information model unchanged (RFC 4512):

- **Entries** in a tree (DIT), named by **DNs**. Naming context: `dc=ciam-ops`.
- **Object classes** (ABSTRACT / STRUCTURAL / AUXILIARY, with inheritance) define MUST and MAY attributes.
- **Attribute types** with syntax, equality rule and single/multi-value.
- The schema is published as a standard LDAP schema file: `schema/ciam-ops.schema.ldif`.

### 2.1 Schema fragments and pinned OIDs

The published schema is **composed**, never hand-edited. Each part of the stack owns a *schema fragment*: the core (the base class `ciamObject`, ownership, and vocabulary shared by several domains), and each domain (infrastructure, directory, federation, pki, governance). Adapters may add fragments for product-specific facts. `scripts/gen-schema.py` composes the standard definitions and every fragment into the file.

- **OIDs are pinned by number** in each definition (`<arc>.1.<n>` for attribute types, `<arc>.2.<n>` for object classes). They are never derived from position. Moving a definition between fragments of one arc never renumbers anything, and a published number is never reused.
- **Each owner has an arc.** The core and its domains share the opsdir arc; an adapter package that adds definitions numbers them under an arc of its own, so packages written independently never collide. In this repository, sub-arcs of the documentation PEN: `.1` the core and its domains, `.2` the showcase's user-directory schema, `.3.<n>` packages, `.4` fields users define in the record.
- Composition is refused when fragments reuse an OID (in any arc) or a name, or when a class uses an attribute or superclass that no fragment defines.
- The store's registry is the composition of the core's, the domains' and the installed adapters' fragments. A definition no installed part defines any more is removed on upgrade, unless entries still use it (then the upgrade is refused).

### 2.2 The standard LDAP schema

LDAP is the base of the model, so the standard LDAP definitions (RFC 4512 `top` and `objectClass`, RFC 4519, RFC 4524 COSINE, RFC 2798 `inetOrgPerson`, RFC 4523, RFC 2079, RFC 2247) are held once, as data, in the core. They serve both LDAP layers: opsdir's own schema takes the standard definitions it uses from them (their OIDs, single-value, superclass, kind, MUST and origin; opsdir adds only value type, portability and description), and the user directories opsdir manages are described against them (§6).

### 2.3 Custom fields and record types

Nobody can foresee every fact a platform needs recorded, so operators define their own, **in the record itself**: each definition is an entry under `ou=custom-schema` (`ciamFieldDefinition`, `ciamRecordTypeDefinition`), approved, kept in history and exported like any other. Its metadata says what it is (description, purpose, owner, sensitivity, status: proposed | active | deprecated, documentation and runbook links), what values it takes (value type, one or many values, unit, example, default, and rules: minimum, maximum, pattern, maximum length), which records carry it (record types a field applies to; a record type's required and optional fields and its parent type), where its value lives in real systems and which adapters read or write it, and how it behaves in a migration (portability; whether an environment may override it).

- **Names start with `x`** (`xCostCenter`, `xFeatureFlag`): the core (`ciam…`) and packages never use that prefix, so their later definitions can't collide. OIDs are pinned numbers under the custom arc.
- The store composes the definitions into its schema next to the core's, the domains' and the packages' fragments: on every `upgrade`, and inside the approved change that adds or changes them, so one change can define a field and use it (definitions are applied first, removed last).
- A definition that can't be built is refused (a name without the prefix, an unknown value type, a rule that doesn't fit the type, an unknown record type). A change that would leave stored entries invalid (a tighter rule, a narrower type) is refused and names them; a definition entries still use can't be deleted.
- How parsers and renderers read and write custom fields is described by the metadata (`ciamValueSource`, `ciamUsedBy`); mapping them in adapters is future work.

## 3. Extensions (RFC 4512 `X-` extensions)

Every attribute type declares two extensions.

### 3.1 `X-PORTABILITY`: what happens to this value in a migration

| Class | Meaning | In a migration |
|---|---|---|
| `intent` | What the platform should be: schema, indexes, ACIs, policies, claim maps | **Moves unchanged.** Renders identically in every environment. |
| `contract` | Names other parties depend on: service FQDNs, SAML entity IDs, ACS/redirect URLs, client IDs, claim names | **Must not change.** Any difference between source and target is a blocker. |
| `binding` | Where and how intent is realized in one environment: hosts, IPs, subnets, zone IDs, sizes, images, firewall sources | **Rewritten per environment.** The only thing written by hand for a new environment. |
| `secret-ref` | Reference to a secret or key in the environment's store | **Re-bound,** never copied. The value never enters the directory. |
| `observed` | Facts measured from the running system: log-derived consumers, config snapshots | Evidence for planning. Never rendered. |
| `meta` | Ownership, status, dates, documentation, change records | Governance. |

### 3.2 `X-VALUE-TYPE`: stricter types than LDAP syntaxes

`string · int · bool · time (GeneralizedTime) · dn (internal reference) · extdn (DN in another directory) · cidr · ip · fqdn · url · port · ref-uri · json · enum:a|b|c · vocab`

An attribute type may also state **value rules** the store enforces on every value: `X-MIN`, `X-MAX` (numbers), `X-PATTERN` (a regular expression the value matches), `X-MAX-LENGTH` (characters). Custom fields use them (§2.3).

`vocab` values are owned by the installed domains and adapters: each declares the values it defines (a provider adapter its provider name and partitions, a product adapter its server roles), the store syncs them on every upgrade and accepts only registered values.

`ref-uri` accepts only reference schemes that some adapter declares it owns. The store syncs them into its `ref_scheme` table on every upgrade. Which schemes exist depends only on the installed adapters: a secret store or cloud adapter declares the schemes it can resolve. Adding one adds its schemes, and the store's validation doesn't change.

## 4. Normative rules

A conforming store MUST enforce all of these, not merely document them:

| # | Rule |
|---|---|
| R1 | **Schema checking.** Object classes known. At least one structural class. Only MUST/MAY attributes. All MUST attributes present. SINGLE-VALUE respected. Every value valid for its `X-VALUE-TYPE`. |
| R2 | **Tree integrity.** The parent entry exists. The RDN value is present in the entry. Non-leaf entries can't be deleted. |
| R3 | **Referential integrity.** Every `dn`-typed value resolves to an existing entry at commit. A referenced entry can't be deleted. *(Stronger than LDAP, where referential integrity is an optional plugin.)* |
| R4 | **No secrets.** `secret-ref` attributes MUST be `ref-uri`. The schema offers no attribute that can hold secret material. |
| R5 | **Governed writes.** Every write carries a change ID. Outside the initial bootstrap, the change MUST exist under `ou=changes` of the naming context with status `approved` or `applied`. |
| R6 | **History.** Every insert, update and delete is recorded with before/after values and change ID. |
| R7 | **Roles, not names.** Renderers look up bindings by `ciamBindingRole` (e.g. `ds-ldaps-service`, `ds-deployment-password`), never by hostname or resource ID. |
| R8 | **Neutral outputs are identical.** Artifacts rendered only from `intent` MUST be byte-identical for every environment. The planner checks this. |
| R9 | **Contracts are stable.** A migration plan MUST flag any `contract` value that differs between source and target. |
| R10 | **Generated means generated.** Rendered files carry a "do not edit" header, written in the file's own comment syntax (a format without comments, such as JSON, relies on the manifest), and a manifest (scope, format, SHA-256). |

## 5. Standard branches

| Branch | Object classes | Holds |
|---|---|---|
| `ou=environments` | `ciamCloud` → `ciamEnvironment` → `ciamServer`, `ou=bindings` (`ciamNetwork`, `ciamSubnetBinding`, `ciamServiceName`, `ciamFirewallRule`, `ciamEgress`, `ciamSecretRef`, `ciamKeyRef`, `ciamBackupTarget`, `ciamInterconnect`) | Where things run, per environment |
| `ou=config` | `ou=declared` (`ciamBackend`, `ciamIndex`, `ciamPasswordPolicy`, `ciamConnectionHandler`, `ciamLogPublisher`, `ciamReplicationTopology`); `ou=observed` (`ciamSnapshot` + mirrored tree) | Desired vs actual server config |
| `ou=user-schema` | `ciamUserAttribute`, `ciamUserObjectClass` | The user directory's schema: every attribute (purpose, PII class, export control) and object class, each standard or defined in the record (§6) |
| `ou=consumers` | `ciamConsumer` | Clients of the user directory (from access logs) |
| `ou=acis` | `ciamAci` | Access rules, with grantee, attributes, justification, review date |
| `ou=identity-services` | `ciamIdentityService` | The platform's own identity provider / OpenID provider as partners and applications know it: public base URL, SAML entity ID, OIDC issuer (contracts), supported scopes, signing algorithms and NameID formats, and the server role that serves it |
| `ou=integrations` | `ciamIntegration` → `ou=claims` (`ciamClaimMap`) | SAML / OIDC / partner federation and claim mappings, in the protocols' own vocabulary (grant types, token endpoint auth methods, scopes, bindings, NameID formats) |
| `ou=certificates` | `ciamCertificate` | Public facts only: fingerprint, dates, SANs, key *role* |
| `ou=external-allowlists` | `ciamExternalAllowlist` | Allowlists in **other parties'** systems that contain **our** addresses (by role) |
| `ou=custom-schema` | `ciamFieldDefinition`, `ciamRecordTypeDefinition` | Fields and record types operators define, with their metadata (§2.3) |
| `ou=runbooks`, `ou=changes`, `ou=incidents`, `ou=owners` | `ciamRunbook`, `ciamChange`, `ciamIncident`, `ciamParty` | Operations and governance. Parties are teams, partners, vendors, and the **operator** of the platform (`ciamOwnerKind: operator`); `ciamDisplayName` is how a party is named in correspondence. |

## 6. Relationship to the real (user) directory

opsdir **never stores user data.** It *describes* the user directory:
- `extdn` values name DNs in it (bind DNs, base DNs, ACI targets). They are syntax-checked but not resolved, because they live in another system.
- `ciamUserAttribute` records describe each attribute of the user directory. Indexes, ACIs, claims and consumers reference those records by `dn`, so R3 applies. You can't remove an attribute record that a claim still maps from.
- The user directory's schema is recorded, not assumed. An attribute or object class is either **standard** (in the standard LDAP schema, §2.2; every compliant server has it) or **defined in the record**: `ciamLdapOid` and `ciamLdapSyntax` (plus matching rules and single-value) for an attribute, `ciamLdapOid`, kind, superclass and MUST/MAY records for a class (`ciamUserObjectClass`). A record that is neither, or that redefines a standard OID, blocks a migration: the target directory can't be built from the record. Renderers write only the defined ones into the server's schema.

## 7. Bindings and roles

An environment is complete when it binds every **required role**. The required roles aren't a fixed list: they are the union of what every domain requires (infrastructure: `network`, `disk-encryption`) and what each **applicable adapter** requires. For example, a directory server adapter may require a subnet for its servers, a stable LDAPS service name, a backup target and the secrets its deployment needs; each adapter package documents its roles. Roles nothing binds are reported as `UNBOUND`.

Consumer firewall rules use the role `fw-consumer-<consumer>`, so the planner can match them across environments. External allowlists refer to *our* roles (`ciamRefersToRole`), so a new environment's address for that role is checked against what the other party has recorded. A service name records the certificate it presents in that environment (`ciamTlsCertificate`), so certificate users are known from data.

**Owners are data.** A finding names the owners of the entry it concerns: a service, a consumer, the network binding, or the environment. It never names a hardcoded team.

## 8. Adapter contract

Every product, cloud provider and secret store is an **adapter**: a self-contained package whose `Adapter` record declares:

| Field | Meaning |
|---|---|
| `applies(environment)` | Whether the adapter applies, decided **from directory data only**: the cloud's `ciamCloudProvider`, or the products (`ciamProductVersion`) on the environment's servers. There is no default target. `None` makes the adapter **declaration-only**: a generic adapter of a standard, which every compliant server would match, is never inferred and renders only where an environment's stack declares it. |
| `required_roles` | Roles the environment must bind for it (§7) |
| `render_neutral(directory)` | Environment-neutral files. They MUST be byte-identical for every environment (R8). |
| `render_env(environment, services)` | Environment-specific files. `services.secret_command(ref-uri)` resolves secret references at run time, through whichever adapter owns the scheme. |
| `checks` | Planner checks it adds, as `(PlanContext) → Findings` |
| `ref_schemes`, `secret_schemes` | Reference schemes it owns, and resolvers for the secret ones (§3.2) |
| `renders`, `neutral_label` | How its outputs are described in a migration plan |
| `formats` | The format of every file it renders, as `(path glob, format)` pairs; rendering refuses a file with no declared format, or one in a format no installed package registers (§9) |
| `products` | The products it renders and reads and the versions it supports, as `(product, PEP 440 range)`; `opsdir check` flags a server whose `ciamProductVersion` is outside the range |

Input is a consistent snapshot of the directory and an environment. Output is files plus `MANIFEST.json` (each file's scope, `environment-neutral` or `environment-specific`, and its SHA-256). Missing required roles are reported as `UNBOUND`, never guessed. Adding a provider or product means adding an adapter and registering it. The data, the core and the other adapters don't change.

Vendor-neutral parts of the stack are **domains**. Each domain record carries its schema fragment (§2.1), required roles, SQL views and reports. Only **connectors** combine domains and adapters: the registry, render composition, the migration planner and the report catalogue.

### 8.1 Standard bases

Products build on the standards they implement instead of repeating them. A base renders a domain in a standard's own form; a product adapter renders the base's files and adds what its product configures beyond the standard:

- **LDAP:** the user directory's schema (only the definitions the record supplies) and tree (naming contexts and the containers the record refers to) as standard LDIF. A generic, declaration-only LDAPv3 adapter renders them for any compliant server; directory products render them too.
- **Product lineages:** products that share a lineage share its base (e.g. one base for the DS lineage's `dsconfig`, ACI syntax and replication checks); what differs between them is data (the product's name, administrator DN, handler names) plus its own setup and join checks.
- **SAML 2.0 and OpenID Connect:** metadata of every SAML partner and of the platform's identity provider, every OIDC client's registration metadata (RFC 7591), and the provider's discovery document. The product supplies its endpoint paths and which identity services it serves, and maps the protocols' vocabulary to its API's names.

## 9. Interchange

- **Formats are data.** Every language or file format opsdir renders or reads (LDIF, JSON, XML, YAML, shell, Java properties, INI, TOML, CSV, C, JavaScript, Groovy, Python, PowerShell, SQL, HTML, Markdown, PEM, plain text, and whatever packages add: HCL, a product's batch syntax, ...) is a registered format with its media type, file extensions, comment syntax and, where a package provides them, a reader and writer. The core registers the standard ones; a package registers the formats it brings. The registered names are the values of `ciamFormat`, so the record can say what language anything it describes is written in.

- **LDIF in, LDIF out.** Content and change records (RFC 2849) are the interchange format. `opsdir export` produces reviewable LDIF for Git.
- The schema file is standard RFC 4512. Directory servers generally ignore unknown `X-` extensions. *Not yet tested against a live LDAP server. The OIDs use the RFC 5612 documentation arc `1.3.6.1.4.1.32473` and must be replaced with a registered arc.*

## 10. Open issues

- Environment overlays (stage/prod sharing most bindings) and per-environment overrides of intent (e.g., smaller replica counts in stage).
- A read-only LDAP front end over the Postgres store (e.g., an LDAP proxy), so operators can `ldapsearch` it.
- Importers that populate `observed` automatically (the adapter contract gains importers alongside renderers): directory access-log mining → `ou=consumers`, a product's configuration export → snapshots, a federation product's admin API → integrations.
- Two-way ITSM sync for `ou=changes`.
- Validation of each adapter's rendered output against the exact product versions it declares.
