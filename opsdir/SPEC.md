# opsdir: an LDAP-model standard for platform configuration

**Status:** draft 0.4 (2026-09-28), Aryan Duntley. Reference implementation in this folder.

*0.2: the schema is composed from per-domain fragments with pinned OIDs (§2.1); reference schemes, required roles and renderers come from adapters (§3.2, §7, §8); owners and the operator are data (§5).*
*0.3: one standard LDAP catalogue for both LDAP layers (§2.2); the user directory's schema is recorded (§6); the platform's own identity services and the federation protocols' standard vocabulary (§5); declaration-only adapters and standard bases (§8).*
*0.4: package-owned fragments under their own OID arcs (§2.1); custom fields and record types defined in the record itself (§2.3); value rules (§3.2); file formats and supported product versions are data (§8, §9).*

## 1. Purpose

A platform's configuration is usually spread across infrastructure-as-code files, CLI batch files, admin consoles, spreadsheets and people's heads. **opsdir** puts it in a directory instead: one tree of typed, schema-checked, cross-referenced entries, the system of record the platform is operated from. Working configuration (infrastructure code, product configuration, setup scripts) is **generated** from that tree by adapters, and read back into it by their importers.

Consequences:
- **A change is a directory entry,** made under an approved change record. Files are re-rendered, never hand-edited.
- **Questions become queries:** blast radius, expiry, drift, who can read what, which external allowlists hold our addresses.
- **Every environment is a read.** The same record is rendered for each environment; only that environment's *bindings* differ. Moving a platform to a new environment is therefore one capability of the record: declare the new bindings, plan, render.

The first domain is a CIAM platform (directory, federation, PKI and the infrastructure they run on), but nothing in the model is specific to it or to any product.

## 2. Information model (inherited from LDAP)

opsdir uses the LDAP information model unchanged (RFC 4512):

- **Entries** in a tree (DIT), named by **DNs**. Naming context: `dc=ciam-ops`.
- **Object classes** (ABSTRACT / STRUCTURAL / AUXILIARY, with inheritance) define MUST and MAY attributes.
- **Attribute types** with syntax, equality rule and single/multi-value.
- The schema is published as a standard LDAP schema file: `schema/ciam-ops.schema.ldif`.

### 2.1 Schema fragments and pinned OIDs

The published schema is **composed**, never hand-edited. Each part of the stack owns a *schema fragment*: the core (the base class `ciamObject`, ownership, and vocabulary shared by several domains), and each domain (infrastructure, directory, federation, pki, governance, configuration, automation, compute, messaging). Adapters may add fragments for product-specific facts. `scripts/gen-schema.py` composes the standard definitions and every fragment into the file.

- **OIDs are pinned by number** in each definition (`<arc>.1.<n>` for attribute types, `<arc>.2.<n>` for object classes). They are never derived from position. Moving a definition between fragments of one arc never renumbers anything, and a published number is never reused.
- **Each owner has an arc.** The core and its domains share the opsdir arc; an adapter package that adds definitions numbers them under an arc of its own, so packages written independently never collide. In this repository, sub-arcs of the documentation PEN: `.1` the core and its domains, `.2` the showcase's user-directory schema, `.3.<n>` packages, `.4` fields users define in the record.
- Composition is refused when fragments reuse an OID (in any arc) or a name, or when a class uses an attribute or superclass that no fragment defines.
- The store's registry is the composition of the core's, the domains' and the installed adapters' fragments. A definition no installed part defines any more is removed on upgrade, unless entries still use it (then the upgrade is refused).

### 2.2 The standard LDAP schema

LDAP is the base of the model, so the standard LDAP definitions (RFC 4512 `top` and `objectClass`, RFC 4519, RFC 4524 COSINE, RFC 2798 `inetOrgPerson`, RFC 4523, RFC 2079, RFC 2247) are held once, as data, in the core. They serve both LDAP layers: opsdir's own entries use some of them (`top`, `objectClass`, `cn`, `ou`, `dc`, `description`, `mail`, `organizationalUnit`, `domain`), and the user directories opsdir manages are described against them (§6).

**opsdir never redefines a standard definition.** The published schema holds only definitions under opsdir's own arcs; the standard ones they build on are every compliant server's own. The store registers the standard definitions its entries use exactly as the standards define them (OID, syntax, matching rule, single-value, superclass, kind, MUST), adding only its own annotations (value type, portability, description), and never publishes them.

### 2.3 Custom fields and record types

Nobody can foresee every fact a platform needs recorded, so operators define their own, **in the record itself**: each definition is an entry under `ou=custom-schema` (`ciamFieldDefinition`, `ciamRecordTypeDefinition`), approved, kept in history and exported like any other. Its metadata says what it is (description, purpose, owner, sensitivity, status: proposed | active | deprecated, documentation and runbook links), what values it takes (value type, one or many values, unit, example, default, and rules: minimum, maximum, pattern, maximum length), which records carry it (record types a field applies to; a record type's required and optional fields and its parent type), where its value lives in real systems and which adapters read or write it, how it behaves in a migration (portability; whether an environment may override it), and whether the census looks for its values in files (`ciamCensusTerm`: terms operators want found wherever they are copied, such as an old brand or domain, an account ID or a bucket name, whatever the field's type).

- **Names start with `x`** (`xCostCenter`, `xFeatureFlag`): the core (`ciam…`) and packages never use that prefix, so their later definitions can't collide. OIDs are pinned numbers under the custom arc.
- The store composes the definitions into its schema next to the core's, the domains' and the packages' fragments: on every `upgrade`, and inside the approved change that adds or changes them, so one change can define a field and use it (definitions are applied first, removed last).
- A definition that can't be built is refused (a name without the prefix, an unknown value type, a rule that doesn't fit the type, an unknown record type). A change that would leave stored entries invalid (a tighter rule, a narrower type) is refused and names them; a definition entries still use can't be deleted.
- **Where the value lives.** `ciamSettingRef` links a definition to the settings of captured config files that hold its value (§9.1): structured and checked like every reference. `ciamValueSource` names places the record does not hold (a console, a register) in free text; `ciamUsedBy` names the adapters that read or write it.

## 3. Extensions (RFC 4512 `X-` extensions)

Every attribute type declares two extensions.

### 3.1 `X-PORTABILITY`: what differs between environments

| Class | Meaning | Across environments (and in a move) |
|---|---|---|
| `intent` | What the platform should be: schema, indexes, ACIs, policies, claim maps | **Moves unchanged.** Renders identically in every environment. |
| `contract` | Names other parties depend on: service FQDNs, SAML entity IDs, ACS/redirect URLs, client IDs, claim names | **Must not change.** Any difference between source and target is a blocker. |
| `binding` | Where and how intent is realized in one environment: hosts, IPs, subnets, zone IDs, sizes, images, firewall sources | **Rewritten per environment.** The only thing written by hand for a new environment. |
| `secret-ref` | Reference to a secret or key in the environment's store | **Re-bound,** never copied. The value never enters the directory. |
| `observed` | Facts measured from the running system: log-derived consumers, config snapshots | Evidence for planning. Never rendered. |
| `meta` | Ownership, status, dates, documentation, change records | Governance. |

### 3.2 `X-VALUE-TYPE`: stricter types than LDAP syntaxes

`string · int · bool · time (GeneralizedTime) · dn (internal reference) · extdn (DN in another directory) · cidr · ip · fqdn · url · port · ref-uri · json · enum:a|b|c · vocab`

An attribute type may also state **value rules** the store enforces on every value: `X-MIN`, `X-MAX` (numbers), `X-PATTERN` (a regular expression the value matches), `X-MAX-LENGTH` (characters). Custom fields use them (§2.3). `X-OVERRIDABLE TRUE` marks `intent` an environment may override (§7.2): in the core, the directory's password-policy lockout, history and age and its replication shape; a custom field when its definition says `ciamOverridable`.

`vocab` values are owned by the installed domains and adapters: each declares the values it defines (a provider adapter its provider name and partitions, a product adapter its server roles), the store syncs them on every upgrade and accepts only registered values.

`ref-uri` accepts only reference schemes that some adapter declares it owns. The store syncs them into its `ref_scheme` table on every upgrade. Which schemes exist depends only on the installed adapters: a secret store or cloud adapter declares the schemes it can resolve. Adding one adds its schemes, and the store's validation doesn't change.

## 4. Normative rules

A conforming store MUST enforce all of these, not merely document them:

| # | Rule |
|---|---|
| R1 | **Schema checking.** Object classes known. At least one structural class. Only MUST/MAY attributes. All MUST attributes present. SINGLE-VALUE respected. Every value valid for its `X-VALUE-TYPE`. |
| R2 | **Tree integrity.** The parent entry exists. The RDN value is present in the entry. Non-leaf entries can't be deleted. |
| R3 | **Referential integrity.** Every `dn`-typed value resolves to an existing entry at commit. A referenced entry can't be deleted. *(Stronger than LDAP, where referential integrity is an optional plugin.)* |
| R4 | **No secrets.** `secret-ref` attributes MUST be `ref-uri`. The schema offers no attribute that can hold secret material, and the store refuses any value (or entry name) that matches a registered form of secret material: the core registers the generic forms (private key blocks, credentials in URLs, signed tokens, secret assignments in configuration syntax, stored LDAP passwords), each adapter its vendor's. The refusal names the attribute and the form, never the value. Importers and scanners redact with the same patterns. |
| R5 | **Governed writes.** Every write carries a change ID. Outside the initial bootstrap, the change MUST exist under `ou=changes` of the naming context with status `approved` or `applied`. |
| R6 | **History.** Every insert, update and delete is recorded with before/after values and change ID. |
| R7 | **Roles, not names.** Renderers look up bindings by `ciamBindingRole` (e.g. `ds-ldaps-service`, `ds-deployment-password`), never by hostname or resource ID. |
| R8 | **Neutral outputs are identical.** Artifacts rendered only from `intent` MUST be byte-identical for every environment, except where an environment overrides an overridable value (§7.2). The planner checks this, and names each override the two environments differ by. |
| R9 | **Contracts are stable.** A migration plan MUST flag any `contract` value that differs between source and target. |
| R10 | **Generated means generated.** Rendered files carry a "do not edit" header, written in the file's own comment syntax (a format without comments, such as JSON, relies on the manifest), and a manifest (scope, format, SHA-256). |

## 5. Standard branches

| Branch | Object classes | Holds |
|---|---|---|
| `ou=environments` | `ciamCloud` → `ciamEnvironment` → `ciamServer`, `ou=stack` (`ciamStackComponent`, `ciamRequiredRole`), `ou=overrides` (`ciamOverride`), `ou=bindings` (`ciamNetwork`, `ciamSubnetBinding`, `ciamServiceName`, `ciamFirewallRule`, `ciamEgress`, `ciamSecretRef`, `ciamKeyRef`, `ciamCertificateRef`, `ciamBackupTarget`, `ciamInterconnect`) | Where things run, per environment |
| `ou=config` | `ou=declared` (`ciamBackend`, `ciamIndex`, `ciamPasswordPolicy`, `ciamConnectionHandler`, `ciamLogPublisher`, `ciamReplicationTopology`); `ou=observed` (`ciamSnapshot` + mirrored tree) | Desired vs actual server config |
| `ou=user-schema` | `ciamUserAttribute`, `ciamUserObjectClass` | The user directory's schema: every attribute (purpose, PII class, export control) and object class, each standard or defined in the record (§6) |
| `ou=consumers` | `ciamConsumer` | Clients of the user directory (from access logs) |
| `ou=acis` | `ciamAci` | Access rules, with grantee, attributes, justification, review date |
| `ou=identity-services` | `ciamIdentityService` | The platform's own identity provider / OpenID provider as partners and applications know it: public base URL, SAML entity ID, OIDC issuer (contracts), supported scopes, signing algorithms and NameID formats, and the server role that serves it |
| `ou=integrations` | `ciamIntegration` → `ou=claims` (`ciamClaimMap`) | SAML / OIDC / partner federation and claim mappings, in the protocols' own vocabulary (grant types, token endpoint auth methods, scopes, bindings, NameID formats) |
| `ou=certificates` | `ciamCertificate` | Public facts only: fingerprint, dates, SANs, key *role* |
| `ou=credentials` | `ciamCredential` | Keys and secrets as metadata, the same in every environment (§7.1); never their material |
| `ou=external-allowlists` | `ciamExternalAllowlist` | Allowlists in **other parties'** systems that contain **our** addresses (by role) |
| `ou=jobs` | `ciamJob`; per environment `ciamJobBinding` (under `ou=bindings`) | The platform's hidden automation: cron entries, timers, scheduled tasks, serverless functions and pipelines: kind, schedules and triggers, the server role it runs on or the binding role that realizes it in each environment, the roles it uses, secrets it expects by name, its code bundle, its owner |
| `ou=baselines`, `ou=workloads` | `ciamHostBaseline`, `ciamWorkload`; per environment `ciamComputeGroup` and `ciamCluster` (under `ou=bindings`) | What the servers and containers run beyond the products. A server role's host baseline: OS, Java runtime and the certificates its truststore adds (linked to `ciamCertificate`; fingerprints the record lacks are named), limits, kernel settings, huge pages, FIPS and SELinux modes, agents, service units, names pinned in `/etc/hosts`. A workload: a server role run as containers (kind, namespace, replicas, images, storage, service account, the identity role it assumes, pod security, network policies, secret names). Per environment, the compute group a role's instances run in (image, size, scale, zones, metadata tokens) and the managed cluster workloads run in (version, add-ons, node pools) |
| `ou=external-services`, `ou=mail-senders`, `ou=event-streams` | `ciamExternalService`, `ciamMailSender`, `ciamEventStream`; per environment `ciamSendingIdentity` and `ciamStreamBinding` (under `ou=bindings`) | What the platform depends on outside itself and what it tells others. An external service (SMTP relay or email API, SMS or voice provider, MFA vendor, CAPTCHA): vendor, endpoint, the domains it allows (contract), the server roles that use it, the binding roles of its credentials, SMS sender IDs, originating numbers and registrations. A mail sender: its address and domain (contract), the service that sends it, the binding role of each environment's sending identity (DKIM, SPF and DMARC facts), bounce handling. An event stream: what carries it, the events, who publishes and reads it, the binding role of each environment's queue or bus |
| `ou=custom-schema` | `ciamFieldDefinition`, `ciamRecordTypeDefinition` | Fields and record types operators define, with their metadata (§2.3) |
| `ou=runbooks`, `ou=changes`, `ou=incidents`, `ou=owners` | `ciamRunbook`, `ciamChange`, `ciamIncident`, `ciamParty` | Operations and governance. Parties are teams, partners, vendors, and the **operator** of the platform (`ciamOwnerKind: operator`); `ciamDisplayName` is how a party is named in correspondence. |

## 6. Relationship to the real (user) directory

opsdir **never stores user data.** It *describes* the user directory:
- `extdn` values name DNs in it (bind DNs, base DNs, ACI targets). They are syntax-checked but not resolved, because they live in another system.
- `ciamUserAttribute` records describe each attribute of the user directory. Indexes, ACIs, claims and consumers reference those records by `dn`, so R3 applies. You can't remove an attribute record that a claim still maps from.
- The user directory's schema is recorded, not assumed. An attribute or object class is either **standard** (in the standard LDAP schema, §2.2; every compliant server has it) or **defined in the record**: `ciamLdapOid` and `ciamLdapSyntax` (plus matching rules and single-value) for an attribute, `ciamLdapOid`, kind, superclass and MUST/MAY records for a class (`ciamUserObjectClass`). A record that is neither, or that redefines a standard OID, blocks a migration: the target directory can't be built from the record. Renderers write only the defined ones into the server's schema.

## 7. Bindings and roles

An environment is complete when it binds every **required role**. The required roles aren't a fixed list: they are the union of what every domain requires (infrastructure: `network`, `disk-encryption`), what each **applicable adapter** requires, and what the environment **declares** as data (`ciamRequiredRole` under its `ou=stack`, with why). For example, a directory server adapter may require a subnet for its servers, a stable LDAPS service name, a backup target and the secrets its deployment needs; each adapter package documents its roles. Roles nothing binds are reported as `UNBOUND`, and a migration plan blocks on every role the target must bind but doesn't.

Consumer firewall rules use the role `fw-consumer-<consumer>`, so the planner can match them across environments. External allowlists refer to *our* roles (`ciamRefersToRole`), so a new environment's address for that role is checked against what the other party has recorded. A service name records the certificate it presents in that environment (`ciamTlsCertificate`), so certificate users are known from data.

### 7.1 Keys, secrets and certificates

Keys and secrets are described in two layers joined by role, like every other binding. A **credential** (`ciamCredential`, `ou=credentials`) is what a key or secret *is*, the same everywhere: its type (private key, symmetric key, keystore, password, API token, client secret, deployment id, ...), algorithm and size, what it is used for, the form its material takes, whether it must be generated and kept in an HSM (`ciamHsmRequired`) and whether its material may leave its store (`ciamExportable`), its rotation period, its **continuity** (`carry-over`: the same material must reach every environment that takes over from or joins this one, such as a directory deployment id or a signing key partners trust; `per-environment`: each environment holds its own) and why, and everywhere it is configured or used (`ciamUsedIn`). Certificates name the role of their private key (`ciamKeyRole`); captured config settings link to it (`role#ciamRefUri`).

Each environment binds the credential's role to where it keeps the material: a secret or key reference (`ciamSecretRef`, `ciamKeyRef`), or for a certificate held in a cloud certificate store, a certificate reference (`ciamCertificateRef`, holding a `ciamCertificate`). A binding records what its store does for the material: protection level (software, HSM, managed HSM, external key store), automatic rotation and the function that rotates it, replica regions (multi-region keys, replicated secrets), who may use and manage it (provider principal ids), when it was last rotated, other places the same environment holds it (`ciamCopyRef`, e.g. a PAM vault) and, when the material was carried over rather than regenerated, the binding it came from (`ciamMaterialFrom`). None of these can hold material (R4).

Reports: `keys ENV` (where an environment keeps every credential, credentials it doesn't bind, material bindings no credential describes), `credentials` (sprawl: every environment and store holding each credential, its copies, the certificates keyed by it, linked settings, where it is used; roles holding material that nothing describes) and `rotation-impact DN` (a credential or certificate: every binding and copy to rotate, settings to re-render, certificates to re-issue and whoever presents or trusts them, partners, the runbook). The planner blocks a move that puts HSM-only material in a software store or that must carry material over from a store it can't leave, asks for carry-over material to be copied before cutover (and recorded), and flags a target store that drops the source's automatic rotation or replicas.

### 7.2 Overlays and overrides

**Overlays.** An environment may be an overlay of another (`ciamOverlayOf`): a stage environment that shares most of production's bindings, say. It inherits its base's bindings, stack components, declared required roles and overrides, except the roles it binds or declares itself (its own binding for a role replaces all of the base's for that role), the roles it drops (`ciamDropsRole`) and the attributes it overrides itself. A base may itself be an overlay. Servers are never inherited. A cycle, a base that is not an environment, or a base on another provider is refused. `opsdir check` names each environment's base.

**Overrides.** An environment may hold its own value for one attribute of a shared entry (`ciamOverride` under its `ou=overrides`: `ciamOverrides` the entry, `ciamOverrideAttribute`, `ciamOverrideValue`, and why in its description), for attributes whose definition says `X-OVERRIDABLE` only. The store refuses an override of any other attribute, a value that is invalid for the attribute (type, vocabulary, rules, single value), or an attribute the entry's classes don't allow, and re-validates every override on upgrade. Every renderer of an environment reads the record with its overrides applied, so an environment-neutral file may carry an environment's value; the MANIFEST lists the overrides it was rendered with. `opsdir report overrides` lists every environment's overrides (its own and inherited) with the shared value and why. The planner reports each attribute the source and target run with different values because of their overrides (an action: confirm the target should behave differently), and blocks on neutral outputs that differ for any other reason. Config file settings vary per environment through links (§9.1), not overrides.

**Owners are data.** A finding names the owners of the entry it concerns: a service, a consumer, the network binding, or the environment. It never names a hardcoded team.

## 8. Adapter contract

Every product, cloud provider and secret store is an **adapter**: a self-contained package whose `Adapter` record declares:

| Field | Meaning |
|---|---|
| `applies(environment)` | Whether the adapter applies, decided **from directory data only**: the cloud's `ciamCloudProvider`, or the products (`ciamProductVersion`) on the environment's servers. There is no default target. `None` makes the adapter **declaration-only**: a generic adapter of a standard, which every compliant server would match, is never inferred and renders only where an environment's stack declares it. |
| `required_roles` | Roles the environment must bind for it (§7) |
| `render_neutral(directory)` | Environment-neutral files. They MUST be byte-identical for every environment (R8). |
| `render_env(environment, services)` | Environment-specific files. `services.secret_command(ref-uri)` resolves secret references at run time, through whichever adapter owns the scheme. |
| `checks` | Planner checks it adds, as `(PlanContext) → Findings`. A check never passes silently: data it needs but doesn't find is a finding with an owner, and a check that fails is reported as a blocker naming it and the error (the other checks still run, and the verdict can't be READY) |
| `ref_schemes`, `secret_schemes` | Reference schemes it owns, and resolvers for the secret ones (§3.2) |
| `renders`, `neutral_label` | How its outputs are described in a migration plan |
| `formats` | The format of every file it renders, as `(path glob, format)` pairs; rendering refuses a file with no declared format, or one in a format no installed package registers (§9) |
| `products` | The products it renders and reads and the versions it supports, as `(product, PEP 440 range)`; `opsdir check` flags a server whose `ciamProductVersion` is outside the range |
| `secret_patterns` | The forms its vendor's secret material takes; the store refuses any value that matches (R4) |
| `importers` | How it reads the product's own exports into the record: `read(files, directory, secret patterns)` returns the containers to create when missing, groups of entries (each group becomes exactly what a subtree holds) and notices. An importer merges with what the record already holds (entries and attributes it doesn't own are kept), withholds anything that may be secret and says so, and names what it can't place. `opsdir import [--change CHG] ADAPTER[/IMPORTER] PATH` lists the change records (`--dry-run`, or no change given) or applies them under an approved change; importing the same export again changes nothing. |

Input is a consistent snapshot of the directory and an environment. Output is files plus `MANIFEST.json` (each file's scope, `environment-neutral` or `environment-specific`, and its SHA-256). Missing required roles are reported as `UNBOUND`, never guessed. Adding a provider or product means adding an adapter and registering it. The data, the core and the other adapters don't change.

A product serving several identity services (such as one per realm) renders, for each, the integrations registered with it (`ciamServedBy`) and those that name none.

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

### 9.1 Config files in the record

A config file is held in the record so it can be rebuilt from the record alone, byte for byte (branch `ou=config-files`, `opsdir capture`, `opsdir file`). A format that can be captured registers a codec: how to cut a file into layout and settings, how to read a setting's value from its text and how to write a changed value in the format's own style. The core's codecs cover Java properties (the key), INI (`section.key`), JSON and JSON with comments (a JSON Pointer to every scalar; its type is kept), XML (`/path/@attribute`, `/path/text()` of leaf elements) and LDIF (`dn|attribute`); a repeated locator is numbered from its second occurrence (`key#2`).

- **Levels** (`ciamCaptureLevel`). `settings`: the layout on the `ciamConfigFile` entry and one `ciamConfigSetting` per setting, each governed and historied; a value is a literal or a link (`ciamValueFrom: role#attribute`) to the binding of the environment the file is rendered for (a secret reference renders as `${secret:<ref-uri>}`). `whole-file`: the file can't be parsed as its format (the reason and position are recorded); its whole text is kept. `reference`: only where the file lives (`ciamRepoPath`), its SHA-256 and why nothing else is stored.
- **Nothing that may be secret is stored.** A setting whose value matches a secret pattern, whose name says it holds a secret (its last word is password, secret, token, pin, credential, or a pair such as api key or client secret) or whose value looks random is withheld (`ciamSecretRequired`) and must be linked to a secret reference. A layout or whole text is stored only when nothing in it raises such a concern; otherwise the file is held as a reference. An operator who has reviewed a flagged text may accept it; the store's guard (R4) applies regardless.
- **Re-capture is a change set.** Capturing a file again changes only the settings that changed; settings keep their entries and history.
- **Rendering.** Each environment's render includes the captured files it receives (those deployed to a role its servers run, or to no role) under `files/<repo path>`, byte for byte with its bindings; the MANIFEST lists them (scope, format, `captured`, SHA-256) and any it could not render, with why. The planner blocks a move when a file the target receives can't be rendered there, and lists files held only as references as actions.
- **Bundles.** Code, scripts, templates and packages are not config: a `ciamBundle` (`ou=bundles`, `opsdir bundle`) records where one lives in version control, what it is, its version, where it is deployed and its SHA-256 (of the file; of a directory, of its files' `sha256  path` lines sorted by path). Its content is never stored; what in its text may be secret material is reported, since it is deployed as it is.
- **Verification.** `opsdir verify --root <checkout>` compares every bundle's digest and every captured file's rebuilt text (a reference's recorded hash) with a checkout of the repo.

## 10. Open issues

- A read-only LDAP front end over the Postgres store (e.g., an LDAP proxy), so operators can `ldapsearch` it.
- More importers (the adapter contract has them alongside renderers; the DS lineage, PingFederate, PingAM, PingIDM and PingGateway ship them): cloud and Terraform inventories → bindings.
- Two-way ITSM sync for `ou=changes`.
- Validation of each adapter's rendered output against the exact product versions it declares.
