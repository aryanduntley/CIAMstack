# CIAMstack - Project Blueprint

**Version**: 1.0
**Status**: Stage 1 (FP Foundation): 1.1 and 1.2 completed; 1.3 next
**Last Updated**: 2026-09-26
**AIMFP Compliance**: Strict

---

## 1. Project Overview

### Idea

CIAMstack is a platform-agnostic, data-centric suite that puts an entire identity/CIAM stack into databases: configuration, infrastructure, dependencies, operational knowledge, and complete *metadata* for keys, certificates and secrets. Everything becomes typed, schema-checked, cross-referenced entries (the opsdir standard: LDAP information model + `X-PORTABILITY` / `X-VALUE-TYPE`, enforced in Postgres). The suite links to real providers and products through adapters and converts in both directions: **files/settings/APIs -> DB** (importers) and **DB -> files** (renderers). A migration renders the same database for a new environment; only the bindings change. Sensitive material is never stored. The DB records only what it is, where it lives and how to reconstruct it.

### Current Phase

Paths 1-3 are complete (FP foundation incl. the product-only docs and management-first showcase; the platform-agnostic core; PingAM, PingIDM and PingGateway). Path 4 (importers) is in progress: DS configuration (config.ldif + archived configs -> observed snapshots, or the declared configuration), DS access logs (-> consumers, values-free, with the `consumers` review report), PingFederate (bulk export -> integrations, claims, certificate facts; data stores checked) and the string census (`opsdir census` -> where the record's values occur in files) are done; cloud & IaC importers (3.5) are in progress: the neutral inventory mapper (core/inventory.py) and the AWS Terraform-state importer are done, then Azure state, cloud CLI inventories, CloudFormation / ARM-Bicep, and the showcase. scripts/test.sh: 842 tests pass (unit + Postgres integration + showcase golden).

### Goals

- Modular, Functional, Procedural codebase: immutable data, pure domain functions, effects at the edges, domain modules with thin orchestrators
- Fully agnostic: no targeted cloud or landing zone, compute style (VM/EC2, Kubernetes), product lineage (PingDS/ForgeRock DS, PingDirectory, PingFederate, PingAccess, AM, IDM, IG, SiteMinder), product version, or enterprise tool vendor (ITSM, SIEM, PAM, PKI/CA, firewall manager). Each is a value in the DB, handled by parsers/adapters
- Two-way conversion for every covered artifact (files >> db >> files), with round-trip tests; output parseable into any major target system
- Keys/certs/secrets described fully enough to rebuild the stack elsewhere (type, algorithm, HSM-backed, exportability, store location ref, rotation, continuity, usedBy); secret material never enters the DB
- Product-internal choices (e.g. where PF keeps OAuth clients: XML, JDBC or LDAP) are database entries with parsers covering every case, never build-time decisions
- Version-neutral moves: versions are data carried unchanged through a migration; upgrades are separate changes
- Cover every STACK.md section 21 gap and every section 22 question as data + parsers
- Management first: the record is what the platform is operated from; migration is one feature, not the product's framing
- Operators can record facts nobody foresaw: custom fields and record types with rich metadata, governed like all data
- Language/format agnostic: every format rendered or read is registered data; adapters declare the formats of their files and the product versions they support

### Success Criteria

- No class with methods and no module-level mutable state in the codebase; pytest + integration suite green
- A new provider, product, version or enterprise-tool vendor is added by schema data + an adapter, without core changes; core modules contain no vendor-, version- or landing-zone-specific branches
- Importers exist for DS config, DS access logs, PF, string census, cloud/IaC; renderers exist for every covered target, and each adapter passes its round-trip tests
- Planner output for a migration lists every blocker (contracts, bindings, keys, allowlists, consumers, certificates, drift, unknowns) with owners and dates
- Rendered artifacts validated against real products (PingDS, PF Admin API, an LDAP server, terraform plan)
- SPEC 1.0 published with a registered OID arc

---

## 2. Technical Blueprint

### Language & Runtime

- **Primary Language**: Python 3.14 (plus PostgreSQL SQL/PLpgSQL for enforcement, Bash for wrappers)
- **Runtime/Framework**: standard library + psycopg 3; PostgreSQL 17
- **Build Tool**: none. Local venv `opsdir/.venv` (`PIP_USER=0 --no-cache-dir`), wrapper scripts

### Architecture Style

- **Paradigm**: Functional Procedural (AIMFP)
- **Pattern**: Pure functions with explicit data flow, effect isolation
- **State Management**: Immutable data structures; the database is the only durable state and every write is governed (change id, history)

### Key Infrastructure

- PostgreSQL 17: the store. It enforces the LDAP model plus R3 referential integrity, R5 governed writes and R6 history. The system cluster on localhost:5432 (role opsdir; databases opsdir for dev/demo and opsdir_test for tests); schema versioned by numbered migrations (opsdir migrate)
- psycopg 3: DB driver (wrapped by the `store` module only)
- Terraform (optional): `fmt`/`validate` of rendered code
- pytest: unit suites (core, packages, showcase) + integration suites against Postgres; `opsdir/scripts/test.sh`

### Package Structure

Current (paths 1-3 done, path 4 in progress): an agnostic core, adapter/base/format packages, and a separate showcase.
```
opsdir/              the core package (pyproject: opsdir), names no platform/product/vendor/secret store
  opsdir/            core/ (records, standard + OID arcs, ldap_schema catalogue, formats, versions, interchange,
                     environment + overlays, capture, secrets, inventory: neutral cloud resources -> bindings)
                     store/ (Postgres: versioned migrations, governed writes, schema phases, re-validation)
                     domains/{infrastructure,directory,federation,pki,governance,custom,configuration}
                     (configuration: captured files, bundles, the census of values copied into files)
                     connectors/ (registry, schema, stack, render, plan, migration, workspace, reports) cli.py
  schema/            ciam-ops.schema.ldif (published export of the core + domain fragments; scripts/gen-schema.py)
  scripts/           dev-install.sh dev-env.sh gen-schema.py test.sh
  tests/             core tests (unit + integration) with mini_estate.py: a fake adapter, no real one needed
packages/            installable packages; adapters register via opsdir.adapters, formats via opsdir.formats:
  standards          opsdir-adapter-ldap (standard LDIF + declaration-only generic adapter), opsdir-base-saml,
                     opsdir-base-oidc
  lineages/products  opsdir-base-ds (OpenDJ -> ForgeRock DS -> PingDS), opsdir-adapter-pingds,
                     opsdir-adapter-opendj, opsdir-adapter-pingfederate, opsdir-adapter-pingam,
                     opsdir-adapter-pingidm, opsdir-adapter-pinggateway (each with an importer of the product's
                     own export: Amster, IDM project, gateway config; the DS lineage imports config.ldif,
                     archived configs and JSON access logs; PingFederate its Admin API bulk export)
  clouds/stores      opsdir-adapter-aws (imports Terraform state), opsdir-adapter-azure,
                     opsdir-adapter-hashicorp-vault, opsdir-adapter-kubernetes, opsdir-adapter-cyberark (PAM)
  formats            opsdir-format-terraform (hcl; Terraform state reader)
examples/showcase/   the fictional estate: example_estate/ data/ exports/ (product exports, generated DS configs
                     and access logs, census files) changes/ golden/ scripts/ tests/ demo.sh
pytest.ini           one test configuration (core, packages, showcase); opsdir/scripts/test.sh runs everything
```
Dependencies point one way: packages -> core; inside the core connectors -> domains -> core and
connectors -> store -> core; domains never import the store. The registry discovers domains (opsdir.domains),
adapters (opsdir.adapters) and formats (opsdir.formats) through entry points; rendering and planning take the
installed adapters as a parameter. Contracts (Domain, Adapter, Format, Report) are records of data and functions.
Naming rule: packages registering an adapter are opsdir-adapter-*, libraries opsdir-base-*, formats opsdir-format-*.
Schema OIDs: each owner has an arc (PEN .1 core/domains, .2 showcase user schema, .3.<n> packages, .4 custom).

---

## 3. Project Themes & Flows

### Themes

1. **Data Model & Standard**: schema, portability classes, value types, branches (`schema.py`, `gen-schema.py`, `ciam-ops.schema.ldif`)
2. **Store & Governance**: Postgres rules R1-R10, history, export (`db.py`, `sql/*.sql`)
3. **Importers (files/APIs -> DB)**: live-system and file adapters (Stage 3+)
4. **Renderers (DB -> files)**: adapter packages (`packages/*`), composed by `connectors/render.py`
5. **Provider & Lineage Agnosticism**: adapter contract and registry (Stage 2)
6. **Keys, Secrets & PKI Metadata**: reference-only key/cert/credential model (Stage 2)
7. **Planning, Queries & Reports**: `plan.py`, `reports.py`, `002_reports.sql`
8. **Tooling, Testing & Showcase**: generators, checker, demo, pytest

### Flows

1. **Schema Bootstrap**: gen-schema -> schema LDIF -> parse -> registry (Themes 1, 2)
2. **Ingest (files -> DB)**: LDIF/importer -> canonicalize -> governed insert -> validation + reference check -> history (Themes 3, 2)
3. **Governed Change**: approved change -> LDIF change records -> atomic apply -> history; rejections enforced (Theme 2)
4. **Render (DB -> files)**: env spec -> snapshot -> env model -> neutral + provider renderers -> manifest (Themes 4, 5, 6)
5. **Migration Planning**: two envs -> render + compare -> PLAN.md + request drafts (Theme 7)
6. **Query & Report**: filters, SQL views, drift, blast radius (Theme 7)
7. **Export & History**: DB -> LDIF for Git review; change history (Theme 2)
8. **Showcase & Verification**: gen-synthetic -> demo -> check-findings; pytest (Theme 8)

---

## 4. Completion Path

### Path 1: FP Foundation (Modular, Functional, Procedural rewrite) - completed
- 1.1 FP core data model, 1.2 Modular layout, 1.3 Test harness, 1.4 Database setup & SQL versioning,
  1.5 Product-only documentation incl. the management-first showcase reframe

### Path 2: Platform-Agnostic Core - completed
- 2.1 Agnostic core + adapter packages, 2.2 Extensible versioned schema, 2.3 Keys/certificates/secrets model,
  2.4 Environment overlays & overrides, 2.5 Reference artifact store & data safety, 2.6 Vendor/version/format
  neutrality, 2.7 Standard bases (LDAP, SAML, OIDC), 2.8 Operations layer

### Path 3: ForgeRock / Ping Product Lineage - completed
- 3.1 PingAM, 3.2 PingIDM, 3.3 PingGateway, as adapter packages on the standard bases

### Path 4: Importers (files/APIs -> DB) - in progress
- DS configuration importer, DS access-log miner (+ consumers review report), PingFederate importer, string census
  (completed); cloud & IaC importers (in progress: AWS Terraform state done; Azure state, CLI inventories,
  CloudFormation / ARM-Bicep, showcase to go)

### Path 5: Stack Coverage
- PF depth, hidden automation, host baseline & Kubernetes workloads, messaging & external services, data profile, observability intent

### Path 6: Renderers & Targets
- PF renderer (real target), Kubernetes/ForgeOps, config management & on-prem, observability renderers, round-trip guarantees, cloud-native IaC renderers (ARM/Bicep, CloudFormation)

### Path 7: Conditional Products & Governance
- PingAccess and SiteMinder adapters, enterprise tool integrations (vendor-agnostic), unknowns register

### Path 8: Interfaces, Validation & Release
- Management interfaces, validation against real products (first an existing AWS platform, then a staging move AWS -> Azure; validation/ folder), SPEC 1.0, docs & showcase, AI interface (MCP server, incl. a consumer verification tool)

Post-completion paths: Added Features (998), Updates (999).

---

## 5. Evolution History

### Version 1 - 2026-09-26

- **Change**: AIMFP adoption of the existing opsdir prototype; scope reset from a demo to the real product
- **Rationale**: The user wants a platform-agnostic, data-centric suite for storing, managing, converting and migrating whole identity stacks. The synthetic demo stays only as a showcase and test fixture. The codebase must be rewritten to Modular/Functional/Procedural form as a project requirement.

### Version 1.1 - 2026-09-26

- **Change**: STACK.md section 22 is no longer treated as out of scope. Every one of those questions (lineage, VM vs Kubernetes, PF client storage, HSM keys, consumer binding style, landing zone, versions, enterprise tool vendors) is answered by data + parsers. Added milestone 2.6 (vendor & version neutrality); broadened 2.1, 3.3 and 6.2.
- **Rationale**: The system is built for agnostic use, so per-estate facts are values in the DB, not build-time decisions.

### Version 1.2 - 2026-09-27

- **Change**: The core names no platform, product, vendor or secret store; every adapter is its own package discovered by entry points; declared stacks, change sets, migration workspaces. New path 3 (ForgeRock/Ping lineage) and milestone 2.7 (standard bases); later paths renumbered 4-8.
- **Rationale**: Management of any stack, with this CIAM stack as the first; migration is one capability of the management system.

### Version 1.3 - 2026-09-28

- **Change**: Standard bases (LDAP once in the core; generic LDAPv3, DS lineage, SAML and OIDC bases; OpenDJ adapter; identity services). Extensible schema (package fragments under own OID arcs; custom fields and record types with rich metadata, value rules, re-validation). Formats and supported product versions as data.
- **Rationale**: Products build on the standards they implement; operators must be able to record facts nobody foresaw; what a managed system is written in is data, not an assumption (only CIAMstack's own code is Python).

### Version 1.4 - 2026-09-30

- **Change**: Paths 1-3 closed; the documentation and showcase describe the product only, management first (the move is one chapter; the target is an ordinary second environment). Path 4 importers: DS config snapshots (import time in the importer contract, .gz exports), DS access logs (values-free consumers; `consumers` review report; dated directory reports), PingFederate bulk export, string census (ciamScannedFile/ciamOccurrence; planner flags hard-coded source values), and the neutral cloud inventory mapper with the AWS Terraform-state importer. New milestone 5.6 (ARM/Bicep and CloudFormation renderers); 7.2 records the testing plan; 7.4 requires a consumer verification MCP tool. README rewritten for adopters (what you can do, adapter catalogue, adapters for other systems).
- **Rationale**: The user will propose the project to an operations team after it is done (open source on GitHub): an existing platform must load without hand-written LDIF, reviews must be easy, and both clouds and their native IaC are covered in full.

---

## 6. User Settings System

### Purpose

Allow users to customize AI behavior on a per-directive basis through atomic key-value preferences stored in `user_preferences.db`.

### Active Preferences

No preferences set yet.

---

## 7. User Custom Directives System

**Status**: NULL. Not applicable: regular software development project (Case 1).

---

## 8. Key Decisions & Constraints

### Architectural Decisions

- **LDAP information model on Postgres**: the model is LDAP (DIT, DNs, classes, MUST/MAY). Postgres adds enforced references, governed writes and history.
- **Portability classes drive migration**: intent / contract / binding / secret-ref / observed / meta. Only bindings are rewritten per environment.
- **Roles, not names (R7)**: renderers resolve bindings by role; provider-specific settings (e.g. NSG priority) are pinned in data, never computed at render time.
- **Adapters, not forks**: providers, compute styles and product lineages plug in through one importer/renderer contract selected by data.
- **Self-contained technologies, explicit connectors**: each technology's schema fragment and parsers/renderers live together in its adapter package; code never mixes systems. Cross-technology behaviour (render composition, migration planning, cross-cutting reports) lives only in connectors.
- **Refactor before expanding**: Stage 1 must keep rendered outputs byte-identical and the findings check passing.

### Constraints

- **FP Compliance Mandatory**: all code must be pure functional (no OOP, no mutations); effects isolated at the edges
- **No secret material, ever**: secret-ref attributes hold reference URIs only (R4); importers scan and redact; the census flags, never stores
- **User data is described, not copied**: counts, distributions and shape only
- **Generated means generated**: rendered files carry do-not-edit headers and SHA-256 manifests (R10)
- **No targeting**: no specific cloud/landing zone, product version or tool vendor is assumed anywhere in core code; each is data selected at run time
- **Versions stay out of a move**: a migration re-hosts the recorded versions; any upgrade is its own change
- **Dev databases**: the local system PostgreSQL 17, role `opsdir` (dev-only password `testpass`; build/test use only, not a security boundary), database `opsdir` (dev/demo, `OPSDIR_DSN`) and `opsdir_test` (tests, `OPSDIR_TEST_DSN`). The private throwaway cluster was removed in milestone 1.4.

---

## 9. Notes & References

### Important Context

- `documentation/STACK.md`: full stack inventory and datification map; section 21 is the gap/build order; section 22's questions are all covered as data + parsers (see Evolution 1.1)
- `opsdir/SPEC.md`: the standard (rules R1-R10, branches, renderer contract)
- `documentation/ops-directory-model.md`: design rationale. It still contains interview/pitch framing that milestone 1.5 removes.
- Synthetic data is fictional ("Example Aero", RFC 5737 IPs, AWS doc account 111122223333, RFC 5612 OID arc)
- Global pip config has `user = true`; venv installs need `PIP_USER=0`

### External References

- PingDS docs (crypto keys, replication, upgrade by adding servers): docs.pingidentity.com / backstage.forgerock.com
- PingFederate Admin API and configuration archive: docs.pingidentity.com/pingfederate
- RFC 4512 (LDAP schema), RFC 4515 (filters), RFC 2849 (LDIF), RFC 5612 (documentation OIDs)
