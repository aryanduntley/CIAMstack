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

A working prototype (`opsdir/`) exists and has been cataloged: LDIF/schema parsers, Postgres store with rules R1-R10, renderers (Terraform AWS/Azure, dsconfig, DS setup, ACI LDIF, illustrative PingFederate JSON), migration planner, reports, CLI, synthetic showcase estate (229 entries) and a findings checker. It contains four classes with methods (`Entry`, `Directory`, `EnvModel`, `Block`), so Stage 1 rewrites it to Modular / Functional / Procedural form without changing behavior.

### Goals

- Modular, Functional, Procedural codebase: immutable data, pure domain functions, effects at the edges, domain modules with thin orchestrators
- Fully agnostic: no targeted cloud or landing zone, compute style (VM/EC2, Kubernetes), product lineage (PingDS/ForgeRock DS, PingDirectory, PingFederate, PingAccess, AM, IDM, IG, SiteMinder), product version, or enterprise tool vendor (ITSM, SIEM, PAM, PKI/CA, firewall manager). Each is a value in the DB, handled by parsers/adapters
- Two-way conversion for every covered artifact (files >> db >> files), with round-trip tests; output parseable into any major target system
- Keys/certs/secrets described fully enough to rebuild the stack elsewhere (type, algorithm, HSM-backed, exportability, store location ref, rotation, continuity, usedBy); secret material never enters the DB
- Product-internal choices (e.g. where PF keeps OAuth clients: XML, JDBC or LDAP) are database entries with parsers covering every case, never build-time decisions
- Version-neutral moves: versions are data carried unchanged through a migration; upgrades are separate changes
- Cover every STACK.md section 21 gap and every section 22 question as data + parsers

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

- PostgreSQL 17: the store. It enforces the LDAP model plus R3 referential integrity, R5 governed writes and R6 history. Local system cluster on 5432, plus a private throwaway cluster in `opsdir/.pgdata` (unix socket, port 54329)
- psycopg 3: DB driver (wrapped by the `store` module only)
- Terraform (optional): `fmt`/`validate` of rendered code
- pytest: unit suite (to be added in 1.3)

### Package Structure

Current (after milestones 1.1 and 1.2): each technology is self-contained; only connectors join them.
```
opsdir/
  opsdir/            core/ store/ domains/{infrastructure,directory,federation,pki,governance}
                     adapters/{pingds,pingfederate,aws,azure,hashicorp_vault} formats/ connectors/ cli.py
  schema/            ciam-ops.schema.ldif (composed from fragments by scripts/gen-schema.py)
  data/              synthetic estate (written by scripts/gen-synthetic.py from fixtures/example_estate)
  fixtures/          example_estate/: the synthetic estate as pure builders, one module per part of the stack
  changes/           approved change LDIF; changes/rejected/ = writes that must fail
  scripts/           gen-schema.py gen-synthetic.py check-findings.py pg-local.sh snapshot-outputs.sh
  tests/golden/      accepted snapshot of every output
  demo.sh opsdir.sh
```
Dependencies point one way: connectors → adapters → domains → store → core (formats used by adapters only).
Adapter contract: a record of functions (no classes).

---

## 3. Project Themes & Flows

### Themes

1. **Data Model & Standard**: schema, portability classes, value types, branches (`schema.py`, `gen-schema.py`, `ciam-ops.schema.ldif`)
2. **Store & Governance**: Postgres rules R1-R10, history, export (`db.py`, `sql/*.sql`)
3. **Importers (files/APIs -> DB)**: live-system and file adapters (Stage 3+)
4. **Renderers (DB -> files)**: `render/*`
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

### Stage 1: FP Foundation (Modular, Functional, Procedural rewrite)
- 1.1 FP core data model (completed)
- 1.2 Modular layout: core, adapters, connectors (completed)
- 1.3 Test harness
- 1.4 Database setup & SQL versioning
- 1.5 Product-only documentation

### Stage 2: Platform-Agnostic Core
- 2.1 Adapter contract & registry
- 2.2 Extensible, versioned schema
- 2.3 Keys, certificates & secrets model (incl. credential sprawl, gap 9)
- 2.4 Environment overlays & overrides
- 2.5 Reference artifact store & data safety
- 2.6 Vendor & version neutrality

### Stage 3: Importers (files/APIs -> DB)
- 3.1 DS configuration importer, 3.2 DS access-log miner, 3.3 PingFederate importer, 3.4 String census, 3.5 Cloud & IaC importers

### Stage 4: Stack Coverage
- 4.1 PF depth, 4.2 Hidden automation, 4.3 Host baseline & Kubernetes workloads, 4.4 Messaging & external services, 4.5 Data profile, 4.6 Observability intent

### Stage 5: Renderers & Targets
- 5.1 PF renderer (real target), 5.2 Kubernetes/ForgeOps, 5.3 Config management & on-prem, 5.4 Observability renderers, 5.5 Round-trip guarantees

### Stage 6: Conditional Products & Governance
- 6.1 PA/IG/AM/IDM/SiteMinder adapters, 6.2 Enterprise tool integrations (ITSM/CMDB, GRC, SIEM, PAM, PKI/CA, firewall managers; vendor-agnostic), 6.3 Unknowns register (per-estate open questions tracked as entries)

### Stage 7: Interfaces, Validation & Release
- 7.1 Management interfaces, 7.2 Validation against real products, 7.3 SPEC 1.0, docs & showcase

Post-completion paths: Added Features (998), Updates (999).

---

## 5. Evolution History

### Version 1 - 2026-09-26

- **Change**: AIMFP adoption of the existing opsdir prototype; scope reset from a demo to the real product
- **Rationale**: The user wants a platform-agnostic, data-centric suite for storing, managing, converting and migrating whole identity stacks. The synthetic demo stays only as a showcase and test fixture. The codebase must be rewritten to Modular/Functional/Procedural form as a project requirement.

### Version 1.1 - 2026-09-26

- **Change**: STACK.md section 22 is no longer treated as out of scope. Every one of those questions (lineage, VM vs Kubernetes, PF client storage, HSM keys, consumer binding style, landing zone, versions, enterprise tool vendors) is answered by data + parsers. Added milestone 2.6 (vendor & version neutrality); broadened 2.1, 3.3 and 6.2.
- **Rationale**: The system is built for agnostic use, so per-estate facts are values in the DB, not build-time decisions.

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
- **Dev databases**: private throwaway cluster (`opsdir/.pgdata`, socket 54329) or the local system PostgreSQL 17 (role `opsdir`, database `opsdir`, dev-only password `testpass`; build/test use only, not a security boundary)

---

## 9. Notes & References

### Important Context

- `STACK.md`: full stack inventory and datification map; section 21 is the gap/build order; section 22's questions are all covered as data + parsers (see Evolution 1.1)
- `opsdir/SPEC.md`: the standard (rules R1-R10, branches, renderer contract)
- `ops-directory-model.md`: design rationale. It still contains interview/pitch framing that milestone 1.5 removes.
- Synthetic data is fictional ("Example Aero", RFC 5737 IPs, AWS doc account 111122223333, RFC 5612 OID arc)
- Global pip config has `user = true`; venv installs need `PIP_USER=0`
- `.pgdata` needs mode 0700 if the folder is copied

### External References

- PingDS docs (crypto keys, replication, upgrade by adding servers): docs.pingidentity.com / backstage.forgerock.com
- PingFederate Admin API and configuration archive: docs.pingidentity.com/pingfederate
- RFC 4512 (LDAP schema), RFC 4515 (filters), RFC 2849 (LDIF), RFC 5612 (documentation OIDs)
