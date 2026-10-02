# CIAMstack - Project Blueprint

**Version**: 1.10
**Status**: Paths 1-4 completed; path 5 (Stack Coverage) in progress: 4.1-4.4 done (PingFederate depth, hidden automation, host baseline & Kubernetes workloads, messaging & external services), 4.5 next; Updates U.6 (shared helpers) and U.7 (deferred notes 352, 331) done, U.4 (package READMEs) open
**Last Updated**: 2026-10-01
**AIMFP Compliance**: Strict

---

## 1. Project Overview

### Idea

CIAMstack is a platform-agnostic, data-centric suite that puts an entire identity/CIAM stack into databases: configuration, infrastructure, dependencies, operational knowledge, and complete *metadata* for keys, certificates and secrets. Everything becomes typed, schema-checked, cross-referenced entries (the opsdir standard: LDAP information model + `X-PORTABILITY` / `X-VALUE-TYPE`, enforced in Postgres). The suite links to real providers and products through adapters and converts in both directions: **files/settings/APIs -> DB** (importers) and **DB -> files** (renderers). A migration renders the same database for a new environment; only the bindings change. Sensitive material is never stored. The DB records only what it is, where it lives and how to reconstruct it.

### Current Phase

Paths 1-4 are complete (FP foundation incl. the product-only docs and management-first showcase; the platform-agnostic core; PingAM, PingIDM and PingGateway; importers). Path 4 importers: DS configuration (config.ldif + archived configs -> observed snapshots, or the declared configuration), DS access logs (-> consumers, values-free, with the `consumers` review report), PingFederate (bulk export -> integrations, claims, certificate facts; data stores checked), the string census (`opsdir census`), and the clouds for AWS and Azure alike: Terraform state, CLI inventories and native IaC (CloudFormation stacks; ARM templates and Bicep with their deployments), all through one neutral mapper (core/inventory.py: roles from tags, container metadata or a per-environment roles.json; account-wide listings counted; the record's value order kept) and one attribute mapping per provider. `import --dry-run` lists what each change sets; the showcase shows planted cloud drift that way. Path 5 (Stack Coverage) is in progress. 4.1 PingFederate depth: the PingFederate package's own schema (arc .3.4) holds data stores, plugin instances (validators, adapters, selectors, token managers), policy contracts, authentication policy trees and fragments, OIDC policies, settings, nodes' facts, cluster discovery as a binding and every other resource held as is, with links checked by the planner (IdP connections and key pairs by the PingFederate id their integration or certificate carries, exactly one). 4.2 hidden automation: the core `automation` domain (`ciamJob`, `ciamJobBinding`, `jobs` report, planner check) fed by opsdir-adapter-linux (cron, systemd timers), the cloud adapters (Lambda/EventBridge/Scheduler/CodePipeline/CodeBuild, Azure Function Apps) and the CI packages opsdir-adapter-github-actions, -gitlab-ci, -azure-devops. 4.3 host baselines and Kubernetes workloads, 4.4 messaging and external services, 4.5 data profile, 4.6 observability intent and 4.12 Google Cloud (a third cloud at parity, with its Terraform state and Cloud Asset Inventory importers and a showcase standby) are done; the cloud milestones 4.7-4.11 come next, each across AWS, Azure and Google Cloud. Open alongside: U.4 (package READMEs; Azure, AWS and Google Cloud done). scripts/test.sh: all tests pass (unit + Postgres integration + showcase golden).

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

Current (paths 1-4 done): an agnostic core, adapter/base/format packages, and a separate showcase.
```
opsdir/              the core package (pyproject: opsdir), names no platform/product/vendor/secret store
  opsdir/            core/ (records, standard + OID arcs, ldap_schema catalogue, formats, versions, interchange,
                     environment + overlays, capture, secrets, inventory: neutral cloud resources -> bindings)
                     store/ (Postgres: versioned migrations, governed writes, schema phases, re-validation)
                     domains/{infrastructure,directory,federation,pki,governance,custom,configuration,
                     automation} (configuration: captured files, bundles, the census of values copied into files;
                     automation: jobs, with the pipeline placement every CI package shares)
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
  clouds/stores      opsdir-adapter-aws and opsdir-adapter-azure (each imports Terraform state, its CLI's
                     output and its native IaC: CloudFormation / ARM-Bicep), opsdir-adapter-gcp (Terraform state,
                     Cloud Asset Inventory + gcloud output),
                     opsdir-adapter-hashicorp-vault, opsdir-adapter-kubernetes, opsdir-adapter-cyberark (PAM)
  hosts/delivery     opsdir-adapter-linux (kind host: cron and systemd timers as jobs; host baseline in 4.3),
                     opsdir-adapter-github-actions, opsdir-adapter-gitlab-ci, opsdir-adapter-azure-devops (kind
                     delivery: pipelines as jobs); all declaration-only for now
  formats            opsdir-format-terraform (hcl; Terraform state reader)
examples/showcase/   the fictional estate: example_estate/ data/ exports/ (product exports, generated DS configs
                     and access logs, census files, generated cloud state/CLI output with planted drift) changes/
                     golden/ scripts/ tests/ demo.sh
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

### Path 4: Importers (files/APIs -> DB) - completed
- 3.1 DS configuration importer, 3.2 DS access-log miner (+ consumers review report), 3.3 PingFederate importer,
  3.4 string census, 3.5 cloud & IaC importers (AWS and Azure: Terraform state, CLI inventories, CloudFormation /
  ARM-Bicep; roles.json; showcase drift via --dry-run)

### Path 5: Stack Coverage - in progress
- Done: 4.1 PingFederate depth, 4.2 hidden automation (jobs: hosts' schedulers, cloud functions and AWS pipelines,
  GitHub Actions / GitLab CI / Azure DevOps)
- Done also: 4.3 host baseline & Kubernetes workloads, 4.4 messaging & external services, 4.5 data profile
  (`opsdir data-profile` streams ldapsearch output to counts, no database; `ldap/data-profile` imports; directory
  domain `ou=data-profile`, reports and planner checks; Adapter.profile_terms + operator `--term`s)
- Done also: 4.6 observability intent (core domain `observability`: alert rules, log routes, canaries; channels,
  log destinations, alarms and checks each cloud runs, from AWS/Azure Terraform state; planner checks)
- Done also: 4.12 Google Cloud adapter (opsdir-adapter-gcp) at parity with AWS and Azure: Terraform renderer
  (Shared VPC data sources, network-tag firewall rules, CMEK/Shielded VM, passthrough LBs with health-check rules),
  gcp/terraform-state and gcp/cli-inventory (Cloud Asset Inventory + gcloud) through one mapping; showcase
  standby/prod on Google Cloud. From now on every cloud milestone covers AWS, Azure and GCP (2026-10-02)
- Next: platform IAM (4.7), edge (4.8), network depth (4.9, with the GCP firewall model as a per-environment choice:
  network tags or firewall policies with secure tags), data services/backup/DR (4.10), cloud governance (4.11)

### Path 6: Renderers & Targets
- PF renderer (real target), Kubernetes/ForgeOps, config management & on-prem, observability renderers, round-trip guarantees, cloud-native IaC renderers (ARM/Bicep, CloudFormation)

### Path 7: Conditional Products & Governance
- PingAccess and SiteMinder adapters, enterprise tool integrations (vendor-agnostic), unknowns register

### Path 8: Interfaces, Validation & Release
- Management interfaces, validation against real products (first an existing AWS platform, then a staging move AWS -> Azure; validation/ folder), SPEC 1.0, docs & showcase, AI interface (MCP server, incl. a consumer verification tool)

Post-completion paths: Added Features (998), Updates (999; open: U.4 package READMEs to a common standard; U.5 no
secret values in rendered Terraform state, completed).

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

### Version 1.5 - 2026-09-30

- **Change**: Path 4 closed with milestone 3.5: AWS and Azure read back from Terraform state, CLI output and native IaC (CloudFormation; ARM/Bicep with an ARM expression evaluator), one neutral mapper and one attribute mapping per provider; roles for what a cloud can't tag from container metadata or a per-environment roles.json (never a placeholder role: ciamBindingRole is required and is what migrations match on); `--dry-run` shows each modification; the showcase plants cloud drift. Updates path reopened: U.4 package READMEs to a common standard (Azure done), U.5 the Azure renderer no longer reads secret values into Terraform state (names-only existence checks).
- **Rationale**: An existing platform, whatever its IaC, must load without hand-written LDIF and show how it differs from the record before anything is written; future sessions must not miss behavior, so each package documents itself to one standard.

### Version 1.6 - 2026-10-01

- **Change**: Milestones 4.1 (PingFederate depth) and 4.2 (hidden automation) done. PingFederate's own objects live in its package's schema (prefix pingfed) rather than STACK.md's planned ciam* classes; core helpers shared across products (bound/secret placeholders, consumer by bind DN, merged_attrs, server_named). New core domain `automation`; adapter kinds `host` and `delivery`; packages opsdir-adapter-linux, -github-actions, -gitlab-ci, -azure-devops (user: CI systems as modules, others added later).
- **Rationale**: The core names no product; links between a product's objects are checked from the record alone; automation nobody owns breaks silently after a move, so every scheduler and CI system feeds one neutral job model the planner and reports read.

### Version 1.7 - 2026-10-01

- **Change**: Milestone U.6: a modularity audit (user, before 4.3) found small helpers re-written in many adapter packages; 16 public core helpers replace them, every module-level constant is read-only, and the package-authoring guide lists the helpers. No output changed (golden snapshot byte-identical) except PingFederate certificate times without a zone, now UTC instead of the machine's local time.
- **Rationale**: Modularity is the key design constraint; 4.3 onward adds many more importers, which would otherwise copy the same helpers again.

### Version 1.8 - 2026-10-01

- **Change**: Milestone 4.3: new built-in core domain `compute`: `ciamHostBaseline` (one per server role: OS, Java runtime and truststore additions, limits, kernel settings, huge pages, FIPS/SELinux, agents, service units, pinned hosts, search domains), `ciamComputeGroup` and `ciamCluster` (per-environment bindings: autoscaling groups / scale sets, managed Kubernetes clusters), `ciamWorkload` (a server role run as containers); reports baselines/compute/workloads; planner checks. opsdir-adapter-linux `linux/baseline`; AWS and Azure read compute groups and EKS/AKS clusters from Terraform state; opsdir-adapter-kubernetes `kubernetes/workloads` (workloads and CronJobs as jobs). Compute groups and clusters are binding roles like any other (`compute-<role>`, `cluster` by default), so the target must bind what the source binds.
- **Rationale**: What servers run beyond the product (custom CAs in the Java truststore, pinned names, kernel limits) breaks silently after a rebuild or a move; VMs and Kubernetes are both first-class realizations of the same server roles.

### Version 1.9 - 2026-10-01

- **Change**: U.7 (deferred notes): AWS firewall rules name ranges, all-ports and non-IPv4 sources instead of truncating (#352); operator-defined census terms (`ciamCensusTerm` on a field definition) and `census --replace` (#331). Milestone 4.4: new built-in core domain `messaging`: `ciamExternalService` (relays, email/SMS/voice providers, MFA, CAPTCHA: allowed domains as contract, the roles that use them, their credential roles), `ciamMailSender`, `ciamSendingIdentity` (binding: DKIM/SPF/DMARC), `ciamEventStream` + `ciamStreamBinding`; reports and planner checks; shared SPF/DMARC parsing. PingFederate notification publishers and CAPTCHA providers become plugin kinds read into it (#368 partly); AWS (SES + Route 53, SQS/SNS/EventBridge/Kinesis) and Azure (Communication Services + Azure DNS, Service Bus/Event Hubs/Event Grid) read sending identities and stream carriers. Deferred notes now name the milestone they're done with (#366 -> 4.10, #395 -> 5.6).
- **Rationale**: Services outside the platform break silently at a move: a CAPTCHA that doesn't allow the new names, reset mail from an unverified domain landing in spam, audit events nobody carries. Census terms are operator data because nobody can list in advance what an estate needs found.

### Version 1.10 - 2026-10-02

- **Change**: Milestone 4.12 (Google Cloud adapter to parity with AWS and Azure) added; every later cloud milestone covers AWS, Azure and GCP (scope gap-checked by Codex, notes #409, #411). U.8: PingFederate cluster discovery is rendered as `pingfederate/cluster/jgroups.properties` (PingFederate 11.0+ configures discovery there) and the protocol is data per environment (`pingfedDiscoveryProtocol` on the `pf-cluster-discovery` binding, class `pingfedClusterDiscovery`; implied by an s3:// bucket or a DNS name), from a protocol table in the adapter (rendered: TCPPING, NATIVE_S3_PING, DNS_PING). AZURE_PING, which Ping doesn't document, is no longer rendered and is a planner blocker.
- **Rationale**: Ping's clustering guides (12.3, 13.0) list TCPPING, NATIVE_S3_PING, DNS_PING, AWS_PING and SWIFT_PING only; the user asked for the choice to be modular data, not hard-coded per cloud.
- **Change**: Milestone 4.5 data profile: built-in directory domain gains `ou=data-profile` (`ciamDataProfile`, `ciamBranchProfile` with `ciamProfiledBranch`, `ciamAttributeProfile`), a streaming values-free profiler (chunked counts merged pairwise; masked branches, scheme names from a known list, operational attributes left out), the profile file format `opsdir-data-profile/1` re-validated on import, reports `data-profile`/`data-profile-attributes` and a planner check. New CLI `opsdir data-profile` (needs no database), tolerant streaming LDIF reader `content_entries`, Adapter contract field `profile_terms` (opsdir-base-ds supplies the DS lineage's), operator `--term NAME=ATTRIBUTE[=VALUE]`, importer `ldap/data-profile`. Showcase: synthetic user data with four planted findings (A30-A33), CHG-2014.
- **Rationale**: user decision (note #417): the data streams through memory where the directory is reachable and only counts are written, so no copy of personal data lands in an export folder and directories of any size fit.
- **Change**: Milestone 4.6 observability: new built-in core domain `observability` (module 41): `ciamAlertRule`, `ciamLogRoute`, `ciamCanary` as intent; bindings `ciamAlertChannel`, `ciamLogDestination` (retention; 0 indefinite), `ciamAlarmBinding`, `ciamCanaryBinding` (what each cloud runs, `ciamRealizes`); reports alerts/log-routes/canaries/monitors; checks on delivery roles, retention vs obligation, legal hold, runbooks, monitoring nobody described. AWS and Azure Terraform state importers (SNS topic an alarm notifies = alert channel). Modularity pass (user: "modularity first"): `core.environment.bound_nowhere` (8 copies), `environment_of` (2 copies), `core.standard.enum_type`, `core.inventory.realization_roles`/`duration_text`.
- **Rationale**: monitoring and audit-log retention are what a move silently loses; alarms a cloud runs must map to described intent, and retention obligations outlive the source.

- **Change**: Milestone 4.12 Google Cloud: new package opsdir-adapter-gcp (module 42): vocabulary gcp/public; references gcp-sm (global and regional, resolved with gcloud), gcp-kms, gcp-cert, gs; credential patterns (service account key, API key, OAuth client secret); Terraform renderer (hashicorp/google ~> 8; health-check probe rules, EXTERNAL named ports, all_ports past five, backends by self_link, after a Codex review verified against Google's docs); importers gcp/terraform-state and gcp/cli-inventory (Cloud Asset Inventory list/export as JSON or JSON lines + gcloud, read once per resource, project numbers read as IDs, get-health for LB membership) through one pairs mapping. Core: `core.sources.json_records`, `core.network.is_private` limited to private-use ranges (U.9: the showcase's public frontends had been rendered private on AWS and Azure). Showcase: `standby/prod`, a warm standby on Google Cloud (47-env-standby; TCPPING discovery; drift via gcp/cli-inventory).
- **Rationale**: a first launch covering the three major clouds; every later cloud milestone now spans AWS, Azure and Google Cloud. The firewall model (network tags vs secure tags) is a per-environment choice scheduled in 4.9 (user decision, note 441).

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
- **Shared helpers, not per-package copies**: anything two packages would write alike (tolerant parsing, files by folder, container entries, DN scope, GeneralizedTime, JSON as written and held, cloud role tags, CI environments, captured product files) is a public, tested core helper (`opsdir.core.sources`, `core.directory`, `core.jsondata`, `core.inventory`, the domains); packages keep only their product's vocabulary. Private helpers aren't in the tracking DB, so the code is searched for an idiom before one is written. Module-level tables are read-only.
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
