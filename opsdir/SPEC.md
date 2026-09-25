# opsdir: an LDAP-model standard for platform configuration

**Status:** draft 0.1 (2026-09-23), Aryan Duntley. Reference implementation in this folder.

## 1. Purpose

A platform's configuration is usually spread across Terraform files, CLI batch files, admin consoles, spreadsheets and people's heads. **opsdir** puts it in a directory instead: one tree of typed, schema-checked, cross-referenced entries. Working configuration (Terraform, `dsconfig`, federation config) is **generated** from that tree.

Consequences:
- **A change is a directory entry,** made under an approved change record. Files are re-rendered, never hand-edited.
- **A migration is a read.** The same databases are rendered for a different environment. Only that environment's *bindings* are new.
- **Questions become queries:** blast radius, expiry, drift, who can read what, which external allowlists hold our addresses.

The first domain is a CIAM platform (PingDS + PingFederate), but nothing in the model is specific to it.

## 2. Information model (inherited from LDAP)

opsdir uses the LDAP information model unchanged (RFC 4512):

- **Entries** in a tree (DIT), named by **DNs**. Naming context: `dc=ciam-ops`.
- **Object classes** (ABSTRACT / STRUCTURAL / AUXILIARY, with inheritance) define MUST and MAY attributes.
- **Attribute types** with syntax, equality rule and single/multi-value.
- The schema is published as a standard LDAP schema file: `schema/ciam-ops.schema.ldif`.

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

`string · int · bool · time (GeneralizedTime) · dn (internal reference) · extdn (DN in another directory) · cidr · ip · fqdn · url · port · ref-uri · json · enum:a|b|c`

`ref-uri` accepts only reference schemes: `aws-sm:// aws-kms:// azkv:// azkv-key:// vault:// s3:// azblob://`.

## 4. Normative rules

A conforming store MUST enforce all of these, not merely document them:

| # | Rule |
|---|---|
| R1 | **Schema checking.** Object classes known. At least one structural class. Only MUST/MAY attributes. All MUST attributes present. SINGLE-VALUE respected. Every value valid for its `X-VALUE-TYPE`. |
| R2 | **Tree integrity.** The parent entry exists. The RDN value is present in the entry. Non-leaf entries can't be deleted. |
| R3 | **Referential integrity.** Every `dn`-typed value resolves to an existing entry at commit. A referenced entry can't be deleted. *(Stronger than LDAP, where referential integrity is an optional plugin.)* |
| R4 | **No secrets.** `secret-ref` attributes MUST be `ref-uri`. The schema offers no attribute that can hold secret material. |
| R5 | **Governed writes.** Every write carries a change ID. Outside the initial bootstrap, the change MUST exist under `ou=changes` with status `approved` or `applied`. |
| R6 | **History.** Every insert, update and delete is recorded with before/after values and change ID. |
| R7 | **Roles, not names.** Renderers look up bindings by `ciamBindingRole` (e.g. `ds-ldaps-service`, `ds-deployment-password`), never by hostname or resource ID. |
| R8 | **Neutral outputs are identical.** Artifacts rendered only from `intent` MUST be byte-identical for every environment. The planner checks this. |
| R9 | **Contracts are stable.** A migration plan MUST flag any `contract` value that differs between source and target. |
| R10 | **Generated means generated.** Rendered files carry a "do not edit" header and a manifest (scope + SHA-256). |

## 5. Standard branches

| Branch | Object classes | Holds |
|---|---|---|
| `ou=environments` | `ciamCloud` → `ciamEnvironment` → `ciamServer`, `ou=bindings` (`ciamNetwork`, `ciamSubnetBinding`, `ciamServiceName`, `ciamFirewallRule`, `ciamEgress`, `ciamSecretRef`, `ciamKeyRef`, `ciamBackupTarget`, `ciamInterconnect`) | Where things run, per environment |
| `ou=config` | `ou=declared` (`ciamBackend`, `ciamIndex`, `ciamPasswordPolicy`, `ciamConnectionHandler`, `ciamLogPublisher`, `ciamReplicationTopology`); `ou=observed` (`ciamSnapshot` + mirrored tree) | Desired vs actual server config |
| `ou=user-schema` | `ciamUserAttribute` | Every attribute of the user directory: purpose, PII class, export control |
| `ou=consumers` | `ciamConsumer` | Clients of the user directory (from access logs) |
| `ou=acis` | `ciamAci` | Access rules, with grantee, attributes, justification, review date |
| `ou=integrations` | `ciamIntegration` → `ou=claims` (`ciamClaimMap`) | SAML / OIDC / partner federation and claim mappings |
| `ou=certificates` | `ciamCertificate` | Public facts only: fingerprint, dates, SANs, key *role* |
| `ou=external-allowlists` | `ciamExternalAllowlist` | Allowlists in **other parties'** systems that contain **our** addresses (by role) |
| `ou=runbooks`, `ou=changes`, `ou=incidents`, `ou=owners` | `ciamRunbook`, `ciamChange`, `ciamIncident`, `ciamParty` | Operations and governance |

## 6. Relationship to the real (user) directory

opsdir **never stores user data.** It *describes* the user directory:
- `extdn` values name DNs in it (bind DNs, base DNs, ACI targets). They are syntax-checked but not resolved, because they live in another system.
- `ciamUserAttribute` records describe each attribute of the user directory. Indexes, ACIs, claims and consumers reference those records by `dn`, so R3 applies. You can't remove an attribute record that a claim still maps from.

## 7. Bindings and roles

An environment is complete when it binds every required role (see `opsdir/render/model.py`, `REQUIRED_ROLES`): `network`, `subnet-ds`, `subnet-pf`, `ds-ldaps-service`, `pf-sso-service`, `pf-egress`, `disk-encryption`, `backup-target`, and the secret roles. Consumer firewall rules use the role `fw-consumer-<consumer>`, so the planner can match them across environments. External allowlists refer to *our* roles (`ciamRefersToRole`), so a new environment's address for that role is checked against what the other party has recorded.

## 8. Renderer contract

Input: a consistent snapshot of the directory and an environment DN. Output: files plus `MANIFEST.json` (each file's scope `environment-neutral` / `environment-specific`, and its SHA-256). Missing required roles are reported as `UNBOUND`, never guessed. A provider (AWS, Azure, on-prem) is selected by `ciamCloudProvider`. Adding a provider means adding a renderer, not changing the data.

## 9. Interchange

- **LDIF in, LDIF out.** Content and change records (RFC 2849) are the interchange format. `opsdir export` produces reviewable LDIF for Git.
- The schema file is standard RFC 4512. Directory servers generally ignore unknown `X-` extensions. *Not yet tested against a live LDAP server. The OIDs use the RFC 5612 documentation arc `1.3.6.1.4.1.32473` and must be replaced with a registered arc.*

## 10. Open issues

- Environment overlays (stage/prod sharing most bindings) and per-environment overrides of intent (e.g., smaller replica counts in stage).
- A read-only LDAP front end over the Postgres store (e.g., an LDAP proxy), so operators can `ldapsearch` it.
- Importers that populate `observed` automatically: DS access-log mining → `ou=consumers`, `dsconfig` export → snapshots, PF Admin API → integrations.
- Two-way ITSM sync for `ou=changes`.
- Validation of rendered `dsconfig`/`setup` flags and PingFederate JSON against the exact product versions.
