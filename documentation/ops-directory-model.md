# The Operations Directory: modeling the CIAM estate as a directory

*Improvement proposal for the Collins / RTX CIAM role. Companion to `../systems-and-workflows.md` (§ refs "spec §") and `../automation-path.md` (§ refs "auto §"). Drafted 2026-09-23 from Aryan's idea, with one Claude↔Codex round (`../../../codex/discussion.txt`, topic `collins-ops-directory`). Everything about RTX's real estate is still unknown; this is a design proposal built for synthetic data.*

---

## 1. The idea

**Everything about the directory lives in a directory.**

PingDS already keeps its own configuration as LDAP entries: the `cn=config` backend is a tree, and `dsconfig` edits entries in it. The proposal takes that one step further. Model the whole *operational estate* around the identity platform the same way: servers, config, schema, ACIs, consumers, integrations, claim mappings, certificates, runbooks, changes, incidents and owners. The result is a small set of structured databases shaped like the directory they describe.

**Aryan's thesis:** the migration to the "next gen RTX cloud environment" should come down to *moving a small handful of databases (even large ones) and letting the new infrastructure configure itself from them.* Migrations should be quick, easy and repeatable.

> **Correction on an earlier claim.** I previously called config-as-code "their direction". **The posting doesn't say that.** It asks for "developing automation" and for defining "platform roadmaps, standards, and runbooks", and it names no tools. Terraform, Ansible, Python and Azure DevOps appear in a **different** RTX posting (the July 2026 Enterprise Services Cloud Platform role that builds Azure landing zones; see `../newStrategy.txt`). So config-as-code is how the *landing zone the directory may move into* is probably built. It is not confirmed practice on the CIAM team. Spec §15 Q10 ("what does 'developing automation' mean on this team today?") is still open.

---

## 2. The core principle: separate what moves from what's bound to a place

The thesis holds exactly as far as everything is classified correctly into one of these five kinds of state:

| Kind | Examples | Environment-neutral? | How it moves |
|---|---|---|---|
| **A. User data** | people, organizations, groups, entitlements, password hashes, registration status | Yes | **PingDS's own replication.** Add replicas in the target, let them converge, shift traffic, retire the old ones. Ping documents "add new servers and retire old ones" as an official upgrade/migration strategy. |
| **B. Platform intent** | schema, indexes, ACIs, password policies, backends, log publishers, replication *topology shape* | Yes | Rendered into `dsconfig` batch files / setup profiles for the target. |
| **C. Federation intent** | PingFederate SP connections, OIDC clients, attribute contracts, claim maps, adapters, policies | Mostly (URLs and certs are bindings) | Rendered into PF Admin API calls / config archive / Terraform. |
| **D. Estate knowledge** | consumers (bind DNs from logs), owners, criticality, dependencies, runbooks, changes, incidents | Yes | It *is* the operations directory. It moves as a file set / DB. |
| **E. Bindings** | hostnames, IPs, subnets, LB/DNS, firewall rules, compute sizes, storage classes, key-vault/KMS **references**, cert-to-hostname | **No.** This is the part that differs per cloud | **Rewritten per environment.** It should be the *only* thing written by hand for a migration. |
| *(Secrets)* | keys, passwords, the DS **deployment ID + password** | N/A | **Never stored.** Only referenced. Re-provisioned into the target's secret store (Key Vault / Secrets Manager) through the normal secrets process. |

**Migration under this model** = keep A–D, write a new E for the target, render and apply, let replication carry A, verify, cut over.

**A fact that shows why the secrets row matters.** PingDS encrypts backend data, backups and passwords with symmetric keys, which are protected by a **shared master key derived from the deployment ID and its password**. Every replica must have the same pair to decrypt what the others encrypted. So target replicas **must join the existing deployment** with the same deployment ID and password. If you stand up a fresh deployment in the new cloud and import LDIF, you lose that continuity. A migration plan that treats "the data" as just a big file would miss this. *(Source: PingDS cryptographic keys docs, see Sources.)*

---

## 3. The operations directory (DIT)

```
dc=ciam-ops
├── ou=environments
│   ├── cloud=aws-current
│   │   └── env=prod | stage | dev
│   │       ├── cn=ds-1 … ds-n            ciamServer: version, AZ, role, replicationId
│   │       ├── cn=pf-engine-1 … n        ciamServer (PingFederate)
│   │       └── ou=bindings               ciamBinding: dnsName, lbTarget, subnet, fwRule, secretRef, kmsRef
│   └── cloud=rtx-next                    (same shape; filled in during migration)
├── ou=config
│   ├── ou=declared                       desired DS config, env-neutral (kind B)
│   └── ou=observed
│       └── snap=<server>-<timestamp>     mirrored cn=config per server (read-only snapshots)
├── ou=schema
│   └── cn=<attributeName>                ciamAttributeRecord: purpose, piiClass, exportControlled,
│                                         readBy → consumer DNs, releasedAs → claim DNs
├── ou=acis
│   └── cn=<aci-id>                       ciamAciRecord: target, bindDN, rights, justification, ticket, reviewedOn
├── ou=consumers
│   └── cn=<bindDN-hash>                  ciamConsumer: bindDN, sourceIPs, opMix, subtrees, attrsRead,
│                                         unindexedSearches, tlsOnly, peakRate, owner →, criticality,
│                                         migrationStatus (unknown/identified/contacted/tested/cutover)
├── ou=integrations
│   └── cn=<app>                          ciamIntegration: protocol (SAML/OIDC/LDAP/header), entityId,
│       │                                 acsUrl/redirectUri, population, mfaRequired, owner →, usesCertificate →
│       └── ou=claims
│           └── cn=<claim>                ciamClaimMap: sourceAttribute →, claimName, transform
├── ou=certificates
│   └── cn=<fingerprint>                  ciamCertificate: subject, issuer, notAfter, purpose,
│                                         usedBy → DNs, rotationRunbook →, partnerContact →   (never the key)
├── ou=runbooks
│   └── cn=<wi-id>                        ciamRunbook: title, version, appliesTo → config DNs, lastValidated
├── ou=changes / ou=incidents             ciamChange / ciamIncident: ticket, approvedBy, modified/involved → DNs
└── ou=owners                             teams and contacts (references only, no HR data)
```

The **DN references** (`→`) are what make this more than an inventory. Together they form a dependency graph that can be queried with ordinary LDAP filters.

### 3.1 Draft schema (illustrative)

```ldif
# OIDs under a private arc would be assigned properly; placeholders shown.
attributeTypes: ( 1.3.6.1.4.1.99999.1.1 NAME 'ciamUsedBy'
  DESC 'DN of an entry that depends on this one'
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )                      # DN syntax
attributeTypes: ( 1.3.6.1.4.1.99999.1.2 NAME 'ciamNotAfter'
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE )         # GeneralizedTime
attributeTypes: ( 1.3.6.1.4.1.99999.1.3 NAME 'ciamMigrationStatus'
  EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.99999.1.4 NAME 'ciamPiiClass'
  EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )

objectClasses: ( 1.3.6.1.4.1.99999.2.1 NAME 'ciamCertificate' SUP top STRUCTURAL
  MUST ( cn $ ciamNotAfter )
  MAY ( description $ ciamUsedBy $ ciamRotationRunbook $ ciamPartnerContact ) )
objectClasses: ( 1.3.6.1.4.1.99999.2.2 NAME 'ciamConsumer' SUP top STRUCTURAL
  MUST ( cn $ ciamBindDN )
  MAY ( ciamSourceIP $ ciamAttrsRead $ ciamOwner $ ciamCriticality $ ciamMigrationStatus ) )
```

Writing the model as real LDAP schema is part of the pitch: it shows schema fluency on screen.

---

## 4. Questions it answers (example queries)

| Question | Query sketch |
|---|---|
| Cert blast radius: what breaks if this partner cert expires? | read `cn=<fp>,ou=certificates` → follow `ciamUsedBy` → integrations → `ciamOwner` |
| What expires in the next 30 days? | `(&(objectClass=ciamCertificate)(ciamNotAfter<=20261023000000Z))` |
| Migration readiness: which consumers aren't ready for cutover? | `(&(objectClass=ciamConsumer)(!(ciamMigrationStatus=tested)))` |
| Unknown consumers (bind DNs with no owner) | `(&(objectClass=ciamConsumer)(!(ciamOwner=*)))`. The target at cutover is **zero** (auto §6). |
| Least privilege: who can read PII-classified attributes? | join `ou=schema (ciamPiiClass=high)` ↔ `ou=acis` ↔ `ou=consumers` |
| Stale runbooks | runbooks whose `appliesTo` DNs changed after `lastValidated` |
| Drift | `ou=config/declared` vs latest `ou=config/observed` snapshot, normalized |
| Claims released to an app | children of `ou=claims,cn=<app>,ou=integrations` |

---

## 5. How it feeds the automation workstreams

| Workstream (auto §3) | What the operations directory provides |
|---|---|
| 3.1 Migration discovery & readiness | `ou=consumers` *is* the dependency register. The readiness report comes from the `cloud=aws-current` vs `cloud=rtx-next` subtrees. |
| 3.2 Config-as-code + drift | `ou=config/declared` vs `ou=config/observed` |
| 3.3 Tier-3 triage | Maps an app → integration → claims → attributes → consumer → servers, so the triage job knows where to look |
| 3.4 Cert / metadata expiry | `ou=certificates` plus `usedBy` gives each warning its blast radius and owner |
| 3.5 Audit evidence | ACI justifications, change records and review dates are already structured |
| 3.7 App onboarding PR | A new app becomes a new `cn=<app>,ou=integrations` subtree, reviewed as a PR |
| 3.9 Runbook upkeep | `appliesTo` + config change timestamps → stale flag |

It is the concrete shape of the "evidence store" in auto §8.1, shared by Module A (consumer discovery) and Module B (triage).

---

## 6. Stress-testing the thesis

### 6.1 A sharper version of the thesis
Codex's main criticism was that "move a handful of DBs and the infra configures itself" will sound naive in an interview unless the next sentence names what does *not* move. The databases are only part of the picture. **The migration succeeds when external contracts stay stable and the bindings are regenerated safely.** The stronger statement:

> "If we separate portable identity-platform intent from environment-specific bindings, most of the migration becomes reconciliation: build the new landing-zone bindings, add replicas, let the data sync, validate every dependency, shift stable endpoints, retire the old stack. The hard part is making hidden dependencies visible before cutover. That's what the operations directory is for."

That keeps Aryan's idea intact (the databases carry everything portable) and puts the difficulty where it really is.

### 6.2 Where it holds
- **User data** moves through supported PingDS replication (kind A). This is the part most people expect to be hard, and here it's the easiest.
- **Portable intent** (B, C, D) can be modeled neutrally and *rendered* for the target through supported tooling: `dsconfig` batch files, DS setup, PF Admin API / config archive, IaC.
- **Readiness becomes queryable**: consumers still bound to server hostnames, certs expiring before cutover, ACIs with no owner, apps depending on a given claim.

### 6.3 Where it breaks (and what to do about it)
| Hard edge | Why it doesn't "move" | Design answer |
|---|---|---|
| **Keys / crypto boundaries** | AWS KMS keys don't move to Azure Key Vault. TLS private keys, PF signing keys and HSM-backed keys are bound to their environment. | Store *references* only. Keys are re-issued or re-wrapped through the secrets process. Keep the DS deployment ID + password continuous (§2). |
| **Hostnames and certificates** | Certs bind to DNS names. If names change, every consumer and partner is affected. | **Stable service DNS names** (never server names). Certs are issued for service names. |
| **SAML / OIDC external contracts** | Entity IDs, ACS URLs, issuer, JWKS and metadata URLs, and signing certs are partner-facing. Changing them means partner work. | **Keep entity IDs and issuer URLs stable.** Plan any signing-cert rotation as its own change, separate from the move. |
| **Consumer network controls** | IP allowlists, firewall rules, private endpoints, Direct Connect / ExpressRoute and NAT egress IPs usually **dominate the timeline**. | **All of it goes in the directory** (Aryan's call): our inbound rules and egress addresses as bindings, and *other parties'* allowlists as `ciamExternalAllowlist` entries that point at our address *roles*. The directory can't apply a change inside a partner's firewall, but on day one it lists every external allowlist the new environment breaks, with the owner, lead time and a do-by date, and drafts each request. Stable addresses make the answer "nothing to change". |
| **Consumer behavior** | Apps may pin certs, hard-code replica hostnames, depend on search timing or read undocumented attributes. | Mine the access logs (auto §3.1). Replay recorded search shapes against the target. |
| **Cross-cloud replication** | Needs a routable, secure, low-latency path between clouds and a clean topology design. | A network design item with its own validation. |
| **Version compatibility** | Backend formats, password storage schemes, plugins and schema need proof for the specific version. | Keep an upgrade out of the move if possible, or test it separately. |
| **Organizational gates** | CAB, DR tests, security review, audit evidence and owner sign-off. These are usually the real long pole. | The directory produces the evidence and the per-consumer sign-off status. It speeds up the gates without skipping them. |

**Rules that make the thesis as true as possible:** stable service DNS · stable entity IDs and issuer · no consumer binding to replica hosts · bindings abstracted into `ou=bindings` · only product-supported export and rendering tools, never hand-edited internals · a diff between desired and observed state that produces a human-reviewable plan · a migration scoreboard (blocker, owner, risk, evidence, rollback) · **data migration and consumer cutover kept as separate phases**.

---

## 7. Prior art (who already does this)

| System | How close | What it shows | Limitation |
|---|---|---|---|
| **FreeIPA / Red Hat IdM** | Very close | Identity, policy, DNS, sudo, HBAC and certificate config all live in 389 Directory Server. Adding a replica = replicating the directory. | Works because the product was *built* around LDAP replication. Hosts, DNS, CA and Kerberos still have sharp edges. |
| **Active Directory Configuration naming context** | Very close, and **the best enterprise analogy** | Forest config, sites, services and replication topology are directory objects. Exchange keeps its whole organization config in AD. | In AD's case the directory *is* the platform. Apps have to be written to trust it. |
| **OpenLDAP / 389-DS / PingDS `cn=config`** | Close, but narrower | Server config as LDAP entries. PingDS is the direct precedent for this proposal. | Covers server config only, not the estate (consumers, certs, owners). |
| **Ping DevOps server profiles / `manage-profile`** | Relevant *pattern* | Layered config in Git applied at container start. `manage-profile generate-profile` emits running config as a reusable profile. | **These are PingDirectory / PingFederate / PingAccess tools, not PingDS** (different lineage: UnboundID vs ForgeRock). PingDS containerizes via ForgeOps. Cite it as "Ping already works this way for its other products", not as a PingDS feature. |
| **PingFederate config archive / bulk export (Ping CLI)** | Relevant | PF config can be exported and imported. | Archives are backup/transport artifacts, not clean declarative intent. URLs, certs, secrets and adapters still need per-environment handling. |
| **Kubernetes etcd + controllers** | Conceptually closest | All cluster state in one DB. Controllers continuously move actual state toward desired state. This is the "infra configures itself from the DB" model exactly. | Restoring etcd doesn't move a business platform. LBs, storage, DNS and identities still bind to an environment. |
| **GitOps (Argo CD / Flux)** | Close operating model | Desired state in Git. A reconciler detects drift and syncs. | Good at declared state. Blind to runtime dependencies discovered from logs unless paired with an inventory. |
| **NetBox / Nautobot** | Close as a "source of truth" | Topology and relationships drive network automation. | Doesn't model identity semantics (ACIs, claim maps, password policy). |
| **ServiceNow CMDB** | Adjacent | CIs and service relationships for change, incident and impact. | Too generic to be the executable control plane for PingDS/PF config. It's the place to integrate with. |
| **Terraform state** | Partial | Declared infrastructure and its dependency graph. | Knows load balancers and DNS. Doesn't know why an ACI exists or which claim feeds which app. |
| **Vault / secret managers** | Partial | Secrets, PKI, rotation. | The operations directory references them and never copies them. |

**What's new here:** the pieces exist separately. Directory-as-config (AD, FreeIPA, `cn=config`), source of truth (NetBox), reconciliation (Kubernetes, GitOps) and config export (Ping profiles, PF archives). What doesn't seem to exist is a **dependency-aware model of a *CIAM* estate**: which ACI serves which bind DN, which app it belongs to, which claim it feeds, which cert it relies on, and who signs off. That link from identity semantics to infrastructure is the gap this fills. *(An absence claim from one research round, not an exhaustive survey.)*

---

## 8. Storage (decided 2026-09-23: Postgres)

**Aryan's decision:** Postgres is the store for everything, declared and observed. It enforces the LDAP information model and references the real LDAP directory rather than copying it. This replaces the earlier Git-first split.

| Layer | Store | Why |
|---|---|---|
| **All entries** (intent, contracts, bindings, secret refs, observed, meta) | **Postgres**, one `entry` table keyed by DN, schema registry loaded from a standard LDAP schema file | Transactions, typed validation, **enforced referential integrity**, full history, SQL reporting |
| **Review and interchange** | **LDIF**: change records are applied under an approved change; `export` produces reviewable LDIF for Git | Keeps the PR/CAB workflow without making Git the database |
| **Dependency queries** | Postgres recursive queries (`dependents()`) | Enough at this scale; no graph DB |
| **LDAP front end** | Optional later, read-only | Only if operators want `ldapsearch`; avoids confusing it with the customer directory |

The **model** is LDAP (DIT, DNs, object classes, MUST/MAY, multi-values). **Postgres adds what LDAP doesn't guarantee:** R3 referential integrity, R5 governed writes and R6 history (SPEC.md §4).

---

## 9. Objections and honest answers

**"We already have ServiceNow CMDB."**
> "Good. I wouldn't replace it. ServiceNow stays the system for CIs, ownership, change and incidents. This is a domain-specific model for the identity platform: ACIs, schema, bind consumers, claim maps, cert usage, DS/PF config, migration readiness. ServiceNow gets summarized CIs and relationships. This layer holds the executable detail needed to build, diff, validate and migrate the platform."

**"This is one more system to run."**
> "That's a real risk. I'd start with the smallest useful version: declared state reviewed in Git plus reports generated from config and log snapshots. No always-on reconciler at first. It has to earn its keep by finding stale consumers, undocumented ACIs, cert blast radius and migration blockers. It only becomes a running service if it removes enough toil or risk to justify owning it."

**Other objections to prepare for:** another source of truth (answer: it's authoritative only for identity-platform intent, and everything else is referenced) · observed data may contain PII (answer: redaction layer, auto §8.1, P6) · LDIF in Git leaks internal hostnames, bind DNs and partner names (answer: the repo gets the same classification and ACLs as the config itself) · who owns data quality · who approves changes (the existing CAB, since the directory produces plans, not changes) · what if the reconciler is wrong (it only proposes, humans apply, auto §2 P2).

---

## 10. How to present it

**Don't pitch** "I invented a meta-directory that makes migrations instant."

**Pitch:**
> "For this migration, I'd build a dependency-aware source of truth that separates identity-platform intent from cloud bindings. The user directory moves through supported PingDS replication. Platform intent is rendered through supported tooling: dsconfig, PF export or its API, IaC. The value isn't magic. It's making hidden dependencies visible early enough that cutover is boring."

**One demo walk (synthetic data):**
1. Here's an ACI.
2. Here's the bind DN that uses it, found in the access logs.
3. Here's the app that owns it.
4. Here's the claim mapping and the DS attribute it depends on.
5. Here's the cert and the DNS name it reaches.
6. Here's what changes in `cloud=rtx-next`, what stays stable, and who has to sign off before cutover.

**Say plainly:**
> "I haven't administered Ping hands-on, so I'd validate this against Ping-supported tools and your existing work instructions. I'm not proposing to hand-edit product internals or replace ServiceNow."

---

## 11. The working demo: `opsdir/`

Built 2026-09-23. See `opsdir/README.md` (how to run, what's verified) and `opsdir/SPEC.md` (the standard).

- **The standard:** LDAP schema (RFC 4512) extended with `X-PORTABILITY` (intent / contract / binding / secret-ref / observed / meta) and `X-VALUE-TYPE`. That makes the *schema itself* say what moves in a migration. There are ten enforced rules (R1–R10).
- **Terraform from the database** (Aryan's point: most shops already use Terraform, and this is a tool *for* Terraformers). A renderer reads the directory and writes the Terraform (AWS or Azure), `dsconfig` batch, DS setup scripts, ACI LDIF and PingFederate config. A change is a directory entry, and the files are regenerated. The rendered Terraform passes `terraform validate` against the real AWS and Azure provider schemas.
- **Migration = a read.** 229 synthetic entries render byte-identical DS/PF config for both clouds. The Azure replicas bootstrap from the AWS replicas, so they join the existing deployment. The planner lists blockers and dated actions, including partner allowlists, and drafts the requests.
- **A design lesson from the build:** adding one Azure rule at first renumbered three others (Terraform churn). Provider-specific settings like NSG priority must be **pinned bindings in the directory**, never computed at render time.

## 12. Open questions / next steps
- **Fit with Aryan's own automation scope.** This is a candidate for the framework's core data model (auto §8.1), under Module A and Module B. Next importers: DS access logs → `ou=consumers`, `dsconfig` export → snapshots, PF Admin API → integrations.
- **Ask them** (adds to spec §15): Do consumers bind to service names or to replica hostnames? Are SAML entity IDs and issuer URLs tied to the current hosting domain? Is the DS upgrade in or out of scope for the move? Is there a CMDB relationship model for the identity platform today?

---

## Sources
- PingDS cryptographic keys (deployment ID/password → shared master key; replicas must share it): https://docs.pingidentity.com/pingds/7.5/security-guide/pki.html
- PingDS upgrade strategies ("add new servers and retire old ones"): https://backstage.pingidentity.com/docs/ds/7.1/upgrade-guide/add-new-servers.html
- PingDS replication: https://backstage.forgerock.com/docs/ds/7.2/config-guide/replication.html
- Ping DevOps server profiles (PingDirectory/PingFederate/PingAccess): https://developer.pingidentity.com/devops/how-to/profilesLayered.html · https://github.com/pingidentity/pingidentity-server-profiles
- PingDirectory `manage-profile`: https://docs.ping.directory/PingDirectory/latest/cli/manage-profile.html
- PingFederate configuration archive: https://docs.pingidentity.com/pingfederate/13.0/administrators_reference_guide/pf_configuration_archive.html
- FreeIPA Directory Server: https://www.freeipa.org/page/Directory_Server · replica install: https://freeipa.readthedocs.io/en/latest/workshop/7-replica-install.html
- OpenLDAP `cn=config`: https://openldap.org/doc/admin27/guide.html
- Kubernetes controllers: https://kubernetes.io/docs/concepts/architecture/controller/
- Argo CD auto-sync: https://argo-cd.readthedocs.io/en/stable/user-guide/auto_sync/
- NetBox: https://netboxlabs.com/docs/learn/
- ServiceNow CMDB: https://www.servicenow.com/docs/r/servicenow-platform/configuration-management-database-cmdb/c_ITILConfigurationManagement.html
- Codex-cited sources were spot-checked for the Ping and FreeIPA claims. The others are well-established but weren't opened this session.
