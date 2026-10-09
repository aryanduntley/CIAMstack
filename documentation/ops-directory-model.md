# The operations record: design rationale

*Why CIAMstack models an identity platform as a directory-shaped record, what that record holds, and where the approach reaches its limits. The standard itself (schema, extensions, rules R1–R10, adapter contract) is [`opsdir/SPEC.md`](../opsdir/SPEC.md); the inventory of everything a platform carries, and how much of it is modeled today, is [`STACK.md`](STACK.md).*

---

## 1. The idea

**Everything about the platform lives in one record, shaped like a directory.**

Directory servers already keep their own configuration as LDAP entries: the `cn=config` backend is a tree, and tools such as `dsconfig` edit entries in it. CIAMstack takes that one step further and models the whole *operational estate* around an identity platform the same way: servers and where they run, product configuration, the user directory's schema, ACIs, the applications and services that bind to the directory, federation integrations and their claims, certificates, keys and secrets (as references), runbooks, changes, incidents and owners.

That record is the **system of record the platform is operated from**:

- **A change is an entry** made under an approved change record and kept in history. Nobody hand-edits a rendered file or clicks through a console to change the platform.
- **Working files are generated from it:** infrastructure code, product configuration, setup scripts. Each environment gets its own render from the same record.
- **Questions become queries:** what expires, what a certificate's rotation breaks, who can read which attributes, what drifted, what nobody owns.
- **Moving the platform is one capability among these,** not the reason the record exists. Because the record already separates what is portable from what is bound to a place (§2), a second environment is rendered from the same intent, and a planner says what still stands in the way.

---

## 2. Separating what is portable from what is bound to a place

Every attribute in the schema declares its **portability class** (`X-PORTABILITY`, SPEC §3.1). The record works because every value is classified as one of these kinds:

| Kind | Examples | The same in every environment? | How it reaches an environment |
|---|---|---|---|
| **User data** | people, organizations, groups, entitlements, password hashes | Yes | **The product's own replication.** CIAMstack never holds it; it records its shape (schema, counts, distributions). New replicas join the existing deployment and converge. |
| **Intent** | schema, indexes, ACIs, password policies, backends, log publishers, replication topology shape, federation connections, OAuth clients, journeys, sync mappings | Yes | Rendered into the product's own configuration (`dsconfig` batch files, setup scripts, product JSON, standard SAML/OIDC documents). |
| **Contract** | service DNS names, SAML entity IDs, OIDC issuers, redirect URIs, bind DNs other teams use | Yes, and it **must not change** | Rendered unchanged; the planner blocks any environment that would change one. |
| **Binding** | hostnames, IPs, subnets, load balancers and DNS records, firewall rules, instance sizes, key-store references | **No**: this is what differs per environment | Written per environment. A new environment is mostly a new set of bindings. |
| **Secret reference** | where a key, password or keystore is kept | No | **Never stored**, only referenced (SPEC R4). Resolved at run time from the environment's secret store. |
| **Observed** | snapshots of live configuration, metrics mined from logs | — | Measured from the live system; evidence, compared with intent (drift). |
| **Meta** | owners, dates, status, documentation | Yes | Kept with the entry. |

**Why the secret row matters.** A DS-lineage directory (PingDS, ForgeRock DS) encrypts backend data, backups and passwords with symmetric keys protected by a **shared master key derived from the deployment ID and its password**. Every replica must share the pair to read what the others encrypted, so a new environment's replicas **must join the existing deployment** with the same deployment ID and password. Standing up a fresh deployment and importing LDIF loses that continuity. The record captures this as data (`ciamContinuity: carry-over` on the credential, `ciamMaterialFrom` on each environment's binding naming where the material comes from), and the planner checks it. *(Source: PingDS cryptographic keys documentation, see Sources.)*

---

## 3. The record's layout

The naming context is `dc=ciam-ops`. The core defines the branches below (SPEC §5); adapter packages add their own under their own schema arcs.

```
dc=ciam-ops
├── ou=environments
│   └── cloud=<name>                        ciamCloud: provider, region, partition
│       └── env=<name>                      ciamEnvironment: lifecycle, overlay of another environment, overrides
│           ├── cn=<server>                 ciamServer: role, hostname, zone, size, image, product version
│           ├── ou=stack                    ciamStackComponent (role -> adapter + version range), ciamRequiredRole
│           ├── ou=overrides                ciamOverride: an overridable value, per environment, with why
│           └── ou=bindings                 ciamNetwork, ciamSubnetBinding, ciamServiceName, ciamExternalHost, ciamFirewallRule,
│                                           ciamEgress, ciamSecretRef, ciamKeyRef, ciamCertificateRef,
│                                           ciamObjectStore (ciamBackupTarget), ciamInterconnect
├── ou=config
│   ├── ou=declared                         desired directory configuration: backends, indexes, password policies,
│   │                                       connection handlers, log publishers, replication topology
│   └── ou=observed                         ciamSnapshot per server: the live configuration, mirrored
├── ou=user-schema                          ciamUserAttribute, ciamUserObjectClass: purpose, PII class, export control,
│                                           standard or defined in the record
├── ou=consumers                            ciamConsumer: bind DN, source addresses, attributes read, owner, status
├── ou=acis                                 ciamAci: target, grantee (a consumer), rights, justification, review date
├── ou=identity-services                    ciamIdentityService: the platform's own IdP / OpenID provider (contracts)
├── ou=integrations                         ciamIntegration (SAML / OIDC / LDAP) -> ou=claims (ciamClaimMap)
├── ou=certificates                         ciamCertificate: public facts only (fingerprint, dates, SANs, key role)
├── ou=credentials                          ciamCredential: what a key or secret is, how it rotates, where it is used
├── ou=external-allowlists                  ciamExternalAllowlist: other parties' allowlists holding our addresses
├── ou=config-files, ou=bundles             files held setting by setting; code and templates by repo path + hash
├── ou=custom-schema                        ciamFieldDefinition, ciamRecordTypeDefinition: operator-defined
├── ou=runbooks, ou=changes, ou=incidents   ciamRunbook, ciamChange, ciamIncident
└── ou=owners                               ciamParty: teams, partners, vendors, the operator
```

Product packages add branches for what only they have: `ou=pingam` (journeys, policy sets), `ou=pingidm` (managed objects, connectors, mappings, schedules), `ou=pinggateway` (routes). Wherever a concept is standard (an OAuth client, a SAML partner, an LDAP server), the product's objects are recorded in the standard branches instead, so every product on the same base reads and renders them.

The **DN references** between entries are what make the record more than an inventory. An ACI names its grantee consumer; a claim names the user attribute it maps from; a certificate names its key; a service name names the certificate it presents. Together they form a dependency graph the store enforces (R3: a referenced entry can't be deleted) and the reports walk.

### 3.1 The schema is real LDAP schema

The schema is published as standard RFC 4512 definitions (`opsdir/schema/ciam-ops.schema.ldif`), with CIAMstack's extensions as legal `X-` qualifiers. For example:

```ldif
attributeTypes: ( 1.3.6.1.4.1.32473.1.1.104 NAME 'ciamNotAfter' DESC 'Expires'
  EQUALITY generalizedTimeMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE
  X-PORTABILITY 'meta' X-VALUE-TYPE 'time' X-ORIGIN 'opsdir' )
objectClasses: ( 1.3.6.1.4.1.32473.1.2.28 NAME 'ciamCertificate' DESC 'Certificate (public facts only)'
  SUP ciamObject STRUCTURAL MUST ( cn $ ciamFingerprint $ ciamNotAfter $ ciamCertPurpose )
  MAY ( ciamSubject $ ciamIssuer $ ciamNotBefore $ ciamSubjectAltName $ ciamKeyRole $
        ciamPartnerContact $ ciamRotationRunbook $ ciamCertificatePem ) X-ORIGIN 'opsdir' )
```

`X-PORTABILITY` makes the schema itself say what differs between environments; `X-VALUE-TYPE` adds stricter types than LDAP syntaxes (DNs, CIDRs, FQDNs, ports, reference URIs, enumerations, vocabularies registered by adapters). OIDs sit under the RFC 5612 documentation arc until a registered arc replaces it; each package's fragment has its own sub-arc with pinned numbers, and operators add fields and record types as entries (SPEC §2.3).

---

## 4. Questions it answers

| Question | How |
|---|---|
| What expires, and when? | `opsdir report expiring` |
| What breaks if this certificate expires or is rotated? | `opsdir report blast-radius <certificate DN>`: follows every reference to it, to integrations, service names and owners |
| What does rotating this key or secret touch? | `opsdir report rotation-impact <credential DN>`: every environment's copy, its certificate, every application that trusts it |
| Where does each environment keep its keys and secrets, and are they kept correctly? | `opsdir report keys <env>`, `opsdir report credentials` |
| Who can read privacy-classified attributes? | `opsdir report pii`: user attributes by PII class ↔ ACIs ↔ consumers |
| What drifted from the declared configuration? | `opsdir report drift`: declared vs the latest observed snapshot, normalized |
| Which applications use the directory, and what should be checked about each? | `opsdir report consumers`: owner, criticality, migration status, TLS, unindexed searches, last seen and reviewed, and what to check (no owner, plain text, high-PII attributes read, no ACI, not seen lately, review due) |
| Which work instructions are stale? | `opsdir report stale`: runbooks whose dependencies changed after they were last validated |
| What does nobody own? | `opsdir report unowned` |
| How does an environment differ from the one it overlays? | `opsdir report overrides` |
| Which files copy a value of the record, on which lines? | `opsdir census PATH` records it; `opsdir report census [DN]` lists it, and `blast-radius` includes the files |
| Any ad-hoc question | `opsdir search -b <base> '<LDAP filter>' [attributes]`, e.g. `(&(objectClass=ciamConsumer)(!(ciamOwner=*)))` for consumers with no owner |

Reports are data registered by domains and adapter packages; SQL reports run in the store, directory reports over a snapshot of the record.

---

## 5. Operating from the record

- **Governed writes.** Every write names a change record under `ou=changes`; unapproved changes, invalid values, secret values in reference fields and deletes that would break references are rejected by the database (R1–R6), and every accepted write lands in history.
- **Rendering.** `opsdir render <cloud>/<env>` builds an environment model (roles, bindings, overrides) and runs every applicable adapter's renderer. Output carries a MANIFEST with each file's scope and SHA-256. Rendered files are never edited; the record is.
- **Declared stacks.** Each environment declares, per role, which adapter and which version range it runs; `opsdir check` says whether the adapters are installed and where to get missing ones.
- **Environments as overlays.** A stage environment can be an overlay of production: it shares what it doesn't bind itself, drops roles it shouldn't have, and overrides values the schema marks `X-OVERRIDABLE`, each with why.
- **Importers.** An adapter's importer reads a product's own export (an Amster export, an IDM project, a gateway configuration) into the record as change records, under an approved change; secret values found on the way are withheld and reported.
- **Files and bundles.** Configuration files are held setting by setting and rebuilt for any environment; code and templates are recorded by repo path and digest and verified against a checkout.
- **Custom fields and record types.** Operators extend the record with their own governed, typed, documented fields (`ciamFieldDefinition`) and record types (`ciamRecordTypeDefinition`).

---

## 6. Moving between environments

Moving a platform, to another cloud, another account or region, or another product version later, uses what the record already holds. A **migration workspace** is a copy of the live record where the target's stack and bindings are declared; the **planner** compares it with the live record; **cutover** applies the workspace's changes back as one approved change set. It works in either direction.

### 6.1 The statement that holds

"Move a few databases and the new infrastructure configures itself" is only half true. The databases carry everything portable; the move succeeds when **external contracts stay stable and bindings are regenerated safely**. Most of a move becomes reconciliation: build the new bindings, add replicas, let the data replicate, validate every dependency, shift stable endpoints, retire the old environment. The hard part is making hidden dependencies visible before cutover, which is what the record is for.

### 6.2 Where it holds

- **User data** moves through the directory's supported replication.
- **Intent** (configuration, federation, access rules, estate knowledge) is modeled neutrally and rendered for the target through supported tooling: `dsconfig` batch files, setup scripts, product APIs or exports, infrastructure code, standard SAML and OIDC documents.
- **Readiness is queryable:** consumers not yet tested, certificates expiring before cutover, ACIs with no owner, applications depending on a claim, keys the target keeps wrongly.

### 6.3 Where it breaks, and what the record does about it

| Hard edge | Why it doesn't simply move | Design answer |
|---|---|---|
| **Keys and crypto boundaries** | Cloud KMS keys don't move between providers; TLS private keys, signing keys and HSM-backed keys are bound to where they live. | Store *references* only. The credential says whether the target must receive the same material (carry over) or may re-issue it, whether it may leave its store at all, and whether it must be HSM-protected; the planner checks each. Keep the directory's deployment ID and password continuous (§2). |
| **Hostnames and certificates** | Certificates bind to DNS names. If names change, every consumer and partner is affected. | **Stable service names** (never server names), certificates issued for service names, and a planner block on any contract that changes. |
| **SAML / OIDC external contracts** | Entity IDs, ACS URLs, issuers, JWKS and metadata URLs and signing certificates are partner-facing. | Entity IDs and issuers are contracts. A signing-certificate rotation is its own change, separate from the move. |
| **Network controls** | IP allowlists, firewall rules, private endpoints, dedicated links and egress addresses usually **dominate the timeline**. | All of it is in the record: our inbound rules and egress addresses as bindings, and *other parties'* allowlists as `ciamExternalAllowlist` entries pointing at our address *roles*. The planner lists every external allowlist a new environment breaks, with owner, lead time and a do-by date, and drafts each request. Stable addresses make the answer "nothing to change". |
| **Consumer behavior** | Applications may pin certificates, hard-code replica hostnames, depend on search timing or read undocumented attributes. | Consumers are records with a status per move (unknown → identified → contacted → tested → cut over); access-log mining fills them from evidence. |
| **Cross-environment replication** | Needs a routable, secure, low-latency path and a clean topology design. | The interconnect is a binding, and the replication path a required role. |
| **Version compatibility** | Backend formats, password storage schemes, plugins and schema need proof for the specific version. | Product versions are data and carried unchanged; an upgrade is a separate change. |
| **Organizational gates** | Change boards, DR tests, security review, audit evidence and owner sign-off. | The record produces the evidence and each consumer's sign-off status. It speeds the gates up without skipping them. |

**Rules that keep moves boring:** stable service DNS names · stable entity IDs and issuers · no consumer binding to replica hosts · bindings only under `ou=bindings` · rendering only through product-supported tools, never hand-edited internals · desired vs observed state compared into a human-reviewable plan · every blocker with an owner, a date and evidence · data migration and consumer cutover as separate phases.

---

## 7. Prior art

| System | How close | What it shows | Limitation |
|---|---|---|---|
| **FreeIPA / Red Hat IdM** | Very close | Identity, policy, DNS, sudo, HBAC and certificate configuration all live in 389 Directory Server. Adding a replica = replicating the directory. | Works because the product was *built* around LDAP replication. Hosts, DNS, CA and Kerberos still have sharp edges. |
| **Active Directory configuration naming context** | Very close | Forest configuration, sites, services and replication topology are directory objects; Exchange keeps its whole organization configuration in AD. | The directory *is* the platform; applications have to be written to trust it. |
| **OpenLDAP / 389-DS / PingDS `cn=config`** | Close, narrower | Server configuration as LDAP entries: the direct precedent. | Covers one server's configuration, not the estate (consumers, certificates, owners). |
| **Ping DevOps server profiles / `manage-profile`** | Relevant pattern | Layered configuration in Git applied at container start; `manage-profile generate-profile` emits running configuration as a profile. | Tools of the PingDirectory / PingFederate / PingAccess line, not the DS lineage, which containerizes through ForgeOps. |
| **PingFederate configuration archive / bulk export** | Relevant | Configuration can be exported and imported. | Archives are transport artifacts, not declarative intent; URLs, certificates, secrets and adapters still need per-environment handling. |
| **Kubernetes etcd + controllers** | Conceptually closest | All cluster state in one store; controllers move actual state toward desired state. | Restoring etcd doesn't move a business platform: load balancers, storage, DNS and identities stay bound to an environment. |
| **GitOps (Argo CD / Flux)** | Close operating model | Desired state in Git; a reconciler detects drift and syncs. | Blind to runtime dependencies found in logs unless paired with an inventory. |
| **NetBox / Nautobot** | Close as a source of truth | Topology and relationships drive network automation. | No identity semantics (ACIs, claim maps, password policy). |
| **CMDBs (e.g. ServiceNow)** | Adjacent | Configuration items and service relationships for change, incident and impact. | Too generic to be the executable control plane for product configuration; the place to integrate with. |
| **Terraform state** | Partial | Declared infrastructure and its dependency graph. | Knows load balancers and DNS, not why an ACI exists or which claim feeds which application. |
| **Vault and other secret managers** | Partial | Secrets, PKI, rotation. | The record references them and never copies them. |

**What CIAMstack adds:** the pieces exist separately (directory-as-configuration, source of truth, reconciliation, configuration export). What is missing elsewhere is a **dependency-aware model of an identity estate**: which ACI serves which bind DN, which application it belongs to, which claim it feeds, which certificate and key it relies on, where that key is kept in each environment, and who signs off. That link from identity semantics to infrastructure is what the record holds.

---

## 8. Storage

| Layer | Store | Why |
|---|---|---|
| **All entries** (intent, contracts, bindings, secret references, observed, meta) | **PostgreSQL**: one entry table keyed by DN, the schema registry synced from the published LDAP schema, versioned migrations | Transactions, typed validation, **enforced referential integrity**, full history, SQL reporting |
| **Review and interchange** | **LDIF**: change records applied under an approved change; `opsdir export` produces reviewable LDIF | Keeps pull-request and change-board review without making Git the database |
| **Dependency queries** | Recursive queries in the store | Enough at this scale; no graph database |
| **Migration workspace** | A second database, a copy of the live record | The target is declared and planned without touching the live record |

The **model** is LDAP (DIT, DNs, object classes, MUST/MAY, multi-valued attributes). **PostgreSQL adds what LDAP doesn't guarantee:** referential integrity (R3), governed writes (R5) and history (R6).

---

## 9. Design questions

**"We already have a CMDB."** The CMDB stays the system for configuration items, ownership, change and incidents. CIAMstack is a domain-specific model for the identity platform: ACIs, schema, bind consumers, claim maps, certificate and key usage, product configuration, readiness. The CMDB receives summarized items and relationships; the record holds the executable detail needed to build, diff, validate and move the platform.

**"Isn't this one more system to run?"** It earns its place by what it finds and what it generates: stale consumers, undocumented ACIs, certificate blast radius, key sprawl, blockers, and the working files themselves. It runs on one PostgreSQL database; there is no always-on reconciler, and renders and plans are run on demand.

**"Another source of truth?"** It is authoritative for identity-platform intent and bindings. Everything else (secrets, user data, other teams' systems) is referenced, not copied.

**"Observed data may contain PII."** The record describes the user directory (schema, consumers, ACIs) and never holds user entries; observed data is limited to configuration, and planned profilers and log miners record statistics, bind DNs and attribute names, never values. Secret values found in imports are withheld and reported.

**"LDIF in Git leaks internal hostnames, bind DNs and partner names."** Exports get the same classification and access control as the configuration they describe.

**"Who approves changes?"** The existing change process: a write names an approved change record, and the record produces plans and diffs for reviewers.

**"What if a plan is wrong?"** Plans propose; people approve and apply. Every finding carries its evidence, and a check that can't run reports that it couldn't, rather than passing silently.

---

## 10. Lessons from the build

- **Provider-specific settings are bindings, pinned in the record.** Adding one Azure network rule at first renumbered three others (Terraform churn). Rule priorities and similar provider values are stored per environment, never computed at render time.
- **The standard files are identical everywhere.** The directory configuration, ACIs, federation configuration and the standard SAML, OIDC and LDAP documents render byte-identical for every environment of the same record; only infrastructure code and per-server scripts differ. The showcase tests hold that line.
- **Nothing passes silently.** A planner check that lacks the data it needs reports a finding instead of an OK.

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
- RFC 4512 (LDAP directory information models): https://www.rfc-editor.org/rfc/rfc4512 · RFC 5612 (documentation OID arc): https://www.rfc-editor.org/rfc/rfc5612
