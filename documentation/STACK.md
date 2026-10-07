# CIAMstack: Stack Inventory & Datification Map

*Every subsystem, file, store and external dependency a production identity (CIAM) platform on the ForgeRock/Ping stack is likely to carry, whether each can live as data in the opsdir record, and what the record covers today. It builds on [`ops-directory-model.md`](ops-directory-model.md) (the design) and [`opsdir/SPEC.md`](../opsdir/SPEC.md) (the standard). Coverage is as of 2026-09-30 (roadmap paths 1–3 done).*

---

## 0. How to read this

**The reference stack.** This is an *external identity* (customer/partner/supplier) platform. PingDS is the directory and PingFederate does federation and SSO, with PingAM, PingIDM and PingGateway where the ForgeRock lineage is present. It runs in a public cloud, with a reverse proxy, an MFA service, several portals as relying parties, and the usual enterprise wrapping (ITSM, SIEM, PAM, PKI). Every item is something an operator has to account for to run, audit or change the platform; moving it to another cloud, account or region is the scenario that tests the inventory hardest, so each class says what happens to the item in a move. The shape is typical of such platforms, not any particular organization's.

**Presence in the estate** (per subsystem):
- **[core]**: the stack can't exist without it.
- **[likely]**: standard for this product family, industry or scale.
- **[maybe]**: conditional. It depends on the product lineage or history. Confirm before modeling.

**Class** is opsdir's `X-PORTABILITY` class (SPEC §3.1), plus one extra letter for things opsdir must *not* hold:

| Code | Class | Across environments and moves |
|---|---|---|
| **I** | intent | Moves unchanged and renders identically everywhere |
| **C** | contract | Names other parties depend on. Must not change. |
| **B** | binding | Rewritten per environment |
| **S** | secret-ref | Re-bound. Only the reference is stored. |
| **O** | observed | Measured from the live system. Evidence only. |
| **M** | meta | Ownership, dates, status, docs |
| **D** | data | User data or runtime state. Moved by the product's own mechanism (replication, DB migration). opsdir holds **statistics and pointers only**. |

**Datify verdict:**
- **●** *model it*: one entry per item. Rendered from the DB or diffed against it.
- **◐** *describe it*: the artifact stays where it is (a binary, a template, a vendor console). opsdir holds its facts: location, version, hash, owner, what depends on it.
- **○** *count it*: user data, runtime state or secret material. opsdir holds counts, checksums, locations and references, never the content.

**opsdir today:** ✔ modeled in the current schema (core or an adapter package) · ~ partial · — gap. "Captured" means the file can be held in the record setting by setting and rebuilt per environment (`opsdir capture`, SPEC §9.1) without a dedicated model; "bundle" means code or templates recorded by repo path and SHA-256 (`opsdir bundle`).

---

## 1. The stack at a glance

```
 PARTIES          customers · suppliers · partners (own IdPs) · B2C · app teams · auditors
                        │                │                       │
 EDGE             DNS (public+private) · CDN/WAF · public certs · LBs (NLB 636, ALB 443)
                  reverse proxy / gateway (PingAccess | IG | F5)  ·  legacy WAM (SiteMinder)
                        │
 EXPERIENCE       portals (registration app, Liferay, supplier portal) · login/reset templates
                  email (SMTP relay, sender domains, SPF/DKIM/DMARC) · CAPTCHA
                        │
 FEDERATION       PingFederate cluster (admin + engines) ── Duo adapter ── Duo cloud
                  SP conns · IdP conns · OAuth/OIDC clients · policies · keys · grant/session stores
                  [maybe] PingAM / PingIDM / PingGateway (ForgeRock lineage)
                        │ LDAPS
 DIRECTORY        PingDS replicas (multi-master) · cn=config · schema · backends · ACIs
                  password policies · replication · changelog · keystores · Rest2LDAP
                        │
 PLATFORM         EC2/AMI/OS or EKS/ForgeOps · EBS · IAM · KMS · Secrets Manager · S3 backups
                  VPC · subnets · SGs/NACLs · TGW/DX/VPN · NAT/EIPs · PrivateLink · enterprise firewalls
                        │
 OPERATIONS       CloudWatch/Prometheus/SIEM · alerting · backups/DR · IaC/Ansible/pipelines
                  artifact repo · licenses · PAM · PKI · ITSM/CMDB · runbooks · compliance evidence
```

---

## 2. Directory: PingDS  [core]

PingDS (ForgeRock DS lineage, 7.x→8.x). `<ds>` is the install root (often `/opt/opendj` or `/opt/ds`).

### 2.1 Server configuration

| Artifact | Location / format | Class | Datify | opsdir today |
|---|---|---|---|---|
| Server config tree (`cn=config`) | `<ds>/config/config.ldif`, edited with `dsconfig` | I + B | ● Declared config as entries. Render a `dsconfig` batch. Snapshot the live one into `ou=observed`. | ~ backends, indexes, pw policies, conn handlers, log publishers, replication; **imported** (`pingds/config` snapshots, `pingds/declared`) |
| Archived config versions | `<ds>/config/archived-configs/` (auto-kept on change) | O | ◐ Import as snapshots. Gives free drift history. | ✔ imported as dated snapshots |
| Backends | JE / LDIF / memory / proxy backends, base DNs, `confidentiality-enabled`, cache sizes | I (+B for db dirs) | ● | ✔ `ciamBackend` |
| Indexes | Equality/presence/substring/ordering/VLV, `index-entry-limit`, confidentiality per index | I | ● | ✔ `ciamIndex` (VLV —) |
| Connection handlers | LDAP 389, LDAPS 636, HTTP(S) 8080/8443, admin 4444, JMX; `listen-address`, SSL cert nickname, cipher suites, protocols | I (ports) + B (addresses) | ● | ✔ `ciamConnectionHandler` (ciphers/protocols —) |
| Password policies | Complexity validators, history, lockout, expiry, storage schemes, `last-login-time-attribute`, idle lockout, grace logins | I | ● | ~ `ciamPasswordPolicy` (validators, idle lockout, last-login config —) |
| Password validators & generators | Character set, length, dictionary (+ dictionary file), repeated chars, similarity | I | ● Dictionary file as ◐ with its hash | — |
| Password storage schemes | PBKDF2-HMAC-SHA256/512, Bcrypt, SSHA512, legacy (SSHA, crypt, MD5) | I | ● List enabled schemes, and count users per scheme (see §3) | ~ `ciamStorageScheme` |
| Plugins | Referential integrity, unique attribute, 7-bit clean, entity tag, attribute cleanup, change number control, custom plugins | I | ● | — |
| Custom extensions | `<ds>/extlib/*.jar`, custom plugin classes | I | ◐ Name, version, SHA-256, source repo | ✔ bundle (`ciamBundle`) |
| Virtual attributes | `isMemberOf`, `entryDN`, `numSubordinates`, collective attrs, user-defined templates | I | ● | — |
| Groups config | Static, dynamic and virtual-static group implementations, `isMemberOf` | I | ● | — |
| Global ACIs | `global-aci` in `cn=Access Control Handler,cn=config` | I | ● Same model as data ACIs | ~ `ciamAci` holds data ACIs. Global ones not separated. |
| Root/admin users & privileges | `uid=admin` (7.x), `uid=monitor`, `ds-privilege-name` sets (`bypass-acl`, `password-reset`, `proxied-auth`, `config-read`…) | I + S | ● Accounts and privileges as entries, passwords as refs | ~ passwords as `ciamCredential` + per-environment refs; accounts and privileges — |
| Replication | Server IDs, group IDs, bootstrap servers, replication ports (8989), purge delay, changelog enablement, assured replication, topology | I (shape) + B (hosts/IDs) | ● | ✔ `ciamReplicationTopology`, `ciamJoinsDeploymentOf` |
| External change log (`cn=changelog`) | Consumers (IDM, sync jobs, CDC) read it, each with a cookie or change number | I + O | ● Register the ECL readers as consumers. Cookies are ○. | — |
| Deployment ID + password | Generated at setup. Derives the shared master key. | S | ○ Reference only. **It must be continuous across a move.** | ✔ `ciamCredential` with `ciamContinuity: carry-over`; planner checks the target receives the same material |
| Keystore / truststore | `<ds>/config/keystore` (PKCS12) + `keystore.pin`, truststore, key-manager and trust-manager providers | S (+ cert facts) | ○ keys · ● cert facts | ~ cert facts ✔, keystores as credentials ✔, provider config — |
| Crypto manager | Cipher and key-wrapping config, attribute/backend encryption settings | I | ● | — |
| Log publishers | Access (JSON/CSV/LDAP), error, debug, replication, HTTP access; filtering criteria; rotation and retention policies | I (+B for paths) | ● | ~ `ciamLogPublisher` (rotation/retention/filters —) |
| Common-audit handlers | JSON / CSV / Syslog / Splunk / JMS / Elasticsearch handler configs | I + B + S | ● | — |
| Alert handlers & SMTP | JMX/SMTP alert handlers, SMTP server config, alert recipients | I + B | ● | — |
| Monitoring endpoints | `cn=monitor`, HTTP `/metrics/prometheus`, `/alive`, `/healthy`; the monitor user | I | ● | — |
| Work queue / threads / JVM tuning | `num-worker-threads`, entry cache, `OPENDJ_JAVA_ARGS` (heap, GC) | I (+B for sizes) | ● | — |
| Disk thresholds | `disk-low-threshold`, `disk-full-threshold` per backend | I | ● | — |
| Rest2LDAP mappings | `<ds>/config/rest2ldap/endpoints/**.json` | I + C (the REST paths) | ● Mapping as entries. Its JSON as ◐ with a hash. | ~ captured; mapping not modeled |
| Setup profiles used | `setup --profile` names + params (AM identity store, AM config, AM CTS, IDM repo, DS user data) | I | ● Record which profiles made which backends | — |
| Scheduled tasks | Recurring backups, purges, imports in the tasks backend (`<ds>/config/tasks.ldif`) | I (+B for targets) | ● | ~ backup target only |
| Product version & build | `<ds>/config/buildinfo`, patch level | M/O | ● | ✔ `ciamProductVersion` |
| CLI defaults | `~/.opendj/tools.properties` (per admin host) | B | ◐ Flag it, since it often embeds hostnames and bind DNs | — |

### 2.2 Directory schema

| Artifact | Location / format | Class | Datify | opsdir today |
|---|---|---|---|---|
| Standard schema | `<ds>/config/schema/00-core.ldif` … | I | ◐ Version reference only | ✔ the standard LDAP catalogue is in the core; each user attribute and class is marked standard or defined in the record |
| Custom schema | `<ds>/config/schema/99-user.ldif` (or custom files), `cn=schema` | I | ● Every custom attributeType and objectClass as an entry, with purpose, PII class and export flag | ✔ `ciamUserAttribute`, `ciamUserObjectClass`; rendered as standard LDIF (`ldap/schema.ldif`) |
| Schema-checking policy | Strictness settings, allowing attribute names with underscores, etc. | I | ● | — |

### 2.3 Directory-hosted operational data (beyond people)

*Whatever else the DS stores. Easy to forget, and it matters for sizing and for which consumers exist.*

| Artifact | Class | Datify | opsdir today |
|---|---|---|---|
| PingFederate **OAuth client storage** (if LDAP-backed) | I (the clients) | ● as `ciamIntegration` (it is intent) | ~ |
| PingFederate **persistent grants** (if LDAP-backed) | D | ○ count + TTLs | — |
| AM config store / CTS / identity store backends (if AM exists) | I / D / D | ● config · ○ CTS/identities | ~ AM configuration via the PingAM package (§8); CTS and identity counts — |
| IDM repo backend (if IDM uses DS) | D | ○ | — |
| Service-account entries (`ou=service-accounts`) | I + S | ● One entry per account, pointing at its consumer, its ACIs and its credential ref | ~ via `ciamConsumer` |
| Delegated-admin groups, role groups | I | ● | — |

---

## 3. User data in the directory  [core]  — class D

Moved by **PingDS replication** (target replicas join the existing deployment). opsdir never copies it. What opsdir *should* hold is **the shape of the data**, because migration risk, cleanup scope and consumer impact all come from it.

| Fact to datify (○ count / ● describe) | Why it matters |
|---|---|
| ● The DIT layout: base DNs, `ou` branches, naming attribute per branch (`uid=<email>`…) | Consumers hard-code base DNs, so the layout is a **contract** |
| ○ Entry counts per branch / objectClass / population | Sizing, import time, replication initialization time |
| ○ Attribute fill rates per attribute | Finds dead attributes and leftovers from systems merged in over the years |
| ○ Password-hash scheme distribution | Legacy schemes must stay enabled on the target, or users need a rehash-on-login plan |
| ○ `lastLoginTime` / `pwdChangedTime` distribution | Inactive-account cleanup scope. Decide before or after the move? |
| ○ Locked / disabled / pending-registration counts | Lifecycle hygiene baseline |
| ○ Group sizes, orphan groups, members pointing at missing DNs | Referential cleanup |
| ○ Largest entries, big multi-valued attributes | Replication and index-entry-limit risks |
| ○ Entries holding challenge questions (KBA) | A modernization target (NIST 800-63B) |
| ● Per-attribute PII class, export-control flag, retention rule | Privacy and export-control gating: what may leave which boundary |
| ○ Duplicate identities (the same person across legacy stores) | Consolidation scope |

Importer: ✔ `ldapsearch … | opsdir data-profile` streams the data once and writes counts only (no values; no database needed); `opsdir import ldap/data-profile` records it under `ou=data-profile` (milestone 4.5): entries per container and class (non-container RDNs masked), attribute fill and sizes linked to `ou=user-schema`, password-hash schemes (known names only), last-login and password-age buckets, locked/disabled/pending, challenge-question holders, group sizes, empty groups and dangling members. Planner: schemes no declared policy uses, values without a scheme, attributes without a user-schema record, dangling members, KBA. Not counted: duplicate identities across stores (a consolidation question beyond one directory).

---

## 4. Federation: PingFederate  [core]

`<pf>` is the install root (often `/opt/pingfederate`). It runs as a cluster: one admin console node plus N engine nodes.

### 4.1 Node and cluster files

| Artifact | Location / format | Class | Datify | opsdir today |
|---|---|---|---|---|
| Node run config | `<pf>/bin/run.properties`: ports (9031 runtime, 9999 admin), operational mode (`CLUSTERED_CONSOLE`/`CLUSTERED_ENGINE`), node tags, `pf.cluster.*`, bind addresses, HSM mode | I + B | ● Render per node | ~ captured and rebuilt per environment (showcase); ✔ node facts on each server (`pingfedNode`: mode, tags, listeners, settings), **imported** (`pingfederate/node-files`) |
| JVM memory | `<pf>/bin/jvm-memory.options` | I (+B for sizes) | ● | ~ capturable |
| Cluster discovery | `<pf>/bin/jgroups.properties` since PingFederate 11.0 (`pf.cluster.discovery.protocol` + `pf.cluster.<PROTOCOL>.*`; `tcp.xml` holds `${DISCOVERY_TAG}`, upgraded installs may keep the element in `<pf>/server/default/conf/tcp.xml`). Ping documents TCPPING, NATIVE_S3_PING, DNS_PING, AWS_PING, SWIFT_PING: NATIVE_S3_PING or DNS_PING on AWS, DNS_PING (AKS) or TCPPING on Azure and GCP (AZURE_PING is a community extension Ping doesn't document); encryption key for cluster traffic | **B** + S | ● **A classic miss when moving.** The discovery protocol is cloud-specific. | ✔ discovery as a **binding** whose protocol is chosen per environment (`pingfedDiscoveryProtocol`: TCPPING, NATIVE_S3_PING, DNS_PING; implied by an s3:// bucket or a DNS name), rendered per environment (`pingfederate/cluster/jgroups.properties`); nodes' protocol **imported** (jgroups.properties, else tcp.xml) and checked; planner flags a target without it, with an unsupported protocol or with another one |
| Jetty / TLS / headers | `<pf>/server/default/conf/jetty-runtime.xml`, `jetty-admin.xml`, response headers, cipher suites | I | ● | ~ capturable |
| Logging | `<pf>/server/default/conf/log4j2.xml`: server, audit, provisioner, transaction, admin and admin-api logs; syslog/Splunk appenders | I + B (targets) | ● | ~ capturable |
| Service wiring | `<pf>/server/default/conf/META-INF/hivemodule.xml` (which store backs clients, grants, sessions) | I | ● | ✔ store kinds per service (`pingfedSettings` `storage`), **imported** from the nodes' files |
| Custom adapters / plugins | `<pf>/server/default/deploy/*.jar` (MFA adapter, custom PCVs, custom data sources) | I | ◐ Name, version, SHA-256, source | ✔ bundle |
| JDBC drivers | `<pf>/server/default/lib/*.jar` | I | ◐ | ✔ bundle |
| Login / error / reset templates | `<pf>/server/default/conf/template/*.html` (Velocity), CSS, images: **branding lives here** (brand names, logos) | I + C (URLs in them) | ◐ Hash + owner, plus a **string scan** for hostnames and old brands (§15) | ~ bundle ✔ (showcase: `login-templates`); string scan — |
| Language packs | `<pf>/server/default/conf/language-packs/*.properties` | I | ◐ | ~ capturable or bundle |
| Config master key | `<pf>/server/default/data/pf.jwk` (encrypts secrets inside the config), or an HSM | S | ○ Reference only. Its continuity decides whether a config archive imports cleanly. | ~ expressible as a `ciamCredential` with carry-over continuity; not declared by the PingFederate package yet |
| Config store | `<pf>/server/default/data/` (XML + config-store files) | I + B + S | ○ Don't parse the files. Datify through the **Admin API** (§4.2) instead. | — |
| Auto config archives | `<pf>/server/default/data/archive/*.zip` | O | ◐ Location, date, hash | — |
| Drop-in deployer | `<pf>/server/default/data/drop-in-deployer/` (config archive applied at start) | I | ◐ | — |
| License | `<pf>/server/default/conf/pingfederate.lic`: expiry, node/connection limits | M | ● Facts (expiry, limits) | — |
| Product version | `<pf>/bin/pf.version` / Admin API `/version` | M/O | ● | ✔ `ciamProductVersion` |

### 4.2 Configuration objects (Admin API `/pf-admin-api/v1`, bulk export `/bulk/export`)

| Object | Class | Datify | opsdir today |
|---|---|---|---|
| **SP connections** (SAML/WS-Fed outbound): entity ID, ACS URLs, bindings, attribute contract, signing/encryption certs, SLO | I + **C** | ● | ✔ `ciamIntegration` (SAML) + claims; **imported** from the bulk export |
| **IdP connections** (inbound partner federation): partner entity ID, SSO URLs, JIT provisioning, attribute mapping | I + C | ● | ~ `ciamJitBaseDn`, partner certificates, **imported**; inbound mapping — |
| **OAuth/OIDC clients**: client ID, redirect URIs, grant types, PKCE, auth method, token policy, scopes | I + C (+S for secrets) | ● | ✔ **imported**, in the OIDC vocabulary (`ciamGrantType`, `ciamTokenAuthMethod`, `ciamScope`); rendered as standard client registrations; token lifetimes ~ (captured ATM file, custom field) |
| OAuth scopes, scope groups, exclusive scopes | I | ● | ✔ `pingfedSettings` `oauth-auth-server` (scopes listed in `pingfedScope`); **imported** |
| Access token managers (JWT / reference), signing key choice, lifetimes | I | ● | ✔ `pingfedPlugin` kind `access-token-manager`, linked to its signing key pairs' certificates (`pingfedKeyPairId`); clients linked to their token manager; **imported** |
| OIDC policies (ID token claims, lifetimes) | I | ● | ✔ `pingfedOidcPolicy`, linked to its token manager; clients linked to their policy; **imported** |
| Token exchange / processors / generators | I | ● | — |
| Authentication policies (trees), policy contracts, authentication selectors (IdP discovery, "select your identity provider") | I | ● These are the login flows, so they deserve first-class modeling | ✔ `pingfedAuthPolicySet` + `pingfedAuthPolicy` per tree and fragment, `pingfedPolicyContract`, selectors as `pingfedPlugin`; linked to what they run; **imported**; planner blocks on references the record lacks |
| IdP adapters: HTML Form, Identifier-First, Duo, Kerberos… | I (+S) | ● | ✔ `pingfedPlugin` (settings, parent, linked validators/adapters; secrets withheld, a credential role per environment); **imported** |
| Password credential validators (LDAP Username PCV → DS) | I + S | ● | ✔ `pingfedPlugin`, linked to its data store; **imported** |
| **Data stores**: LDAP (DS hosts, bind DN, pool sizes, LDAPS), JDBC | I + B (hosts) + S | ● **Consumer link to the directory.** Hosts must be *service names*. | ✔ `pingfedDataStore` (PingFederate package schema): hosts that are service names become a target role rendered per environment, bind DN linked to its consumer, credentials withheld and named by a credential role; **imported**; planner flags fixed hosts and plain LDAP |
| Local identity profiles (PF-native registration & profile management), if used | I | ● | — |
| Password reset / change settings (email or SMS OTP), notification publishers (SMTP) | I + B + S | ● | — |
| CAPTCHA providers | I + S | ● | — |
| Signing key pairs, SSL server key pairs, decryption keys | S + cert facts | ○ keys · ● cert facts (fingerprint, expiry, `usedBy`) | ✔ `ciamCertificate` + `ciamCredential` (carry-over, HSM, exportable); cert facts **imported** |
| Trusted CAs, partner metadata URLs & refresh | I + C | ● | — |
| Virtual host names, base URL, SAML entity ID of *our* IdP, OIDC issuer | **C** | ● **Must not change** | ✔ `ciamIdentityService` (base URL, entity ID, issuer); SAML metadata and OIDC discovery rendered |
| Redirect validation allowlist | I | ● | — |
| Session settings, persistent session storage, session revocation | I | ● | — |
| Outbound provisioning (SCIM/connectors to SaaS apps) + provisioner DB | I + D | ● channels · ○ state | — |
| Admin accounts & admin console auth (native / OIDC / cert), roles (Admin, Crypto, User Admin, Auditor) | I + S | ● | — |
| Server settings: contact info, notifications (cert-expiry emails), roles & protocols enabled | I | ● | — |
| Cluster replication state (config pushed to engines) | O | ● "Is replicated?" flag + timestamp | — |

### 4.3 PingFederate runtime stores  (class D)

| Store | Where | Datify |
|---|---|---|
| Persistent grants (refresh tokens, consents) | JDBC DB or LDAP (DS) | ○ count, TTL, store ref. Migrate or accept re-consent (a decision to record). The database itself is ● a managed database bound by role (§14), so the JDBC data store names its role, not a host. |
| Persistent authentication sessions | JDBC DB | ○ Usually dropped at cutover, which means users re-login. Record that as a decision. |
| Client storage (if not XML) | JDBC / LDAP | ● it's intent (see above) |
| Provisioner state | JDBC | ○ |
| Account-linking records (federated IdP ↔ local account) | JDBC | ○ **Must migrate**, or partners' users lose their linkage |

---

## 5. MFA service (e.g. Duo)  [likely]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| Duo "applications" (one per integration): name, type, integration key, **secret key**, API hostname | Duo Admin Panel / Admin API | I + S + B (API host) | ● App facts, keys as refs | — |
| Policies (global, per-app, per-group): enrollment, allowed methods, remembered devices, networks | Duo Admin API | I | ● | — |
| PF Duo adapter config | PF Admin API (§4.2) | I + S | ● | — |
| Duo Authentication Proxy (if used for LDAP/RADIUS) | `authproxy.cfg` on a host | I + B + S | ● | — |
| User enrollments, devices, bypass codes | Duo cloud | D | ○ counts. They don't move, because Duo is SaaS. It only matters if the integration keys change. | — |
| Duo network egress (our side reaching `api-*.duosecurity.com`) | Firewall / proxy | B | ● as egress + external dependency | ~ `ciamEgress` |

---

## 6. Edge: DNS, certificates, load balancers, WAF, reverse proxy  [core]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| Public DNS zones & records (sso., login., ldap. service names) | Route 53 / enterprise DNS (Infoblox) | **C** (names) + B (targets) | ● | ✔ `ciamServiceName`; `ciamDnsZoneBinding` (public/private, who runs it: a zone run outside the platform gets a drafted request), `ciamDnsRecord` |
| Private DNS zones, resolver rules, conditional forwarders to on-prem | Route 53 Resolver / on-prem DNS | B | ● | ✔ `ciamDnsForwarder`: Resolver rules, DNS Private Resolver forwarding rules, Cloud DNS forwarding zones, rendered and read back |
| DNS health checks / failover records | Route 53 | B | ● | ✔ `ciamRoutingPolicy` (failover, weighted) on service names and records: Route 53 routing with health checks, Traffic Manager, Cloud DNS weighted round robin |
| TTLs (lower them before cutover) | same | B | ● Planner rule: TTL ≤ N days before cutover | ✔ `ciamTtlSeconds`; the planner dates the lowering ahead of cutover by the old TTL |
| Public TLS certs (DigiCert/Entrust/ACM), SANs | ACM / CA portal | cert facts + S | ● facts · ○ keys | ✔ |
| NLB for LDAPS (TCP 636 passthrough), target groups, health checks | ELB | B | ● | ✔ service names + `ciamTrafficPolicy` (passthrough, health, stickiness, draining); what runs read back as `ciamEdgeFact` |
| ALB for PF HTTPS: listeners, TLS policy, stickiness, rules | ELB | B + I (TLS policy) | ● | ✔ `ciamTrafficPolicy` (terminate/reencrypt, TLS minimum and profile mapped to each cloud's named policy, backend validation): ALB, Application Gateway v2, Application Load Balancer |
| WAF web ACLs, managed rule groups, IP sets, rate limits | AWS WAF / Akamai / F5 ASM | I (rules) + B (attachment) | ● | ✔ `ciamProtectionPolicy` (mode, categories, rate limits aimed at the endpoints products declare, address and country rules, exclusions, DDoS tier): WAFv2, Application Gateway / Front Door WAF, Cloud Armor; `ciamEdgeService` read back |
| CDN (if in front of login pages) | CloudFront / Akamai | B | ● | ✔ `ciamCdn`: CloudFront, Front Door, Cloud CDN (nothing cached for sign-on), the WAF on the CDN |
| **PingAccess** (if in the CIAM path): `<pa>/conf/run.properties`, `<pa>/data/PingAccess.mv.db` (H2 config DB), `pa.jwk`, applications, resources, sites, virtual hosts, rules, identity mappings (header injection), web sessions, token provider → PF, agents, key pairs, cluster | PA Admin API `/pa-admin-api/v3` | I + C + B + S | ● via Admin API, like PF | — |
| PingGateway / ForgeRock IG (if used): `config/routes/*.json`, `admin.json`, `config.json` | Files | I + B | ● | ✔ PingGateway package: routes linked to their integration and issuer, rendered per environment; `admin.json`/`config.json` captured |
| F5 BIG-IP (if used): VIPs, pools, iRules, profiles, certs | UCS archive / AS3 declarations | I + B | ● via AS3 JSON | — |
| Header-based SSO contracts (header names apps trust) | Gateway rules | **C** | ● | ✔ `ciamHeaderContract` (identity, client address, …): setters the target lacks, spoofable headers, client addresses lost behind a terminating balancer |

---

## 7. Legacy access management and portals  [maybe / likely]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| **SiteMinder** policy store: domains, realms, rules, policies, user directories (pointing at DS?), ACOs | Policy store (LDAP/DB); `XPSExport` XML | I + B | ● Import via XPSExport. It's a directory consumer, plus a retirement candidate. | — |
| SiteMinder web agents: `WebAgent.conf`, `SmHost.conf` (trusted host registration), agent keys | Web servers | B + S | ● facts · ○ keys | — |
| Registration / approval app: pending requests DB, approval workflow, email templates | App DB / ServiceNow | I + D | ● workflow & templates as ◐ · ○ requests | — |
| Liferay portal: `portal-ext.properties`, SAML/OIDC plugin configs, IdP list (the "select your identity provider" page), `osgi/configs/*.config` | Portal servers | I + C + B | ● The SAML SP settings are the portal's half of an integration | ~ integration side only |
| Supplier-portal integration (e.g. a supplier identity hub): metadata, attribute contract, trust | PF IdP/SP connection + partner | I + C | ● | ~ |
| Legacy portals still binding directly to LDAP | App configs (unknown) | C (bind DN, base DN, hostnames) | ● **Found from access logs**, then recorded as consumers | ✔ `ciamConsumer`, **imported** from the JSON access logs (`pingds/access-log`) |

---

## 8. ForgeRock-lineage components (only if present)  [maybe]

A DS-lineage directory (PingDS, not PingDirectory) often comes with the rest of the ForgeRock lineage. Confirm which parts are present. **Covered today:** PingAM, PingIDM and PingGateway are adapter packages, each with an importer for its own export (Amster export, IDM project, gateway configuration) and per-environment rendering; ForgeOps rendering is on the roadmap (§21).

| Component | Config artifacts | Datify |
|---|---|---|
| **PingAM** (ForgeRock AM) | Realms, journeys/trees, nodes, scripts, OAuth2 provider, agents, CTS settings. Export via **Amster** (JSON) or the REST config API. Config store in DS. | ● via Amster export → entries. Scripts as ◐ with a hash. |
| **PingIDM** (ForgeRock IDM) | `conf/*.json` (sync mappings, `managed.json`, `provisioner.openicf-*.json` connectors, schedules, `boot.properties`), `script/` | ● Mappings and connectors are pure intent. Connector credentials are refs. |
| **PingGateway** (IG) | `config/routes/*.json` | ● |
| **ForgeOps** (Kubernetes) | Kustomize overlays, Helm values, image tags, `ds-operator` / secret-agent CRs, StatefulSets, PVC sizes, storage classes | ● Overlay values are exactly I vs B. Render them instead of Terraform-for-EC2. |

---

## 9. Messaging: email, SMS, CAPTCHA  [likely]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| SMTP relay (SES / Exchange Online / on-prem relay), port, auth | PF notification publisher, DS SMTP config, portal apps | B + S | ● | ✔ `ciamExternalService` (kind `smtp-relay`: endpoint, port, the roles that use it, its credential role), the core `messaging` domain; **imported** from PingFederate's SMTP notification publisher |
| **Sender addresses** (e.g. a `portaladmin@…` address under an older brand) | PF / portal templates | **C** | ● **User-visible contract.** Changing it goes through the change process. | ✔ `ciamMailSender` (address and domain as contract, the service that sends it, bounce handling); imported from the publisher's From address |
| SPF / DKIM / DMARC records for sender domains | DNS | B + C | ● New sending IPs or services must be added to SPF/DKIM **before** cutover, or reset emails get spam-foldered | ✔ `ciamSendingIdentity` per environment (DKIM verified, SPF authorized, DMARC policy), **read** from SES identities + Route 53 and Communication Services domains + Azure DNS; the planner blocks a target identity that isn't verified |
| Email templates (welcome, reset, registration) | PF templates / app | I | ◐ hash + string scan | — |
| SMS / voice OTP provider (if any) | Twilio etc. | I + S | ● | ✔ `ciamExternalService` (kinds `sms`, `voice`: sender IDs, originating numbers as contract, country registrations, spend limit); no importer yet |
| CAPTCHA site/secret keys, allowed domains | Google/hCaptcha console | I + S + C (domains) | ● **Allowed domains must include new hostnames** | ✔ `ciamExternalService` (kind `captcha`: vendor, allowed domains as contract, the secret's credential role); **imported** from PingFederate's CAPTCHA providers; the planner blocks target names the allowed domains don't cover |

---

## 10. Network  [core]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| VPC / VNet, CIDRs | AWS | B | ● | ✔ `ciamNetwork` |
| Subnets per tier & AZ, route tables | AWS | B | ● | ✔ `ciamSubnetBinding`, `ciamRouteTable` (routes as '<destination> <kind> [<target role>] [for <roles>]'; network domain) |
| Security groups / NSGs / VPC firewall rules, NACLs | AWS / Azure / Google Cloud | B (+I intent: "PF engines may reach DS on 636") | ● Store the **intent rule** once and the per-cloud realization as a binding | ✔ `ciamFirewallRule` (pinned priorities, a fix pins them after a fresh import), `ciamNetworkAcl` (stateless rules, checked against the ports matrix), Google Cloud network firewall policies (`ciamFirewallPolicy`) |
| **Enterprise firewall rules** (Palo Alto / Check Point, on-prem and cloud edge) | Firewall manager (Panorama, Tufin, AlgoSec) | B | ● Same rule model. Import from the firewall manager's export. | ~ same class, no importer |
| Transit Gateway attachments & route tables, Direct Connect / ExpressRoute, site-to-site VPN | AWS networking | B | ● | ✔ `ciamInterconnect` (kind, peer gateway, BGP, acceptance, the peer environment) |
| NAT gateways + **Elastic IPs (egress)** | AWS | B | ● **Partners allowlist these** | ✔ `ciamEgress` |
| Ingress public IPs (NLB EIPs, static IPs) | AWS | B | ● Partners and consumers allowlist these too | ✔ `ciamFrontendIp` |
| **PrivateLink / VPC endpoint services** exposing LDAPS to other VPCs or accounts; allowed principals | AWS | B + C (endpoint service name) | ● Each connected endpoint is a consumer | ✔ `ciamEndpointService` (principals, acceptance, the consumers connecting; Azure Private Link Service, Google Cloud service attachments) |
| VPC endpoints we use (S3, KMS, Secrets Manager, SSM) | AWS | B | ● | ✔ `ciamPrivateEndpoint` (what it reaches, the roles behind it, private DNS; Azure private endpoints, Private Service Connect, private services access with its allocated range) |
| Egress forward proxy (Zscaler / Squid) + allowlists for partner metadata, JWKS, OCSP/CRL, Duo, vendor update URLs | Proxy config | B | ● | ✔ `ciamProxy` (firewall or forward proxy, its allowed destinations; the sites products need checked against it; products told about an explicit proxy, a fix links their settings) |
| **Other parties' allowlists holding our addresses** | Partners, app teams, SaaS vendors | B (theirs) | ● | ✔ `ciamExternalAllowlist` |
| Cross-cloud replication path (DS 8989 between clouds) | Interconnect + FW | B | ● | ✔ |
| NTP sources | chrony config / VPC time sync | B | ● Clock skew breaks SAML and replication | ✔ `ciamTimeSource` |
| Flow logs: scope, destination, retention | VPC / VNet / subnet flow logs | B | ● | ✔ `ciamFlowLog` (retention compared with the source's; a fix carries it over) |
| Load-balancer and cluster ports matrix (389/636/4444/8989/8443/9031/9999/7600 JGroups…) | Derived | I | ● Derive it from connection handlers + PF run.properties, then diff against the firewall rules | ✔ derived from what products declare (`Adapter.listeners`), checked against firewall rules and network ACLs; a fix admits exactly the uncovered ranges |

---

## 11. Compute and operating system  [core]

### 11.1 VM style (EC2)

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| Instances: type, AZ, ENI/private IP, tags | EC2 | B | ● | ✔ `ciamServer` |
| AMI / golden image (CIS-hardened RHEL), image pipeline | EC2 Image Builder / Packer | B + I (baseline) | ● image ref · ◐ Packer template | ✔ `ciamImageRef` (servers and compute groups); the image pipeline as `ciamImageBuild` on a compute group (by hand: Image Builder isn't read yet) |
| EBS volumes: size, type, IOPS/throughput, encryption key | EC2 | B | ● DS db performance lives here | ◐ `ciamVolume` (core `data` domain: each server role's boot and data disks, size, class, IOPS/throughput, encryption, snapshot policy); rendered and read back on AWS (EBS volumes with attachments, root block devices; state and CLI) Azure (managed disks with attachments, OS disks; state, CLI and ARM) and Google Cloud (disks with attachments, boot disks; state, Cloud Asset Inventory and gcloud), planner blocks a smaller target disk and names lost encryption and snapshots |
| Instance profile / IAM role | IAM | B | ● | — |
| User data / cloud-init | Launch template | I + B | ● Rendered, never hand-written | ~ DS setup scripts rendered |
| SSM: Parameter Store params, Patch Manager baselines, State Manager associations, Session Manager prefs, SSM documents | SSM | I + B + S | ● | — |
| OS tuning: `/etc/security/limits.conf` (nofile for DS), `sysctl` (TCP keepalive, somaxconn), transparent huge pages | Host | I | ● One baseline per role | ✔ `ciamHostBaseline` (compute domain): `ciamOsLimit`, `ciamKernelSetting`, `ciamHugePages`, one baseline per role, **imported** from servers' files (`linux/baseline`); drift between servers named |
| systemd units (`opendj.service`, `pingfederate.service`), env files, restart policies | Host | I | ● | ✔ `ciamServiceUnit` (user, restart policy); env files not read yet |
| **JDK**: vendor/version, `cacerts` truststore additions, `java.security` overrides | Host | I + cert facts | ● **Custom CA additions to cacerts are a classic silent failure** after a rebuild | ✔ `ciamJdk`; truststore additions linked to `ciamCertificate` (`ciamTrustsCertificate`) or kept by fingerprint and **flagged by the planner** (`ciamTrustedFingerprint`); `java.security` not read yet |
| Local service accounts, sudoers, SSH keys / authorized_keys | Host | I + S | ● accounts & sudo rules · ○ keys | — |
| **Cron jobs & scripts** (backups, cleanups, cert checks, log shipping, reports) | `/etc/cron.*`, crontabs, `/opt/scripts` | I + B | ● **Hidden automation.** Every job is an entry with its purpose, schedule and owner. The script itself is ◐ (hash + repo). | ✔ `ciamJob` (automation domain): cron and systemd timers **imported** from servers' files (`linux/jobs`), one job per server role, linked to the bundle it runs; serverless functions and AWS pipelines as per-environment `ciamJobBinding` from the cloud importers; CI pipelines **imported** (GitHub Actions, GitLab CI, Azure DevOps); `jobs` report; planner flags jobs the target can't run and jobs nobody owns |
| `/etc/hosts` entries | Host | B | ● **Pinned names are migration landmines.** Flag any. | ✔ `ciamPinnedHost`: every pin is a planner action |
| `resolv.conf` / search domains | Host | B | ● | ✔ `ciamSearchDomain` |
| Host agents: EDR (CrowdStrike), vuln scanner (Tenable/Qualys), Splunk UF, CloudWatch agent, SSM agent | Host | I + B + S | ● Agent, version and config ref per role | ✔ `ciamHostAgent` (recognized from the package list: name and version); agent config refs not yet |
| auditd rules, SELinux mode/policies, FIPS mode | Host | I | ● FIPS mode changes which crypto providers DS and PF may use | ✔ `ciamSelinuxMode`, `ciamFipsMode`; auditd rules not read yet |
| logrotate configs | Host | I | ● | — |

### 11.2 Kubernetes style (EKS/AKS, if ForgeOps)
Cluster version, node groups, namespaces, StatefulSets, PVCs & storage classes, ingress controller, cert-manager issuers, external-secrets / secret-agent, network policies, IRSA / workload identity, Helm releases. All ● and split I/B exactly like §8's ForgeOps row. **Today:** Kubernetes secrets as references (`k8s-secret://`); clusters as bindings (`ciamCluster`: version, add-ons, node pools, zones) read from EKS and AKS Terraform state; workloads (`ciamWorkload`, compute domain: kind, namespace, replicas, images, storage size and class, service account and the workload-identity role it assumes, pod security, network policies, ingress hosts, secret names) and CronJobs (as jobs) **imported** from manifests (`kubernetes/workloads`, opsdir-adapter-kubernetes). Compute groups (autoscaling groups, scale sets) are bindings (`ciamComputeGroup`: image, size, scale, zones, metadata tokens). Not yet: operator custom resources (DS operator, secret agent, external-secrets), Helm releases as such, cert-manager issuers.

---

## 12. Secrets, keys and PKI  [core]

Everything here is **S** in opsdir: a `ref-uri`, never a value (SPEC R4).

| Artifact | Where | Datify | opsdir today |
|---|---|---|---|
| Secrets Manager secrets (names, rotation Lambdas, rotation schedule) | AWS | ● ref + rotation facts | ✔ `ciamSecretRef` + rotation facts (`ciamAutoRotate`, `ciamRotationFunction`, `ciamLastRotated`) |
| KMS keys: aliases, key policies, grants, multi-region settings | AWS | ● ref + policy intent (who may decrypt what) | ✔ `ciamKeyRef` + protection level, key users/admins, replica regions (grants —) |
| Key Vault / Managed HSM | Azure | ● | ✔ (`azkv://`, `azkv-key://`, `azkv-cert://`) |
| Secret Manager (global and regional; rotation notifies a Pub/Sub topic), Cloud KMS (software, HSM, single-tenant HSM, external) | Google Cloud | ● | ✔ (`gcp-sm://`, `gcp-kms://`, `gcp-cert://`); rotation period and protection level **imported** |
| Kubernetes secrets (containerized deployments) | Cluster | ● ref | ✔ (`k8s-secret://`) |
| CloudHSM (if PF keys are HSM-backed) | AWS | ● ref. **HSM keys don't export.** Rotating the signing key becomes a partner-facing change. | ✔ `ciamHsmRequired`, `ciamExportable`, `ciamProtectionLevel`; planner blocks a carry-over that can't leave its store |
| PAM (CyberArk): safes, accounts (`uid=admin`, service-account passwords, PF admin), platforms, CPM rotation, reconcile accounts | PAM | ● ref per account + rotation policy | ~ `cyberark://` refs (as a binding or `ciamCopyRef`) + rotation policy; platforms/CPM — |
| **Credential sprawl:** the same service-account password stored in DS, PF data store config, PAM, scripts | Everywhere | ● One `ciamSecretRef` per credential, with `usedBy` → every place it's configured. Rotation becomes a query. | ✔ `ciamCredential` + `ciamUsedIn`, `ciamCopyRef`; `credentials` and `rotation-impact` reports |
| Internal PKI: issuing CA (AD CS / Venafi / private CA), templates, CRL/OCSP URLs | PKI | ● CA + chain facts. Certificate-lifecycle tool refs. | — |
| Keystores: DS (PKCS12), PF, PA, JDK cacerts, partner trust anchors | Various | ● Cert facts per keystore with `usedBy` | ✔ cert facts; keystores as credentials |
| DS deployment ID/password, PF `pf.jwk`, PA `pa.jwk`, cluster encryption keys | Product | ● ref. Continuity requirement recorded. | ✔ `ciamContinuity` + `ciamMaterialFrom` (planner: copy before cutover) |

---

## 13. Observability  [core]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| CloudWatch log groups (retention, KMS), metric filters, alarms, dashboards | AWS | I + B | ● Alarms as intent ("replication delay > 5 s for 5 min → page"), realized per cloud | ✔ `ciamAlertRule` (neutral signal, condition, severity, runbook, delivering role), `ciamLogRoute` (log kinds, roles, destination role, retention obligation, legal hold); bindings `ciamAlertChannel`, `ciamLogDestination` (retention); what the cloud runs: `ciamAlarmBinding`, `ciamCanaryBinding` realizing a rule or canary (tag `Realizes`); **imported** from AWS, Azure and Google Cloud Terraform state, and Google Cloud's Cloud Asset Inventory (milestones 4.6, 4.12); rendering per provider: 5.4 |
| CloudWatch agent config JSON | Host / SSM | I + B | ● | — |
| Prometheus scrape configs, recording and alerting rules, Grafana dashboards | Monitoring stack | I | ● rules · ◐ dashboards (JSON hash) | — |
| SIEM: Splunk inputs/props/transforms, indexes, saved searches, correlation searches; or Sentinel DCRs and analytics rules | SIEM | I + B | ● Detection intent + data routing. **Retention obligations** as meta. | — |
| Alert routing: SNS topics, PagerDuty/Opsgenie services, ServiceNow Event Management | Various | I + B | ● | ✔ an alert rule's role binds a channel per environment (`ciamAlertChannel`: topic, action group, paging service); SNS topics alarms notify, Azure action groups and Cloud Monitoring notification channels **imported** as channels |
| Synthetic login canaries (CloudWatch Synthetics scripts, external uptime monitors) | Various | I + B + S (test creds) | ● canaries · ◐ scripts | ✔ `ciamCanary` (service role checked, flow, interval, credential role, alert fed); Synthetics canaries and Application Insights standard tests **imported** as `ciamCanaryBinding`; scripts as bundles |
| Log archives needed for audit (historical access logs, PF audit logs) | S3 / SIEM | D | ○ location, retention, legal hold. **Must survive decommission.** | ✔ log routes' retention obligation and legal hold; planner blocks a target destination keeping logs less long, and names legal-hold sources to keep |

---

## 14. Backup and DR  [core]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| `dsbackup` schedules, backup locations, encryption | DS tasks + S3 | I + B | ● | ✔ `ciamBackupTarget` (schedule ~) |
| Managed databases the stack uses (PingFederate/AM/IDM repositories, grant, session and token stores): engine and version, edition, size, high availability, encryption key, TLS, backup retention and point-in-time restore, deletion protection, parameters, endpoint, credential secret | RDS/Aurora, Azure Database Flexible Server, Cloud SQL | B | ● | ✔ `ciamDatabase` (core `data` domain), bound by role so products name it; rendered into each cloud's Terraform (password only in the secret store) and read back from Terraform state, CLI output, ARM and Cloud Asset Inventory; `databases` report; the ranges admitted to its port (`ciamSourceCidr`: the database's security group or NSG rules; on Google Cloud the private services access peering, a `peered-service` private endpoint whose range the egress allowlist admits); planner blocks another engine or major version and names lost availability, encryption, protection, retention and parameters, with fixes |
| Backup buckets and other object stores: versioning, immutability (Object Lock, immutability policies, retention locks), lifecycle, replication, public access, KMS (bucket policy ~) | S3, Blob Storage, Cloud Storage | B | ● | ✔ `ciamObjectStore` depth (core `data` domain): rendered for the three clouds when the stack keeps the store (a keeper's comment with what to ask otherwise; Cloud Storage's copy as a Storage Transfer Service replication job), read back from Terraform state, CLI output, ARM and Cloud Asset Inventory; `object-stores` report; planner names lost versioning, public access block, encryption and copies, a weaker or shorter lock, and backups deleted before their retention, with fixes |
| AWS Backup plans/vaults, EBS snapshot policies (DLM) | AWS | B | ● | ◐ snapshot policies as `ciamSnapshotPolicy` (frequency, start, retention, copy regions, consistency): Lifecycle Manager policies on AWS and snapshot-schedule resource policies on Google Cloud rendered and read back. Backup services as `ciamBackupVault` (key, lock governance/compliance and its days, cross-region restore) and `ciamBackupPlan` (the roles it protects, its vault, every hours from a start, window, retention, copy regions, its own restore-test interval), compared by role whichever mechanism each environment uses (a source's snapshot policy may be a target's backup plan); AWS Backup vaults (with their lock), plans and selections by tag `Role`, and Azure Backup's Data Protection vaults (redundancy, immutability, customer-managed key), disk backup policies and a backup instance per disk (with the vault identity's grants; on Azure a disk's scheduled snapshots are a backup plan's), and Google Backup and DR vaults (their location the plans' copy region, minimum enforced retention), disk backup plans (rule, schedule, window) and an association per disk, rendered and read back from state, the CLIs, ARM and Cloud Asset Inventory |
| PF config archive backups (auto + scheduled exports) | PF + storage | B | ● | — |
| DR design: region, RTO/RPO targets, standby replicas, failover runbook | Docs | I + M | ● RTO/RPO as meta, DR topology as intent | ✔ the core `recovery` domain: `ciamRecoveryObjective` under `ou=recovery` (RTO and RPO minutes for the roles it names, its runbook), `ciamStandby` on a standby environment (whose, mode hot / warm / pilot-light / cold, failover runbook; region from its cloud) and `ciamFailoverDrill` records under `ou=failover-drills` (from, to, result, minutes until service, minutes of changes lost); the planner holds both environments of a move to each objective (best recovery point, counting only copies outside the environment's region: replication into an environment in another region, an object-store replica, point-in-time restore whose backups are copied to another region (`ciamCopyRegion` on the database), or the interval of a snapshot policy or backup plan copying to another region, with a fix copying as often as the RPO allows; copies kept in the region are named but don't count; recovery time from the latest passed restore test or drill; a drill's data loss), re-points the source's standbys and joined deployments at the target at cutover (a fix), and names a target nothing stands by for, standbys in their primary's region or without a runbook, and failover DNS whose primary is the source's; reports `recovery`, `standbys`, `failover-drills`. Intent and evidence only: failover routing is the edge domain's (rendered), replication and backups the directory and data domains' |
| **Restore test records** (date, result, duration) | Tickets / docs | M | ● "Last successful restore test", which the planner can enforce | ✔ `ciamRestoreTest` records under `ou=restore-tests` (when, environment, the role restored and from what, level `disk` or `application`, result, minutes, runbook); the planner holds both environments to them for every role the source protects (target: a failed latest test blocks; no passed application-level test before cutover, or an overdue one, is an action; source: never tested, failed, overdue), due every `restore-test-interval-days` (an estate setting, 90 by default) or a plan's own interval; `opsdir report restore-tests` |
| Backup readability across the move (same deployment ID/password) | — | — | ● A planner check, already enforced | ✔ |

---

## 15. Cross-cutting: strings hiding in files

Most of the migration risk isn't in any one subsystem. It's **the same value copied into many places**. opsdir needs an **observed "string census"**: scan every config file, template, script and export for these values and record each occurrence as an `observed` entry pointing at the value's owning entry.

| Value | Typically hides in |
|---|---|
| Replica hostnames / IPs | App configs, PF LDAP data store, cron scripts, `/etc/hosts`, `tools.properties`, monitoring targets, partner allowlists |
| Service FQDNs | Templates, email links, SAML metadata, CAPTCHA allowed domains, CORS/redirect allowlists |
| Bind DNs & base DNs | Every consumer's config |
| Certificate fingerprints | Partner metadata, pinned clients, JDK cacerts, PA/PF trust stores |
| Legacy brand names & domains | Email senders, templates, page titles, reset links |
| Account IDs, ARNs, bucket names | Scripts, IAM policies, backup jobs, pipelines |
| Secret *values* (should be none) | Scripts, env files, run.properties. **The census must flag these, never store them.** |

Result: "change this hostname" becomes a query that lists every file and every party affected.

**Today:** `opsdir census PATH` records each scanned file (`ciamScannedFile`, with the server it came from and its secret concerns by line) and each value found (`ciamOccurrence`: the owning entry, the attribute, the lines; never the value). `opsdir report census [DN]` lists them, `blast-radius` includes them, and the planner asks to change files that hard-code a source value the target doesn't keep. Legacy brand names aren't record values yet, so they aren't looked for.

---

## 16. Delivery: IaC, config management, pipelines, artifacts  [likely]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| Terraform code, modules, tfvars | Git | I + B | ● **Generated from opsdir** (already done for the core) | ✔ renderer (AWS/Azure/Google Cloud) |
| **Terraform state** (S3 + DynamoDB lock) | AWS | O + B | ◐ Location, and a drift source. A new cloud gets new state. Imports need a plan. | ~ AWS, Azure and Google Cloud state **imported** into servers and bindings (`aws/terraform-state`, `azure/terraform-state`, `gcp/terraform-state`; `--dry-run` shows drift); Google Cloud also from Cloud Asset Inventory and `gcloud` (`gcp/cli-inventory`) |
| CloudFormation stacks (legacy) | AWS | O | ◐ Inventory, then retire | — |
| Ansible: inventory, group_vars/host_vars, roles, playbooks, Vault-encrypted vars | Git | I + B + S | ● Inventory and vars come from opsdir. Roles are ◐. | — |
| Packer templates, image pipeline | Git | I | ◐ | — |
| CI/CD pipelines (Jenkins, GitHub Actions, Azure DevOps, GitLab): definitions, service connections, runners/agents | CI | I + B + S | ● Pipeline facts + credential refs. Self-hosted runner network location is a binding. | ~ `ciamJob` kind `pipeline`: schedules, triggers, runners, environments, secrets by name **imported** (packages `opsdir-adapter-github-actions`, `-gitlab-ci`, `-azure-devops`; AWS CodePipeline/CodeBuild by the AWS adapter as job bindings); service connections, runner network placement and Jenkins — |
| Artifact repository (Artifactory/Nexus/S3): PingDS zip, PF zip, adapters, JDK, agents; checksums | Repo | I | ● Exact artifact coordinates + SHA-256 per product version | — |
| Container registry (ECR/ACR) + image tags | Registry | B | ● | — |
| Ping licenses & support entitlements (Backstage), Duo licensing, user-count limits | Vendor portals | M | ● expiry, limits, contract owner | — |

---

## 17. Admin plane: who operates the stack  [core]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| Who may do what: permission sets (verbs on binding roles) and the principals holding them (workloads, deployers, operators, break-glass, services) | record | I | ● | ✔ `ciamPermissionSet`, `ciamPrincipal` (`report principals`) |
| Workload identities and their grants (IAM roles + instance profiles, managed identities, service accounts) | AWS / Azure / Google Cloud | B | ● | ✔ `ciamIdentityBinding` (grants, denials, ceilings, trust); rendered least-privilege per cloud; read from state and CLI output; effective access allowed / denied / unknown, cloud evaluators' verdicts preferred |
| CI deployer trust (OIDC: GitHub Actions, GitLab, Azure DevOps) | landing zone | B | ● | ✔ the identity binding's `ciamTrustedBy`; rendered to `terraform/landing-zone/` (OIDC provider + role, federated credential, workload identity pool) |
| Workforce SSO to the clouds (IAM Identity Center permission sets, Entra groups and PIM, Google groups) | Entra ID / AWS / Google | I + B | ● | ✔ operator principals bound to a group or permission set; landing-zone renders; access path `workforce-sso` |
| Organization guardrails (SCPs / RCPs, Azure Policy and deny assignments, organization policies and IAM deny policies) | landing zone | B | ● | ✔ `ciamGuardrail` (what it prevents, neutrally; its denies and ceilings); rendered from verified mappings; a missing one is a request to the landing zone's owners |
| Admin access to PF / PA consoles (OIDC via workforce IdP), roles | PF / PA | I | ● | — |
| Personal DS admin accounts, delegated support roles (password reset, unlock) | DS | I | ● | ~ ACIs |
| Bastions / jump hosts / VPN / Session Manager / IAP | Network | B | ● | ✔ `ciamAccessPath` (`report access-paths`); a way in the target lacks is named |
| Break-glass procedures and accounts | PAM + runbook | I + M | ● | ✔ break-glass principal: credential role, runbook, last tested (stale after 180 days) |
| Access reviews for platform admins (IGA, e.g. SailPoint) | IGA | M | ● review dates, reviewer, result | ✔ review date and interval on each principal (overdue is an action); reviewer and result: — |

---

## 18. Governance, ITSM and compliance  [core]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| Change records (CAB), standard-change templates | ServiceNow | M | ● Two-way sync by ticket ID | ✔ `ciamChange` (sync —) |
| Incidents, problems, postmortems | ServiceNow / docs | M | ● | ✔ `ciamIncident` |
| CMDB CIs + relationships | ServiceNow | M | ● Publish a summary into CMDB. opsdir holds the executable detail. | — |
| Service catalog items (app-onboarding intake form) | ServiceNow | I | ● The form fields map 1:1 to a `ciamIntegration` draft | — |
| Assignment groups, on-call schedules, escalation paths | ITSM / PagerDuty | M | ● as `ciamParty` + schedules | ~ `ciamParty` |
| Runbooks / work instructions | Confluence / SharePoint / KB | M | ● entry + `appliesTo` + `lastValidated` · ◐ document itself | ✔ `ciamRunbook` |
| Architecture & data-flow diagrams | Docs | M | ◐ Rendering them *from* opsdir is a future feature | — |
| Security plan and authorization boundary, control mappings (e.g. NIST 800-53 / 800-171, ISO 27001, SOC 2, SOX ITGC) | GRC tool | M | ● Control → evidence query (e.g. "list ACIs with review older than 12 months") | — |
| Risk register, exceptions/waivers (with expiry) | GRC | M | ● | — |
| Data classification & retention schedule | Policy | M | ● feeds `ciamPiiClass`, `ciamRetentionRule` | ✔ (each environment's `ciamDataClassification`: estate domain) |
| Cloud accounts, tagging policy, cost centers | Cloud org / finance | B + M | ● | ✔ the core `estate` domain: each cloud's account (`ciamAccountRef`: AWS account, Azure subscription, Google Cloud project; renderers default each root's account input to it, AWS refuses another), resource group and data classification per environment, a party's cost center (`ciamCostCenter`), and the tag policy (`ciamTagRule` under `ou=tag-policy`: key and source: owner, cost center, classification, environment, cloud, literal) applied to every rendered resource (AWS provider default tags, Azure tags merged per resource, Google Cloud default labels in label form); a tag an environment can give no value is an action; every cloud import names the resources it places without a required tag; `opsdir report tags` |
| Vendor contracts, DPAs, partner federation agreements | Legal / procurement | M | ◐ | — |

---

## 19. External parties  [core]

| Party | What they hold that depends on us | Datify | opsdir today |
|---|---|---|---|
| Federation partners (inbound IdPs, outbound SPs) | Our metadata URL, entity ID, signing cert, ACS/SSO URLs | ● contacts, lead times, what they pin | ✔ `ciamParty` + integrations |
| App teams (relying parties & LDAP binders) | Hostnames, bind DNs, client IDs, claim names | ● | ✔ `ciamConsumer`, `ciamIntegration` |
| Network/firewall teams (ours and theirs) | Rules for our IPs | ● | ✔ `ciamExternalAllowlist` |
| Supplier identity hubs | Federation config | ● | ~ |
| SaaS vendors (MFA, CAPTCHA, email) | Keys, allowed domains, IPs | ● | ✔ `ciamExternalService` (MFA, CAPTCHA, email, SMS vendors with contacts and allowed domains) |
| Auditors | Evidence formats and cadences | ● | — |

---

## 20. What cannot be datified, and what to record instead

| Thing | Why not | Record instead |
|---|---|---|
| User entries & password hashes | They're the product's data. Replication moves them, and copying adds privacy risk. | §3 profile (counts, distributions, shape) |
| Secret and key material | SPEC R4 | refs, rotation facts, continuity requirements |
| Runtime tokens, sessions, grants | Ephemeral or product-owned | counts, TTLs, the decision (migrate vs drop) |
| Binaries, JARs, images | Opaque | coordinates + SHA-256 |
| HTML templates, scripts, dashboards | Free-form | hash, owner, string-census hits |
| HSM-resident keys | Non-exportable by design | ref + a rotation plan as a change |
| Partners' own systems | Not ours | what they pin, contact, lead time, drafted request |
| Tribal knowledge | Not written down | an `ou=unknowns` list: questions with owners, closed when answered |

---

## 21. Coverage today, and the build order

**Modeled today (✔):**
- **Where things run:** clouds and environments (overlays of other environments, per-environment overrides with why, declared stacks and required roles), servers, and bindings: networks, subnets, service names, firewall rules, egress, interconnects, secret, key and certificate references, object stores (backup targets among them).
- **Directory:** backends, indexes, password policies, connection handlers, log publishers, replication topology, declared vs observed snapshots; the user directory's schema (every attribute and object class, standard or defined in the record); consumers and ACIs.
- **Federation:** the platform's own identity services (base URL, entity ID, issuer), SAML and OIDC integrations with claim maps in the protocols' own vocabulary.
- **Keys and secrets:** certificates (public facts), credentials with continuity, HSM, exportability and rotation facts, one per key or secret and bound per environment; secret stores AWS Secrets Manager/KMS, Azure Key Vault, Google Cloud Secret Manager/Cloud KMS, HashiCorp Vault, Kubernetes secrets, CyberArk.
- **Products on the standard bases:** PingDS and OpenDJ (DS lineage), PingFederate, PingAM (realms, journeys, policy sets), PingIDM (managed objects, connectors, mappings, schedules), PingGateway (routes); importers for the PingAM, PingIDM and PingGateway exports.
- **Files:** config files held setting by setting and rebuilt per environment; code and templates as bundles, verified against a checkout.
- **Governance:** owners and parties, changes, incidents, runbooks, external allowlists, custom fields and record types.
- **Access:** permission sets and principals (intent); per environment the cloud identities they act as with what each cloud grants, denies and caps, the organization guardrails and the ways operators come in; effective access judged allowed, denied or unknown, cloud evaluators' verdicts preferred.
- **Network:** route tables, network ACLs, private endpoints, endpoint services, egress firewalls and forward proxies (with the sites they allow), interconnects, time sources and flow logs, per environment; the ports matrix derived from what products declare; the landing zone's plumbing rendered into its keepers' roots.
- **Data services:** managed databases (engine and version, availability, encryption, TLS, backups and point-in-time restore, deletion protection, parameters, credential secret) per environment, bound by role so products name them; object stores' versioning, immutability, encryption, lifecycle, public access and replication; rendered for the three clouds and read back.
- **Edge:** traffic and protection policies and header contracts (intent, with the endpoints products declare); per environment the DNS zones (and who runs them), records with TTLs and routing, forwarders, and what the load balancers, firewalls, DDoS protection and CDNs run, read back in the policies' terms.

**Renderers:** Terraform (AWS, Azure, Google Cloud, edge included: layer 7 load balancers, WAFs, DDoS protection, CDNs, DNS; managed databases and object stores; the landing zone's own root for its owners), cloud evaluator scripts (`access/evaluate.sh`), `dsconfig` batch and setup scripts (PingDS, OpenDJ), standard LDIF (user schema and tree), ACI LDIF, PingFederate JSON (illustrative subset), SAML metadata, OIDC client registrations and discovery, PingAM (Amster entities), PingIDM (project files), PingGateway (routes), captured files.

**Gaps, in roadmap order** (the roadmap is tracked in `.aimfp-project/`):

| Roadmap path | Closes | New classes / importers / renderers |
|---|---|---|
| **4. Importers** | the model is only as good as its data | ~~DS configuration~~ (done: `config.ldif` and archived configs → snapshots, or the declared configuration); ~~DS access-log miner~~ (done: JSON access logs → `ciamConsumer`, values-free); ~~PingFederate~~ (done: bulk export → integrations, claims, certificate facts; data stores checked; adapters, token managers, data stores and storage locations with path 5's PingFederate depth); ~~string census~~ (done, §15: `opsdir census` → `ciamScannedFile`/`ciamOccurrence`: file, server, lines, owning entry; secrets flagged by line); Terraform state, cloud CLI inventories and native IaC (AWS and Azure done, Google Cloud with milestone 4.12: `*/terraform-state`, `*/cli-inventory` (Cloud Asset Inventory and `gcloud` for Google Cloud), `aws/cloudformation`, `azure/arm`; roles for what a cloud can't tag from `roles.json`) → bindings |
| **5. Stack coverage** | §4, §9–§14, §17 | ~~PingFederate depth~~ (done, milestone 4.1, in the PingFederate package's own schema rather than `ciam*` classes: data stores, validators, adapters, selectors, token managers, policy contracts, authentication policies and fragments, OIDC policies, authorization server settings, links between them checked by the planner, nodes' files with `tcp.xml` discovery as a **binding**, every other resource held as is); ~~hidden automation~~ (done, milestone 4.2: the core `automation` domain's `ciamJob` and `ciamJobBinding`; cron and timers from servers' files, Lambda / EventBridge / Scheduler / CodePipeline / CodeBuild and Azure Function Apps from the cloud importers, GitHub Actions / GitLab CI / Azure DevOps pipelines from their own packages); ~~host baseline and Kubernetes workloads~~ (done, milestone 4.3: the core `compute` domain's `ciamHostBaseline` per server role from servers' files, `ciamComputeGroup` and `ciamCluster` bindings from AWS and Azure state, `ciamWorkload` and CronJobs from Kubernetes manifests; the planner flags truststore additions the record lacks, pinned names, missing baselines, weaker target compute and workloads with nowhere to run); ~~messaging and external services~~ (done, milestone 4.4: the core `messaging` domain's `ciamExternalService`, `ciamMailSender`, `ciamSendingIdentity` and `ciamEventStream`/`ciamStreamBinding`; PingFederate's notification publishers and CAPTCHA providers, SES and Communication Services identities with their DNS, queues, topics and buses from AWS and Azure); ~~data profile~~ (done, milestone 4.5: `opsdir data-profile` streams ldapsearch output to counts, `ldap/data-profile` records them under `ou=data-profile`; reports and planner checks on schemes, undescribed attributes, dangling members); ~~observability intent~~ (done, milestone 4.6: the core `observability` domain's alert rules, log routes and canaries, channels and log destinations as bindings, and the alarms and checks each cloud runs, imported from AWS and Azure Terraform state; planner checks on delivery, retention, legal hold and monitoring nobody described); ~~Google Cloud~~ (done, milestone 4.12: `opsdir-adapter-gcp` at parity with AWS and Azure: Terraform with Shared VPC data sources, network-tag firewall rules, CMEK and Shielded VM, passthrough load balancers with their health-check rules; Secret Manager and Cloud KMS references; Terraform state and Cloud Asset Inventory / `gcloud` importers through one mapping, covering compute groups, GKE, Pub/Sub and Cloud Monitoring; PingFederate discovery by TCPPING or DNS_PING; the firewall model as a per-environment choice (secure tags) is in 4.9); ~~platform IAM and admin plane~~ (done, milestone 4.7: the core `access` domain; neutral permissions mapped per cloud, least-privilege workload identities, the landing zone (CI OIDC trust, workforce access, guardrails) rendered for its owners and asked of them, IAM read from Terraform state and CLI output on all three clouds, effective access allowed / denied / unknown with the AWS policy simulator's and Google's Policy Troubleshooter's verdicts as evidence); ~~edge and traffic protection~~ (done, milestone 4.8: the core `edge` domain; traffic and protection policies and header contracts as intent, DNS zones, records, forwarders and edge services as bindings; layer 7 load balancers, WAFs, DDoS protection, CDNs and DNS rendered for the three clouds and read back from Terraform state and CLI output; TTL lowering, zone owners' requests, unprotected sign-on endpoints and header contracts checked); ~~network depth~~ (done, milestone 4.9: the core `network` domain; route tables, network ACLs, private endpoints, endpoint services, egress firewalls and forward proxies, interconnect depth, time sources and flow logs as bindings, rendered for the three clouds (the landing zone's plumbing into its keepers' roots, with import blocks and requests) and read back from every importer source; the ports matrix derived from what products declare; assisted fixes the planner's findings offer, with options, inputs, prerequisites and verify-after; import conflicts decided, never assumed, and import runs recorded); data services, backup and DR (in progress, milestone 4.10: ~~multi-host external systems~~, ~~managed databases~~ and ~~object storage depth~~ done: the core `data` domain's `ciamDatabase` on RDS/Aurora, Flexible Server and Cloud SQL and object stores' protection on S3, Blob Storage and Cloud Storage, rendered and read back, checked by the planner; volumes and snapshots, backup plans and restore tests, DR to come); cloud governance, audit and cost |
| **6. Renderers & targets** | working files for every covered target | PingFederate Admin API payloads / Terraform provider (replacing the illustrative subset), Kubernetes/ForgeOps overlays, config management and on-prem, observability rules, per-adapter round-trip tests (import → render → import), each cloud's native IaC alongside Terraform (ARM templates / Bicep for Azure, CloudFormation for AWS) |
| **7. Conditional products & governance** | §6–§7, §18 | PingAccess, SiteMinder (XPSExport), cloud-managed identity services; vendor-neutral ITSM/CMDB, GRC, SIEM, PAM, PKI and firewall-manager integrations; the unknowns register (`ciamUnknown`: question, owner, blocking, answer) in the planner's verdict |
| **8. Interfaces, validation & release** | operating it day to day | full CLI, a read-only LDAP front end or HTTP API, an MCP server for AI assistants, validation against real product instances, SPEC 1.0 with a registered OID arc |

---

## 22. Questions to answer for each estate

These don't change the model; they decide which parts of it an estate uses and which importers and renderers matter first.

1. Which products are present beyond the directory and federation server: PingAM, PingIDM, PingGateway, PingAccess, SiteMinder?
2. Virtual machines or Kubernetes (ForgeOps)? This decides §11.1 vs §11.2 and which renderer matters.
3. Where does PingFederate keep clients, grants and sessions: XML, JDBC or LDAP (DS)?
4. Are signing keys HSM-backed?
5. Do consumers bind to service names or to replica hostnames?
6. If a move is planned: to which cloud, account or region, and what is pre-built there (network, DNS, PKI, SIEM, PAM)?
7. Is a product version upgrade in or out of the move?
8. Which ITSM, SIEM, PAM, PKI and firewall-manager products are in place? Each one is an importer.
