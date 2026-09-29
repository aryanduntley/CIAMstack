# CIAMstack: Stack Inventory & Datification Map

*Every subsystem, file, store and external dependency that a production PingDS + PingFederate CIAM estate on AWS is likely to carry. Every item here has to be accounted for in a migration, and each is assessed for whether it can live as data in the opsdir database. Drafted 2026-09-24. It builds on `ops-directory-model.md` (the design) and `opsdir/SPEC.md` (the standard).*

---

## 0. How to read this

**The reference stack.** This is an *external identity* (customer/partner/supplier) platform. PingDS is the directory and PingFederate does federation and SSO. It runs on AWS, with an enterprise reverse proxy, Duo MFA, several portals as relying parties, and the usual enterprise wrapping (ITSM, SIEM, PAM, PKI). It is **moving to a different cloud landing zone** (another AWS org or GovCloud, or Azure). This is the most likely shape of a large merged aerospace/defense estate. Nothing here is confirmed about any real company.

**Presence in the estate** (per subsystem):
- **[core]**: the stack can't exist without it.
- **[likely]**: standard for this product family, industry or scale.
- **[maybe]**: conditional. It depends on the product lineage or history. Confirm before modeling.

**Class** is opsdir's `X-PORTABILITY` class (SPEC §3.1), plus one extra letter for things opsdir must *not* hold:

| Code | Class | In a migration |
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

**opsdir today:** ✔ modeled in the current schema · ~ partial · — gap.

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
| Server config tree (`cn=config`) | `<ds>/config/config.ldif`, edited with `dsconfig` | I + B | ● Declared config as entries. Render a `dsconfig` batch. Snapshot the live one into `ou=observed`. | ~ backends, indexes, pw policies, conn handlers, log publishers, replication |
| Archived config versions | `<ds>/config/archived-configs/` (auto-kept on change) | O | ◐ Import as snapshots. Gives free drift history. | — |
| Backends | JE / LDIF / memory / proxy backends, base DNs, `confidentiality-enabled`, cache sizes | I (+B for db dirs) | ● | ✔ `ciamBackend` |
| Indexes | Equality/presence/substring/ordering/VLV, `index-entry-limit`, confidentiality per index | I | ● | ✔ `ciamIndex` (VLV —) |
| Connection handlers | LDAP 389, LDAPS 636, HTTP(S) 8080/8443, admin 4444, JMX; `listen-address`, SSL cert nickname, cipher suites, protocols | I (ports) + B (addresses) | ● | ✔ `ciamConnectionHandler` (ciphers/protocols —) |
| Password policies | Complexity validators, history, lockout, expiry, storage schemes, `last-login-time-attribute`, idle lockout, grace logins | I | ● | ~ `ciamPasswordPolicy` (validators, idle lockout, last-login config —) |
| Password validators & generators | Character set, length, dictionary (+ dictionary file), repeated chars, similarity | I | ● Dictionary file as ◐ with its hash | — |
| Password storage schemes | PBKDF2-HMAC-SHA256/512, Bcrypt, SSHA512, legacy (SSHA, crypt, MD5) | I | ● List enabled schemes, and count users per scheme (see §3) | ~ `ciamStorageScheme` |
| Plugins | Referential integrity, unique attribute, 7-bit clean, entity tag, attribute cleanup, change number control, custom plugins | I | ● | — |
| Custom extensions | `<ds>/extlib/*.jar`, custom plugin classes | I | ◐ Name, version, SHA-256, source repo | — |
| Virtual attributes | `isMemberOf`, `entryDN`, `numSubordinates`, collective attrs, user-defined templates | I | ● | — |
| Groups config | Static, dynamic and virtual-static group implementations, `isMemberOf` | I | ● | — |
| Global ACIs | `global-aci` in `cn=Access Control Handler,cn=config` | I | ● Same model as data ACIs | ~ `ciamAci` holds data ACIs. Global ones not separated. |
| Root/admin users & privileges | `uid=admin` (7.x), `uid=monitor`, `ds-privilege-name` sets (`bypass-acl`, `password-reset`, `proxied-auth`, `config-read`…) | I + S | ● Accounts and privileges as entries, passwords as refs | ~ secret refs only |
| Replication | Server IDs, group IDs, bootstrap servers, replication ports (8989), purge delay, changelog enablement, assured replication, topology | I (shape) + B (hosts/IDs) | ● | ✔ `ciamReplicationTopology`, `ciamJoinsDeploymentOf` |
| External change log (`cn=changelog`) | Consumers (IDM, sync jobs, CDC) read it, each with a cookie or change number | I + O | ● Register the ECL readers as consumers. Cookies are ○. | — |
| Deployment ID + password | Generated at setup. Derives the shared master key. | S | ○ Reference only. **It must be continuous across the migration.** | ✔ roles `ds-deployment-id/password` |
| Keystore / truststore | `<ds>/config/keystore` (PKCS12) + `keystore.pin`, truststore, key-manager and trust-manager providers | S (+ cert facts) | ○ keys · ● cert facts | ~ cert facts ✔, provider config — |
| Crypto manager | Cipher and key-wrapping config, attribute/backend encryption settings | I | ● | — |
| Log publishers | Access (JSON/CSV/LDAP), error, debug, replication, HTTP access; filtering criteria; rotation and retention policies | I (+B for paths) | ● | ~ `ciamLogPublisher` (rotation/retention/filters —) |
| Common-audit handlers | JSON / CSV / Syslog / Splunk / JMS / Elasticsearch handler configs | I + B + S | ● | — |
| Alert handlers & SMTP | JMX/SMTP alert handlers, SMTP server config, alert recipients | I + B | ● | — |
| Monitoring endpoints | `cn=monitor`, HTTP `/metrics/prometheus`, `/alive`, `/healthy`; the monitor user | I | ● | — |
| Work queue / threads / JVM tuning | `num-worker-threads`, entry cache, `OPENDJ_JAVA_ARGS` (heap, GC) | I (+B for sizes) | ● | — |
| Disk thresholds | `disk-low-threshold`, `disk-full-threshold` per backend | I | ● | — |
| Rest2LDAP mappings | `<ds>/config/rest2ldap/endpoints/**.json` | I + C (the REST paths) | ● Mapping as entries. Its JSON as ◐ with a hash. | — |
| Setup profiles used | `setup --profile` names + params (AM identity store, AM config, AM CTS, IDM repo, DS user data) | I | ● Record which profiles made which backends | — |
| Scheduled tasks | Recurring backups, purges, imports in the tasks backend (`<ds>/config/tasks.ldif`) | I (+B for targets) | ● | ~ backup target only |
| Product version & build | `<ds>/config/buildinfo`, patch level | M/O | ● | ✔ `ciamProductVersion` |
| CLI defaults | `~/.opendj/tools.properties` (per admin host) | B | ◐ Flag it, since it often embeds hostnames and bind DNs | — |

### 2.2 Directory schema

| Artifact | Location / format | Class | Datify | opsdir today |
|---|---|---|---|---|
| Standard schema | `<ds>/config/schema/00-core.ldif` … | I | ◐ Version reference only | — |
| Custom schema | `<ds>/config/schema/99-user.ldif` (or custom files), `cn=schema` | I | ● Every custom attributeType and objectClass as an entry, with purpose, PII class and export flag | ✔ `ciamUserAttribute` (attributes ✔; custom objectClasses —) |
| Schema-checking policy | Strictness settings, allowing attribute names with underscores, etc. | I | ● | — |

### 2.3 Directory-hosted operational data (beyond people)

*Whatever else the DS stores. Easy to forget, and it matters for sizing and for which consumers exist.*

| Artifact | Class | Datify | opsdir today |
|---|---|---|---|
| PingFederate **OAuth client storage** (if LDAP-backed) | I (the clients) | ● as `ciamIntegration` (it is intent) | ~ |
| PingFederate **persistent grants** (if LDAP-backed) | D | ○ count + TTLs | — |
| AM config store / CTS / identity store backends (if AM exists) | I / D / D | ● config · ○ CTS/identities | — |
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
| ○ Attribute fill rates per attribute | Finds dead attributes and legacy leftovers (e.g. names from pre-merger companies) |
| ○ Password-hash scheme distribution | Legacy schemes must stay enabled on the target, or users need a rehash-on-login plan |
| ○ `lastLoginTime` / `pwdChangedTime` distribution | Inactive-account cleanup scope. Decide before or after the move? |
| ○ Locked / disabled / pending-registration counts | Lifecycle hygiene baseline |
| ○ Group sizes, orphan groups, members pointing at missing DNs | Referential cleanup |
| ○ Largest entries, big multi-valued attributes | Replication and index-entry-limit risks |
| ○ Entries holding challenge questions (KBA) | A modernization target (NIST 800-63B) |
| ● Per-attribute PII class, export-control flag, retention rule | Privacy and ITAR gating, what may leave which boundary |
| ○ Duplicate identities (the same person across legacy stores) | Consolidation scope |

Importer: an `ldapsearch`-driven profiler that emits statistics only (no values). Shape: `observed` entries under `ou=user-schema` and a new `ou=data-profile`.

---

## 4. Federation: PingFederate  [core]

`<pf>` is the install root (often `/opt/pingfederate`). It runs as a cluster: one admin console node plus N engine nodes.

### 4.1 Node and cluster files

| Artifact | Location / format | Class | Datify | opsdir today |
|---|---|---|---|---|
| Node run config | `<pf>/bin/run.properties`: ports (9031 runtime, 9999 admin), operational mode (`CLUSTERED_CONSOLE`/`CLUSTERED_ENGINE`), node tags, `pf.cluster.*`, bind addresses, HSM mode | I + B | ● Render per node | — |
| JVM memory | `<pf>/bin/jvm-memory.options` | I (+B for sizes) | ● | — |
| Cluster discovery | `<pf>/server/default/conf/tcp.xml` (JGroups): S3_PING / NATIVE_S3_PING / DNS_PING on AWS, AZURE_PING / DNS_PING on Azure; encryption key for cluster traffic | **B** + S | ● **A classic migration miss.** The discovery protocol is cloud-specific. | — |
| Jetty / TLS / headers | `<pf>/server/default/conf/jetty-runtime.xml`, `jetty-admin.xml`, response headers, cipher suites | I | ● | — |
| Logging | `<pf>/server/default/conf/log4j2.xml`: server, audit, provisioner, transaction, admin and admin-api logs; syslog/Splunk appenders | I + B (targets) | ● | — |
| Service wiring | `<pf>/server/default/conf/META-INF/hivemodule.xml` (which store backs clients, grants, sessions) | I | ● | — |
| Custom adapters / plugins | `<pf>/server/default/deploy/*.jar` (Duo adapter, custom PCVs, custom data sources) | I | ◐ Name, version, SHA-256, source | — |
| JDBC drivers | `<pf>/server/default/lib/*.jar` | I | ◐ | — |
| Login / error / reset templates | `<pf>/server/default/conf/template/*.html` (Velocity), CSS, images: **branding lives here** (legacy company names, logos) | I + C (URLs in them) | ◐ Hash + owner, plus a **string scan** for hostnames and legacy brands (§15) | — |
| Language packs | `<pf>/server/default/conf/language-packs/*.properties` | I | ◐ | — |
| Config master key | `<pf>/server/default/data/pf.jwk` (encrypts secrets inside the config), or an HSM | S | ○ Reference only. Its continuity decides whether a config archive imports cleanly. | ~ generic `pf-signing-key` role only |
| Config store | `<pf>/server/default/data/` (XML + config-store files) | I + B + S | ○ Don't parse the files. Datify through the **Admin API** (§4.2) instead. | — |
| Auto config archives | `<pf>/server/default/data/archive/*.zip` | O | ◐ Location, date, hash | — |
| Drop-in deployer | `<pf>/server/default/data/drop-in-deployer/` (config archive applied at start) | I | ◐ | — |
| License | `<pf>/server/default/conf/pingfederate.lic`: expiry, node/connection limits | M | ● Facts (expiry, limits) | — |
| Product version | `<pf>/bin/pf.version` / Admin API `/version` | M/O | ● | ✔ `ciamProductVersion` |

### 4.2 Configuration objects (Admin API `/pf-admin-api/v1`, bulk export `/bulk/export`)

| Object | Class | Datify | opsdir today |
|---|---|---|---|
| **SP connections** (SAML/WS-Fed outbound): entity ID, ACS URLs, bindings, attribute contract, signing/encryption certs, SLO | I + **C** | ● | ✔ `ciamIntegration` (SAML) + claims |
| **IdP connections** (inbound partner federation): partner entity ID, SSO URLs, JIT provisioning, attribute mapping | I + C | ● | ~ `ciamJitBaseDn`; inbound mapping — |
| **OAuth/OIDC clients**: client ID, redirect URIs, grant types, PKCE, auth method, token policy, scopes | I + C (+S for secrets) | ● | ✔ (auth method, token lifetimes —) |
| OAuth scopes, scope groups, exclusive scopes | I | ● | — |
| Access token managers (JWT / reference), signing key choice, lifetimes | I | ● | — |
| OIDC policies (ID token claims, lifetimes) | I | ● | — |
| Token exchange / processors / generators | I | ● | — |
| Authentication policies (trees), policy contracts, authentication selectors (IdP discovery, "select your identity provider") | I | ● These are the login flows, so they deserve first-class modeling | — |
| IdP adapters: HTML Form, Identifier-First, Duo, Kerberos… | I (+S) | ● | — |
| Password credential validators (LDAP Username PCV → DS) | I + S | ● | — |
| **Data stores**: LDAP (DS hosts, bind DN, pool sizes, LDAPS), JDBC | I + B (hosts) + S | ● **Consumer link to the directory.** Hosts must be *service names*. | ~ as a consumer |
| Local identity profiles (PF-native registration & profile management), if used | I | ● | — |
| Password reset / change settings (email or SMS OTP), notification publishers (SMTP) | I + B + S | ● | — |
| CAPTCHA providers | I + S | ● | — |
| Signing key pairs, SSL server key pairs, decryption keys | S + cert facts | ○ keys · ● cert facts (fingerprint, expiry, `usedBy`) | ✔ `ciamCertificate` |
| Trusted CAs, partner metadata URLs & refresh | I + C | ● | — |
| Virtual host names, base URL, SAML entity ID of *our* IdP, OIDC issuer | **C** | ● **Must not change** | ✔ `ciamEntityId`, `ciamIssuer` |
| Redirect validation allowlist | I | ● | — |
| Session settings, persistent session storage, session revocation | I | ● | — |
| Outbound provisioning (SCIM/connectors to SaaS apps) + provisioner DB | I + D | ● channels · ○ state | — |
| Admin accounts & admin console auth (native / OIDC / cert), roles (Admin, Crypto, User Admin, Auditor) | I + S | ● | — |
| Server settings: contact info, notifications (cert-expiry emails), roles & protocols enabled | I | ● | — |
| Cluster replication state (config pushed to engines) | O | ● "Is replicated?" flag + timestamp | — |

### 4.3 PingFederate runtime stores  (class D)

| Store | Where | Datify |
|---|---|---|
| Persistent grants (refresh tokens, consents) | JDBC DB or LDAP (DS) | ○ count, TTL, store ref. Migrate or accept re-consent (a decision to record). |
| Persistent authentication sessions | JDBC DB | ○ Usually dropped at cutover, which means users re-login. Record that as a decision. |
| Client storage (if not XML) | JDBC / LDAP | ● it's intent (see above) |
| Provisioner state | JDBC | ○ |
| Account-linking records (federated IdP ↔ local account) | JDBC | ○ **Must migrate**, or partners' users lose their linkage |

---

## 5. MFA: Duo  [likely]

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
| Public DNS zones & records (sso., login., ldap. service names) | Route 53 / enterprise DNS (Infoblox) | **C** (names) + B (targets) | ● | ✔ `ciamServiceName`, `ciamDnsZone` |
| Private DNS zones, resolver rules, conditional forwarders to on-prem | Route 53 Resolver / on-prem DNS | B | ● | — |
| DNS health checks / failover records | Route 53 | B | ● | — |
| TTLs (lower them before cutover) | same | B | ● Planner rule: TTL ≤ N days before cutover | — |
| Public TLS certs (DigiCert/Entrust/ACM), SANs | ACM / CA portal | cert facts + S | ● facts · ○ keys | ✔ |
| NLB for LDAPS (TCP 636 passthrough), target groups, health checks | ELB | B | ● | ~ (`ciamFrontendIp`) |
| ALB for PF HTTPS: listeners, TLS policy, stickiness, rules | ELB | B + I (TLS policy) | ● | ~ |
| WAF web ACLs, managed rule groups, IP sets, rate limits | AWS WAF / Akamai / F5 ASM | I (rules) + B (attachment) | ● | — |
| CDN (if in front of login pages) | CloudFront / Akamai | B | ● | — |
| **PingAccess** (if in the CIAM path): `<pa>/conf/run.properties`, `<pa>/data/PingAccess.mv.db` (H2 config DB), `pa.jwk`, applications, resources, sites, virtual hosts, rules, identity mappings (header injection), web sessions, token provider → PF, agents, key pairs, cluster | PA Admin API `/pa-admin-api/v3` | I + C + B + S | ● via Admin API, like PF | — |
| PingGateway / ForgeRock IG (if used): `config/routes/*.json`, `admin.json`, `config.json` | Files | I + B | ● | — |
| F5 BIG-IP (if used): VIPs, pools, iRules, profiles, certs | UCS archive / AS3 declarations | I + B | ● via AS3 JSON | — |
| Header-based SSO contracts (header names apps trust) | Gateway rules | **C** | ● | — |

---

## 7. Legacy access management and portals  [maybe / likely]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| **SiteMinder** policy store: domains, realms, rules, policies, user directories (pointing at DS?), ACOs | Policy store (LDAP/DB); `XPSExport` XML | I + B | ● Import via XPSExport. It's a directory consumer, plus a retirement candidate. | — |
| SiteMinder web agents: `WebAgent.conf`, `SmHost.conf` (trusted host registration), agent keys | Web servers | B + S | ● facts · ○ keys | — |
| Registration / approval app: pending requests DB, approval workflow, email templates | App DB / ServiceNow | I + D | ● workflow & templates as ◐ · ○ requests | — |
| Liferay portal: `portal-ext.properties`, SAML/OIDC plugin configs, IdP list (the "select your identity provider" page), `osgi/configs/*.config` | Portal servers | I + C + B | ● The SAML SP settings are the portal's half of an integration | ~ integration side only |
| Supplier-portal integration (e.g. Exostar federation): metadata, attribute contract, trust | PF IdP/SP connection + partner | I + C | ● | ~ |
| Legacy portals still binding directly to LDAP | App configs (unknown) | C (bind DN, base DN, hostnames) | ● **Found from access logs**, then recorded as consumers | ✔ `ciamConsumer` |

---

## 8. ForgeRock-lineage components (only if present)  [maybe]

The name "PingDS" (not PingDirectory) hints at a ForgeRock-lineage stack, which may include these. Confirm first.

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
| SMTP relay (SES / Exchange Online / on-prem relay), port, auth | PF notification publisher, DS SMTP config, portal apps | B + S | ● | — |
| **Sender addresses** (e.g. a legacy-company `portaladmin@…` address) | PF / portal templates | **C** | ● **User-visible contract.** Changing it goes through the change process. | — |
| SPF / DKIM / DMARC records for sender domains | DNS | B + C | ● New sending IPs or services must be added to SPF/DKIM **before** cutover, or reset emails get spam-foldered | — |
| Email templates (welcome, reset, registration) | PF templates / app | I | ◐ hash + string scan | — |
| SMS / voice OTP provider (if any) | Twilio etc. | I + S | ● | — |
| CAPTCHA site/secret keys, allowed domains | Google/hCaptcha console | I + S + C (domains) | ● **Allowed domains must include new hostnames** | — |

---

## 10. Network  [core]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| VPC / VNet, CIDRs | AWS | B | ● | ✔ `ciamNetwork` |
| Subnets per tier & AZ, route tables | AWS | B | ● | ✔ `ciamSubnetBinding` (route tables —) |
| Security groups / NSGs, NACLs | AWS / Azure | B (+I intent: "PF engines may reach DS on 636") | ● Store the **intent rule** once and the per-cloud realization as a binding | ✔ `ciamFirewallRule` (NACLs —) |
| **Enterprise firewall rules** (Palo Alto / Check Point, on-prem and cloud edge) | Firewall manager (Panorama, Tufin, AlgoSec) | B | ● Same rule model. Import from the firewall manager's export. | ~ same class, no importer |
| Transit Gateway attachments & route tables, Direct Connect / ExpressRoute, site-to-site VPN | AWS networking | B | ● | ✔ `ciamInterconnect` |
| NAT gateways + **Elastic IPs (egress)** | AWS | B | ● **Partners allowlist these** | ✔ `ciamEgress` |
| Ingress public IPs (NLB EIPs, static IPs) | AWS | B | ● Partners and consumers allowlist these too | ✔ `ciamFrontendIp` |
| **PrivateLink / VPC endpoint services** exposing LDAPS to other VPCs or accounts; allowed principals | AWS | B + C (endpoint service name) | ● Each connected endpoint is a consumer | — |
| VPC endpoints we use (S3, KMS, Secrets Manager, SSM) | AWS | B | ● | — |
| Egress forward proxy (Zscaler / Squid) + allowlists for partner metadata, JWKS, OCSP/CRL, Duo, vendor update URLs | Proxy config | B | ● | — |
| **Other parties' allowlists holding our addresses** | Partners, app teams, SaaS vendors | B (theirs) | ● | ✔ `ciamExternalAllowlist` |
| Cross-cloud replication path (DS 8989 between clouds) | Interconnect + FW | B | ● | ✔ |
| NTP sources | chrony config / VPC time sync | B | ● Clock skew breaks SAML and replication | — |
| Load-balancer and cluster ports matrix (389/636/4444/8989/8443/9031/9999/7600 JGroups…) | Derived | I | ● Derive it from connection handlers + PF run.properties, then diff against the firewall rules | — |

---

## 11. Compute and operating system  [core]

### 11.1 VM style (EC2)

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| Instances: type, AZ, ENI/private IP, tags | EC2 | B | ● | ✔ `ciamServer` |
| AMI / golden image (CIS-hardened RHEL), image pipeline | EC2 Image Builder / Packer | B + I (baseline) | ● image ref · ◐ Packer template | ✔ `ciamImageRef` |
| EBS volumes: size, type, IOPS/throughput, encryption key | EC2 | B | ● DS db performance lives here | ~ |
| Instance profile / IAM role | IAM | B | ● | — |
| User data / cloud-init | Launch template | I + B | ● Rendered, never hand-written | ~ DS setup scripts rendered |
| SSM: Parameter Store params, Patch Manager baselines, State Manager associations, Session Manager prefs, SSM documents | SSM | I + B + S | ● | — |
| OS tuning: `/etc/security/limits.conf` (nofile for DS), `sysctl` (TCP keepalive, somaxconn), transparent huge pages | Host | I | ● One baseline per role | — |
| systemd units (`opendj.service`, `pingfederate.service`), env files, restart policies | Host | I | ● | — |
| **JDK**: vendor/version, `cacerts` truststore additions, `java.security` overrides | Host | I + cert facts | ● **Custom CA additions to cacerts are a classic silent failure** after a rebuild | — |
| Local service accounts, sudoers, SSH keys / authorized_keys | Host | I + S | ● accounts & sudo rules · ○ keys | — |
| **Cron jobs & scripts** (backups, cleanups, cert checks, log shipping, reports) | `/etc/cron.*`, crontabs, `/opt/scripts` | I + B | ● **Hidden automation.** Every job is an entry with its purpose, schedule and owner. The script itself is ◐ (hash + repo). | — |
| `/etc/hosts` entries | Host | B | ● **Pinned names are migration landmines.** Flag any. | — |
| `resolv.conf` / search domains | Host | B | ● | — |
| Host agents: EDR (CrowdStrike), vuln scanner (Tenable/Qualys), Splunk UF, CloudWatch agent, SSM agent | Host | I + B + S | ● Agent, version and config ref per role | — |
| auditd rules, SELinux mode/policies, FIPS mode | Host | I | ● FIPS mode changes which crypto providers DS and PF may use | — |
| logrotate configs | Host | I | ● | — |

### 11.2 Kubernetes style (EKS/AKS, if ForgeOps)
Cluster version, node groups, namespaces, StatefulSets, PVCs & storage classes, ingress controller, cert-manager issuers, external-secrets / secret-agent, network policies, IRSA / workload identity, Helm releases. All ● and split I/B exactly like §8's ForgeOps row.

---

## 12. Secrets, keys and PKI  [core]

Everything here is **S** in opsdir: a `ref-uri`, never a value (SPEC R4).

| Artifact | Where | Datify | opsdir today |
|---|---|---|---|
| Secrets Manager secrets (names, rotation Lambdas, rotation schedule) | AWS | ● ref + rotation facts | ✔ `ciamSecretRef` + rotation facts (`ciamAutoRotate`, `ciamRotationFunction`, `ciamLastRotated`) |
| KMS keys: aliases, key policies, grants, multi-region settings | AWS | ● ref + policy intent (who may decrypt what) | ✔ `ciamKeyRef` + protection level, key users/admins, replica regions (grants —) |
| Key Vault / Managed HSM (target side) | Azure | ● | ✔ (`azkv://`) |
| CloudHSM (if PF keys are HSM-backed) | AWS | ● ref. **HSM keys don't export.** Rotating the signing key becomes a partner-facing change. | ✔ `ciamHsmRequired`, `ciamExportable`, `ciamProtectionLevel`; planner blocks a carry-over that can't leave its store |
| PAM (CyberArk): safes, accounts (`uid=admin`, service-account passwords, PF admin), platforms, CPM rotation, reconcile accounts | PAM | ● ref per account + rotation policy | ~ `cyberark://` refs (as a binding or `ciamCopyRef`) + rotation policy; platforms/CPM — |
| **Credential sprawl:** the same service-account password stored in DS, PF data store config, PAM, scripts | Everywhere | ● One `ciamSecretRef` per credential, with `usedBy` → every place it's configured. Rotation becomes a query. | ✔ `ciamCredential` + `ciamUsedIn`, `ciamCopyRef`; `credentials` and `rotation-impact` reports |
| Internal PKI: issuing CA (AD CS / Venafi / private CA), templates, CRL/OCSP URLs | PKI | ● CA + chain facts. Certificate-lifecycle tool refs. | — |
| Keystores: DS (PKCS12), PF, PA, JDK cacerts, partner trust anchors | Various | ● Cert facts per keystore with `usedBy` | ✔ cert facts |
| DS deployment ID/password, PF `pf.jwk`, PA `pa.jwk`, cluster encryption keys | Product | ● ref. Continuity requirement recorded. | ✔ `ciamContinuity` + `ciamMaterialFrom` (planner: copy before cutover) |

---

## 13. Observability  [core]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| CloudWatch log groups (retention, KMS), metric filters, alarms, dashboards | AWS | I + B | ● Alarms as intent ("replication delay > 5 s for 5 min → page"), realized per cloud | — |
| CloudWatch agent config JSON | Host / SSM | I + B | ● | — |
| Prometheus scrape configs, recording and alerting rules, Grafana dashboards | Monitoring stack | I | ● rules · ◐ dashboards (JSON hash) | — |
| SIEM: Splunk inputs/props/transforms, indexes, saved searches, correlation searches; or Sentinel DCRs and analytics rules | SIEM | I + B | ● Detection intent + data routing. **Retention obligations** as meta. | — |
| Alert routing: SNS topics, PagerDuty/Opsgenie services, ServiceNow Event Management | Various | I + B | ● | — |
| Synthetic login canaries (CloudWatch Synthetics scripts, external uptime monitors) | Various | I + B + S (test creds) | ● canaries · ◐ scripts | — |
| Log archives needed for audit (historical access logs, PF audit logs) | S3 / SIEM | D | ○ location, retention, legal hold. **Must survive decommission.** | ~ `ciamRetentionDays` |

---

## 14. Backup and DR  [core]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| `dsbackup` schedules, backup locations, encryption | DS tasks + S3 | I + B | ● | ✔ `ciamBackupTarget` (schedule ~) |
| S3 backup bucket: versioning, Object Lock, lifecycle, replication, bucket policy, KMS | AWS | B | ● | ~ |
| AWS Backup plans/vaults, EBS snapshot policies (DLM) | AWS | B | ● | — |
| PF config archive backups (auto + scheduled exports) | PF + storage | B | ● | — |
| DR design: region, RTO/RPO targets, standby replicas, failover runbook | Docs | I + M | ● RTO/RPO as meta, DR topology as intent | — |
| **Restore test records** (date, result, duration) | Tickets / docs | M | ● "Last successful restore test", which the planner can enforce | — |
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

---

## 16. Delivery: IaC, config management, pipelines, artifacts  [likely]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| Terraform code, modules, tfvars | Git | I + B | ● **Generated from opsdir** (already done for the core) | ✔ renderer (AWS/Azure) |
| **Terraform state** (S3 + DynamoDB lock) | AWS | O + B | ◐ Location, and a drift source. A new cloud gets new state. Imports need a plan. | — |
| CloudFormation stacks (legacy) | AWS | O | ◐ Inventory, then retire | — |
| Ansible: inventory, group_vars/host_vars, roles, playbooks, Vault-encrypted vars | Git | I + B + S | ● Inventory and vars come from opsdir. Roles are ◐. | — |
| Packer templates, image pipeline | Git | I | ◐ | — |
| CI/CD pipelines (Jenkins, GitHub Actions, Azure DevOps, GitLab): definitions, service connections, runners/agents | CI | I + B + S | ● Pipeline facts + credential refs. Self-hosted runner network location is a binding. | — |
| Artifact repository (Artifactory/Nexus/S3): PingDS zip, PF zip, adapters, JDK, agents; checksums | Repo | I | ● Exact artifact coordinates + SHA-256 per product version | — |
| Container registry (ECR/ACR) + image tags | Registry | B | ● | — |
| Ping licenses & support entitlements (Backstage), Duo licensing, user-count limits | Vendor portals | M | ● expiry, limits, contract owner | — |

---

## 17. Admin plane: who operates the stack  [core]

| Artifact | Where | Class | Datify | opsdir today |
|---|---|---|---|---|
| Workforce SSO to AWS (IAM Identity Center permission sets, SAML roles) | Entra ID / AWS | I + B | ● | — |
| Admin access to PF / PA consoles (OIDC via workforce IdP), roles | PF / PA | I | ● | — |
| Personal DS admin accounts, delegated support roles (password reset, unlock) | DS | I | ● | ~ ACIs |
| Bastions / jump hosts / VPN / Session Manager | Network | B | ● | — |
| Break-glass procedures and accounts | PAM + runbook | I + M | ● | — |
| Access reviews for platform admins (IGA, e.g. SailPoint) | IGA | M | ● review dates, reviewer, result | — |

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
| Security plan entries (SSP / ATO boundary, CMMC/NIST 800-171 control mapping), SOX ITGC controls | GRC tool | M | ● Control → evidence query (e.g. "list ACIs with review older than 12 months") | — |
| Risk register, exceptions/waivers (with expiry) | GRC | M | ● | — |
| Data classification & retention schedule | Policy | M | ● feeds `ciamPiiClass`, `ciamRetentionRule` | ✔ |
| Vendor contracts, DPAs, partner federation agreements | Legal / procurement | M | ◐ | — |

---

## 19. External parties  [core]

| Party | What they hold that depends on us | Datify | opsdir today |
|---|---|---|---|
| Federation partners (inbound IdPs, outbound SPs) | Our metadata URL, entity ID, signing cert, ACS/SSO URLs | ● contacts, lead times, what they pin | ✔ `ciamParty` + integrations |
| App teams (relying parties & LDAP binders) | Hostnames, bind DNs, client IDs, claim names | ● | ✔ `ciamConsumer`, `ciamIntegration` |
| Network/firewall teams (ours and theirs) | Rules for our IPs | ● | ✔ `ciamExternalAllowlist` |
| Supplier identity hub (e.g. Exostar) | Federation config | ● | ~ |
| SaaS vendors (Duo, CAPTCHA, email) | Keys, allowed domains, IPs | ● | — |
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

## 21. Coverage vs opsdir today, and the build order

**Modeled today (✔):** servers, bindings (network, subnets, service names, firewall rules, egress, interconnects, secret/key refs, backup targets), DS backends/indexes/password policies/connection handlers/log publishers/replication, user-attribute records, consumers, ACIs, integrations + claim maps, certificates, external allowlists, runbooks, changes, incidents, owners. Renderers: Terraform (AWS, Azure), `dsconfig` batch, DS setup scripts, ACI LDIF, PingFederate JSON (illustrative subset).

**Gaps, in suggested order** (by migration risk removed per unit of work):

| # | Gap | New classes / importers / renderers |
|---|---|---|
| 1 | **Observed importers** (the model is only as good as its data) | DS access-log miner → `ciamConsumer`; `config.ldif` / `dsconfig` export → snapshots; PF Admin API bulk export → integrations, adapters, data stores, keys |
| 2 | **String census** (§15) | File scanner → `ciamOccurrence` (observed): file, host, line, value-hash, owning entry |
| 3 | **PF depth** | `ciamAuthPolicy`, `ciamAdapter`, `ciamDataStore`, `ciamAccessTokenManager`, `ciamOidcPolicy`, `ciamScope`, `ciamNotificationPublisher`; PF node files (`run.properties`, `tcp.xml` discovery as a **binding**) |
| 4 | **Hidden automation** | `ciamJob` (cron/scheduled task/Lambda/pipeline): schedule, host role, purpose, owner, script hash |
| 5 | **Host baseline** | `ciamHostBaseline` per server role: OS, JDK + cacerts additions, limits, sysctl, agents, FIPS, systemd units |
| 6 | **Messaging** | `ciamMailSender` (address as contract, SPF/DKIM facts), `ciamExternalService` (Duo, CAPTCHA, SMTP, SMS) with allowed-domain and egress needs |
| 7 | **Data profile** (§3) | `ou=data-profile` statistics entries, from a values-free profiler |
| 8 | **Observability intent** | `ciamAlertRule`, `ciamLogRoute`, `ciamCanary`, rendered to CloudWatch / Azure Monitor |
| 9 | **Credential sprawl** | ✔ done (milestone 2.3): `ciamCredential` with `ciamUsedIn`, PAM refs (`ciamCopyRef`), `credentials` and `rotation-impact` reports |
| 10 | **Conditional products** | PingAccess, SiteMinder (XPSExport importer), AM (Amster importer), IDM (conf/*.json importer), ForgeOps overlay renderer |
| 11 | **Governance sync** | ServiceNow change/CMDB sync, a GRC control → query mapping |
| 12 | **Unknowns register** | `ciamUnknown` (question, owner, blocking?, answer), included in the planner's verdict |

---

## 22. Unknowns that reshape this map

1. Which lineage is present beyond PingDS + PF: AM, IDM, IG, PingAccess, SiteMinder?
2. VM (EC2) or Kubernetes (ForgeOps)? This decides §11.1 vs §11.2 and which renderer matters.
3. Where PF keeps clients, grants and sessions: XML, JDBC or LDAP (DS)?
4. Are signing keys HSM-backed?
5. Do consumers bind to service names or to replica hostnames?
6. Target landing zone: another AWS org/GovCloud or Azure (Government)? What's pre-built there (network, DNS, PKI, SIEM, PAM)?
7. Is a DS version upgrade in or out of the move?
8. Which ITSM, SIEM, PAM, PKI and firewall-manager products are in place? Each one is an importer.
