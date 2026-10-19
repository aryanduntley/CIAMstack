# Security

*How access to CIAMstack itself is controlled, what the database enforces whoever connects, and how CIAMstack handles the secrets and credentials of the systems it manages. The step-by-step runbooks are [`RECORD-DATABASE.md`](RECORD-DATABASE.md) (the record's database) and [`API-DEPLOYMENT.md`](API-DEPLOYMENT.md) (the HTTP API); the reference is [`opsdir/README.md`](../opsdir/README.md#people-change-records-and-approval). What an attacker could do with each part, and what limits it, is the [threat model](THREAT-MODEL.md).*

---

## Short answers

| Question | Answer |
|---|---|
| **Who can sign in?** | Only people recorded in the record. Through the HTTP API with the company's single sign-on, or, for administrators, over SSH to the CIAMstack server and then the CLI with their own database login. Nobody is created automatically. |
| **Does it integrate with enterprise SSO?** | Yes. The API accepts OpenID Connect access tokens (signed JWTs) from the company's identity provider, such as PingFederate, Microsoft Entra ID or Okta. Teams can follow the provider's groups, so removing someone from a group removes their rights with their next token. |
| **What is the privilege model?** | Role-based grants scoped by attributes. A grant gives actions (`read`, `render`, `plan`, `propose`, `approve`, `apply`, `settings`, ...) to a person or team, limited to environments and to what given teams own or keep. Change approval sits on top, separately: every write needs an approved change. Underneath are three PostgreSQL roles (section 6). |
| **Can a directory engineer change the cloud configuration?** | Only if granted. A grant of `apply` limited to what the directory team owns or keeps (`--owner directory`) covers only those entries, and the database checks it on every write. An entry without its own owner belongs to its environment's owners. (With no grant recorded at all, a single-team install's default, anyone recorded can.) |
| **Can someone who can render also approve?** | `render` and `approve` are separate actions, granted separately. Even with both, nobody approves their own change, and production can require more approvers than other environments. |
| **Can an application or the API's account bypass approval by connecting to PostgreSQL directly?** | No. The rules are enforced inside the database by triggers on the record's tables, for every login. The day-to-day and API logins don't own the tables, so they can't disable the triggers or change the schema. The API's login acting for nobody holds no grants and approves nothing. Only the schema owner can change the rules: it never signs in, and is reached only through the migration login, which should not be kept on the server day to day. |
| **What stops a compromised CIAMstack process from changing its own governance data?** | It runs as a runtime login. Grants, people and settings are governed writes like any other: they need the `settings` action and a change approved by someone else, and history can't be changed, removed or added to except by the store's own writes. The exception to plan for is the API server: the database trusts it to say which person each request is for, so whoever controls that host can act as any recorded person. It is the most sensitive part of the deployment ([threat model](THREAT-MODEL.md)). |
| **How does an operator's identity reach the history?** | On the CLI, the database login is the person's own. Through the API, the server verifies the token, finds the recorded person, and names them to the database for each transaction. The database believes that only from the login the record's `api-login` setting names, and records the person as the author, approver or writer in history, with the API client and the teams they held. |
| **What can the PostgreSQL service account do?** | `opsdir_app` (and the API and per-person logins, its members) can use the schema, read and write the record's rows (every write passing the store's rules), read the tables only upgrades write (migrations, secret patterns, vocabulary, reference schemes) and the history (only the store's write trigger adds history rows), and run the store's functions. It can't create, alter or drop anything, and `opsdir posture` fails a production record whose day-to-day login is a superuser, owns the schema, or can create roles or databases or bypass row security. |
| **Does CIAMstack deploy to production?** | No. It renders files and reads systems back, read-only. Deploying is done by the company's pipelines or operators with their own credentials ([changes and deployment](CHANGES-AND-DEPLOYMENT.md)). |

## 1. Principles

- **The database is the enforcement point.** Approval, permissions, history and the ban on secret values are enforced by the record's PostgreSQL database on every write, whatever client makes it: the CLI, the API, a script or `psql`. A client can't skip a rule by going around the tools.
- **Every action is a recorded person's.** People sign in as themselves. Nobody is created automatically, and an approval is never the author's own.
- **No secret values, anywhere CIAMstack writes.** The record holds references to secrets, never the secrets. The same holds for rendered files, Terraform state, evidence packages and exports.
- **CIAMstack holds no standing credentials for the systems it manages.** Reading a cloud or product uses the operator's own login, or a reference resolved in memory for one run.
- **Least privilege for its own logins.** The day-to-day login can change rows only, never the schema or the history, and CIAMstack never needs database administrator rights.

## 2. Who reaches CIAMstack, and how

```
people (browser, scripts; later the console and MCP)
   │  HTTPS + an access token from the company's identity provider
   ▼
reverse proxy (TLS) ──► opsdir-api on 127.0.0.1 ──► record database (TLS, as opsdir_api)

administrators ── SSH with their keys ──► CIAMstack server: opsdir CLI ──► record database (TLS, own login)

DBA ──► record database: runs the reviewed role script once; backups and restores
```

| Who | Reaches it through | Signs in with | Uses it for |
|---|---|---|---|
| **People** (operators, approvers, application owners, auditors) | The HTTP API, behind a TLS reverse proxy | An access token from the company's identity provider (single sign-on) | Browsing, reports, plans and render previews, proposing, approving and applying changes, uploading exports |
| **Administrators** | SSH to the CIAMstack server, then the CLI | Their SSH keys, then their own database login | Setup, recording people, teams and grants, collection, upgrades, break-glass work |
| **The API service** | A database connection from the server | Its own login, `opsdir_api` | Acting for the person each verified token names, and nobody else |
| **The DBA** | The database | The database's own administration | Running the role script once (reviewed first), backups, restores |
| **Scripts and pipelines** | The HTTP API | A person's token | Whatever that person may do. A client-credentials token with no person behind it can do nothing. |

There is one CIAMstack server per company record. People using the API never connect to the database: only the API service holds `opsdir_api`'s credentials.

## 3. Identities

- **People** are entries in the record (`ou=people`), recorded by an administrator under an approved change. Through the API, a person is matched by the identity provider's issuer and subject (`ciamIdpSubject`), compared exactly. A token for anyone not recorded gets a 403.
- **On the server**, each person has a database login of their own: by peer authentication over the local socket (`opsdir db-roles --login peer --person alice`), or with a client certificate, Kerberos or a cloud database token for a remote database. Each person's login has the runtime login's rights and no more.
- **Teams** have recorded members, or follow the identity provider's groups (`ciamIdpGroup`, by immutable group ID). A mapped team's members are whoever the provider puts in the group, request by request, so removing someone from the group removes the team's grants with their next token. If the provider says a token's group list is incomplete (Entra ID's group overage), the call is refused rather than guessed.

## 4. What each person may do

**Actions.** Every command is one action: `read`, `render`, `plan`, `migrate`, `propose`, `approve`, `apply`, `settings`, `workspace` or `admin`. It is checked against the record's grants before the command runs, and the database checks it again on every write.

**Grants** give an action to a person or a team (`opsdir grant`), optionally limited to environments (`--env`) and to what given teams own or keep (`--owner`). Grants are governed records: recording one needs an approved change, approved by someone other than its author.

- With no grant recorded, every action is allowed. That is a single-team install's default, and the showcase's.
- Once any grant is recorded, only recorded people act, and every action other than reading needs a grant.
- **Reading is open to every recorded person.** This is by design: the record holds no secret values, and teams need to see what they depend on. There are no hidden tiers among operators. What is restricted is changing things.
- Writes to what governs the record itself (people, grants, settings) need `settings`.

**Approval.**

- Every write names a change record, and the database accepts it only once the change is approved: proposed, then approved, then applied (or rejected).
- The database records who wrote a change record and who approved it, from the session itself. Neither can be set by a write.
- **The approver is never the author** while `approval-separation` is on (the default). Only a one-person install turns it off, and `opsdir posture` fails a production record that does.
- **Risk-tiered approval:** `approvals-required` sets how many distinct people approve a change, per environment (for example two for production, one elsewhere). A change stays proposed until it has them, and its approvals start over if what it proposes changes.
- Once grants are recorded, the approver must hold `approve` for what the change touches, so an approver from another team can't approve a change to what isn't theirs.

**Break-glass.** The schema owner (reached through the migration login) is the database's break-glass. It isn't subject to grants, and every write it makes shows in history as the owner's.

## 5. What the database enforces, whoever connects

| Rule | What is refused |
|---|---|
| Schema checking (R1) | Unknown object classes and fields, missing required fields, values of the wrong type |
| Tree and referential integrity (R2, R3) | References to entries that don't exist; deleting something still in use |
| No secrets (R4) | Any value or entry name matching a registered form of secret material (private keys, credentials in URLs, signed tokens, secret assignments, stored LDAP passwords, and each installed adapter's vendor forms). The refusal names the attribute and the form, never the value. |
| Governed writes (R5) | Any write under a change that isn't approved |
| History (R6) | Changing or removing a history row, by anyone; adding one other than by an entry write (the store sets who and when on every row). Only `opsdir init`, which rebuilds the record, drops it. |
| Authorship | Setting or changing who wrote or approved a change; approving one's own change |
| Areas | A write by a login without `apply` covering the entry's environment and teams; an approval by someone without `approve` there |
| Record identity | Changing the org code or record ID once set, or removing the identity entry |

The store's functions run with a pinned search path, and the role script takes the right to create temporary tables away from PUBLIC, so no login can substitute a table of its own for the record's inside the store's rules.

## 6. The record's database

- **Three roles** (`opsdir db-roles` prints the script the DBA reviews and runs):

  | Role | Signs in | Can |
  |---|---|---|
  | `opsdir_owner` | never | own the schema |
  | `opsdir_migrate` | for `init` and `upgrade` only | become the owner for those runs |
  | `opsdir_app` | day to day | read and write rows under the store's rules; not create, alter or drop anything, change secret patterns or vocabulary, or add, change or remove history rows |

  The API's login (`opsdir_api`) and each person's login are members of `opsdir_app`.
- **Sign-in without passwords in the environment:** a password file (mode 0600), a client certificate, Kerberos, or an AWS RDS IAM or Azure Entra token (`OPSDIR_DB_AUTH`).
- **TLS off the host.** `opsdir` refuses an off-host connection that doesn't verify the server's certificate and name (`sslmode=verify-full`), unless `OPSDIR_DB_TLS` names a weaker mode on purpose.
- **`pg_hba.conf`** admits the logins over TLS from the CIAMstack server's address only.
- **FIPS 140-3**, where required: the system's libpq and OpenSSL in FIPS mode (`opsdir[c]`), not psycopg's bundled copies. `opsdir posture` reports what the process loaded and negotiated, as evidence, not proof of validation ([details](RECORD-DATABASE.md#fips-140-3-for-the-database-connection)).
- **Backups** hold the whole record and history but no secret values. Treat them as the company's configuration data: encrypted, readable only by the DBA or a backup role, with a copy in another account or site ([who can reach the backups](RECORD-DATABASE.md#who-can-reach-the-backups), and [what can and can't be rebuilt](RECORD-DATABASE.md#if-the-database-is-lost-what-can-and-cant-be-rebuilt) if the database is lost).

## 7. The HTTP API

- **Tokens are checked locally**: a signed JWT, an asymmetric algorithm only (`RS256`, `PS256`, `ES256` by default; `none` and HMAC refused), the key its `kid` names from the provider's published keys, the exact issuer, the audience, expiry and not-before within a small leeway, and a subject. Opaque tokens needing introspection aren't accepted.
- **The database trusts "acting for person X" only from the API's own login**, named by the record's `api-login` setting under an approved change. Any other login naming a person is ignored and writes as itself.
- **Each request** opens a connection, finds the person, checks the action and its area, and runs as that person. History records the person, the API client the token was issued to, and the mapped teams they held.
- **Deployment hardening:** the API listens on `127.0.0.1` behind a TLS reverse proxy (TLS 1.2 or later, HSTS), trusts forwarded headers only from that proxy, caps request bodies and file counts, runs as its own unprivileged user under systemd (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`), and keeps no files: uploads over 1 MB are spooled privately for the request, after the token is accepted. Its configuration file holds no secret.
- **It holds no provider credentials.** People collect exports with their own access and upload them.

## 8. Secrets of the systems CIAMstack manages

- **References only.** A credential entry says what the secret is, how it rotates, whether a new environment must receive the same material, whether it may leave its store and whether it must be HSM-protected. Each environment binds it to where the material is kept (`vault://`, `aws-sm://`, Azure Key Vault, Google Secret Manager, `k8s-secret://`, `cyberark://`). The material itself never passes through CIAMstack.
- **Imports withhold them.** An importer that meets a secret value in a product's export withholds it and reports it. Which secret role it comes from is then a person's choice, offered as a fix and never guessed. A captured configuration file is held whole only when nothing in it may be secret. A setting that may hold one is withheld and must be linked to a secret reference, and a file that can't be held safely is held as a reference.
- **The census flags them.** When `opsdir census` scans files for copied values, secret material it finds is flagged by line, never stored.
- **Renders never contain them.** Rendered setup scripts resolve references at deploy time, with the deployer's own access to the secret store. Workloads on Kubernetes read them through the External Secrets Operator or the Secrets Store CSI driver. Rendered Terraform refers to secrets by metadata only, so no secret value enters Terraform state. Where a resource would need a secret value in state, it isn't rendered: it goes to its owner as an action.
- **Exports, evidence packages and reports** come from the record, so they hold none either.

## 9. Credentials CIAMstack uses to read other systems

Reading the live system (`opsdir collect`) is read-only and uses the operator's own access:

- **Clouds:** the operator's own CLI login. Before reading anything, each collector checks that the login is the account, subscription or project the record names, and reads nothing if it isn't.
- **Products, directories and state objects** that need more: a collection source in the record names the reference of the credential, never the credential. The reference is resolved through its secret store for the run and held in memory only. It reaches a tool only on its standard input or in CIAMstack's own HTTP request. A client certificate is loaded through an anonymous in-memory file (Linux `memfd`), never written to disk. Failing calls' error output is shown with resolved values masked.
- **Read-only by construction:** collectors make GETs. A POST is made only to the read-only query paths a collector declares (such as a certificate search), and any other is refused. Calls carrying provider debug switches are never run.
- **Git, Kubernetes ConfigMaps and SSH** are each off until an approved change turns them on. They use the operator's own Git credentials, kubectl context and SSH agent. SSH requires a known host key and runs only fixed `find` and `cat` commands on validated paths. Kubernetes Secrets are never read.
- **Evidence without credentials:** an applied collection records the identity the provider saw, each call and the SHA-256 of what it returned, and which references were resolved, never a credential. `--save` keeps the raw export, which may hold sensitive configuration: keep it on encrypted storage.
- **ITSM:** CIAMstack holds no ITSM credential. It reads exported tickets as evidence and drafts work tickets that the team files with its own credentials.

## 10. Audit trail

- **History** records every insert, update and delete with its before and after values, the change, and the login (and, through the API, the person, client and teams). It is append-only for everyone.
- **Change records** carry their author, approvers and ITSM ticket references.
- **Import runs** record what was read, when the export was taken, and each file's SHA-256. **Collection attempts** record every run's outcome, including failures.
- **Render manifests** record each file's SHA-256, the scope, and who requested the render.

## 11. Adapters are code you install

An adapter runs inside CIAMstack with its rights. Install adapters only from sources the company trusts, at reviewed versions. Each environment's declared stack names the adapters and version ranges it accepts, and `opsdir check` reports any installed adapter outside them. Installing one adds its secret patterns, reference schemes and vocabulary to the record at the next `opsdir upgrade`.

## 12. AI is optional and never approves

Nothing in CIAMstack needs an AI. The planned MCP interface will be a client of the same operations as the CLI and API, with the same permission checks: an AI acts as the person who asked, never with more rights, and can propose a change but never approve one. Secret resolution won't be exposed to it.

## 13. Checking a deployment

`opsdir posture`, run as the runtime login, checks the record's database and how it is reached. A production record (`opsdir setting deployment production`) fails on:

- an off-host connection without verified TLS;
- a password in the connection string or environment;
- the development defaults;
- a day-to-day login that is superuser, owns or can create in the schema, or can create roles or databases or bypass row security;
- a TLS minimum older than 1.2, or password hashing other than SCRAM-SHA-256;
- pending or unknown migrations;
- a missing record identity;
- approval separation turned off.

It warns about PUBLIC rights, default privileges and missing recovery targets, and reports approval tiers, the client library, FIPS evidence and cloud naming. The deployment checklists are at the end of [`API-DEPLOYMENT.md`](API-DEPLOYMENT.md#checklist) and in [`RECORD-DATABASE.md`](RECORD-DATABASE.md#setting-it-up).

## 14. What isn't built or verified yet

- **Not built:** the web console and the MCP interface. Their access will go through the same API and permission checks.
- **Not verified on real infrastructure:** sign-in with cloud database tokens on real RDS, Aurora and Azure Flexible Server (public and Government), FIPS end to end on a real CIAMstack server, and the collectors against live systems (their tests replay recorded output).
- **Planned hardening:** tamper-evident history, signed render manifests, an adapter allowlist, approvals a compromised API server can't make for someone else, signed releases with an SBOM, and a quoting review of every renderer and collection command ([threat model](THREAT-MODEL.md#5-planned-hardening)).
- **Read access is not narrowed** within a record: every recorded person can read everything in it. A boundary that needs separation from other readers gets its own record ([`ORGANIZATIONS.md`](ORGANIZATIONS.md)).

## 15. Reporting a vulnerability

Report suspected vulnerabilities privately to the author, at the address in the README's [License](../README.md#license) section, rather than in a public issue.
