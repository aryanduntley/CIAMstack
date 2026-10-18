# CIAMstack

**Run your identity platform from one governed record, and move it to another cloud or product without rebuilding it from scratch.**

CIAMstack is proprietary: all rights reserved, and using it requires the author's written permission ([License](#license)).

## The problem

Large organizations run sign-in for their customers, partners and staff on a stack of identity products (a user directory, federation, access management, gateways) running on cloud or on-premises infrastructure. How that stack fits together is spread across config files on servers, product admin consoles, cloud consoles, several Terraform repositories, secret stores, certificate spreadsheets, tickets and what a few people remember.

That makes everyday work slow and risky. Nobody can quickly say what an application depends on or what breaks if a certificate is replaced. Compliance evidence is rebuilt by hand for each assessment. And moving the platform, for example from AWS to Azure Government, turns into a long project of rediscovering the whole estate, rewriting everything, and finding forgotten dependencies (partner allowlists pinning old addresses, hostnames hard-coded in scripts, certificates expiring mid-move) at cutover.

## What CIAMstack does

CIAMstack keeps everything about the identity platform in one PostgreSQL database, the **record**: servers and where they run, directory and federation configuration, access rules, the applications that depend on the platform, certificates, keys and secrets (as references only, never the values), owners, runbooks and changes. Three ideas run through it:

- **Record.** Every entry is typed, schema-checked and linked to what it depends on, so questions like "what does this application touch?" are answered in seconds.
- **Govern.** Every change names an approved change record, and the database itself refuses changes that aren't approved, values of the wrong type, secret values, and deletions that would break something still in use. Every change is kept in history.
- **Render.** The working files you deploy (Terraform, ARM/Bicep, CloudFormation, product configuration, Ansible, Kubernetes values) are generated from the record for each environment, and the live platform can be read back to show where reality and the record disagree.

The record defines the **identity technology** (which products, how they are configured, who depends on them) and the **infrastructure** it runs on (which cloud, accounts, regions, networks, secret stores) independently. Because of that, a migration doesn't need its own script for every combination of source and target. You declare the target, whether it is another cloud, another product or both. The planner compares it with what runs today and lists every blocker and action it finds, with owners and dates. The target's files are then generated from the same record. Infrastructure moves, product changes and combinations of the two use the same framework, provided an adapter exists for each product and platform involved.

What it aims to give a team (to be measured in a pilot, not claimed):

- **Less manual discovery:** the estate and its dependencies are inventoried once, from the systems themselves, and kept current.
- **Fewer migration surprises:** missing configuration, dependencies and blockers are found before cutover, not during it.
- **Repeatable changes:** consistent, reviewable output for every environment instead of manual procedures.

Migrations are declarative and automated, with people in control: approvals, blockers, open questions and verification are explicit steps, and nothing is cut over unattended.

In short, CIAMstack makes an identity estate **known, governed and reproducible**: known because it is recorded and read back from the live systems, governed because every change is approved and kept, reproducible because every environment is generated from the same record.

The command-line tool and Python package are called `opsdir` (operations directory). The core names no vendor: each product, cloud and tool is a separate installable **adapter** package. Today's adapters cover the ForgeRock/Ping stack (PingDS, OpenDJ, PingFederate, PingAM, PingIDM, PingGateway, PingAccess) and SiteMinder as a product to retire, on AWS (including GovCloud), Azure (commercial and Government), Google Cloud and on-premises, with secret stores, PKI, ITSM, SIEM and network tooling around them. New adapters can be written without touching the core.

**Status:** pre-production. The core and adapters are built and tested offline (about 4,400 automated tests). They haven't yet been validated against real product instances or cloud accounts, and everything is driven from the command line today ([Where it stands](#where-it-stands)).

## Bringing it into an organization

Onboarding is **read-only first**: nothing in production changes until the record has been checked against reality, and every phase is useful on its own.

1. **Stand up the record.** A PostgreSQL database wherever the organization chooses (on-premises or managed in any cloud), one per company: a parent organization and each subsidiary keep their own record, so each stays inside its own compliance boundary and is run by its own teams. Install the core and the adapters for the products in use; define the environments, clouds and accounts, regions, data residency, teams and owners.
2. **Declare the stack.** For each environment, which product or service fills each role (directory, federation, access management, gateway, cloud, secret store, DNS, load balancer, firewall, SIEM, ITSM, PKI) and its version range. `opsdir check` confirms the adapters are installed.
3. **Read each service in,** in any order: product exports, Terraform state, cloud inventories, logs and config files, or read-only collection. The first inventory, dependency graph and findings list come out of this step.
4. **Verify the record against reality.** Render each environment and compare it with what was imported; each disagreement is a conflict a person decides. `opsdir plan` on the current environment gives the first findings: expiring certificates, unowned items, drift, weak audit trails, missing backups.
5. **Operate from the record.** Changes go through approved change records, regular collection turns drift into findings, and teams adopt the generated files in place of hand-maintained ones, one team at a time.

A pilot can stop after step 4: one non-production environment, read-only, producing an inventory, a dependency graph and a findings list at no risk to production. Owners and keepers (the team that keeps each piece of infrastructure) are part of the record, so findings, renders and drafted requests reach the team responsible for each part: directory, federation, cloud, network and DNS, security and SIEM, PKI, compliance and application owners.

## What you can do with it

### See the whole platform in one place

- **Load what you have.** Describe the platform as LDIF (`opsdir load`), or read a product's own export straight in: directory servers' configuration (`config.ldif` and its archived versions) and access logs (which applications bind, from where, reading what), a PingFederate bulk export, a PingAM Amster export, a PingIDM project, a PingGateway configuration, a SiteMinder policy store; AWS, Azure and Google Cloud Terraform state, CLI output and asset inventories, CloudFormation stacks or ARM/Bicep deployments (`opsdir import`). Secret values found along the way are withheld and reported, never stored.
- **Read the live system, read-only.** `opsdir collect` runs each adapter's read-only collectors against an environment under your own login to the provider (opsdir never sees or stores cloud credentials), after checking the login is the account the record names, and records how each collection went. Data only the provider knows (its regions, quota limits, compliance frameworks) is listed by `opsdir prerequisites` with the command that fetches each.
- **Hold your config files, not just point at them.** `opsdir capture` keeps a configuration file setting by setting and `opsdir file` rebuilds it for any environment; `opsdir bundle` records code, scripts and templates by repo path and SHA-256, and `opsdir verify` checks them against a checkout.
- **Find where values are copied.** `opsdir census` scans servers' and applications' files (scripts, configs, `/etc/hosts`, templates) for values the record holds (hostnames, addresses, DNs, URLs, fingerprints, cloud resource IDs) and for terms you define (an old brand or domain, an account ID), and records each file and line. This is the list of what must change in a move. Secret material found is flagged by line, never stored.
- **Know the shape of your user data without copying it.** `opsdir data-profile` reads a directory's entries once, where the directory is reachable, and keeps counts only: entries per container and object class, how full each attribute is, password hashing schemes, idle, locked and disabled accounts, empty groups and dangling members.
- **Hold data where it may be.** Each environment names the data residency it is held to (`eu`, `us-gov`, ...); the planner blocks a target region outside it and a move that drops FIPS endpoints.
- **Know who depends on what.** Applications that bind to the directory, federation partners and their claims, the ACIs each relies on, the certificates and keys behind them, and other parties' allowlists that hold your addresses are all entries with owners.

### Answer operational questions in seconds

Each question below is one command. [`documentation/REPORTS.md`](documentation/REPORTS.md) describes what each one shows and what the planner does with it.

| Question | Command |
|---|---|
| What expires soon? | `opsdir report expiring` |
| What breaks if this certificate expires or is replaced? | `opsdir report blast-radius <certificate>` |
| What does rotating this key or secret touch? | `opsdir report rotation-impact <credential>` |
| What does this application touch, across every product and cloud? | `opsdir application <name>` |
| What depends on this, and what does it depend on? | `opsdir graph <name>` |
| The estate in numbers | `opsdir summary` |
| Where does each environment keep its keys and secrets, and correctly? | `opsdir report keys <env>`, `opsdir report credentials` |
| Who can read privacy-classified attributes? | `opsdir report pii` |
| What has drifted from the intended configuration? | `opsdir report drift` |
| Which applications use the directory? | `opsdir report consumers` |
| Which runbooks are out of date? What does nobody own? | `opsdir report stale`, `opsdir report unowned` |
| How does stage differ from production, and why? | `opsdir report overrides` |
| What hidden automation runs (cron, timers, functions, pipelines), and who owns it? | `opsdir report jobs` |
| Which outside services, mail senders and event streams does the platform rely on? | `opsdir report external-services`, `mail-senders`, `event-streams` |
| What do the servers run beyond the products, and on what compute? | `opsdir report baselines`, `compute`, `workloads` |
| What is the platform watched for, and where do its logs go and for how long? | `opsdir report alerts`, `log-routes`, `canaries`, `monitors` |
| Who records what is done to each cloud, and is the target's audit trail as complete? | `opsdir report audit-trails` |
| What watches and assesses each cloud (threat detection, vulnerability scanning, posture)? | `opsdir report security-services` |
| Where does sensitive data lie, and does the target keep looking? | `opsdir report data-discovery` |
| Do the target's quotas allow what it needs, and is spending watched? | `opsdir report quotas`, `budgets` |
| Who reports a cyber incident, to whom and how fast (for example DFARS 252.204-7012)? | `opsdir report incident-reporting`, `reportable-incidents` |
| Which weaknesses are being corrected, which risks are accepted, and is the CMMC status kept? | `opsdir report poam`, `exceptions`, `assessments` |
| Which cloud authorization (FedRAMP) does each environment rely on, and what falls outside it? | `opsdir report authorizations`, `responsibilities`, `regulated-data` |
| What evidences each control, and can an assessor get it? | `opsdir report evidence`, `opsdir evidence --boundary <boundary>` |
| Who and what may act on the platform, under which guardrails? | `opsdir report principals`, `identities`, `guardrails`, `access-paths` |
| How does traffic reach the platform, and what protects it? | `opsdir report edge-policies`, `edge-services`, `dns`, `header-contracts` |
| How does each environment route out, and which sites may it reach? | `opsdir report routes`, `private-endpoints`, `endpoint-services`, `egress-sites` |
| Are the managed databases available, encrypted and backed up in every environment? | `opsdir report databases` |
| Which cloud-managed identity services (Cognito, Entra External ID) are used, and can a target's do what applications need? | `opsdir report managed-identity` |
| Are the backup buckets versioned, locked, encrypted and copied elsewhere? | `opsdir report object-stores` |
| When was each part of the record last read back from the live system? | `opsdir report imports` |
| What doesn't anyone know yet, and who must answer it? | `opsdir report unknowns` |
| Does every secret reference point at something its store still holds? | `opsdir report secret-inventory` |
| Do the change records agree with the ITSM tickets? | `opsdir report tickets` |
| Which CA issued each certificate, and was any revoked or renewed behind the record's back? | `opsdir report certificate-authorities`, `issued-certificates` |
| Which outside PKIs (DoD, ECA) are trusted, under which restrictions? | `opsdir report trust-bundles`, `trust-policies` |
| What do the certificate managers know that the record doesn't? | `opsdir report managed-certificates` |
| What does a product being retired hold that the target has nothing for? | `opsdir report source-objects` |
| How did each live collection end? | `opsdir report collections` |
| How big is the user data, which password schemes does it use, how many accounts are idle? | `opsdir report data-profile` |
| Which files copy this hostname (or any value), on which lines? | `opsdir report census` |
| Anything else | `opsdir search -b <base> '<LDAP filter>'` |

### Change the platform safely

- **Every change is governed.** Writes name an approved change record; the database rejects unapproved changes, invalid values, secret values in reference fields and deletions that would break something still in use.
- **Read the live system back, and decide where it disagrees.** Where the live system and the record disagree, each difference is a conflict you decide, taking the live value or keeping the record's; neither side is assumed right.
- **Fix what the plan finds.** Where a finding has a known record change, the plan offers it (`opsdir fix`) as exact records for a person to approve. Some fixes are a choice (which secret holds a credential is never guessed), and some need values only you know.
- **Every change is kept.** `opsdir history` shows who changed what under which change; `opsdir export` produces LDIF for review in Git. ITSM tickets (ServiceNow, Jira Service Management, BMC Helix) are read as evidence and compared with the record; a ticket never approves anything on its own.
- **Every environment is rendered from the same record.** `opsdir render <cloud>/<env>` writes the environment's Terraform, directory configuration and setup scripts, federation configuration, standard SAML/OIDC/LDAP documents and product files, with a MANIFEST of hashes. Configuration meant to be identical across environments renders byte-identical; only each environment's own bindings differ. Infrastructure another team keeps goes to that team: its own Terraform root, or a drafted request.
- **Environments share what they should.** A stage environment can be an overlay of production: it inherits the shared intent and overrides only documented values, each with why.
- **Extend the record yourself.** Define your own fields and record types (a support tier, a feature flag) as governed, typed, documented entries.

### Prepare and run a platform move

Moving to another cloud, account, region or product uses everything above:

- **Plan against the live record.** `opsdir plan <from> <to>` compares the target with production and returns a verdict listing every blocker and action with its owner, and a do-by date for each action from its lead time: changed contracts (service names, SAML entity IDs, OIDC issuers), missing firewall rules and backups, certificates expiring before cutover, keys the target would keep wrongly (not in an HSM, regenerated instead of carried over), services the target cloud or its authorization doesn't offer, and **other parties' allowlists that still pin your old addresses**, with a drafted request to each party.
- **Work in a copy.** `opsdir workspace create` copies the live record; declare the target's stack and bindings there, plan, render and review, while the platform keeps being operated from the live record. `opsdir workspace cutover` applies the result as one approved change (a three-way merge that refuses conflicting edits).
- **Company mergers (planned).** Each company's record carries its own identity, so when two companies merge, one record can be brought into the other: its entries move under the incoming company's name, things both companies record (a shared vendor, partner application or CA) are proposed as matches for a person to confirm, and the history comes along with its original approvals. Moving the incoming company onto the other's platform is then an ordinary move, planned as above. A company that leaves the group takes its own record with it.
- **Run it end to end.** `opsdir migrate <from> <to>` checks both stacks, plans and renders the target, and exits non-zero while blockers remain. It works in either direction. Passing means the record and the renders are consistent; operational readiness is then proven in a stage environment.

## Adapters

Adapters are separate installable packages. Installing one registers it with the core; nothing in the core changes. Each environment declares which adapters and versions it runs, and `opsdir check` confirms they are installed.

**Standards (shared by every product that implements them)**
- `opsdir-adapter-ldap`: the user directory's schema and tree as standard LDIF; a generic LDAPv3 adapter for any compliant directory server.
- `opsdir-base-saml`: SAML 2.0 metadata for every partner and for the platform's own identity provider.
- `opsdir-base-oidc`: OpenID Connect client registrations and the provider's discovery document.

**Directory servers**
- `opsdir-base-ds`: the DS lineage (OpenDJ → ForgeRock DS → PingDS): `dsconfig` batch, ACI syntax, replication checks.
- `opsdir-adapter-pingds`: PingDS 7–8: `dsconfig` batch, ACIs, per-server setup scripts that join the existing replication deployment; **imports each server's configuration** and **finds the directory's consumers in its access logs**.
- `opsdir-adapter-opendj`: OpenDJ 4: the same, with `setup` and `dsreplication` scripts.

**Federation, access management, identity management and gateways**
- `opsdir-adapter-pingfederate`: PingFederate 11–13: connections, OIDC clients, data stores and authentication as Admin API requests checked against the version's OpenAPI spec, or as Terraform for Ping's provider; **imports the Admin API bulk export**.
- `opsdir-adapter-pingam`: PingAM / ForgeRock AM 7–8: realms, OAuth2/OIDC clients, SAML, journeys and policy sets as Amster entities; **imports Amster exports**.
- `opsdir-adapter-pingidm`: PingIDM / ForgeRock IDM 7–8: managed objects, connectors, sync mappings and schedules as project files; **imports IDM projects**.
- `opsdir-adapter-pinggateway`: PingGateway 2023–2026 / ForgeRock IG 7: routes per environment, linked to the clients and issuers they rely on; **imports gateway configurations**.
- `opsdir-adapter-pingaccess`: PingAccess 8.2–9.x: applications, resources, sites, web sessions, identity mappings and rules as Admin API requests; **imports Admin API reads and configuration exports**.
- `opsdir-adapter-siteminder`: Broadcom SiteMinder as a **product to retire**: **imports its policy store export** (12.8, 12.9), Web Agent and Access Gateway files; what has no modern equivalent is listed as source objects with an owner, so nothing is silently lost. It renders nothing.

**Clouds and on-premises**
- `opsdir-adapter-aws`: Terraform and CloudFormation for AWS, commercial and GovCloud; Secrets Manager, KMS, Certificate Manager and S3 references; **imports Terraform state, AWS CLI output and CloudFormation stacks**, and AWS Private CA inventories.
- `opsdir-adapter-azure`: Terraform, ARM and Bicep for Azure, commercial or Government; Key Vault references; Microsoft Sentinel; **imports Terraform state, Azure CLI output and ARM/Bicep deployments**.
- `opsdir-adapter-gcp`: Terraform for Google Cloud; Secret Manager, Cloud KMS, Certificate Manager and Cloud Storage references; **imports Terraform state and Cloud Asset Inventory / `gcloud` output**.
- `opsdir-adapter-onprem`: environments on your own hardware: the site as the region, and the site's teams asked for what fronts and connects the servers unless an add-on below renders it.
- `opsdir-adapter-ansible`: an environment's servers as an Ansible inventory, and the host configuration the record holds as playbooks, on any cloud or on-premises.
- Network add-ons, rendered through Ansible: `opsdir-adapter-f5` (F5 BIG-IP, AS3 declarations), `opsdir-adapter-haproxy` (HAProxy), `opsdir-adapter-panos` (Palo Alto Panorama and PAN-OS firewall rules, **read back** to find rules changed out of band), `opsdir-adapter-infoblox` (Infoblox DNS), `opsdir-adapter-windows-dns` (Windows / Active Directory DNS).

**Secret stores** (resolved at run time; values never reach the database or a rendered file)
- AWS Secrets Manager and KMS, Azure Key Vault, Google Cloud Secret Manager and Cloud KMS, in the cloud adapters.
- `opsdir-adapter-hashicorp-vault`: `vault://` references; inventories KV mounts and **imports PKI mounts** (metadata only).
- `opsdir-adapter-kubernetes`: `k8s-secret://` references; also **imports Kubernetes manifests** as workloads.
- `opsdir-adapter-cyberark`: `cyberark://` references through the Credential Provider; inventories the vault and tells real rotation from ordinary edits.

**Kubernetes, hosts and CI** (what runs beyond the products)
- `opsdir-adapter-forgeops`: **renders ForgeOps** Helm values and Kustomize overlays for PingAM, PingIDM, PingDS and PingGateway on Kubernetes.
- `opsdir-adapter-ping-devops`: **renders values for Ping's ping-devops Helm chart** for PingFederate on Kubernetes.
- `opsdir-adapter-linux`: **imports Linux servers' own files**: crontabs and systemd timers as jobs, and each server's baseline (OS, Java and its truststore additions, limits, FIPS and SELinux modes, agents).
- `opsdir-adapter-github-actions`, `opsdir-adapter-gitlab-ci`, `opsdir-adapter-azure-devops`: **import CI pipeline definitions** as jobs (schedules, runners, the secrets they name).

**Monitoring and SIEM**
- `opsdir-adapter-prometheus`: the record's alert rules as Prometheus alerting rules, on servers or as a `PrometheusRule` on Kubernetes.
- `opsdir-adapter-splunk`: **renders Splunk indexes** (searchable and archived retention), detections as scheduled saved searches and forwarder inputs; **reads them back**.
- `opsdir-adapter-elastic`: **renders Elastic Security** data stream retention, ES|QL detection rules and Fleet policies; **reads them back**.

**IT service management** (read-only: ticket evidence, never an approval)
- `opsdir-adapter-servicenow`, `opsdir-adapter-jira-sm`, `opsdir-adapter-bmc-helix`: **import the change tickets** the record's change records name, for the planner to compare with the record.

**PKI** (metadata only; never a key)
- `opsdir-adapter-adcs`: Microsoft AD CS: **imports each CA's issued certificates**, its revocation endpoints and the forest's certificate templates, flagging risky issuance.
- `opsdir-adapter-ejbca`: Keyfactor EJBCA: **imports each CA's issued certificates** and profiles through a read-only REST collector.
- `opsdir-adapter-venafi`: CyberArk Certificate Manager (formerly Venafi), Self-Hosted and SaaS: **imports its certificate inventory**, reconciled with the record.
- `opsdir-adapter-dod-pki`: DISA's DoD PKE trust bundles (DoD, ECA, JITC, WCF), with each bundle's signed manifest verified; new roots are proposed for approval, dropped and expiring ones flagged.
- `opsdir-adapter-x509`: any CA: **observes revocation endpoints** (CRLs, OCSP) read-only and checks them against the CA certificates the record holds.

**Compliance**
- `opsdir-adapter-fedramp`: **imports a cloud offering's FedRAMP Certification Package Overview** as the authorization an environment relies on, with the services inside its boundary.
- `opsdir-format-oscal`: writes OSCAL POA&Ms, system security plan control implementations and assessment results from the record, and reads OSCAL back.

**Formats**
- `opsdir-format-terraform` (HCL laid out like `terraform fmt`), `opsdir-format-arm` (ARM template JSON and Bicep), `opsdir-format-cloudformation` (YAML or JSON templates), `opsdir-format-sigma` (detections as Sigma rules for any other SIEM).

### Adapters for other systems

Anything not listed can be added as a package, by your team or anyone else, without touching the core or the other adapters: another directory or federation product, a cloud-managed identity service, another cloud, secret store, ITSM or monitoring tool. An adapter declares when it applies, the roles an environment must bind for it, its renderers and importers, its planner checks, the secret-reference schemes it owns, the file formats it writes, the product versions it supports and, if it needs them, schema definitions of its own. How to write one: [`opsdir/README.md`](opsdir/README.md#writing-an-adapter-package); the contract: [`opsdir/SPEC.md`](opsdir/SPEC.md) §8.

## Try it

Installing or running CIAMstack needs a written evaluation or commercial license from the author ([License](#license)). With one, the requirements are Python 3.11+ and PostgreSQL.

**Supported platforms:**
- The server is Linux: one company-wide CIAMstack server per company record (or a container).
- People on any OS reach it through the API, the console or MCP as they arrive; today, a terminal on the server.
- The CLI runs directly on Linux, on macOS (POSIX; expected to work, not yet tested) and on Windows through WSL2.
- Every file CIAMstack reads and writes is UTF-8 with LF line endings, whatever the server's locale.

Set up the role and databases once ([Database](opsdir/README.md#database)), then:

```bash
opsdir/scripts/dev-install.sh     # venv (opsdir/.venv) + the core + every package, editable
examples/showcase/demo.sh         # a fictional estate operated from the record; outputs in examples/showcase/out/
opsdir/opsdir.sh --help           # the CLI, against the local dev database
opsdir/scripts/test.sh            # every test: core, packages, showcase; unit + integration
```

The [showcase](examples/showcase/README.md) walks through all of the above on a fictional company's platform (PingDS, PingFederate, PingAM, PingIDM and PingGateway on AWS, with a stage overlay and a warm standby on Google Cloud), then plans moving production to Azure, where AM, IDM, PingGateway and PingFederate run on Kubernetes (AKS) and the directory stays on virtual machines. Its problems are planted on purpose, and the tests check that the planner finds every one. Terraform is optional: `opsdir/scripts/fetch-tools.sh` puts a verified copy in the gitignored `tools/` folder, after which the demo and the tests also check every rendered root with `terraform fmt` and `validate`.

## Where it stands

**Built and tested offline** (about 4,400 automated tests: unit tests, integration tests against PostgreSQL, and golden-output comparisons of the full fictional estate):
- the governed store, with versioned schema upgrades and full history;
- every report, search, guardrail and planner check above, with offered fixes;
- importers and renderers for every adapter listed, and round trips: each render reads back through the adapter's own importer with no drift;
- migration workspaces, the planner and the migration runner, in both directions;
- the production setup of the record's own database:
  - TLS required off the server's host;
  - separate owner, upgrade and day-to-day roles, the day-to-day one unable to change the schema or the history;
  - sign-in by password file, client certificate, Kerberos or an AWS/Azure database token;
  - a posture check, each company's record identity, and a backup and restore procedure tested against a real PostgreSQL 17 server;
- people, teams and permissions:
  - each person signs in as themselves;
  - the database records who wrote and who approved every change, and refuses an approval by the change's own author;
  - per-person and per-team grants by action, environment and owning team are checked before every command and again by the database on every write;
  - 'my area' views.

Rendered AWS and Azure Terraform passes `terraform validate` against the provider schemas, Kubernetes output is checked by kustomize, helm and kubeconform, and PingFederate requests are checked against Ping's Admin API spec.

**Not yet verified:** rendered product configuration against real product instances, `terraform plan` against real cloud accounts, Kubernetes output deployed to a real cluster, the read-only collectors against live systems (their tests replay recorded output), and the Google Cloud Terraform with `terraform validate`. See [what's verified](examples/showcase/README.md#whats-verified-and-what-isnt).

**Not built yet:** an HTTP API with company single sign-on, a web console, guided onboarding, and combining two companies' records after a merger. Everything today is driven from the command line.

**Next:** validation against real products and accounts in a sandbox, then the API and the console. What each part of an identity platform carries and how much of it is modeled today: [`documentation/STACK.md`](documentation/STACK.md).

## Documentation

- [`opsdir/README.md`](opsdir/README.md): install, CLI, database, workspaces, architecture, writing adapters.
- [`opsdir/SPEC.md`](opsdir/SPEC.md): the standard: LDAP schema with portability classes, rules R1–R10, the adapter contract.
- [`documentation/SCHEMA.md`](documentation/SCHEMA.md): the schema reference: how the database stores the record (its PostgreSQL tables, column by column), the directory tree, and every object class and field, with types and descriptions, for the core, each domain and each adapter package that adds its own.
- [`documentation/REPORTS.md`](documentation/REPORTS.md): every report and what the planner does with it.
- [`documentation/RECORD-DATABASE.md`](documentation/RECORD-DATABASE.md): running the record's own database in production: setup, sign-in, backups, restore, upgrades.
- [`documentation/ops-directory-model.md`](documentation/ops-directory-model.md): design rationale: why a directory-shaped record, what differs between environments, where moves get hard, prior art.
- [`documentation/STACK.md`](documentation/STACK.md): the full inventory of what an identity platform carries and how much of it is modeled today.

## Layout

```
opsdir/                   the core: an installable Python package on PostgreSQL
packages/                 adapter, base and format packages (listed above)
examples/showcase/        a runnable fictional estate: data, product exports, demo, golden outputs
documentation/            schema reference, reports, production database runbook, design rationale, stack inventory
pytest.ini                one test configuration for the core, the packages and the showcase
LICENSE                   copyright and terms: all rights reserved
.aimfp-project/           development tracking (roadmap, tracked files and functions)
```

The code is Modular, Functional and Procedural: immutable records, pure functions, and effects (database, files, printing) kept at the edges.

## Where everything lives (and how to remove it)

| Thing | Path | Remove with |
|---|---|---|
| Python venv (`psycopg`, `packaging`, `pytest`, the packages) | `opsdir/.venv/` | `rm -rf opsdir/.venv` |
| Rendered output | `out/` wherever the CLI ran (the demo: `examples/showcase/out/`) | `rm -rf examples/showcase/out` |
| Python bytecode and build metadata | `__pycache__/`, `*.egg-info/` | `find . -name __pycache__ -o -name '*.egg-info' \| xargs rm -rf` |
| Dev and test databases | role `opsdir`; databases `opsdir`, `opsdir_workspace`, `opsdir_test`, `opsdir_test_workspace` in the local PostgreSQL | `for d in opsdir_test_workspace opsdir_test opsdir_workspace opsdir; do sudo -u postgres dropdb $d; done; sudo -u postgres dropuser opsdir` |

Deleting the `CIAMstack/` folder removes everything but the databases. Outside this folder, running `terraform` to validate rendered output leaves checkpoint files in `~/.terraform.d/`.

## License

Copyright (c) 2026 Aryan Duntley. All rights reserved.

CIAMstack (the core, every package, the examples, the documentation and the schema) is proprietary software, and no license is granted. Using, copying, modifying, distributing, deploying or running it, in whole or in part, needs the author's prior written permission. Being able to see the repository grants none of these rights: GitHub's Terms of Service let GitHub users view and fork a public repository on GitHub, and nothing more.

Evaluation, pilot and commercial licenses are available by written agreement: Aryan Duntley, aryanduntley@gmail.com.

Third-party material kept in the repository, such as the vendor API specifications the PingFederate adapter validates against, stays under its owners' terms. The full text is in [`LICENSE`](LICENSE).
