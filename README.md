# CIAMstack

**Run your identity platform from one governed record instead of scattered config files, consoles and spreadsheets.**

CIAMstack (the `opsdir` tool) keeps everything about an identity (CIAM) platform in one PostgreSQL database: servers and where they run, directory and federation configuration, access rules, the applications that depend on the platform, certificates, keys and secrets (as references only), owners, runbooks and changes. Every entry is typed, schema-checked and linked to what it depends on, and every change is approved and kept in history. The working files you deploy (Terraform, product configuration, setup scripts) are generated from the record, for every environment.

It is built for the ForgeRock/Ping stack on AWS, Azure and Google Cloud today, and nothing in its core is tied to a vendor: each product, cloud and secret store is an installable **adapter** package, and new ones can be written for other systems.

## What you can do with it

### See the whole platform in one place

- **Load what you have.** Describe the platform as LDIF (`opsdir load`), or read a product's own export straight in: directory servers' configuration (`config.ldif` and its archived versions) and access logs (which applications bind, from where, reading what), a PingFederate bulk export, AWS, Azure and Google Cloud Terraform state, CLI output (Cloud Asset Inventory and `gcloud` for Google Cloud), CloudFormation stacks or ARM/Bicep deployments, a PingAM Amster export, a PingIDM project, a PingGateway configuration (`opsdir import`). Secret values found along the way are withheld and reported, never stored.
- **Hold your config files, not just point at them.** `opsdir capture` keeps a configuration file setting by setting and `opsdir file` rebuilds it for any environment; `opsdir bundle` records code, scripts and templates by repo path and SHA-256, and `opsdir verify` checks them against a checkout.
- **Find where values are copied.** `opsdir census` scans servers' and applications' files (scripts, configs, `/etc/hosts`, templates) for the values the record holds (hostnames, addresses, service names, bind and base DNs, URLs, fingerprints, cloud resource IDs) and for terms you define (a field marked as a census term: an old brand or domain, an account ID, a bucket name), and records each file and line, pointing at the entry the value belongs to. Secret material in them is flagged by line, never stored. `--replace` makes a scan the whole census, dropping files no longer there.
- **Know the shape of your user data, without copying it.** `ldapsearch … | opsdir data-profile --env CLOUD/ENV` reads the directory's entries once, where the directory is reachable (no database needed), and writes counts only: entries per container and object class, how full each attribute is, password values by hashing scheme, time since the last login and password change, locked and disabled accounts, empty groups and members pointing nowhere. `opsdir import ldap/data-profile` records it; the planner names legacy password schemes, attributes the record doesn't describe (no PII class) and dangling members.
- **Fetch what only the provider knows.** Some data has to come from the cloud itself, such as each provider's list of regions. Adapters declare it as prerequisites: `opsdir prerequisites` shows what is met, pending or not needed yet, with the provider command that fetches each. `opsdir import ADAPTER/IMPORTER --run` runs that command under your own login to the provider (opsdir never sees or stores the credentials), or you run it yourself and import its output. A refresh adds new regions and shows changed names as conflicts to take or keep; a region the provider stops listing is kept and marked, never deleted.
- **Hold data where it may be.** The estate defines its own residencies (`eu`, `us-gov`, ...) and the catalog regions each allows; each environment names the one its data is held to. The planner blocks a target region outside it, flags regions the provider doesn't list, and blocks a move that drops FIPS endpoints (`opsdir report regions`, `opsdir report residency`).
- **Know who depends on what.** Applications that bind to the directory, federation partners and their claims, the ACIs each one relies on, the certificates and keys behind them, and other parties' allowlists that hold your addresses are all entries with owners.

### Answer operational questions in seconds

| Question | Command |
|---|---|
| What expires soon? | `opsdir report expiring` |
| What breaks if this certificate expires or is replaced? | `opsdir report blast-radius <certificate DN>` |
| What does rotating this key or secret touch? | `opsdir report rotation-impact <credential DN>` |
| Where does each environment keep its keys and secrets, and correctly? | `opsdir report keys <env>`, `opsdir report credentials` |
| Who can read privacy-classified attributes? | `opsdir report pii` |
| What has drifted from the intended configuration? | `opsdir report drift` |
| Which applications use the directory, and what should we check about each? | `opsdir report consumers` |
| Which runbooks are out of date? What does nobody own? | `opsdir report stale`, `opsdir report unowned` |
| How does stage differ from production, and why? | `opsdir report overrides` |
| What hidden automation runs (cron, timers, functions, pipelines), and who owns it? | `opsdir report jobs` |
| Which outside services does the platform depend on, which addresses does it send mail from, and where do its events go? | `opsdir report external-services`, `opsdir report mail-senders`, `opsdir report event-streams` |
| What do the servers run beyond the products (OS, Java truststore additions, limits, agents), and on what compute or cluster? | `opsdir report baselines`, `opsdir report compute`, `opsdir report workloads` |
| What is the platform watched for, where do its logs go and for how long, and what does each cloud actually run? | `opsdir report alerts`, `opsdir report log-routes`, `opsdir report canaries`, `opsdir report monitors` |
| Who records what is done to each environment's cloud, and is the target's trail as complete as the source's? | `opsdir report audit-trails` (CloudTrail, the Activity Log, Cloud Audit Logs: scope, activity, all regions, integrity (validated, or kept in a locked or unlocked immutable store: clouds without log digests protect their records where they export them), where the records go and for how long, who keeps the trail); `opsdir plan` blocks a target with no trail and gives actions where its trail is weaker |
| Who and what may act on the platform, as which cloud identity, under which guardrails, and is it reviewed? | `opsdir report principals`, `opsdir report identities`, `opsdir report guardrails`, `opsdir report access-paths` |
| How does traffic reach the platform, what protects it, and what does each environment's edge and DNS run? | `opsdir report edge-policies`, `opsdir report edge-services`, `opsdir report dns`, `opsdir report header-contracts` |
| How does each environment route out, which private endpoints and endpoint services does it have, and which outside sites may the servers reach? | `opsdir report routes`, `opsdir report private-endpoints`, `opsdir report endpoint-services`, `opsdir report egress-sites` |
| Which managed databases does the platform run on, and are they as available, encrypted, protected and backed up in every environment? | `opsdir report databases` |
| Are the backup buckets versioned, locked, encrypted, private and copied elsewhere in every environment? | `opsdir report object-stores` |
| When was each part of the record last read back from the live system? | `opsdir report imports` |
| How big is the user data, which password schemes does it hold, how many accounts are idle? | `opsdir report data-profile`, `opsdir report data-profile-attributes` |
| Which files copy this server's hostname (or any value), on which lines? | `opsdir report census [<DN>]` |
| Anything else | `opsdir search -b <base> '<LDAP filter>'` |

### Change the platform safely

- **Every change is governed.** Writes name an approved change record; the database rejects unapproved changes, invalid values, secret values in reference fields and deletions that would break something still in use.
- **Read the live system back, and decide where it disagrees.** Importers read products' exports and clouds' Terraform state, CLI output and asset inventories. Where the live system and the record disagree, each difference is a conflict you decide, taking the live value or keeping the record's; neither side is assumed right.
- **Fix what the plan finds.** Where a finding has a known record change, the plan offers it (`opsdir fix`). Some fixes are exact; some are a choice (which secret holds a credential: never guessed); some take values only you know (the target's own references, a role for an external host); some wait for a fresh import first; some stay open until an import confirms the live system followed. Proposing writes the exact records for a person to approve, and the store checks them before they're held.
- **Every change is kept.** `opsdir history` shows who changed what under which change; `opsdir export` produces LDIF for review in Git.
- **Every environment is rendered from the same record.** `opsdir render <cloud>/<env>` writes the environment's Terraform, directory configuration and setup scripts, federation configuration, standard SAML/OIDC/LDAP documents and product files, with a MANIFEST of hashes. Configuration that should be identical across environments renders byte-identical; only the environment's own bindings differ.
- **Environments share what they should.** A stage environment can be an overlay of production: it inherits the shared intent and overrides only documented values (fewer replicas, a different lockout threshold), each with why.
- **Extend the record yourself.** Define your own fields and record types (a support tier, a feature flag) as governed, typed, documented entries (`opsdir report custom`).

### Prepare and run a platform move

Moving to another cloud, account or region uses everything above:

- **Plan against the live record.** `opsdir plan <from> <to>` compares the target with production and returns a verdict listing every blocker and action with its owner, and a do-by date for each action from its lead time: changed contracts (service names, SAML entity IDs, OIDC issuers), missing firewall rules and backups, applications not yet tested against the target, certificates expiring before cutover, keys the target would keep wrongly (not in an HSM, regenerated instead of carried over), directory replicas that must join the existing replication deployment, and **other parties' allowlists that still pin your old addresses**, with a drafted request to each party.
- **Work in a copy.** `opsdir workspace create` copies the live record; declare the target's stack and bindings there, plan, render and review, while the platform keeps being operated from the live record. `opsdir workspace cutover` applies the result as one approved change (a three-way merge that refuses conflicting edits).
- **Run it end to end.** `opsdir migrate <from> <to>` checks both stacks, plans and renders the target, and exits non-zero unless it is ready. It works in either direction.

## Adapters

Adapters are separate installable packages. Installing one registers it with the core; nothing in the core changes. Each environment declares which adapters and versions it runs, and `opsdir check` confirms they are installed.

**Standards (shared by every product that implements them)**
- `opsdir-adapter-ldap`: the user directory's schema and tree as standard LDIF; a generic LDAPv3 adapter for any compliant directory server.
- `opsdir-base-saml`: SAML 2.0 metadata for every partner and for the platform's own identity provider.
- `opsdir-base-oidc`: OpenID Connect client registrations and the provider's discovery document.

**Directory servers**
- `opsdir-base-ds`: the DS lineage (OpenDJ → ForgeRock DS → PingDS): `dsconfig` batch, ACI syntax, replication checks.
- `opsdir-adapter-pingds`: PingDS 7–8: `dsconfig` batch, ACIs, per-server setup scripts that join the existing replication deployment, continuity checks; **imports each server's configuration** (`config.ldif` and its archived versions) as snapshots for drift, or as the declared configuration, and **finds the directory's consumers in its access logs**.
- `opsdir-adapter-opendj`: OpenDJ 4: the same record as `dsconfig`, ACIs, `setup` and `dsreplication` scripts; imports server configuration and access logs the same way.

**Federation, access management, identity management and gateway**
- `opsdir-adapter-pingfederate`: PingFederate 11–12: SP connections, OIDC clients and IdP connections as Admin API-shaped JSON, plus the standard SAML and OIDC documents at PingFederate's paths; **imports the Admin API bulk export** (connections, clients, claims, certificates; data stores checked).
- `opsdir-adapter-pingam`: PingAM / ForgeRock AM 7–8: realms, OAuth2/OIDC clients, SAML, authentication journeys and policy sets as Amster entities; **imports Amster exports**.
- `opsdir-adapter-pingidm`: PingIDM / ForgeRock IDM 7–8: managed objects, connectors, sync mappings and schedules as project files, each connector pointing at the right host in every environment; **imports IDM projects**.
- `opsdir-adapter-pinggateway`: PingGateway 2023–2026 / ForgeRock IG 7: routes rendered per environment and linked to the client and issuer they rely on; **imports gateway configurations**.

**Clouds**
- `opsdir-adapter-aws`: Terraform for AWS (VPC, subnets, instances, load balancers, security groups, DNS); Secrets Manager, KMS, Certificate Manager and S3 references; **imports Terraform state, AWS CLI output and CloudFormation stacks** into the environment's servers and bindings.
- `opsdir-adapter-azure`: Terraform for Azure, commercial or government (virtual network, subnets, VMs, load balancers, network security rules with pinned priorities, DNS); Key Vault secret, key and certificate references; **imports Terraform state, Azure CLI output and ARM/Bicep deployments** into the environment's servers and bindings.
- `opsdir-adapter-gcp`: Terraform for Google Cloud (the landing zone's Shared VPC network and subnetworks, instances with CMEK disks and Shielded VM, VPC firewall rules by network tag with pinned priorities, passthrough load balancers with their health-check rules, Cloud DNS); Secret Manager, Cloud KMS, Certificate Manager and Cloud Storage references; **imports Terraform state and Cloud Asset Inventory / `gcloud` output** into the environment's servers and bindings.

**Secret stores** (resolved at run time; values never reach the database or a rendered file)
- AWS Secrets Manager and KMS (in `opsdir-adapter-aws`), Azure Key Vault (in `opsdir-adapter-azure`), Google Cloud Secret Manager and Cloud KMS (in `opsdir-adapter-gcp`).
- `opsdir-adapter-hashicorp-vault`: `vault://` references, resolved with the Vault CLI.
- `opsdir-adapter-kubernetes`: `k8s-secret://` references, resolved with `kubectl`; also **imports Kubernetes manifests** as workloads (below).
- `opsdir-adapter-cyberark`: `cyberark://` references, resolved with the Credential Provider SDK.

**Hosts, clusters and CI** (what runs beyond the products)
- `opsdir-adapter-linux`: **imports Linux servers' own files**: their crontabs and systemd timers as jobs, and each server role's host baseline (OS, Java runtime and the certificates its truststore adds, limits, kernel settings, FIPS and SELinux modes, agents, service units, names pinned in `/etc/hosts`).
- `opsdir-adapter-kubernetes`: **imports manifests** (`kubectl get -o yaml`, rendered Helm or Kustomize) as workloads (a server role run as containers: replicas, images, storage, workload identity, pod security, network policies, ingress hosts, secret names) and CronJobs as jobs. EKS and AKS clusters and autoscaling groups / scale sets are read by the cloud adapters.
- `opsdir-adapter-github-actions`, `opsdir-adapter-gitlab-ci`, `opsdir-adapter-azure-devops`: **import CI pipeline definitions** as jobs (schedules, triggers, runners, environments, the secrets they name).

**Formats**
- `opsdir-format-terraform`: HCL laid out like `terraform fmt`, shared by the cloud adapters.

### Adapters for other systems

Anything not listed can be added as a package, by your team or anyone else, without touching the core or the other adapters: another directory or federation product, another cloud, another secret store, an ITSM or monitoring tool. An adapter declares when it applies (from the record's data), the roles an environment must bind for it, its renderers and importers, its planner checks, the secret-reference schemes it owns, the file formats it writes, the product versions it supports and, if it needs them, schema definitions under its own OID arc. How to write one: [`opsdir/README.md`](opsdir/README.md#writing-an-adapter-package); the contract: [`opsdir/SPEC.md`](opsdir/SPEC.md) §8. The roadmap already includes PingAccess, SiteMinder, Kubernetes/ForgeOps, configuration-management, ARM/Bicep and CloudFormation renderers, and importers for cloud inventories.

## Try it

Requirements: Python 3.11+ and PostgreSQL. Set up the role and databases once ([Database](opsdir/README.md#database)), then:

```bash
opsdir/scripts/dev-install.sh     # venv (opsdir/.venv) + the core + every package, editable
examples/showcase/demo.sh         # a fictional estate operated from the record; outputs in examples/showcase/out/
opsdir/opsdir.sh --help           # the CLI, against the local dev database
opsdir/scripts/test.sh            # every test: core, packages, showcase; unit + integration
```

The [showcase](examples/showcase/README.md) walks through all of the above on a fictional company's platform (PingDS, PingFederate, PingAM, PingIDM and PingGateway on AWS, with a stage overlay, and a warm standby being built on Google Cloud), then plans moving production to a second environment on Azure. Its problems are planted on purpose, and the tests check that the planner finds every one. Terraform is optional: `opsdir/scripts/fetch-tools.sh` puts a verified copy in the gitignored `tools/` folder, after which the demo and the test suite also check every rendered root with `terraform fmt` and `validate`.

## Where it stands

**Working and tested (1616 tests):** the governed store with versioned schema upgrades and full history; every report, search and guardrail above; rendering for every adapter listed; the directory-configuration, access-log, PingFederate, PingAM, PingIDM and PingGateway importers, the AWS, Azure and Google Cloud importers (Terraform state, CLI output and Cloud Asset Inventory, native templates for AWS and Azure), the Linux host, Kubernetes manifest and CI pipeline importers; the values-free data profile of a directory's user data; observability intent (alert rules, log routes with retention obligations, canaries) and what AWS, Azure and Google Cloud monitoring runs of it; the edge (traffic and protection policies, header contracts, DNS zones, records and forwarders; load balancers, web application firewalls, DDoS protection and CDNs rendered for AWS, Azure and Google Cloud and read back from Terraform state and CLI output; TTL lowering, zone owners' requests, header contracts and unprotected sign-on endpoints checked); network depth (route tables, network ACLs, private endpoints, endpoint services, egress firewalls and forward proxies, interconnects, time sources and flow logs, rendered for the three clouds with the landing zone's plumbing in its keepers' roots, and read back; the ports matrix derived from what products declare); assisted fixes and import conflicts; platform access (permission sets and principals; each cloud's identities, grants, denies, ceilings, guardrails and ways in, read from Terraform state and CLI output; least-privilege identities and the landing zone rendered; effective access allowed / denied / unknown, cloud evaluators' verdicts as evidence); the census of values copied into files; overlays and overrides; keys and secrets across six secret stores; captured files and bundles; custom fields and record types; migration workspaces, the planner and the migration runner in both directions. The rendered AWS and Azure Terraform passes `terraform validate` against the provider schemas; the Google Cloud Terraform follows the `hashicorp/google` 8.x schema and is validated with the rest in milestone 7.2.

**Not yet verified:** rendered product configuration against real product instances (PingDS `dsconfig`/`setup`, PingFederate Admin API payloads, which are an illustrative subset today, PingAM, PingIDM, PingGateway), and `terraform plan` against real accounts. See [what's verified](examples/showcase/README.md#whats-verified-and-what-isnt).

**Next:** stack coverage (path 5), after PingFederate depth, hidden automation, host baselines and Kubernetes workloads, messaging and external services, the data profile, observability intent, a Google Cloud adapter at parity with AWS and Azure, and platform IAM and the admin plane, the edge and network depth: the rest of the cloud estate on all three clouds (data and backup, governance). What is covered and what is still a gap, subsystem by subsystem: [`documentation/STACK.md`](documentation/STACK.md) §21.

## Documentation

- [`opsdir/README.md`](opsdir/README.md): install, CLI, database, workspaces, architecture, writing adapters.
- [`opsdir/SPEC.md`](opsdir/SPEC.md): the standard: LDAP schema with portability classes, rules R1–R10, the adapter contract.
- [`documentation/ops-directory-model.md`](documentation/ops-directory-model.md): design rationale: why a directory-shaped record, what differs between environments, where moves get hard, prior art.
- [`documentation/STACK.md`](documentation/STACK.md): the full inventory of what an identity platform carries and how much of it is modeled today.

## Layout

```
opsdir/                   the core: an installable Python package on PostgreSQL
packages/                 adapter, base and format packages (listed above)
examples/showcase/        a runnable fictional estate: data, product exports, demo, golden outputs
documentation/            design rationale and stack inventory
pytest.ini                one test configuration for the core, the packages and the showcase
.aimfp-project/           project tracking (blueprint, roadmap, tracked files and functions)
docs/                     local dev notes; git-ignored, never part of the project
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
