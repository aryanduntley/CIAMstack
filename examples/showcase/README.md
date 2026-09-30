# Showcase: operating a fictional estate from the opsdir record

A runnable example of opsdir with real adapter packages. The estate is **Example Aero**, a fictional company whose identity platform (PingDS, PingFederate, PingAM, PingIDM and PingGateway) runs on AWS: production (`source/prod`) and a stage environment (`source/stage`). A second environment on Azure (`target/prod`) is being built, and production will move there. The walk-through starts with running the platform from the record; the move is its last chapter. The showcase is the only part of the repository that names platforms outside the adapter packages.

> **All data is synthetic and fictional:** "Example Aero", partners "Skyline Air" / "Harbor MRO", RFC 5737 documentation IPs, the AWS documentation account `111122223333`, made-up resource IDs.

## Run it

```bash
../../opsdir/scripts/dev-install.sh      # once: the core and the adapter packages
./demo.sh                                # the whole walk-through against the local dev database; outputs in out/
TERRAFORM=/path/to/terraform ./demo.sh   # plus terraform fmt + validate on the rendered Terraform
```

`demo.sh` regenerates `data/` and the directory servers' exports, rebuilds the dev database (`opsdir init`, then `load data/*.ldif`), reads the product exports and the directory servers' configuration and access logs in, asks the record questions, shows the guardrails rejecting bad writes, renders each environment, then plans the move to the second environment, applies three approved changes and plans again.

## What it shows

**Operating the platform**

1. **One record.** Over 400 entries in one database hold the whole platform: servers and bindings per environment, directory configuration and ACIs, consumers, federation integrations and their claims, certificates, keys and secrets as references, owners, runbooks, changes and incidents. Every attribute says what kind of value it is (intent, contract, binding, secret reference, observed, meta: `opsdir report portability`). Each environment declares its stack (`aws` or `azure`, `pingds`, `pingfederate`, `pingam`, `pingidm`, `pinggateway`); `opsdir check` confirms the adapters are installed at acceptable versions.
2. **Product configuration read in.** The partner realm runs on PingAM. Its configuration arrives the way an AM team has it, as an Amster export (`exports/amster`), and `opsdir import --change CHG-2004 pingam exports/amster` reads it into the record under an approved change: the OAuth2 client becomes a standard integration registered with the realm, the sign-in journey (every node and where each outcome leads) and the policy set are held as entries, the OAuth2 provider settings are captured setting by setting, and the SMTP password is withheld. The partner identity sync on PingIDM arrives the same way (`exports/idm`, an IDM project): the directory connector's host becomes the `ds-ldaps-service` role and its bind account is linked to the `idm-sync` consumer record, so each environment renders its own host; its credentials are withheld until an approved change (CHG-2005) names the secret roles they come from. The partner portal's PingGateway route (`exports/ig`) signs partner staff in with the AM realm: on import it is linked to the `partner-portal` client the Amster import recorded and to the realm's issuer. And what the production directory servers actually run arrives as their own files: a copy of each server's `config/` directory (`exports/ds-config/<hostname>/config.ldif`, and for ds-2 an archived configuration the server saved before a change), read in by `opsdir import --change CHG-2006 --at 20260920030000Z pingds/config exports/ds-config` as dated snapshots of each server. Who uses the directory comes from its access logs: three days of each server's JSON access log (`exports/ds-access-logs`), read by `opsdir import --change CHG-2007 pingds/access-log exports/ds-access-logs`. The importer records what each consumer does (where it connects from, its operations, the attributes it reads, unindexed searches, whether it uses TLS, its peak rate) next to what its operators recorded (owner, criticality, migration status, last review), without reading a filter or a value: the end users PingFederate checks passwords for are counted, not recorded.
3. **Questions become queries.** Certificates by expiry, the blast radius of a partner's signing certificate, who can read privacy-classified attributes, the consumers to review (`opsdir report consumers`: each one's owner, status, TLS, unindexed searches, when last seen and reviewed, and what to check: here the legacy report account has no owner, uses plain text, searches unindexed and reads high-PII attributes, and the portal's review is over a year old), and LDAP filter searches over the record.
4. **Keys and secrets as data.** Every key and secret is a credential entry (what it is, how it rotates, whether another environment must receive the same material) bound per environment to where it is kept: Secrets Manager and KMS in AWS, Key Vault in Azure, with a CyberArk copy of the directory root password. `opsdir report keys source/prod` shows production's key placement (the directory root password's rotation is overdue), `report credentials` the sprawl, and `report rotation-impact` everything rotating the signing key touches (every environment's secrets, its certificate and every application that trusts it).
5. **Custom fields and record types.** The operator defines `xCostCenter` (on owners), `xDataResidency` (on environments), `xTokenLifetimeMinutes` (on integrations) and a `xFeatureFlag` record type with its own fields, as entries with their metadata; `opsdir report custom` shows each and where it is used. Config files are held in the record setting by setting (`report capture`) and rebuilt from it for any environment (`opsdir file run.properties --env source/prod`); code and templates deployed as they are are recorded by repo path and hash (`report bundles`).
6. **Drift and hygiene.** Each server's imported configuration is compared with the declared one (`opsdir report drift`): a missing index on ds-2 (the cause of incident INC-2231; ds-2's archived configuration, saved on 2026-09-12 22:40, still has it, which dates the unrecorded change), an unrecorded index and a changed lockout threshold on ds-3. Also a stale runbook, and PII readable by an unowned legacy account. Settings every server has from setup (the default and root password policies, the LDIF handler, the error and debug loggers) are declared too, and `dsconfig.batch` sets them rather than creating them.
7. **Guardrails enforced by the database.** An unapproved change, deleting a certificate still in use, a secret value in a reference field, and a missing required attribute are all **rejected**. Every accepted write is kept in history under its change (`opsdir history`).
8. **Environments as overlays.** `source/stage` is an overlay of `source/prod`: it shares production's network, subnets, egress, disk key and firewall rules (but not the consumers'), and has its own servers, service names, secrets and backups. It overrides three shared values (one directory replica, a higher lockout threshold for test automation, short tokens for one application), so its `dsconfig.batch` differs from production's only there; `opsdir report overrides` lists them with why, and its MANIFEST records them. Environments also declare roles they must bind as data (`ciamRequiredRole`).

**Moving production to a second environment**

9. **One record, two clouds.** The directory configuration, ACIs and PingFederate configuration render **byte-identical** for AWS and Azure, and so do the standard files the products build on: the user directory's schema and tree as standard LDIF, SAML metadata of every partner and of the platform's own IdP, OIDC client registrations and the discovery document, and the PingAM realm. Only Terraform and the per-server setup scripts differ. (A test renders the same record as OpenDJ instead of PingDS: the standard files and ACIs are identical, the product files are OpenDJ's.)
10. **Continuity.** The Azure replicas' setup scripts bootstrap from the AWS replicas, so they **join the existing directory deployment** (same deployment ID, so encrypted data and backups stay readable). Secrets are resolved at run time from references (`aws secretsmanager …` vs `az keyvault …`).
11. **The planner finds what blocks cutover.** The estate is **deliberately broken**: the problems are planted by the fixture in `example_estate/` (written out by `scripts/gen-synthetic.py`) and listed in `data/expected-findings.json`, so "NOT READY, 10 blockers" is the *correct* result. It finds a changed service name (contract break), missing firewall rules and backup target, untested or unowned consumers, certificates expiring before cutover, keys the target keeps wrongly (the disk key needs an HSM but the target vault protects it in software; the PingFederate signing key must be carried over, not regenerated; the target drops automatic rotation), the IDM connectors' missing secret roles and the HR database connector that reaches the same host from every environment, and **other parties' allowlists** that pin old addresses. Each has an owner and a do-by date from its lead time, plus a drafted request to each party. `scripts/check-findings.py` checks the planner against that list before and after the changes: every planted problem detected, nothing unexpected, and the fixed ones gone.
12. **Changes as entries.** Approved changes (LDIF records) produce exactly the expected diffs: a new network security rule and a DNS name fix in the Terraform, and the IDM connectors' secret roles (CHG-2005). Blockers go from 10 to 6.

`opsdir migrate source/prod target/prod` runs the whole move (check, plan, render); `opsdir migrate target/prod source/prod` runs it the other way, rendering the AWS environment from the same record.

## What's verified, and what isn't

| Verified | Not verified |
|---|---|
| Rendered Terraform passes `terraform fmt -check` and **`terraform validate`** against the `hashicorp/aws ~> 5` and `hashicorp/azurerm ~> 4` provider schemas | No `plan`/`apply` against real accounts (fictional IDs) |
| Every database rule (schema, references, change governance, secret references, vocabulary) exercised | `dsconfig` / `setup` flags follow the PingDS 7.x documentation but haven't been run against a real PingDS |
| LDIF round trip (load, export) and change sets (diff, apply) | PingFederate JSON is an illustrative subset of Admin API shapes, not validated against a live Admin API |
| | The schema file has not been loaded into a real LDAP server; OpenDJ `setup`/`dsreplication` flags follow the OpenDJ 4.x documentation, unrun |
| | SAML metadata and OIDC documents are schema-shaped but not yet loaded into a real SAML/OIDC product |

## Layout

```
example_estate/     the estate as pure builders, one module per part of the stack (build() composes them)
data/               the generated LDIF (329 entries) and expected-findings.json
changes/            approved change records; changes/rejected/ = writes that must fail
golden/             the accepted snapshot of every command's output
scripts/            gen-synthetic.py, check-findings.py, snapshot-outputs.sh
tests/              showcase tests: unit (the estate in memory vs golden) and integration (Postgres snapshot,
                    workspaces, upgrades with real data)
exports/            product exports read in by importers: amster/ (PingAM), idm/ (PingIDM), ig/ (PingGateway),
                    ds-config/ (each production directory server's config/ directory) and ds-access-logs/ (three days of
                    their JSON access logs), both generated with data/
demo.sh             the walk-through
```

## Checking a change

The showcase tests run with everything else (`../../opsdir/scripts/test.sh` from anywhere). The unit tests build the estate in memory with the store's own preparation functions; its renders, plans, findings, drift, searches and export must equal `golden/` byte for byte, before and after the approved changes. The integration tests run `scripts/snapshot-outputs.sh` against Postgres (`opsdir_test`) and compare every captured output with `golden/`, one test per file, and check the guardrails directly.

To snapshot by hand: `OPSDIR_DSN=... scripts/snapshot-outputs.sh /tmp/snap && diff -r golden /tmp/snap`. The script regenerates the published schema, `data/`, `exports/ds-config/` and `exports/ds-access-logs/` (they must reproduce the committed files), then runs every command on a fresh load. A refactor must leave the diff empty; an intended change of output is reviewed, then the snapshot replaces `golden/`. It drops and reloads the `opsdir` schema in the target database.
