# Showcase: a fictional estate on the opsdir record

A runnable example of opsdir with real adapter packages. The estate is **Example Aero**, a fictional company whose identity platform runs PingDS and PingFederate on AWS (the `source` environment) and is being moved to Azure Government (the `target` environment). It is the only part of the repository that names platforms outside the adapter packages.

> **All data is synthetic and fictional:** "Example Aero", partners "Skyline Air" / "Harbor MRO", RFC 5737 documentation IPs, the AWS documentation account `111122223333`, made-up resource IDs.

## Run it

```bash
../../opsdir/scripts/dev-install.sh      # once: the core and the adapter packages
./demo.sh                                # the whole story against the local dev database; outputs in out/
TERRAFORM=/path/to/terraform ./demo.sh   # plus terraform fmt + validate on the rendered Terraform
```

`demo.sh` regenerates `data/`, rebuilds the dev database (`opsdir init`, then `load data/*.ldif`), runs reports and searches, renders both environments, plans the move, shows the guardrails rejecting bad writes, applies the two approved changes and plans again.

## What it shows

The estate is **deliberately broken**. The problems are planted by the fixture in `example_estate/` (written out by `scripts/gen-synthetic.py`) and listed in `data/expected-findings.json`, so "NOT READY, 10 blockers" is the *correct* result. `scripts/check-findings.py` checks the planner against that list before and after the changes: every planted problem detected, nothing unexpected, and the fixed ones gone.

1. **One record, two clouds.** The directory configuration, ACIs and PingFederate configuration render **byte-identical** for AWS and Azure, and so do the standard files the products build on: the user directory's schema and tree as standard LDIF, SAML metadata of every partner and of the platform's own IdP, OIDC client registrations and the discovery document. Only Terraform and the per-server setup scripts differ. (A test renders the same record as OpenDJ instead of PingDS: the standard files and ACIs are identical, the product files are OpenDJ's.)
2. **Declared stacks.** Each environment declares its adapters (`aws` or `azure`, `pingds`, `pingfederate`); `opsdir check` confirms they are installed at acceptable versions.
3. **Migration continuity.** The Azure replicas' setup scripts bootstrap from the AWS replicas, so they **join the existing directory deployment** (same deployment ID, so encrypted data and backups stay readable). Secrets are resolved at run time from references (`aws secretsmanager …` vs `az keyvault …`).
4. **The planner finds what blocks cutover:** a changed service name (contract break), missing firewall rules and backup target, untested or unowned consumers, certificates expiring before cutover, keys the target keeps wrongly (the disk key needs an HSM but the target vault protects it in software; the PingFederate signing key must be carried over, not regenerated; the target drops automatic rotation), and **other parties' allowlists** that pin old addresses. Each has an owner and a do-by date from its lead time, plus a drafted request to each party.
5. **Guardrails enforced by the database:** an unapproved change, deleting a certificate still in use, a secret value in a reference field, and a missing required attribute are all **rejected**.
6. **Changes as entries.** Approved changes (LDIF records) produce exactly the expected diffs: a new network security rule and a DNS name fix in the Terraform, and the IDM connectors' secret roles (CHG-2005). Blockers go from 10 to 6.
7. **Custom fields and record types.** The operator defines `xCostCenter` (on owners), `xDataResidency` (on environments), `xTokenLifetimeMinutes` (on integrations) and a `xFeatureFlag` record type with its own fields, as entries with their metadata; `opsdir report custom` shows each and where it is used.
8. **Keys and secrets as data.** Every key and secret is a credential entry (what it is, how it rotates, whether the target must receive the same material) bound per environment to where it is kept: Secrets Manager and KMS in AWS, Key Vault in Azure, with a CyberArk copy of the directory root password. `opsdir report keys target/prod` shows the target's key placement, `report credentials` the sprawl, and `report rotation-impact` everything rotating the signing key touches (both environments' secrets, its certificate and every application that trusts it).
9. **Environments as overlays.** `source/stage` is an overlay of `source/prod`: it shares production's network, subnets, egress, disk key and firewall rules (but not the consumers'), and has its own servers, service names, secrets and backups. It overrides three shared values (one directory replica, a higher lockout threshold for test automation, short tokens for one application), so its `dsconfig.batch` differs from production's only there; `opsdir report overrides` lists them with why, and its MANIFEST records them. Production and the target also declare roles they must bind as data (`ciamRequiredRole`).
10. **A product's own export, read into the record.** The partner realm runs on PingAM. Its configuration arrives the way an AM team has it, as an Amster export (`exports/amster`), and `opsdir import --change CHG-2004 pingam exports/amster` reads it into the record under an approved change: the OAuth2 client becomes a standard integration registered with the realm, the sign-in journey (every node and where each outcome leads) and the policy set are held as entries, the OAuth2 provider settings are captured setting by setting, and the SMTP password is withheld. Both clouds then render the realm identically (Amster entities, SAML metadata, OIDC registration and discovery at AM's paths), and the plan confirms the journey is complete. The partner identity sync on PingIDM arrives the same way (`exports/idm`, an IDM project): the directory connector's host becomes the `ds-ldaps-service` role and its bind account is linked to the `idm-sync` consumer record, so each environment renders its own host; the credentials are withheld, the planner blocks until an approved change (CHG-2005) names the secret roles they come from, and it flags the HR database connector, which reaches the same host from every environment. The partner portal's PingGateway route (`exports/ig`) signs partner staff in with the AM realm: on import it is linked to the `partner-portal` client the Amster import recorded and to the realm's issuer, so the plan can confirm both exist; the portal application itself is another team's, reached at a fixed host, which the plan asks to confirm.
11. **Drift and hygiene.** A missing index on ds-2 (the cause of incident INC-2231), an unrecorded index and policy change on ds-3, a stale runbook, and PII readable by an unowned legacy account.

`opsdir migrate source/prod target/prod` runs the whole move (check, plan, render); `opsdir migrate target/prod source/prod` runs it the other way, rendering the AWS target from the same record.

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
data/               the generated LDIF (252 entries) and expected-findings.json
changes/            approved change records; changes/rejected/ = writes that must fail
golden/             the accepted snapshot of every command's output
scripts/            gen-synthetic.py, check-findings.py, snapshot-outputs.sh
tests/              showcase tests: unit (the estate in memory vs golden) and integration (Postgres snapshot,
                    workspaces, upgrades with real data)
demo.sh             the walk-through
```

## Checking a change

The showcase tests run with everything else (`../../opsdir/scripts/test.sh` from anywhere). The unit tests build the estate in memory with the store's own preparation functions; its renders, plans, findings, drift, searches and export must equal `golden/` byte for byte, before and after the approved changes. The integration tests run `scripts/snapshot-outputs.sh` against Postgres (`opsdir_test`) and compare every captured output with `golden/`, one test per file, and check the guardrails directly.

To snapshot by hand: `OPSDIR_DSN=... scripts/snapshot-outputs.sh /tmp/snap && diff -r golden /tmp/snap`. The script regenerates the published schema and `data/` (they must reproduce the committed files), then runs every command on a fresh load. A refactor must leave the diff empty; an intended change of output is reviewed, then the snapshot replaces `golden/`. It drops and reloads the `opsdir` schema in the target database.
