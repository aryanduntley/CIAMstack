# opsdir: the CIAM operations directory (synthetic demo)

The whole identity platform (servers, bindings, directory config, consumers, ACIs, integrations, claims, certificates, external allowlists, runbooks, changes) lives in **LDAP-modeled Postgres databases**. A small renderer reads them and writes working **Terraform (AWS or Azure), `dsconfig` batch files, DS setup scripts, ACI LDIF and PingFederate config**.

- **A change is a directory entry,** not a file edit.
- **A migration is a read** of the same databases with a different environment's bindings.

The standard is in [`SPEC.md`](SPEC.md). The reasoning behind it is in [`../ops-directory-model.md`](../ops-directory-model.md).

> **All data is synthetic and fictional:** "Example Aero", partners "Skyline Air" / "Harbor MRO", RFC 5737 documentation IPs, the AWS documentation account `111122223333`, made-up resource IDs. The "rtx-next" environment is *assumed* to be Azure Government for the demo; the real target is unconfirmed.

## Run it

```bash
python3 -m venv .venv && PIP_USER=0 .venv/bin/pip install --no-cache-dir "psycopg[binary]"   # once
./demo.sh                                                           # the whole story, output in out/
TERRAFORM=/path/to/terraform ./demo.sh                              # plus terraform fmt + validate
```

`./opsdir.sh` runs the CLI against a **private throwaway Postgres cluster** in `.pgdata/` (unix socket only, port 54329), started by `scripts/pg-local.sh`. It never touches a system Postgres. Set `OPSDIR_DSN` to use another database. `scripts/pg-local.sh destroy` removes the cluster.

```bash
./opsdir.sh init                  # tables, rules, LDAP schema
./opsdir.sh load                  # data/*.ldif under change BOOTSTRAP
./opsdir.sh report expiring|pii|drift|stale|unowned|portability
./opsdir.sh report blast-radius "cn=skyline-air-idp-signing,ou=certificates,dc=ciam-ops"
./opsdir.sh search -b ou=consumers,dc=ciam-ops '(&(objectClass=ciamConsumer)(!(ciamMigrationStatus=tested)))' ciamOwner
./opsdir.sh render rtx-next/prod  # → out/rtx-next-prod/{terraform,ds,pingfederate}
./opsdir.sh plan aws-current/prod rtx-next/prod    # → PLAN.md + change-request drafts for external parties
./opsdir.sh modify --change CHG-2001 changes/CHG-2001-mro-firewall-rtx-next.ldif
./opsdir.sh export > snapshot.ldif
```

## What the demo shows

The synthetic estate is **deliberately broken**. The problems are planted by `scripts/gen-synthetic.py` and listed in `data/expected-findings.json`. So "NOT READY, 7 blockers" is the *correct* result, not a failure of the tool. `scripts/check-findings.py` checks the planner against that list before and after the changes: every planted problem detected, nothing unexpected, and the two fixed ones gone. It exits non-zero on any mismatch.

1. **One set of databases, two clouds.** The DS config, ACIs and PingFederate config render **byte-identical** for AWS and Azure. Only Terraform and the per-server setup scripts differ.
2. **Migration continuity.** The Azure replicas' setup scripts bootstrap from the AWS replicas, so they **join the existing DS deployment** (same deployment ID, so encrypted data and backups stay readable). Secrets are fetched at run time from references (`aws secretsmanager …` vs `az keyvault …`).
3. **The planner finds what blocks cutover:** a changed service name (contract break), missing firewall rules and backup target, untested or unowned consumers, certificates expiring before cutover, and **other parties' allowlists** that pin our old IPs. Each comes with an owner and a do-by date from their lead time, plus a drafted request to each party.
4. **Guardrails enforced by the database:** an unapproved change, deleting a certificate still in use, putting a secret value in a reference field, and a missing required attribute are all **rejected**.
5. **Changes as entries.** Two approved changes (two LDIF records) produce exactly the expected Terraform diff: a new NSG rule and a DNS name fix. Blockers go from 7 to 5.
6. **Drift and hygiene.** A missing index on ds-2 (the cause of incident INC-2231), an unrecorded index and policy change on ds-3, a stale runbook, and PII readable by an unowned legacy account.

## What's verified, and what isn't

| Verified | Not verified |
|---|---|
| Rendered Terraform passes `terraform fmt -check` and **`terraform validate`** against the real `hashicorp/aws ~> 5` and `hashicorp/azurerm ~> 4` provider schemas | No `plan`/`apply` against real accounts (fictional IDs) |
| All database rules (schema, references, change governance, secret refs) exercised by the demo | `dsconfig` / `setup` flags follow PingDS 7.x docs but haven't been run against a real PingDS |
| LDIF round trip (load → export) | PingFederate JSON is an illustrative subset of Admin API shapes, not validated against a live `/pf-admin-api/v1` |
| | Schema file not yet loaded into a real LDAP server |

## Layout

```
SPEC.md                    the standard (rules R1–R10, portability classes, branches)
schema/ciam-ops.schema.ldif  RFC 4512 schema with X-PORTABILITY / X-VALUE-TYPE   (from scripts/gen-schema.py)
sql/001_core.sql           Postgres: entries, schema registry, validation, references, governance, history
sql/002_reports.sql        views: certificates, PII exposure, stale runbooks, unowned, blast radius
data/*.ldif                synthetic estate, 229 entries                          (from scripts/gen-synthetic.py)
data/expected-findings.json  the planted problems the planner must report
scripts/check-findings.py  checks the planner's output against that list
changes/                   approved change records to apply; changes/rejected/ = writes that must fail
opsdir/                    Python: LDIF + schema parsers, db layer, LDAP filters, renderers, planner, CLI
demo.sh                    end-to-end run
```
