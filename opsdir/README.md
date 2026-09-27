# opsdir: the CIAM operations directory

The whole identity platform (servers, bindings, directory config, consumers, ACIs, integrations, claims, certificates, external allowlists, runbooks, changes) lives in **LDAP-modeled Postgres databases**. **Adapters** read them and write working configuration. Today that is **Terraform (AWS or Azure), `dsconfig` batch files, DS setup scripts, ACI LDIF and PingFederate config**. Which adapters apply to an environment is decided from the data itself: its cloud provider and the products on its servers.

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

`./opsdir.sh` runs the CLI against a **private throwaway Postgres cluster** in `.pgdata/` (unix socket only, port 54329), started by `scripts/pg-local.sh`. `scripts/pg-local.sh destroy` removes the cluster. To use another database, run `.venv/bin/python -m opsdir …` with `OPSDIR_DSN` set, for example the local dev database: `OPSDIR_DSN="host=localhost port=5432 user=opsdir password=testpass dbname=opsdir"`.

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

The synthetic estate is **deliberately broken**. The problems are planted by the fixture in `fixtures/example_estate/` (written out by `scripts/gen-synthetic.py`) and listed in `data/expected-findings.json`. So "NOT READY, 7 blockers" is the *correct* result, not a failure of the tool. `scripts/check-findings.py` checks the planner against that list before and after the changes: every planted problem detected, nothing unexpected, and the two fixed ones gone. It exits non-zero on any mismatch.

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

Each part of the stack is self-contained, and only `connectors/` combines them. Dependencies point one way: `connectors → adapters → domains → store → core`, and `formats` is used by adapters only.

```
opsdir/                      the Python package
  core/                      technology-neutral: knows no product, cloud or vendor
    directory.py             Entry/Directory immutable records and lookups (get, follow, children, subtree, referrers)
    search.py                RFC 4515 filter subset compiled to predicates; LDAP search
    environment.py           EnvModel: one environment's servers and bindings, looked up by role (R7)
    contract.py              the plug-in records: Domain, Adapter, Report, Services, PlanContext
    standard.py              the opsdir standard as data: value types, OID arc, schema fragments → published schema
    findings.py              Findings records, merge, owner labels (responsible)
    manifest.py network.py naming.py paths.py
    interchange/             ldif.py (RFC 2849 read/write), rfc4512.py (schema definitions read/write)
  store/                     Postgres: postgres.py (init, load, governed changes, snapshot read),
                             queries.py, sql/ (entries, schema registry, rules R1–R6, graph functions)
  domains/                   vendor-neutral parts of the stack, each with its schema fragment, SQL views,
    infrastructure/          checks and reports: clouds, environments, servers, bindings, allowlists
    directory/               LDAP user directory: declared/observed config and drift, consumers, ACIs, PII view
    federation/              SAML/OIDC integrations and claim maps
    pki/                     certificates and their expiry
    governance/              owners (including the operator), changes, incidents, runbooks
  adapters/                  one package per product, cloud provider or secret store
    pingds/                  dsconfig batch, ACI LDIF, setup scripts; replication checks
    pingfederate/            Admin API-shaped SP connections, OIDC clients, IdP connections
    aws/ azure/              Terraform per provider; secret resolvers (aws-sm, azkv)
    hashicorp_vault/         vault:// secret resolver
  formats/terraform_hcl.py   HCL formatting (no cloud knowledge)
  connectors/                the only code that joins parts: registry.py (what exists and applies),
                             render.py, plan.py (migration planner), reports.py, sql/ (cross-domain views)
  cli.py                     thin orchestrator
schema/ciam-ops.schema.ldif  published RFC 4512 schema, composed from the fragments by scripts/gen-schema.py
data/*.ldif                  the synthetic estate, 230 entries, written by scripts/gen-synthetic.py
data/expected-findings.json  the planted problems the planner must report
fixtures/example_estate/     the synthetic estate as pure builders, one module per part of the stack
changes/                     approved change records to apply; changes/rejected/ = writes that must fail
scripts/                     gen-schema.py, gen-synthetic.py, check-findings.py, pg-local.sh, snapshot-outputs.sh
tests/golden/                accepted snapshot of every output (see "Checking a change")
demo.sh opsdir.sh            end-to-end walk-through; CLI wrapper for the private cluster
```

## Adding a product, cloud provider or secret store

1. Create `opsdir/adapters/<name>/` with an `adapter.py` that defines `ADAPTER = Adapter(...)`. It declares `applies(m)` (decided from directory data only, such as the cloud's `ciamCloudProvider` or the servers' `ciamProductVersion`), the roles it requires, its renderers, its planner checks, the reference schemes it owns and their resolvers, and how its outputs are described.
2. Add one line to `ADAPTERS` in `connectors/registry.py`.

Core, store, domains and the other adapters don't change. A new vendor-neutral part of the stack is added the same way as a `Domain`: a schema fragment (with new, never-reused OID numbers), SQL views, checks and reports, plus one line in `DOMAINS`.

## Checking a change

```bash
OPSDIR_DSN=... scripts/snapshot-outputs.sh /tmp/snap && diff -r tests/golden /tmp/snap
```

This regenerates the schema and data (they must reproduce the files on disk), then runs every command on a fresh load: init, reports, searches, renders of both clouds, plans with request drafts, the rejected writes, the approved changes, history, export and the findings checks. A refactor must leave the diff empty. An intended change of output is reviewed, and then the snapshot replaces `tests/golden/`. The script drops and reloads the `opsdir` schema in the target database.
