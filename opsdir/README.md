# opsdir: the CIAM operations directory

The whole identity platform (servers, bindings, directory config, consumers, ACIs, integrations, claims, certificates, external allowlists, runbooks, changes) lives in **LDAP-modeled Postgres databases**. **Adapters** read them and write working configuration. Today that is **Terraform (AWS or Azure), `dsconfig` batch files, DS setup scripts, ACI LDIF and PingFederate config**. Which adapters apply to an environment is decided from the data itself: its cloud provider and the products on its servers.

- **A change is a directory entry,** not a file edit.
- **A migration is a read** of the same databases with a different environment's bindings.

The standard is in [`SPEC.md`](SPEC.md). The reasoning behind it is in [`../documentation/ops-directory-model.md`](../documentation/ops-directory-model.md).

> **All data is synthetic and fictional:** "Example Aero", partners "Skyline Air" / "Harbor MRO", RFC 5737 documentation IPs, the AWS documentation account `111122223333`, made-up resource IDs. The migration runs between two environments named for their role: `source` (AWS, in service) and `target` (Azure Government, being built).

## Run it

```bash
scripts/dev-install.sh   # once (and after changing any pyproject.toml): venv + core + every package, editable
./demo.sh                                                           # the whole story, output in out/
TERRAFORM=/path/to/terraform ./demo.sh                              # plus terraform fmt + validate
```

`./opsdir.sh` runs the CLI against `OPSDIR_DSN`, by default the local dev database (`scripts/dev-env.sh`; see [Database](#database)). Any other database works the same way: `OPSDIR_DSN=... .venv/bin/python -m opsdir …`.

```bash
./opsdir.sh init                  # DROPS the opsdir schema, then creates it: tables, rules, views, LDAP schema
./opsdir.sh upgrade               # upgrades it in place instead: pending migrations, keeping data and history
./opsdir.sh load                  # data/*.ldif under change BOOTSTRAP
./opsdir.sh check                 # each environment's declared stack vs the installed adapters (non-zero exit on problems)
./opsdir.sh report expiring|pii|drift|stale|unowned|portability
./opsdir.sh report blast-radius "cn=skyline-air-idp-signing,ou=certificates,dc=ciam-ops"
./opsdir.sh search -b ou=consumers,dc=ciam-ops '(&(objectClass=ciamConsumer)(!(ciamMigrationStatus=tested)))' ciamOwner
./opsdir.sh render target/prod  # → out/target-prod/{terraform,ds,pingfederate}
./opsdir.sh plan source/prod target/prod    # → PLAN.md + change-request drafts for external parties
./opsdir.sh modify --change CHG-2001 changes/CHG-2001-mro-firewall-target.ldif
./opsdir.sh export > snapshot.ldif
```

## Database

One PostgreSQL server and one role, `opsdir`, with two databases:

| Database | Used by | Its `opsdir` schema |
|---|---|---|
| `opsdir` | `./opsdir.sh`, `demo.sh` (via `OPSDIR_DSN`, default in `scripts/dev-env.sh`) | upgraded in place by `upgrade`; `init` and `demo.sh` rebuild it |
| `opsdir_workspace` | a migration workspace for the dev record (via `OPSDIR_WORKSPACE_DSN`, default in `scripts/dev-env.sh`) | rebuilt by `workspace create` and after every cutover |
| `opsdir_test` | the integration tests (via `OPSDIR_TEST_DSN`, default in `tests/support.py`) | dropped and rebuilt by every test run |
| `opsdir_test_workspace` | the workspace integration tests (via `OPSDIR_TEST_WORKSPACE_DSN`) | dropped and rebuilt by every test run |

The tests never use `OPSDIR_DSN`. One-time setup on a new machine (the role needs no special privileges; the password is for local dev and tests only):

```bash
sudo -u postgres psql -c "create role opsdir login password 'testpass'"
sudo -u postgres createdb -O opsdir -T template0 opsdir
sudo -u postgres createdb -O opsdir -T template0 opsdir_test
sudo -u postgres createdb -O opsdir -T template0 opsdir_workspace
sudo -u postgres createdb -O opsdir -T template0 opsdir_test_workspace
```

### Migration workspaces

The live record is what you operate from. To prepare a move without touching it, copy it into a workspace database and declare the target there (its stack and bindings); every command runs against the workspace with `--workspace`:

```bash
./opsdir.sh workspace create                          # copy the live record (OPSDIR_DSN) into the workspace
./opsdir.sh --workspace modify --change CHG-… file.ldif   # declare the target, as governed changes
./opsdir.sh --workspace plan source/prod target/prod  # plan and render from the workspace
./opsdir.sh workspace status                          # what the workspace changed; did the live record move on?
./opsdir.sh workspace diff                            # the workspace's changes as LDIF change records
./opsdir.sh workspace cutover --change CHG-…          # apply them to the live record (one approved change), re-copy
```

The workspace remembers the live snapshot it was copied from. At cutover, if the live record changed other entries meanwhile, the workspace's changes still apply; if both changed the same entry, the cutover is refused and names it. Everything is applied in one transaction under the approved change, through the store's rules.

### Schema upgrades

The store's SQL comes in two kinds (`opsdir/store/migrations.py`):

- **Migrations** (`opsdir/store/sql/migrations/NNNN_name.sql`) create and change what holds data: tables, the rule functions and their triggers. Each is applied once, in order, and recorded with its checksum in `opsdir.schema_migration`. **Never edit an applied migration**; add the next number. `upgrade` refuses a database whose applied migrations were edited, that has migrations this code doesn't know, or that was created before versioning (`init` rebuilds those).
- **Definitions** (`opsdir/store/sql/definitions/`, and every domain's and connector's `sql/`) hold no data: views and report functions. Every `upgrade` drops the views and re-applies all definitions, so they are edited in place. A function whose signature changes is dropped by a migration.

Every `upgrade` also syncs the LDAP schema registry from the registered schema fragments (new and changed definitions; removing a published definition is refused) and the reference schemes the adapters own, and replaces the **vocabulary**: the values of `vocab` attributes (cloud provider, provider partition, server and target roles) that the installed domains and adapters define. The store rejects any other value, and `upgrade` refuses to drop values that entries still use (an adapter was uninstalled). Everything runs in one transaction, one migrator at a time.

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

Each part of the stack is self-contained, and only `connectors/` combines them. Dependencies point one way: adapter packages (`../packages/`) depend on the core, never the reverse; the registry discovers them through entry points. Inside the core, `connectors → domains → core` and `connectors → store → core`; domains never import the store.

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
  store/                     Postgres: postgres.py (connect, load, governed changes, snapshot read),
                             migrations.py (init, upgrade), queries.py, sql/migrations/ (entries, schema
                             registry, rules R1–R6), sql/definitions/ (graph functions, portability view)
  domains/                   vendor-neutral parts of the stack, each with its schema fragment, SQL views,
    infrastructure/          checks and reports: clouds, environments, servers, bindings, allowlists
    directory/               LDAP user directory: declared/observed config and drift, consumers, ACIs, PII view
    federation/              SAML/OIDC integrations and claim maps
    pki/                     certificates and their expiry
    governance/              owners (including the operator), changes, incidents, runbooks
  connectors/                the only code that joins parts: registry.py (what exists and applies),
                             render.py, plan.py (migration planner), reports.py, sql/ (cross-domain views)
  cli.py                     thin orchestrator
schema/ciam-ops.schema.ldif  published RFC 4512 schema, composed from the fragments by scripts/gen-schema.py
data/*.ldif                  the synthetic estate, 230 entries, written by scripts/gen-synthetic.py
data/expected-findings.json  the planted problems the planner must report
fixtures/example_estate/     the synthetic estate as pure builders, one module per part of the stack
changes/                     approved change records to apply; changes/rejected/ = writes that must fail
scripts/                     gen-schema.py, gen-synthetic.py, check-findings.py, snapshot-outputs.sh, test.sh,
                             dev-env.sh (local dev defaults: OPSDIR_DSN)
tests/unit/ tests/support.py pytest unit suite (no database); pytest.ini configures it
tests/integration/           pytest integration suite (Postgres); scripts/test.sh runs both
tests/golden/                accepted snapshot of every output (see "Checking a change")
demo.sh opsdir.sh            end-to-end walk-through; CLI wrapper for the local dev database
```

## Adding a product, cloud provider or secret store

1. Create a package (see `../packages/` for the existing ones) with a module that defines `ADAPTER = Adapter(...)`. It declares `applies(m)` (decided from directory data only, such as the cloud's `ciamCloudProvider` or the servers' `ciamProductVersion`), the roles it requires, its renderers, its planner checks, the reference schemes it owns and their resolvers, and how its outputs are described.
2. Register it in its package's `pyproject.toml` under `[project.entry-points."opsdir.adapters"]` and install the package. The registry discovers it; nothing in the core changes.

Core, store, domains and the other adapters don't change. A new vendor-neutral part of the stack is added the same way as a `Domain`: a schema fragment (with new, never-reused OID numbers), SQL views, checks and reports, and an `order`, registered under `[project.entry-points."opsdir.domains"]`.

## Checking a change

```bash
scripts/test.sh                              # everything: unit + integration (~4 s, database required)
.venv/bin/python -m pytest                   # unit suite only, no database (well under a second)
.venv/bin/python -m pytest -m integration    # integration suite only (skipped if the database is unreachable)
```

The unit suite tests the pure modules (LDIF, RFC 4512, filters, directory, environment, schema fragments, store preparation, HCL) and builds the synthetic estate in memory with the store's own preparation functions. Its renders, plans, findings, drift, searches and export must equal `tests/golden/` byte for byte, before and after the approved changes. It does not run the store's rules (R1-R10), which live in Postgres triggers.

The integration suite runs `scripts/snapshot-outputs.sh` once against Postgres and checks every captured output against `tests/golden/`, one test per file. It also checks the guardrails directly (each rejected write fails with its reason, each approved change applies and appears in history), independent of the baseline, and that the database ends up exactly where the in-memory estate does. It also tests migrations: a fresh database gets every migration, an upgrade keeps entries, references and history, and edited, unknown or pre-versioning databases are refused. It uses `OPSDIR_TEST_DSN`, else `opsdir_test` (see [Database](#database)), and **drops and rebuilds the `opsdir` schema there**. It never uses `OPSDIR_DSN`.

To run the snapshot by hand: `OPSDIR_DSN=... scripts/snapshot-outputs.sh /tmp/snap && diff -r tests/golden /tmp/snap`. It regenerates the schema and data (they must reproduce the files on disk), then runs every command on a fresh load: init, reports, searches, renders of both clouds, plans with request drafts, the rejected writes, the approved changes, history, export and the findings checks. A refactor must leave the diff empty. An intended change of output is reviewed, and then the snapshot replaces `tests/golden/`. The script drops and reloads the `opsdir` schema in the target database.
