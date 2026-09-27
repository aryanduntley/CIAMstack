# opsdir: database-first management of an identity platform

opsdir is the system of record an identity platform is operated from. Its servers, bindings, directory configuration, consumers, access rules, federation integrations, claims, certificates, external allowlists, runbooks and changes live as **typed, schema-checked, cross-referenced entries** in an LDAP-modeled PostgreSQL store. Everything else is built on that record: reports and queries, user interfaces, and every working file, which **adapter packages** render from it (and, over time, import back).

- **A change is an entry,** made under an approved change record and kept in history. It is never a hand edit to a file or a console.
- **Questions become queries:** blast radius, expiry, drift, who can read what, which outside parties' allowlists hold our addresses.
- **Moving a platform is one capability, not the point:** declare the target's stack and bindings in a workspace, plan, render, cut over. The intent (directory configuration, access rules, federation) is the same record, rendered for new bindings.

This package is the **core**. It names no cloud, product, vendor or secret store: those are adapter packages (in this repository under [`../packages/`](../packages/)) that the core discovers when they are installed. The standard is in [`SPEC.md`](SPEC.md); a runnable example estate is in [`../examples/showcase/`](../examples/showcase/).

## Install

```bash
scripts/dev-install.sh      # venv in .venv + this core + every package in ../packages, editable
                            # (re-run after changing any pyproject.toml)
```

On a machine whose global pip config sets `user = true`, pip refuses it inside a venv; the script sets `PIP_USER=0` and `--no-cache-dir` (nothing is written to `~/.cache/pip`). The core alone is `pip install -e .`; it runs without any adapter, but then renders nothing.

## Use

`./opsdir.sh` runs the CLI from anywhere against `OPSDIR_DSN` (by default the local dev database, `scripts/dev-env.sh`). Relative paths are relative to where you run it; outputs default to `out/` there.

```bash
./opsdir.sh init                      # DROPS the opsdir schema, then creates it (all migrations, views, registry)
./opsdir.sh upgrade                   # upgrade it in place instead: pending migrations, keeping data and history
./opsdir.sh load FILE.ldif...         # load LDIF content under change BOOTSTRAP
./opsdir.sh check [CLOUD/ENV...]      # each environment's declared stack vs the installed adapters
./opsdir.sh modify --change CHG-… FILE.ldif   # apply LDIF change records under an approved change
./opsdir.sh search -b BASE 'FILTER' [ATTR...] # RFC 4515 search, as LDIF or a table of attributes
./opsdir.sh report NAME [DN]          # portability, unowned, blast-radius DN, and every domain's reports
./opsdir.sh render CLOUD/ENV [-o DIR] # everything the environment's adapters render, plus MANIFEST.json
./opsdir.sh plan SRC DST [-o DIR]     # what blocks moving SRC to DST, dated actions, request drafts
./opsdir.sh migrate SRC DST [-o DIR]  # check both stacks, plan, render the target; exit 1 unless ready
./opsdir.sh export [-b BASE]          # entries as LDIF (for review)
./opsdir.sh history [DN]              # governed changes
./opsdir.sh workspace create|status|diff|cutover     # migration workspaces (below)
./opsdir.sh --workspace COMMAND …     # any command against the workspace instead of the live record
```

## Database

One PostgreSQL server and one role, `opsdir`. For local development and tests there are four databases:

| Database | Used by | Its `opsdir` schema |
|---|---|---|
| `opsdir` | the live record for local use (`OPSDIR_DSN`, default in `scripts/dev-env.sh`) | upgraded in place by `upgrade`; `init` rebuilds it |
| `opsdir_workspace` | its migration workspace (`OPSDIR_WORKSPACE_DSN`, default in `scripts/dev-env.sh`) | rebuilt by `workspace create` and after every cutover |
| `opsdir_test` | the integration tests (`OPSDIR_TEST_DSN`) | dropped and rebuilt by every test run |
| `opsdir_test_workspace` | the workspace integration tests (`OPSDIR_TEST_WORKSPACE_DSN`) | dropped and rebuilt by every test run |

The tests never use `OPSDIR_DSN`. One-time setup (the role needs no special privileges; the password is for local development only):

```bash
sudo -u postgres psql -c "create role opsdir login password 'testpass'"
sudo -u postgres createdb -O opsdir -T template0 opsdir
sudo -u postgres createdb -O opsdir -T template0 opsdir_workspace
sudo -u postgres createdb -O opsdir -T template0 opsdir_test
sudo -u postgres createdb -O opsdir -T template0 opsdir_test_workspace
```

### Schema upgrades

- **Migrations** (`opsdir/store/sql/migrations/NNNN_name.sql`) create and change what holds data: tables, the rule functions and their triggers. Each is applied once, in order, and recorded with its checksum in `opsdir.schema_migration`. **Never edit an applied migration**; add the next number. `upgrade` refuses a database whose applied migrations were edited, that has migrations this code doesn't know, or that was created before versioning (`init` rebuilds those).
- **Definitions** (`opsdir/store/sql/definitions/`, and every domain's and connector's `sql/`) hold no data: views and report functions. Every `upgrade` drops the views and re-applies all definitions, so they are edited in place.
- Every `upgrade` also syncs the **schema registry** from the registered schema fragments (removing a published definition is refused), the **reference schemes** the installed adapters own, and the **vocabulary** (below). Everything runs in one transaction, one upgrade at a time.

## Stacks and vocabulary

Each environment declares its **stack** under `ou=stack`: one `ciamStackComponent` per role, naming the adapter that fills it (as its package registers it), the adapter versions it accepts (a PEP 440 range) and where to get it. When an environment declares a stack, exactly those adapters render it, and rendering refuses a declared adapter that isn't installed; without one, adapters are chosen from the data (each adapter's `applies`). `opsdir check` reports, per component: not installed (and where to get it), a version outside the range, installed but not matching the environment's data, or an adapter that applies to the data but isn't declared.

Some attributes take values no core schema can list: the cloud provider, its partition, server and target roles. Their value type is `vocab`: each installed domain or adapter declares the values it defines, `upgrade` syncs them, and the store rejects any other value. Uninstalling an adapter whose values entries still use is refused at `upgrade`.

## Migration workspaces

The live record is what you operate from. To prepare a move without touching it, copy it into a workspace and declare the target there:

```bash
./opsdir.sh workspace create                               # copy the live record into the workspace
./opsdir.sh --workspace modify --change CHG-… target.ldif  # declare the target's stack and bindings (governed)
./opsdir.sh --workspace migrate CLOUD/ENV CLOUD2/ENV       # check, plan and render from the workspace
./opsdir.sh workspace status                               # what changed; did the live record move on?
./opsdir.sh workspace diff                                 # the workspace's changes as LDIF change records
./opsdir.sh workspace cutover --change CHG-…               # apply them to the live record, then re-copy
```

The workspace remembers the live snapshot it was copied from. At cutover, if the live record changed other entries meanwhile, the workspace's changes still apply (a three-way merge); if both changed the same entry, the cutover is refused and names it. The changes are applied in one transaction under the approved change, through every rule of the store.

## Architecture

```
opsdir/                      the package (names no platform, product, vendor or secret store)
  core/                      technology-neutral records and pure functions: directory snapshot and lookups, RFC 4515
                             search, environment model (bindings by role, declared stack), contracts (Domain,
                             Adapter, Report, Services, PlanContext), the standard (value types, OID arc, schema
                             fragments), findings, manifest, change sets, interchange (LDIF, RFC 4512, export)
  store/                     PostgreSQL: postgres.py (connect, load, governed changes, snapshot read), migrations.py
                             (init, upgrade), workspace.py (workspace base), queries.py, sql/migrations, sql/definitions
  domains/                   vendor-neutral parts of the stack, each with naming, schema fragment, checks, reports and
    infrastructure/          SQL views: clouds, environments, servers, bindings, stacks, external allowlists
    directory/               the LDAP user directory: declared/observed configuration and drift, consumers, ACIs
    federation/              SAML/OIDC integrations and claim maps
    pki/                     certificates and their expiry
    governance/              owners (including the operator), changes, incidents, runbooks
  connectors/                the only code that joins parts: registry (discovers domains and adapters through entry
                             points), stack (declared stacks vs installed adapters), render, plan (migration planner),
                             migration (runner), workspace (copy, diff, cutover), reports, sql (cross-domain views)
  cli.py                     thin orchestrator
schema/ciam-ops.schema.ldif  the published RFC 4512 schema of the core and its domains (scripts/gen-schema.py)
scripts/                     dev-install.sh, dev-env.sh (local defaults), gen-schema.py, test.sh
tests/                       core tests: unit (no database) and integration; mini_estate.py = a two-environment
                             estate and a fake provider adapter, so the core is tested without any real adapter
```

Dependencies point one way. Adapter packages depend on the core, never the reverse; the registry discovers them. Inside the core, `connectors → domains → core` and `connectors → store → core`; domains depend on `core` only (their reports are data: SQL text or a pure function of the snapshot). The code is Modular, Functional and Procedural: immutable records, pure functions, effects (database, files, printing) at the edges.

## Writing an adapter package

An adapter is one cloud provider, product or secret store. It lives in its own installable package:

1. A module that defines `ADAPTER = Adapter(...)` (`opsdir.core.contract`): its name and kind (`provider`, `product` or `secret-store`), `applies(m)` decided from directory data only, the roles it requires, its renderers (environment-neutral and environment-specific), its planner checks, the reference schemes it owns and their resolvers, how its outputs are described, and the `vocab` values it defines.
2. Its `pyproject.toml` depends on `opsdir` and registers it:

   ```toml
   [project.entry-points."opsdir.adapters"]
   example = "opsdir_adapter_example.adapter:ADAPTER"
   ```
3. Tests in the package's `tests/` (the repository-root `pytest.ini` collects them).

Installing the package is all it takes: nothing in the core changes. A new vendor-neutral part of the stack is added the same way as a `Domain` (schema fragment with new, never-reused OID numbers, SQL views, checks, reports, vocabulary, an `order`), registered under `[project.entry-points."opsdir.domains"]`.

## Tests

From the repository root (one `pytest.ini` collects the core, every package and the showcase):

```bash
opsdir/scripts/test.sh                                   # everything: unit + integration, databases required
opsdir/.venv/bin/python -m pytest                        # unit tests only, no database
opsdir/.venv/bin/python -m pytest -m integration         # integration tests only (skipped if unreachable)
opsdir/.venv/bin/python -m pytest opsdir/tests           # the core alone
```

The core's tests use a mini estate and a fake adapter, and pass with no adapter package installed. The integration tests create, upgrade and refuse schemas against Postgres (they drop and rebuild the `opsdir` schema in the test databases). End-to-end behaviour with real adapters and golden outputs is tested by the showcase.
