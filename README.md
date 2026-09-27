# CIAMstack

A program that **datifies** a CIAM platform: every piece of its configuration, infrastructure, dependencies and operational knowledge becomes typed, cross-referenced entries in one database. The working files are **generated** from that database: Terraform, `dsconfig` batches, DS setup scripts, ACI LDIF and PingFederate config.

- **A change is an entry,** made under an approved change record. It's never a hand edit to a file.
- **A migration is a read:** render the same database for a new environment. Only that environment's *bindings* are new.
- **Questions become queries:** blast radius, expiry, drift, who can read what, which outside parties' allowlists hold our addresses.

Nothing is tied to one stack. Clouds, compute styles, product lineages, versions and enterprise tools are values in the database, handled by **adapters**. Each part of the stack is self-contained (its schema, parsers and renderers live together), and only **connectors** combine them. The first adapters cover **PingDS, PingFederate, AWS, Azure and HashiCorp Vault**.

The code is Modular, Functional and Procedural: immutable records, pure functions, and effects (database, files, printing) kept at the edges.

## Layout

```
README.md                 this file
STACK.md                  the full stack inventory: every subsystem, file and store, what can be
                          datified, and what opsdir covers today vs the gaps (build order in §21)
ops-directory-model.md    design rationale: portable intent vs bindings, prior art, objections
docs/notes.txt            working notes (demo summary, environment/cleanup notes)
opsdir/                   the reference implementation (Python + Postgres)
  SPEC.md                 the standard: LDAP schema + X-PORTABILITY / X-VALUE-TYPE, rules R1–R10
  README.md               how to run it, the package layout, what's verified and what isn't
  opsdir/                 the package: core/ store/ domains/ adapters/ formats/ connectors/ cli.py
  schema/ data/ changes/ fixtures/ scripts/ tests/   (see opsdir/README.md)
.aimfp-project/           AIMFP project tracking (blueprint, roadmap, tracked files and functions)
```

## Quick start

Everything is self-contained in `opsdir/`. Nothing is installed system-wide.

```bash
cd opsdir
python3 -m venv .venv && PIP_USER=0 .venv/bin/pip install --no-cache-dir "psycopg[binary]"   # once
./demo.sh          # full walk-through; outputs in opsdir/out/
./opsdir.sh --help # the CLI (starts the private Postgres cluster if needed)
```

`PIP_USER=0` is needed because this machine's global pip config sets `user = true`, which pip refuses inside a venv. `--no-cache-dir` keeps pip from writing to `~/.cache/pip`.

Requirements: Python 3 and PostgreSQL. By default `./opsdir.sh` runs a private throwaway cluster from the server binaries in `/usr/lib/postgresql/*/bin`. To use an existing database instead, set `OPSDIR_DSN`. The local development database on this machine is:

```bash
export OPSDIR_DSN="host=localhost port=5432 user=opsdir password=testpass dbname=opsdir"   # dev/test only
```

Terraform is optional (`TERRAFORM=/path/to/terraform ./demo.sh` adds `fmt` + `validate`).

## Where everything lives (and how to remove it)

| Thing | Path | Remove with |
|---|---|---|
| Python venv (only `psycopg`) | `opsdir/.venv/` | `rm -rf opsdir/.venv` |
| Private Postgres cluster | `opsdir/.pgdata/`, socket in `opsdir/.pgsock/` (port 54329, unix socket only) | `opsdir/scripts/pg-local.sh destroy` |
| Rendered output | `opsdir/out/` | `rm -rf opsdir/out` |
| Python bytecode | `__pycache__/` under `opsdir/` | `find opsdir -name __pycache__ -exec rm -rf {} +` |
| Local dev database (optional) | role and database `opsdir` in the system PostgreSQL (localhost:5432) | `sudo -u postgres dropdb opsdir && sudo -u postgres dropuser opsdir` |

Deleting the `CIAMstack/` folder removes all of it. Stop the cluster first (`opsdir/scripts/pg-local.sh stop`) if it's running. Anything else outside this folder is listed in `docs/notes.txt`.

## Status

A working foundation, rewritten into Modular/Functional/Procedural form and split into self-contained parts (milestones 1.1 and 1.2), running on **synthetic data** (230 fictional entries, "Example Aero"). `opsdir/scripts/snapshot-outputs.sh` captures every output, and `opsdir/tests/golden/` holds the accepted baseline. The demo passes its own checks: the planner finds all 7 planted blockers, and 5 remain after two approved changes. The rendered Terraform passes `terraform validate` against the real AWS and Azure provider schemas. **Not verified:** `dsconfig`/`setup` flags have not been run against a real PingDS, the PingFederate JSON is an illustrative subset of the Admin API, and the schema hasn't been loaded into a real LDAP server. See `opsdir/README.md` for the full table.

The roadmap (7 stages) is tracked in AIMFP (`.aimfp-project/`). Next are the test harness (pytest plus the snapshot as an integration test), database setup with versioned SQL migrations, and the rest of the documentation. After that come the platform-agnostic core (adapter contract, versioned schema, keys/secrets model) and the `STACK.md` §21 gaps, starting with the observed-state importers.

## Note on inherited docs

`ops-directory-model.md` was written in another workspace. Its relative links to `../systems-and-workflows.md`, `../automation-path.md` and the codex discussion log don't resolve here. `STACK.md` covers the stack content those links pointed to.
