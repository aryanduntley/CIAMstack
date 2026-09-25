# CIAMstack

A program that **datifies** a CIAM platform: every piece of its configuration, infrastructure, dependencies and operational knowledge becomes typed, cross-referenced entries in one database. The working files are **generated** from that database: Terraform, `dsconfig` batches, DS setup scripts, ACI LDIF and PingFederate config.

- **A change is an entry,** made under an approved change record. It's never a hand edit to a file.
- **A migration is a read:** render the same database for a new environment. Only that environment's *bindings* are new.
- **Questions become queries:** blast radius, expiry, drift, who can read what, which outside parties' allowlists hold our addresses.

The first target is a **PingDS + PingFederate estate on AWS moving to another cloud landing zone**. Nothing in the model is tied to that product pair.

## Layout

```
README.md                 this file
STACK.md                  the full stack inventory: every subsystem, file and store, what can be
                          datified, and what opsdir covers today vs the gaps (build order in §21)
ops-directory-model.md    design rationale: portable intent vs bindings, prior art, objections
notes.txt                 working notes (demo summary, environment/cleanup notes)
opsdir/                   the reference implementation (Python + Postgres)
  SPEC.md                 the standard: LDAP schema + X-PORTABILITY / X-VALUE-TYPE, rules R1–R10
  README.md               how to run the demo, what's verified and what isn't
  schema/ sql/ data/ changes/ scripts/ opsdir/   (see opsdir/README.md)
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

Requirements: Python 3 and PostgreSQL server binaries (`/usr/lib/postgresql/*/bin`, used only to run a private cluster). Terraform is optional (`TERRAFORM=/path/to/terraform ./demo.sh` adds `fmt` + `validate`).

## Where everything lives (and how to remove it)

| Thing | Path | Remove with |
|---|---|---|
| Python venv (only `psycopg`) | `opsdir/.venv/` | `rm -rf opsdir/.venv` |
| Private Postgres cluster | `opsdir/.pgdata/`, socket in `opsdir/.pgsock/` (port 54329, unix socket only) | `opsdir/scripts/pg-local.sh destroy` |
| Rendered output | `opsdir/out/` | `rm -rf opsdir/out` |
| Python bytecode | `opsdir/opsdir/**/__pycache__/` | `find opsdir -name __pycache__ -exec rm -rf {} +` |

Deleting the `CIAMstack/` folder removes all of it. Stop the cluster first (`opsdir/scripts/pg-local.sh stop`) if it's running. Anything outside this folder is listed in `notes.txt`.

## Status

A working prototype on **synthetic data** (229 fictional entries, "Example Aero"). The demo passes its own checks: the planner finds all 7 planted blockers, and 5 remain after two approved changes. The rendered Terraform passes `terraform validate` against the real AWS and Azure provider schemas. **Not verified:** `dsconfig`/`setup` flags have not been run against a real PingDS, the PingFederate JSON is an illustrative subset of the Admin API, and the schema hasn't been loaded into a real LDAP server. See `opsdir/README.md` for the full table.

Next work is the gap list in `STACK.md` §21, starting with the observed-state importers (DS access logs, `cn=config`, the PingFederate Admin API) and a string census across config files.

## Note on inherited docs

`ops-directory-model.md` was written in another workspace. Its relative links to `../systems-and-workflows.md`, `../automation-path.md` and the codex discussion log don't resolve here. `STACK.md` covers the stack content those links pointed to.
