# CIAMstack

A database-first management system for identity (CIAM) platforms. Every piece of a platform's configuration, infrastructure, keys-as-references, dependencies and operational knowledge becomes **typed, governed, cross-referenced entries in one database**, the system of record the platform is operated from. Reports, user interfaces and every working file (infrastructure code, product configuration, setup scripts) are built on it instead of config files and consoles scattered everywhere.

- **A change is an entry,** made under an approved change record and kept in history, never a hand edit to a file or a console.
- **Questions become queries:** blast radius, expiry, drift, who can read what, which outside parties' allowlists hold our addresses.
- **Moving a platform is one capability:** a migration workspace declares the target's stack and bindings, the planner compares it with the live record, and the target is rendered from the same intent.
- **Sensitive data is never stored,** only referenced.

Nothing in the core is tied to a platform. Clouds, products, versions and secret stores are values in the database, handled by **adapter packages** that the core discovers when they are installed. Products build on **standard bases**: LDAP (the record itself is LDAP-modeled, so the standard LDAP schema lives in the core; a generic LDAPv3 adapter renders it for any compliant server), SAML 2.0 and OpenID Connect. The first packages cover the ForgeRock/Ping directory and federation stack (PingDS and OpenDJ on a shared DS-lineage base, PingFederate on the SAML and OIDC bases), AWS, Azure and the HashiCorp Vault, Kubernetes and CyberArk secret stores; more follow as packages, never as core changes.

The code is Modular, Functional and Procedural: immutable records, pure functions, and effects (database, files, printing) kept at the edges.

## Layout

```
opsdir/                   the core: an installable Python package on PostgreSQL (see opsdir/README.md)
  SPEC.md                 the standard: LDAP schema + X-PORTABILITY / X-VALUE-TYPE, rules R1–R10
packages/                 installable packages; adapters register themselves with the core, bases are libraries:
  standards               opsdir-adapter-ldap/ (standard LDIF + generic LDAPv3 adapter)
                          opsdir-base-saml/  opsdir-base-oidc/
  lineages, products      opsdir-base-ds/ (OpenDJ → ForgeRock DS → PingDS)  opsdir-adapter-pingds/
                          opsdir-adapter-opendj/  opsdir-adapter-pingfederate/  opsdir-adapter-pingam/
                          opsdir-adapter-pingidm/  opsdir-adapter-pinggateway/
  clouds, secret stores   opsdir-adapter-aws/  opsdir-adapter-azure/  opsdir-adapter-hashicorp-vault/
                          opsdir-adapter-kubernetes/  opsdir-adapter-cyberark/
  formats                 opsdir-format-terraform/ (shared HCL formatter)
examples/showcase/        a runnable fictional estate using those packages: data, demo, golden outputs
documentation/            project-level documentation
  STACK.md                the full stack inventory: every subsystem, file and store, what can be
                          datified, and what is covered today vs the gaps (build order in §21)
  ops-directory-model.md  design rationale: portable intent vs bindings, prior art, objections
pytest.ini                one test configuration for the core, the packages and the showcase
.aimfp-project/           AIMFP project tracking (blueprint, roadmap, tracked files and functions)
docs/                     local dev notes; git-ignored, never part of the project
```

## Quick start

Requirements: Python 3.11+ and PostgreSQL. Set up the role and databases once ([Database](opsdir/README.md#database)), then:

```bash
opsdir/scripts/dev-install.sh     # venv (opsdir/.venv) + the core + every package, editable
examples/showcase/demo.sh         # the whole story on the fictional estate; outputs in examples/showcase/out/
opsdir/opsdir.sh --help           # the CLI, against the local dev database
opsdir/scripts/test.sh            # every test: core, packages, showcase; unit + integration
```

Terraform is optional (`TERRAFORM=/path/to/terraform examples/showcase/demo.sh` adds `fmt` + `validate`).

## Where everything lives (and how to remove it)

| Thing | Path | Remove with |
|---|---|---|
| Python venv (`psycopg`, `packaging`, `pytest`, the packages) | `opsdir/.venv/` | `rm -rf opsdir/.venv` |
| Rendered output | `out/` wherever the CLI ran (the demo: `examples/showcase/out/`) | `rm -rf examples/showcase/out` |
| Python bytecode and build metadata | `__pycache__/`, `*.egg-info/` | `find . -name __pycache__ -o -name '*.egg-info' \| xargs rm -rf` |
| Dev and test databases | role `opsdir`; databases `opsdir`, `opsdir_workspace`, `opsdir_test`, `opsdir_test_workspace` in the local PostgreSQL | `for d in opsdir_test_workspace opsdir_test opsdir_workspace opsdir; do sudo -u postgres dropdb $d; done; sudo -u postgres dropuser opsdir` |

Deleting the `CIAMstack/` folder removes everything but the databases. Outside this folder, running `terraform` to validate rendered output leaves checkpoint files in `~/.terraform.d/`.

## Status

The foundation is in place: a Modular/Functional/Procedural core with versioned schema upgrades, governed writes and full history; an agnostic core that discovers domains and adapter packages; declared stacks with `opsdir check`; adapter-owned vocabulary validated by the store; change sets, migration workspaces with a three-way cutover, and a migration runner that works in either direction. The showcase passes its own checks (the planner finds all 7 planted blockers, and 5 remain after two approved changes) and its rendered Terraform passes `terraform validate`. **Not verified:** product configuration against real product instances; see [`examples/showcase/README.md`](examples/showcase/README.md).

Standard bases are in place: the standard LDAP schema in the core, the user directory's schema recorded (standard or defined in the record) and rendered as standard LDIF, the DS lineage shared by PingDS and OpenDJ, and SAML metadata, OIDC client registrations and discovery rendered from the federation domain. PingAM (ForgeRock AM) is an adapter package on these bases: realms are identity services, OAuth2 clients and SAML partners are standard integrations, journeys and policy sets are held in its own schema, and an Amster export is read into the record by its importer (`opsdir import`). PingIDM (ForgeRock IDM) is one too: managed objects, connectors, mappings and schedules as entries, each connector naming the role of the system it reaches and of its credentials so every environment renders its own, read from an IDM project directory by its importer. PingGateway (ForgeRock Identity Gateway) completes the lineage: its routes are entries linked to the integration whose client they sign users in as and the OpenID provider they trust, rendered per environment and read from a gateway configuration by its importer. The roadmap is tracked in AIMFP (`.aimfp-project/`). Next: importers that read the other live systems (PingDS, PingFederate, clouds) into the record, and the renderers of path 6.

## Note on inherited docs

`documentation/ops-directory-model.md` was written in another workspace and still carries some of that framing; its relative links to `../systems-and-workflows.md`, `../automation-path.md` and a discussion log don't resolve here. `documentation/STACK.md` covers the stack content those links pointed to. Both are rewritten in milestone 1.5.
