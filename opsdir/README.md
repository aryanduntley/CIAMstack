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
./opsdir.sh import [--change CHG-…] ADAPTER[/IMPORTER] PATH [--dry-run] [--at TIME] [--take K|all] [--keep K|all]
                                      # read a product's export into the record (conflicts decided: below)
./opsdir.sh collect [--env CLOUD/ENV] [--adapter A[/I]] [--list] [--dry-run] [--change CHG-…] [--save DIR]
                                      # read the live system for the importers, read-only (below), then import
./opsdir.sh capture --change CHG-… FILE       # hold a config file in the record (settings, whole, or a reference)
./opsdir.sh file NAME [--env CLOUD/ENV]       # rebuild a captured file from the record
./opsdir.sh census --change CHG-… PATH        # where the record's values occur in files (secrets flagged, not stored);
                                              # --replace: PATH is the whole census
./opsdir.sh setting NAME VALUE [--change CHG-…] [--dry-run]   # an estate setting's value (opsdir report settings)
./opsdir.sh search -b BASE 'FILTER' [ATTR...] # RFC 4515 search, as LDIF or a table of attributes
./opsdir.sh report NAME [DN]          # portability, unowned, blast-radius DN, settings, and every domain's reports (consumers,
                                      # keys ENV, drift, ...); dates as of --as-of
./opsdir.sh render CLOUD/ENV [-o DIR] [--target ADAPTER=T[,T]]  # everything the environment's adapters render, plus MANIFEST.json
./opsdir.sh plan SRC DST [-o DIR]     # what blocks moving SRC to DST, dated actions, request drafts
./opsdir.sh migrate SRC DST [-o DIR]  # check both stacks, plan, render the target; exit 1 unless ready
./opsdir.sh export [-b BASE]          # entries as LDIF (for review)
./opsdir.sh history [DN]              # governed changes
./opsdir.sh workspace create|status|diff|cutover     # migration workspaces (below)
./opsdir.sh --workspace COMMAND …     # any command against the workspace instead of the live record
```

An adapter may offer several render targets (`Adapter.render_targets`): PingFederate renders its configuration as
Admin API requests (`admin-api`) and as Terraform for Ping's provider (`terraform`). `--target pingfederate=terraform`
renders one; every target is rendered by default except those an adapter offers only when asked (PingFederate's
`terraform-imports`, import blocks adopting an existing PingFederate's objects), and MANIFEST.json records the targets chosen. An adapter or
target the environment doesn't have is refused, naming those it has. Plans and migrations render every target.


## Collecting from the live system

`opsdir collect` reads the live system for the installed adapters' importers instead of you gathering their exports,
read-only, and imports the result exactly as `opsdir import` would (preview, conflicts to take or keep, applied only
under an approved change). Each adapter declares collectors (`core.contract.Collector`): the exact calls that produce
its importers' files, in rounds (a list, then each item's details), and a check that your provider login is the
account, subscription or project the record names (nothing is read when it isn't).

- Credentials are never stored. Clouds use your own CLI login. What needs more (a product's admin API, a directory, a
  Terraform state object) is declared per environment as a collection source (`ciamCollectionSource`: the importer,
  the URL or object, the role of the binding holding the credential's reference, the login name, the role of the CA
  certificate its endpoint is trusted by): the reference is resolved through its secret store when collecting, held
  in memory for the run, and reaches a tool only on its standard input or opsdir's own HTTP GET (`live.py`); a failing
  call's error output is shown with resolved values masked. Calls carrying provider debug switches are never run.
- A collection is complete or not imported: an import makes the record's subtrees exactly what the export holds, so a
  failed call (or a collector asking for more than 8 rounds or 2000 calls, or saying why it must stop) leaves the record as it is and says why.
- An applied collection records how it was collected on its import run (its `ciamImportRun` entry): the identity the
  provider saw, each call (command or URL, never a credential) with the SHA-256 of what it returned, and the
  credential references resolved. `--save DIR` also keeps the raw export and its manifest: it may hold sensitive
  configuration, keep it on encrypted storage.
- Every collection run under a change records its **attempt**, whatever the outcome (its `ciamCollectionAttempt`
  entry under `ou=imports`, one per importer and environment, replaced by the next attempt; history keeps the earlier
  ones): complete, incomplete (a call failed or was refused: nothing imported) or skipped (the identity check failed
  or the collector couldn't start), when it ran, the change, the identity seen, the calls made (each with the hash of
  what it returned, `absent` or `failed`) and the problems, credentials masked. A failed collection is never
  imported, but it is not forgotten: `opsdir report collections` lists the last attempt of each. A dry run or a run
  without `--change` records nothing (it says how many failed collections went unrecorded).
- Without `--env`, `collect` reads provider-wide data (region lists, quota limits): the same calls `import --run` makes.
- `--list` shows the calls each collector starts with and runs nothing.

### Configuration sources: Git, Kubernetes, SSH

Any importer's collection can also read configuration kept in a Git repository, a Kubernetes ConfigMap or files on a
host (PingGateway routes, PingFederate node files, DS configuration directories, crontabs, CI repositories): a
collection source for that importer whose `ciamSourceRef` names it. Each kind is read only once its estate setting
allows it; all three are off until an approved change turns them on (`opsdir setting collect-from-ssh TRUE --change
CHG-…`), and a declared source of a kind that's off makes the collection say which setting would allow it.

| `ciamSourceRef` | What runs | Becomes |
|---|---|---|
| `git+https://host/org/repo.git?ref=main&dir=gateway&prefix=routes/` (or `git+ssh://git@host/...`) | `git clone --depth 1 --single-branch [--branch REF]` into a private work directory | the files under `dir` (else all) placed under `prefix`; `.git` is never read |
| `k8s://CONTEXT/NAMESPACE/configmap/NAME?prefix=routes/` | `kubectl --context CONTEXT -n NAMESPACE get configmap NAME -o json` | each data key a file under `prefix` (Secrets are never read) |
| `k8s://CONTEXT/NAMESPACE/workloads?prefix=` | `kubectl --context CONTEXT -n NAMESPACE get statefulsets,deployments,daemonsets,cronjobs,services,ingresses,networkpolicies,serviceaccounts -o json` and `kubectl --context CONTEXT get namespace NAMESPACE -o json` | manifests (`kubernetes/workloads`): `CONTEXT/NAMESPACE/objects.json` and `namespace.json` under `prefix`; Secrets are never listed, and literal env values, `managedFields` and the last-applied annotation are dropped before anything is hashed, saved or imported |
| `ssh://user@host[:port]/BASE?dir=config&match=*.json` | `ssh -o BatchMode=yes -o StrictHostKeyChecking=yes` running `find BASE/dir -type f [-name MATCH]`, then `cat --` each (`zcat --` for `.gz`, saved without `.gz`) | each file under `prefix` (default `host/`), `dir` kept in its path |
| `ssh://user@host/BASE?files=bin/run.properties,data/x.xml` | `cat --` each listed file | the same |

What they read is your own access: your Git credentials, kubectl context, SSH agent and known hosts; nothing is held.
An unknown or changed host key fails (add the host to `known_hosts` first). SSH runs only those fixed commands, on paths
that must look like paths (letters, digits, `_./@+=,:-`, no `..`) and are quoted, and hosts, users and object names
can't pose as options. A file kept that isn't regular UTF-8 text (a link, a binary) fails the collection.

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
- Every `upgrade` also syncs the **schema registry** from the registered schema fragments (the core's, the domains' and each installed adapter's), the **reference schemes** the installed adapters own, and the **vocabulary** (below). A definition no installed part defines any more (an uninstalled adapter's) is removed; the upgrade is refused while entries still use it. Everything runs in one transaction, one upgrade at a time.

## Stacks and vocabulary

Each environment declares its **stack** under `ou=stack`: one `ciamStackComponent` per role, naming the adapter that fills it (as its package registers it), the adapter versions it accepts (a PEP 440 range) and where to get it. When an environment declares a stack, exactly those adapters render it, and rendering refuses a declared adapter that isn't installed; without one, adapters are chosen from the data (each adapter's `applies`). `opsdir check` reports, per component: not installed (and where to get it), a version outside the range, installed but not matching the environment's data, or an adapter that applies to the data but isn't declared.

Some attributes take values no core schema can list: the cloud provider, its partition, server and target roles. Their value type is `vocab`: each installed domain or adapter declares the values it defines, `upgrade` syncs them, and the store rejects any other value. Uninstalling an adapter whose values entries still use is refused at `upgrade`.

## Custom fields and record types

The record can't foresee every fact, so operators add their own as governed entries under `ou=custom-schema`: a `ciamFieldDefinition` (a field any listed record type may carry) or a `ciamRecordTypeDefinition` (a new kind of record). Names start with `x`. The metadata covers what it is and why (description, purpose, owner, sensitivity, status, documentation and runbook links), its values (type, one or many, unit, example, default, min/max, pattern, max length), which records carry it, where the value lives in real systems and which adapters use it, and its portability in a migration (and whether an environment may override it).

```bash
./opsdir.sh modify --change CHG-… define-and-use.ldif   # one change can define a field and set it on entries
./opsdir.sh report custom                               # every custom field and record type, and how many entries use it
```

The store composes the definitions into its schema in the same transaction (and on every `upgrade`), enforces the value rules on every write, and refuses a change that would leave stored entries invalid or delete a definition entries still use.

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

## Imports and conflicts

An importer reads a product's export or a cloud's inventory and turns it into change records (`--dry-run` lists them and applies nothing: that is how drift is read). Adding what the record lacks, such as an entry, an attribute, a value or an object class, just goes in. An import that would replace or remove something the record holds means the live system and the record disagree. Neither side is assumed to be right. Each such disagreement is a **conflict**, listed with a key, the record's value and the live value:

```
conflict cn=key-disk,ou=bindings,env=prod,cloud=source,…|ciamAutoRotate: record TRUE -> live FALSE
```

An applied import is refused until every conflict is decided. `--take KEY` lets the live value in. `--keep KEY` keeps the record's: that change is left out, so the record still renders its own value and the next import shows the conflict again. Either flag also takes `all`.

Every applied import also records an **import run** for each scope it read, under `ou=imports`: the importer, the scope, when the export was taken (`--at`, default now) and the change. There is one entry per importer and scope, replaced by the next run; history keeps the earlier ones. A dry run records nothing. `opsdir report imports` lists when each part of the record was last read back. Fixes that must not act on a stale picture of the live system check these runs.

## Assisted fixes

When a planner check knows the exact record change that resolves a finding, the finding offers it as a fix: the LDIF change records, the steps outside the record that go with it (a deploy, a live change, a party's confirmation) and what applying it could hide. `PLAN.md` lists the fixes offered; nothing is applied without a change.

```bash
opsdir fix list FROM TO                          # the fixes the plan offers
opsdir fix show FROM TO KEY                      # one fix: change records, manual steps, risks
opsdir fix propose FROM TO KEY --change CHG-… [--option O] [--input K=V …]   # record it as a proposed change, for a person to approve
opsdir fix apply FROM TO KEY --change CHG-… [--option O] [--input K=V …]     # apply it under an approved change
opsdir fix approved --change CHG-…               # once a proposed change is approved: apply its records, mark it applied
```

The fixes offered so far, each the exact record change for its finding:

| Finding | Fix |
|---|---|
| A service name changes between the environments (R9) | the target binds the stable name (and its zone) |
| Server roles can't reach each other's ports in the target (ports matrix) | exactly the uncovered ranges, on the matching firewall rule or a new one |
| A product isn't told about the target's explicit egress proxy | the captured file's settings, linked to the proxy binding's derived values |
| The target's directory servers don't join the source's replication | `ciamJoinsDeploymentOf` on the target environment |
| Private DNS, endpoint-service principals (same provider), flow-log or log-route retention, metadata tokens, compute group size weaker in the target | the source's (or the obligation's) value on the target binding |
| A firewall rule opens ports nothing listens on | the stray ports dropped (the rule deleted when all are) |
| An endpoint service anyone may connect to unaccepted | acceptance required |
| A private endpoint reaches a role its environment doesn't bind | that role dropped from it |

Some fixes are a choice, and offer options instead of one change (`fix show` lists them; `propose` and `apply` need `--option`): the secret role a withheld credential comes from (PingFederate data stores, plugins, resources and nodes; PingIDM connectors: one option per secret role the target binds, those whose name matches the object's first, never picked for anyone), which entry keeps a PingFederate id several claim, and an override that makes the environments differ (run the source's value, or the shared one; only the target's own overrides are changed, an inherited one gets a target override instead).

Some fixes take inputs: values only the operator knows, such as a provider reference, a DNS name or a bucket. `fix show` shows each input in the records as `<key>` and lists it with an example (the source's value, where there is one), any default, and the pattern its values must match. `propose` and `apply` refuse until every input without a default is given with `--input KEY=VALUE`. Repeat a key to give it several values; `KEY=` leaves the attribute out. An input is a reference or a name, never a secret, and the proposal holds the records with the values filled in.

| Finding | Fix (inputs) |
|---|---|
| A role the source binds isn't bound in the target | the source's bindings of the role copied under the target's bindings. Intent and meta values are copied. Binding and secret-reference values, and DNs inside the source environment, are inputs (the source's value as the example, never as a default: copied, it would point at the source's resources). Contract values, and references to something outside the environment (a consumer), default to the source's. Dates and observed facts are left out. With several bindings of the role, each input's key starts with the binding's name (`backup-a.ciamStorageRef`). |
| A product reaches a fixed host from every environment (a PingFederate data store with one host, a PingIDM connector's `host`, a PingGateway route's base URI) | the host recorded as the source's `ciamExternalHost` (a system the platform reaches but doesn't run) of a role the operator gives (`role`, never guessed; the port too for a route). Importing the product again names the role instead of the host, and the target then gets the core's binding fix for the role |
| PingFederate's cluster discovery isn't recorded, uses a protocol the adapter doesn't render, or lacks what its protocol needs | the `pf-cluster-discovery` binding: an option per rendered protocol (the source's: the one its nodes run, when they all agree). NATIVE_S3_PING takes the bucket (`ciamStorageRef`, `s3://…`) and DNS_PING the DNS name (`ciamFqdn`); TCPPING takes nothing. A binding of another class (an object store) is replaced by a `pingfedClusterDiscovery` binding of the same name. |

Some fixes wait for something to happen first, and `fix show` lists it under "First". Pinning firewall priorities is one: rules a provider orders by number (Azure network security groups, Google Cloud firewall rules and policy rules) render a free slot when they have no pinned `ciamRulePriority`. A slot free in the record may already be held by a live rule the record lacks. So the planner's action for unpinned rules offers a fix (`priorities:<environment>`) that pins the slots the render assigns, but `propose` and `apply` refuse it until an import run covers those rules from an export taken after their last change. Changes under `BOOTSTRAP` don't count, and neither do changes made by that import itself. The refusal says what to import.

Some fixes change the record ahead of the live system. The record then says something the live system doesn't do yet, so such a fix also marks the value as awaiting verification (`ciamVerifyPending`: the attribute, and the adapter whose import confirms it). The check that offered the fix keeps reporting the value until an import by that adapter covers the entry. If the live value matches, the import clears the mark. If it differs, that's a conflict: taking the live value clears the mark, and keeping the record's leaves it. The first such fix lowers a changing name's TTL in the source to 60 s (`ttl:<name>`).

Proposing writes only the change record (status `proposed`, its records in `ciamChangeRecords`), which is what an AI may do through the operations layer; the store refuses the records themselves under a change nobody approved. With `--workspace` the fixes are the workspace's and reach the live record at cutover. Fixes never carry secret values, never edit observed facts or attestations (grants read from a cloud, test results, review dates), and a fix to a captured file links its settings to bindings (`ciamValueFrom`), since the file is shared by every environment with the role.

## Architecture

```
opsdir/                      the package (names no platform, product, vendor or secret store)
  core/                      technology-neutral records and pure functions: directory snapshot and lookups, RFC 4515
                             search, environment model (bindings by role, declared stack), contracts (Domain,
                             Adapter, Report, Services, PlanContext), the standard (value types, OID arc, schema
                             fragments), the standard LDAP schema (ldap_schema: RFC 4519/4524/2798/... definitions,
                             the one source for both opsdir's schema and the user directories it manages),
                             findings, manifest, change sets, interchange (LDIF, RFC 4512, export)
  store/                     PostgreSQL: postgres.py (connect, load, governed changes, snapshot read), migrations.py
                             (init, upgrade), workspace.py (workspace base), queries.py, sql/migrations, sql/definitions
  domains/                   vendor-neutral parts of the stack, each with naming, schema fragment, checks, reports and
    infrastructure/          SQL views: clouds, environments, servers, bindings, stacks, external allowlists
    directory/               the LDAP user directory: its schema (attributes and object classes, standard or
                             defined in the record), declared/observed configuration and drift, consumers, ACIs
    federation/              SAML/OIDC integrations and claim maps, the platform's own identity services, and the
                             protocols' standard vocabulary (grant types, auth methods, bindings, NameID formats)
    pki/                     certificates and their expiry
    governance/              owners (including the operator), changes, incidents, runbooks
    configuration/           config files held setting by setting, bundles, the string census
    automation/              jobs: cron, timers, scheduled tasks, functions, pipelines (what runs, when, where, owner)
    compute/                 host baselines per server role, compute groups and clusters per environment, workloads
                             (server roles run as containers)
    messaging/               external services (mail relays, SMS, MFA vendors, CAPTCHA), mail senders and sending
                             identities, identity event streams
    custom/                  fields and record types operators define as entries, composed into the store's schema
  connectors/                the only code that joins parts: registry (discovers domains and adapters through entry
                             points), schema (the store's schema: code fragments + the record's custom definitions),
                             stack (declared stacks vs installed adapters), render, plan (migration planner),
                             migration (runner), workspace (copy, diff, cutover), reports, collecting (live
                             read-only collection: rounds, completeness, evidence), sql (cross-domain views)
  live.py                    the effects of collecting: provider commands and HTTP GETs, credentials resolved in memory
  cli.py                     thin orchestrator
schema/ciam-ops.schema.ldif  the published RFC 4512 schema of the core and its domains (scripts/gen-schema.py)
scripts/                     dev-install.sh, dev-env.sh (local defaults), gen-schema.py, test.sh, fetch-tools.sh,
                             validate-terraform.sh
tests/                       core tests: unit (no database) and integration; mini_estate.py = a two-environment
                             estate and a fake provider adapter, so the core is tested without any real adapter
```

Dependencies point one way. Adapter packages depend on the core, never the reverse; the registry discovers them. Inside the core, `connectors → domains → core` and `connectors → store → core`; domains depend on `core` only (their reports are data: SQL text or a pure function of the snapshot). The code is Modular, Functional and Procedural: immutable records, pure functions, effects (database, files, printing) at the edges.

## Writing an adapter package

An adapter is one cloud provider, product or secret store. It lives in its own installable package:

1. A module that defines `ADAPTER = Adapter(...)` (`opsdir.core.contract`): its name and kind (`provider`, `product` or `secret-store`), `applies(m)` decided from directory data only (or `None` for a generic adapter of a standard, which every compliant server would match: it renders only where an environment's stack declares it), the roles it requires, its renderers (environment-neutral and environment-specific), its planner checks, the reference schemes it owns and their resolvers, how its outputs are described, and the `vocab` values it defines.
2. Its `pyproject.toml` depends on `opsdir` and registers it:

   ```toml
   [project.entry-points."opsdir.adapters"]
   example = "opsdir_adapter_example.adapter:ADAPTER"
   ```
3. Tests in the package's `tests/` (the repository-root `pytest.ini` collects them).
4. The format of every file it renders, `formats=(("ds/*.ldif", "ldif"), ...)`, and the product versions it supports, `products=(("SomeProduct", ">=7,<9"),)`. A format the core doesn't register (a product's own syntax, HCL, ...) is registered by the package that brings it, as a `Format` (`opsdir.core.contract`) under `[project.entry-points."opsdir.formats"]`.
5. Optionally, schema definitions of its own: `schema=fragment(attributes, classes, arc, origin)` (`opsdir.core.standard`), numbered under an OID arc the package owns, so packages written independently never collide. The store composes them on `upgrade`; the core's published schema file holds only the core and its domains.
6. Shared helpers instead of its own copies. Before writing a helper, look for it in the core:

   | Need | Use |
   |---|---|
   | Parse an imported file without raising (a file that isn't the format is named, not an error) | `opsdir.core.sources`: `json_document(text, kind)`, `parsed(loader, text, errors, kind)` for any other parser (a YAML loader: the core depends on none) |
   | An import's files by folder (one per server, repository, project) | `opsdir.core.sources`: `by_folder(files)`, `folders(files, roots)`, `under(files, root)` |
   | A container entry, a DN's RDN value, a DN at or below a base | `opsdir.core.directory`: `ou_entry(dn)`, `rdn_of(dn)`, `within(dn, base)` |
   | Times as the record holds them (GeneralizedTime, UTC) | `opsdir.core.directory`: `gtime(datetime)`, `gtime_of_iso(text)` |
   | JSON written as files, JSON an attribute holds, values that may be secret | `opsdir.core.jsondata`: `indented`, `canonical`, `held_json(entry, attr)`, `without_secrets`, `with_values`, `rendered_in_place` |
   | Entries an importer re-imports (owned attributes replaced, the rest kept) | `opsdir.core.directory`: `merged_attrs(existing, owned, names)` |
   | A product's config file kept as captured settings | `opsdir.domains.configuration.record`: `captured_file(fmt, prefix, folder, path, text, patterns, role)` |
   | Cloud inventory: resources, role tags, role map, layout | `opsdir.core.inventory`: `resource`, `tagged_role(tags)`, `of_types(found, *types)`, `layout_import`, `per_file` |
   | CI pipelines as jobs | `opsdir.domains.automation.pipelines`: `FoundPipeline`, `pipeline_groups`, `environment_name` |

   Anything two packages would write alike belongs in the core (or an `opsdir-base-*` library), public and tested. Module-level tables are read-only (`MappingProxyType`, tuples, `frozenset`).

Installing the package is all it takes: nothing in the core changes. Products build on the standard bases rather than repeat them: a directory adapter renders the standard LDAP files (`opsdir-adapter-ldap`) and a DS-lineage product the lineage's files (`opsdir-base-ds`); a federation adapter renders SAML metadata and OIDC documents at its own endpoint paths (`opsdir-base-saml`, `opsdir-base-oidc`) and maps the standard vocabulary to its API's names. Packages that register an adapter are named `opsdir-adapter-*`, libraries `opsdir-base-*`, formatters `opsdir-format-*`. A new vendor-neutral part of the stack is added the same way as a `Domain` (schema fragment with new, never-reused OID numbers, SQL views, checks, reports, vocabulary, an `order`), registered under `[project.entry-points."opsdir.domains"]`.

## Tests

From the repository root (one `pytest.ini` collects the core, every package and the showcase):

```bash
opsdir/scripts/test.sh                                   # everything: unit + integration, databases required
opsdir/.venv/bin/python -m pytest                        # unit tests only, no database
opsdir/.venv/bin/python -m pytest -m integration         # integration tests only (skipped if unreachable)
opsdir/.venv/bin/python -m pytest opsdir/tests           # the core alone
opsdir/scripts/fetch-tools.sh                            # once: Terraform into tools/ (gitignored), verified
opsdir/.venv/bin/python -m pytest -m terraform           # rendered Terraform checked by terraform fmt + validate
opsdir/scripts/validate-terraform.sh [tree ...]          # the same on any render output (default: the golden renders)
```

Third-party tools the tests run on rendered output live in `tools/` at the repository root: one gitignored folder per machine, fetched by `scripts/fetch-tools.sh` (Terraform's zip checked against HashiCorp's signed checksums) and removed by deleting it. The `terraform` tests check every Terraform root of the showcase's golden renders and a sample with every kind of network plumbing on each cloud (`examples/showcase/tests/terraform/`); they are skipped when `tools/bin/terraform` is absent and run by `scripts/test.sh` when it is there (the first run downloads the providers into `tools/`).

The core's tests use a mini estate and a fake adapter, and pass with no adapter package installed. The integration tests create, upgrade and refuse schemas against Postgres (they drop and rebuild the `opsdir` schema in the test databases). End-to-end behaviour with real adapters and golden outputs is tested by the showcase.
