# opsdir-adapter-ldap

The standard LDAPv3 base: the user directory's schema and tree as standard LDIF, a subschema LDIF read back onto the user schema, and the values-free data profile of any directory (its importer and its collector). Directory adapters (the DS lineage: PingDS, OpenDJ, through `opsdir-base-ds`) build on it, and its generic adapter `ldap` renders it for any compliant server.

**Applies to** environments that name it in their stack: the generic adapter is **declaration-only** (`applies` is `None`): every compliant server would match it, so it is never inferred from the data. An environment whose directory is a plain LDAP server names it (`ciamStackRole: directory`, `ciamAdapter: ldap`); declaring a `ldap/data-profile` collection source opts an environment into profiling. It defines no server roles and no product versions. Indexes, password policies, access control and replication are not standardized in LDAPv3; product adapters render them.

**Depends on** `opsdir` only. Collection runs OpenLDAP's `ldapsearch`. Installing the package registers the adapter with opsdir (entry point `opsdir.adapters`: `ldap`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

## What it renders

Environment-neutral only (`adapter.render_standard`), from the directory domain's records:

| From the record | Rendered as |
|---|---|
| The attribute types and object classes the record defines itself under `ou=user-schema` (those whose definition it supplies, with no problem; the standard ones every compliant server has, RFC 4519, 4524, 2798, ..., are left out) | `ldap/schema.ldif`: RFC 4512 definitions in one RFC 2849 modify of `cn=schema` (`add: attributeTypes`, `add: objectClasses`, superclasses first, `X-ORIGIN 'opsdir'`), as servers of the DS lineage and 389 Directory Server accept online. Only a comment when there is nothing to add |
| The declared backends' base DNs (`ou=backends,ou=declared`) and every container the record refers to in them (any `extdn` value: ACI targets, subtrees consumers read, parents of bind DNs, provisioning bases) | `ldap/dit.ldif`: the naming contexts, then the containers, parents first, as `domain` (`dc`), `organizationalUnit` (`ou`) or `organization` (`o`) entries; an RDN type with no standard container class gets a comment to create it by hand, and nothing below a non-container is written. No user data |

Apply `schema.ldif` with `ldapmodify` and `dit.ldif` with `ldapadd -c` (entries that exist are skipped). A server that keeps its schema elsewhere (under `cn=config`) has its own adapter: `schema_ldif(d, subschema_dn)` takes another subschema DN. A product whose servers ship some definitions themselves passes `keep` (`render_standard(d, keep)`, `schema_ldif(d, keep=...)`: which defined records the schema adds), as the DS lineage does for its vendors' arcs.

For other directory adapters:

```python
from opsdir_adapter_ldap.adapter import render_standard, FORMATS   # {path: text} of the files above; their format
from opsdir_adapter_ldap.schema import schema_ldif                 # with another subschema DN if the product needs one
from opsdir_adapter_ldap.dit import dit_ldif, tree
from opsdir_adapter_ldap.schema_import import SCHEMA_IMPORTER      # registered by the DS lineage's products
```

## What it reads back

### The schema: `ldap/schema`

`schema_import.py` reads every `.ldif` file given (its own `ldap/schema.ldif`, or a server's schema export: any record, added or modified, holding `attributeTypes` / `objectClasses` values) onto the user-schema records of the same LDAP names:

| Definition | Recorded on the user-schema record (match key: its LDAP name) |
|---|---|
| `attributeTypes` | `ciamUserAttribute`: OID, DESC (`ciamPurpose`), EQUALITY, SUBSTR, ORDERING, SYNTAX, SINGLE-VALUE |
| `objectClasses` | `ciamUserObjectClass`: OID, DESC, SUP, kind, MUST and MAY (as the attributes' records) |

What only the record says (PII class, retention, export control, owners) is kept; where the render writes a default for an unset value (`SUP top`, no `SINGLE-VALUE`) the record's absence (or `FALSE`) stays, so the render reads back unchanged. Named, not recorded: a definition that isn't RFC 4512, an attribute type or object class with no user-schema record (an attribute record needs its PII class, which no schema gives), and a MUST/MAY attribute with no record. The DS lineage registers it as `pingds/schema` and `opendj/schema`, so their renders read back (milestone 5.5). The generic adapter declares no `reads_back` of its own.

### The shape of the user data: `ldap/data-profile`

```bash
ldapsearch -H ldaps://ds.example.test -D "uid=reader,…" -W -b dc=example,dc=com -o ldif-wrap=no "(objectClass=*)" "*" "+" \
  | opsdir data-profile --env source/prod --term last-login=lastLoginTime > profile.json   # counts only; no database
opsdir import --dry-run ldap/data-profile profile.json            # one or more files, or a folder of them
opsdir import --change CHG-… ldap/data-profile profile.json
```

`opsdir data-profile` (the core's directory domain) reads the LDIF once, as it streams (any LDIF: ldapsearch output with its `version`, `search` and `result` lines, or an export), and keeps counts only; nothing a value holds reaches the file, and the data never lands on disk. It needs no database, so it runs wherever the directory can be read. Ask for operational attributes (`"+"`) too: the password policy's times and flags are operational. What it counts, written to `ou=data-profile` as `ciamDataProfile` `cn=<cloud>-<env>`:

| Counted | How |
|---|---|
| Entries, per container and object class | `ou=branches`: one `ciamBranchProfile` per container (`ciamProfiledBranch`, a masked pattern rather than a reference, so renderers and the census never take it for an entry), the entries directly under it by class. Every RDN that isn't a container's (`ou`, `o`, `dc`, `c`, `l`, `st`) is masked (`uid=*,ou=people,…`), so an entry with entries under it never names itself |
| Each attribute | `ou=attributes`: one `ciamAttributeProfile` per attribute: entries holding it, the most values one entry holds, the largest value's size, linked to its `ou=user-schema` record when the record describes it |
| Password values by hashing scheme | `ciamHashSchemeCount` (`SSHA512=812000`), from the `{SCHEME}` prefix (`userPassword`) or `SCHEME$` (`authPassword`); only schemes the terms name are recorded by name, anything else is `unrecognized` (so a clear-text password starting with `{` never reaches the record); no prefix is `none` |
| Time since the last login and the last password change | `ciamLastLoginAge`, `ciamPasswordAge`: `<30d`, `30-90d`, `90-365d`, `1-2y`, `>2y`, `never`, `unreadable`, for accounts (entries with a password, or a login or password-change time) |
| Account states | locked (`pwdAccountLockedTime`), disabled, pending, holders of challenge questions, as the installed products' terms define them |
| Static groups | `groupOfNames` / `groupOfUniqueNames`: how many, how many empty, the largest, and member DNs that aren't among the entries read (profile the whole naming context, or members outside it count as dangling) |

What attributes mean is the data profile's `Terms`: the LDAP standards' (the password policy draft's `pwdLastSuccess`, `pwdChangedTime`, `pwdAccountLockedTime`; RFC 4519 groups; RFC 3112), plus each installed adapter's `profile_terms` (the DS lineage's last-login and disabled attributes: `opsdir-base-ds`), plus the estate's own, given with `--term NAME=ATTRIBUTE[=VALUE]` (repeatable; names: `last-login`, `password-changed`, `password`, `scheme`, `locked`, `disabled`, `pending`, `kba`, `member`, `group-class`, `operational`), for instance `--term last-login=lastLoginTime --term kba=challengeAnswer --term pending=registrationStatus=pending`. An unknown term is refused before anything is read. Operational attributes the server keeps for itself (`createTimestamp`, `entryUUID`, `pwd*`, the lineage's `ds-*`, ...) are read for these terms but not counted as user data. Memory holds one chunk of entries (10,000) and the DNs groups refer to.

The importer (`profile.py`) reads every `.json` file of the path, checks it again as the command wrote it (masked branches, scheme and attribute names, counts as numbers: a file edited by hand can't bring a value in), and replaces the environment's profile (one per environment; the newest file wins). Named and not imported: a file that isn't a profile, an environment the record doesn't have, an older file for an environment a newer one describes, and files that aren't `.json`. Reports: `data-profile`, `data-profile-attributes`. Planner (directory domain): password schemes no declared policy uses as its default (keep them enabled on the target, or rehash on login), values without a scheme, attributes with no `ou=user-schema` record (no PII class), dangling group members and challenge questions are actions; a source with directory servers and no profile is an action too.

### Collecting the profile (`opsdir collect`)

`opsdir collect --env CLOUD/ENV --ldap-ca CA.pem` runs the search above itself and profiles it as it streams (`collect.py`, collector `data-profile`, which declares the `--ldap-ca` option: `LDAP_CA`): nothing a value holds is held whole, written or kept, and the export is the profile's counts only (`data-profile-<env>.json`, dated when collecting). The environment declares the directory to read (a replica, preferably):

```ldif
dn: cn=profile,ou=bindings,env=prod,cloud=source,ou=environments,dc=ciam-ops
objectClass: ciamCollectionSource
ciamBindingRole: collect-data-profile
ciamImporter: ldap/data-profile
ciamSourceRef: ldaps://ds-replica.example.test:1636/ou=people,dc=example,dc=test
ciamLoginName: uid=profiler,ou=admins,dc=example,dc=test
ciamCredentialRole: profiler-password      # a binding whose ciamRefUri references the password
```

It runs OpenLDAP's `ldapsearch -x -y /dev/stdin` (simple bind, the password only on its standard input) against the first readable source, paged (`-E pr=1000/noprompt`), unwrapped, all user and operational attributes; the CA certificate the server is checked against is the operator's PEM file (`--ldap-ca`, as `LDAPTLS_CACERT`), never stored. The port defaults to 636. Named: a source without a bind DN, a credential, or a base DN in its `ldaps://<host>:<port>/<base DN>` URL. Least privilege: an account with read, search and compare on the user branch, targetattr `*||+`, nothing else.

## Schema, vocabulary and secret patterns

None of its own: the user schema, the declared configuration and the data profile are the core directory domain's. It owns no vocabulary, reference schemes or secret patterns. Format: `ldap/*.ldif` (LDIF).

## Roles, server roles and planner checks

No required roles, server roles, planner checks or version changes of its own; the data profile's planner findings are the directory domain's (above).

## Known limits

- **Schema in `cn=schema`** only: a server keeping its schema under `cn=config` needs its own adapter (or another subschema DN).
- **The tree holds containers only** (`dc`, `ou`, `o`); other RDN types are named for a person to create.
- **Not run against a live directory** beyond what the DS lineage's tests and the showcase exercise (milestone 7.2).
- **The data profile's terms** cover the standards and the installed adapters; an estate's own attributes need `--term`.

## Tests

`tests/test_ldap.py`: registered and declaration-only, rendered only where a stack names it, the schema adding only what the record defines (superclasses first), parsing back as one modify, nothing to add without definitions, the tree as the naming context and the containers the record refers to, the tree file as standard entries. `tests/test_ldap_schema_import.py`: the rendered schema reading back unchanged, an edited definition saying what changed and keeping what only the record says, definitions with no record named. `tests/test_ldap_profile.py`: a profile file becoming the environment's data profile, the latest file per environment winning, what can't be recorded named. `tests/test_ldap_collect.py`: the search streaming through the profiler, a source without a base DN.

```bash
opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-ldap/tests
```
