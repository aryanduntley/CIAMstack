# opsdir-adapter-ldap

The standard LDAPv3 base: the user directory's schema and tree as standard LDIF. Directory adapters (the DS lineage: PingDS, OpenDJ) build on it, and a generic adapter renders it for any compliant server.

Environment-neutral outputs, rendered from the directory domain's records:

| File | Holds |
|---|---|
| `ldap/schema.ldif` | The attribute types and object classes the record defines under `ou=user-schema` (RFC 4512 definitions in one modify of `cn=schema`). The standard ones (RFC 4519, 4524, 2798, ...) are left out: every compliant server has them. |
| `ldap/dit.ldif` | The naming contexts (the declared backends' base DNs) and every container the record refers to in them (ACI targets, subtrees consumers read, parents of bind DNs, provisioning bases), as `domain`, `organizationalUnit` or `organization` entries. No user data. |

The generic adapter `ldap` is **declaration-only**: every compliant server would match it, so it is never inferred from the data. An environment whose directory is a plain LDAP server names it in its stack (`ciamStackRole: directory`, `ciamAdapter: ldap`). Indexes, password policies, access control and replication are not standardized in LDAPv3; product adapters render them.

## The shape of the user data: `ldap/data-profile`

```bash
ldapsearch -H ldaps://ds.example.test -D "uid=reader,…" -W -b dc=example,dc=com -o ldif-wrap=no "(objectClass=*)" "*" "+" \
  | opsdir data-profile --env source/prod --term last-login=lastLoginTime > profile.json   # counts only; no database
opsdir import --dry-run ldap/data-profile profile.json            # one or more files, or a folder of them
opsdir import --change CHG-… ldap/data-profile profile.json
```

`opsdir data-profile` reads the LDIF once, as it streams (any LDIF: ldapsearch output with its `version`, `search` and `result` lines, or an export), and keeps counts only; nothing a value holds reaches the file, and the data never lands on disk. It needs no database, so it runs wherever the directory can be read. Ask for operational attributes (`"+"`) too: the password policy's times and flags are operational. What it counts, written to `ou=data-profile` as `ciamDataProfile` `cn=<cloud>-<env>`:

| Counted | How |
|---|---|
| Entries, per container and object class | `ou=branches`: one `ciamBranchProfile` per container (`ciamProfiledBranch`, a masked pattern rather than a reference, so renderers and the census never take it for an entry), the entries directly under it by class. Every RDN that isn't a container's (`ou`, `o`, `dc`, `c`, `l`, `st`) is masked (`uid=*,ou=people,…`), so an entry with entries under it never names itself |
| Each attribute | `ou=attributes`: one `ciamAttributeProfile` per attribute: entries holding it, the most values one entry holds, the largest value's size, linked to its `ou=user-schema` record when the record describes it |
| Password values by hashing scheme | `ciamHashSchemeCount` (`SSHA512=812000`), from the `{SCHEME}` prefix (`userPassword`) or `SCHEME$` (`authPassword`); only schemes the terms name are recorded by name, anything else is `unrecognized` (so a clear-text password starting with `{` never reaches the record); no prefix is `none` |
| Time since the last login and the last password change | `ciamLastLoginAge`, `ciamPasswordAge`: `<30d`, `30-90d`, `90-365d`, `1-2y`, `>2y`, `never`, `unreadable`, for accounts (entries with a password, or a login or password-change time) |
| Account states | locked (`pwdAccountLockedTime`), disabled, pending, holders of challenge questions, as the installed products' terms define them |
| Static groups | `groupOfNames` / `groupOfUniqueNames`: how many, how many empty, the largest, and member DNs that aren't among the entries read (profile the whole naming context, or members outside it count as dangling) |

What attributes mean is the data profile's `Terms`: the LDAP standards' (the password policy draft's `pwdLastSuccess`, `pwdChangedTime`, `pwdAccountLockedTime`; RFC 4519 groups; RFC 3112), plus each installed adapter's `profile_terms` (the DS lineage's last-login and disabled attributes: `opsdir-base-ds`), plus the estate's own, given with `--term NAME=ATTRIBUTE[=VALUE]` (repeatable; names: `last-login`, `password-changed`, `password`, `scheme`, `locked`, `disabled`, `pending`, `kba`, `member`, `group-class`, `operational`), for instance `--term last-login=lastLoginTime --term kba=challengeAnswer --term pending=registrationStatus=pending`. An unknown term is refused before anything is read. Operational attributes the server keeps for itself (`createTimestamp`, `entryUUID`, `pwd*`, the lineage's `ds-*`, ...) are read for these terms but not counted as user data. Memory holds one chunk of entries (10,000) and the DNs groups refer to.

The importer reads every `.json` file of the path, checks it again as the command wrote it (masked branches, scheme and attribute names, counts as numbers: a file edited by hand can't bring a value in), and replaces the environment's profile; an environment the record doesn't have, an older file for an environment a newer one describes, and other files are named and not imported. Reports: `data-profile`, `data-profile-attributes`. Planner (directory domain): password schemes no declared policy uses as its default (keep them enabled on the target, or rehash on login), values without a scheme, attributes with no `ou=user-schema` record (no PII class), dangling group members and challenge questions are actions; a source with directory servers and no profile is an action too.

For other directory adapters:

```python
from opsdir_adapter_ldap.adapter import render_standard   # {path: text} of the files above
from opsdir_adapter_ldap.schema import schema_ldif         # with another subschema DN if the product needs one
from opsdir_adapter_ldap.dit import dit_ldif, tree
```

Installing the package registers the adapter with opsdir (entry point `opsdir.adapters`: `ldap`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
