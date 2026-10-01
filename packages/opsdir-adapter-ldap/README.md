# opsdir-adapter-ldap

The standard LDAPv3 base: the user directory's schema and tree as standard LDIF. Directory adapters (the DS lineage: PingDS, OpenDJ) build on it, and a generic adapter renders it for any compliant server.

Environment-neutral outputs, rendered from the directory domain's records:

| File | Holds |
|---|---|
| `ldap/schema.ldif` | The attribute types and object classes the record defines under `ou=user-schema` (RFC 4512 definitions in one modify of `cn=schema`). The standard ones (RFC 4519, 4524, 2798, ...) are left out: every compliant server has them. |
| `ldap/dit.ldif` | The naming contexts (the declared backends' base DNs) and every container the record refers to in them (ACI targets, subtrees consumers read, parents of bind DNs, provisioning bases), as `domain`, `organizationalUnit` or `organization` entries. No user data. |

The generic adapter `ldap` is **declaration-only**: every compliant server would match it, so it is never inferred from the data. An environment whose directory is a plain LDAP server names it in its stack (`ciamStackRole: directory`, `ciamAdapter: ldap`). Indexes, password policies, access control and replication are not standardized in LDAPv3; product adapters render them.

For other directory adapters:

```python
from opsdir_adapter_ldap.adapter import render_standard   # {path: text} of the files above
from opsdir_adapter_ldap.schema import schema_ldif         # with another subschema DN if the product needs one
from opsdir_adapter_ldap.dit import dit_ldif, tree
```

Installing the package registers the adapter with opsdir (entry point `opsdir.adapters`: `ldap`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
