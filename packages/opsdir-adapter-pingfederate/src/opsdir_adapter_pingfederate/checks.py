"""PingFederate planner checks: every data store can reach its system from the target (a target role and a credential
role the target binds); a data store with a fixed host, and a directory reached without TLS, are actions."""
import json

from opsdir.core.directory import children, one, rdn_value, values
from opsdir.core.environment import one_role
from opsdir.core.findings import findings, merge_findings, responsible
from .datastores import store_hosts
from .naming import DATA_STORES


def _data_store(ctx, s):
    name, target, credential = rdn_value(s), one(s, "pingfedTargetRole"), one(s, "pingfedCredentialRole")
    kind, owner = one(s, "pingfedStoreType"), responsible(ctx.d, s, ctx.dst.env)
    config = json.loads(one(s, "pingfedConfig") or "{}")
    missing = [r for r in (target, credential) if r and one_role(ctx.dst, r) is None]
    blockers = (*((("PingFederate", f"Data store `{name}` has withheld credentials but no credential role: nothing says "
                    f"which secret {ctx.dst.label} gives it. Set pingfedCredentialRole.", owner),)
                  if values(s, "pingfedWithheld") and not credential else ()),
                *(("PingFederate", f"Data store `{name}` needs role `{r}`, which {ctx.dst.label} doesn't bind.", owner)
                  for r in missing))
    fixed = not target and store_hosts({"type": kind, **config})
    plain = kind == "LDAP" and config.get("useSsl") is False and not config.get("useStartTLS")
    actions = (*((("PingFederate", f"Data store `{name}` reaches a fixed host from every environment (no target role): "
                   f"confirm {ctx.dst.label} can reach it, or record the system's service name.", owner, None),)
                 if fixed else ()),
               *((("PingFederate", f"Data store `{name}` connects to the directory without TLS: turn on LDAPS or "
                   "StartTLS.", owner, None),) if plain else ()))
    return findings(blockers=blockers, actions=actions)


def check_data_stores(ctx):
    """Data stores the target can't give what they need are blockers; fixed hosts and plain LDAP are actions."""
    stores = children(ctx.d, DATA_STORES, "pingfedDataStore")
    if not stores:
        return findings()
    parts = merge_findings([_data_store(ctx, s) for s in stores])
    if parts.blockers or parts.actions:
        return parts
    return parts._replace(ok=(*parts.ok, f"PingFederate's {len(stores)} data store(s) reach their systems through "
                                         f"roles {ctx.dst.label} binds."))
