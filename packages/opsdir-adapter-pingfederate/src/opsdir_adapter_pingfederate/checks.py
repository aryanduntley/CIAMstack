"""PingFederate planner checks: every data store can reach its system from the target (a target role and a credential
role the target binds); a data store with a fixed host, and a directory reached without TLS, are actions. Every plugin
instance and authentication policy names only objects the record has, and every plugin instance's withheld secrets
come from a credential role the target binds."""
import json

from opsdir.core.directory import children, one, rdn_value, values
from opsdir.core.environment import one_role
from opsdir.core.findings import findings, merge_findings, responsible
from .datastores import store_hosts
from .naming import DATA_STORES, DEFAULT_POLICY, FRAGMENTS
from .objects import NOT_RECORDED, missing, why_unresolved
from .plugins import KINDS, plugin_refs
from .policies import fragment_refs, node_refs


def _config(e, attr="pingfedConfig"):
    return json.loads(one(e, attr) or "{}")


def _credentials(ctx, e, what, owner):
    """Blockers: withheld values nothing names a secret for, and roles the target doesn't bind."""
    credential = one(e, "pingfedCredentialRole")
    unbound = [r for r in (one(e, "pingfedTargetRole"), credential) if r and one_role(ctx.dst, r) is None]
    return (*((("PingFederate", f"{what} has withheld credentials but no credential role: nothing says which secret "
                f"{ctx.dst.label} gives it. Set pingfedCredentialRole.", owner),)
              if values(e, "pingfedWithheld") and not credential else ()),
            *(("PingFederate", f"{what} needs role `{r}`, which {ctx.dst.label} doesn't bind.", owner) for r in unbound))


def _data_store(ctx, s):
    name, target, kind = rdn_value(s), one(s, "pingfedTargetRole"), one(s, "pingfedStoreType")
    owner, config = responsible(ctx.d, s, ctx.dst.env), _config(s)
    fixed = not target and store_hosts({"type": kind, **config})
    plain = kind == "LDAP" and config.get("useSsl") is False and not config.get("useStartTLS")
    actions = (*((("PingFederate", f"Data store `{name}` reaches a fixed host from every environment (no target role): "
                   f"confirm {ctx.dst.label} can reach it, or record the system's service name.", owner, None),)
                 if fixed else ()),
               *((("PingFederate", f"Data store `{name}` connects to the directory without TLS: turn on LDAPS or "
                   "StartTLS.", owner, None),) if plain else ()))
    return findings(blockers=_credentials(ctx, s, f"Data store `{name}`", owner), actions=actions)


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


def _named(ctx, e, what, refs):
    owner = responsible(ctx.d, e, ctx.dst.env)
    return tuple(("PingFederate", f"{what} names {why_unresolved(ctx.d, k, i, NOT_RECORDED)}.", owner)
                 for k, i in missing(ctx.d, refs))


def _plugin(ctx, p):
    kind = one(p, "pingfedPluginKind")
    label = KINDS[kind].label
    what = f"{label[0].upper()}{label[1:]} `{rdn_value(p)}`"
    return findings(blockers=(*_named(ctx, p, what, plugin_refs(kind, _config(p))),
                              *_credentials(ctx, p, what, responsible(ctx.d, p, ctx.dst.env))))


def check_authentication(ctx):
    """Plugin instances and authentication policies that name what the record doesn't have, and plugin instances the
    target can't give their secrets, are blockers."""
    plugins = [p for k in KINDS.values() for p in children(ctx.d, k.base, "pingfedPlugin")]
    trees = children(ctx.d, DEFAULT_POLICY, "pingfedAuthPolicy")
    fragments = children(ctx.d, FRAGMENTS, "pingfedAuthPolicy")
    if not (plugins or trees or fragments):
        return findings()
    parts = merge_findings([
        *(_plugin(ctx, p) for p in plugins),
        *(findings(blockers=_named(ctx, t, f"Authentication policy `{rdn_value(t)}`",
                                   node_refs(_config(t, "pingfedPolicyTree")))) for t in trees),
        *(findings(blockers=_named(ctx, f, f"Policy fragment `{rdn_value(f)}`",
                                   fragment_refs({**_config(f), "rootNode": _config(f, "pingfedPolicyTree")})))
          for f in fragments)])
    if parts.blockers:
        return parts
    return parts._replace(ok=(*parts.ok, f"PingFederate's {len(plugins)} plugin instance(s) and {len(trees)} "
                                         f"authentication policy tree(s) name only what the record has."))
