"""PingFederate planner checks: every data store can reach its system from the target (a target role and a credential
role the target binds); a data store with a fixed host, and a directory reached without TLS, are actions. Every plugin
instance, authentication policy and OIDC policy names only objects the record has, and every plugin instance's
withheld secrets come from a credential role the target binds."""
import json

from opsdir.core.directory import children, one, rdn_value, values
from opsdir.core.environment import one_role
from opsdir.core.findings import findings, merge_findings, responsible
from .datastores import store_hosts
from .generic import held_resources, resource_label
from .naming import DATA_STORES, DEFAULT_POLICY, DISCOVERY_ROLE, FRAGMENTS, OIDC_POLICIES
from .nodes import binding_kind, clustered
from .oauth import oidc_policy_refs
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


def check_references(ctx):
    """Plugin instances, authentication policies and OIDC policies that name what the record doesn't have, and plugin
    instances and resources held as is that the target can't give their secrets, are blockers."""
    plugins = [p for k in KINDS.values() for p in children(ctx.d, k.base, "pingfedPlugin")]
    trees = children(ctx.d, DEFAULT_POLICY, "pingfedAuthPolicy")
    fragments = children(ctx.d, FRAGMENTS, "pingfedAuthPolicy")
    oidc = children(ctx.d, OIDC_POLICIES, "pingfedOidcPolicy")
    held = held_resources(ctx.d)
    if not (plugins or trees or fragments or oidc or held):
        return findings()
    parts = merge_findings([
        *(_plugin(ctx, p) for p in plugins),
        *(findings(blockers=_named(ctx, t, f"Authentication policy `{rdn_value(t)}`",
                                   node_refs(_config(t, "pingfedPolicyTree")))) for t in trees),
        *(findings(blockers=_named(ctx, f, f"Policy fragment `{rdn_value(f)}`",
                                   fragment_refs({**_config(f), "rootNode": _config(f, "pingfedPolicyTree")})))
          for f in fragments),
        *(findings(blockers=_named(ctx, o, f"OIDC policy `{rdn_value(o)}`", oidc_policy_refs(_config(o))))
          for o in oidc),
        *(findings(blockers=_credentials(ctx, r, resource_label(r), responsible(ctx.d, r, ctx.dst.env))) for r in held)])
    if parts.blockers:
        return parts
    return parts._replace(ok=(*parts.ok, f"PingFederate's {len(plugins)} plugin instance(s), {len(trees)} authentication "
                                         f"policy tree(s) and {len(oidc)} OIDC policy(-ies) name only what the record "
                                         "has."))


def _where(b):
    return one(b, "ciamStorageRef") or one(b, "ciamFqdn")


def _discovery(ctx, nodes, src, dst, owner):
    src_kind, dst_kind = (binding_kind(b) if b is not None else None for b in (src, dst))
    put = "put pingfederate/cluster/discovery.xml in place of the discovery protocol in each node's tcp.xml"
    if dst is None and src is not None:
        return findings()          # a role the source binds and the target doesn't: the core's binding check says so
    if dst is None:
        return findings(blockers=[("PingFederate", f"PingFederate's cluster ({len(nodes)} clustered node(s) in "
                                   f"{ctx.src.label}) has no recorded discovery, so nothing says where its members "
                                   f"find each other in {ctx.dst.label}: bind role `{DISCOVERY_ROLE}` in both (s3://"
                                   "bucket, azblob://account/container or a DNS service name).", owner)])
    if dst_kind is None:
        return findings(blockers=[("PingFederate", f"{ctx.dst.label} binds `{DISCOVERY_ROLE}` to neither storage nor a "
                                   "service name: bind it to s3://bucket, azblob://account/container or a DNS service "
                                   "name.", owner)])
    if src_kind and src_kind != dst_kind:
        return findings(actions=[("PingFederate", f"PingFederate's cluster discovery changes from {src_kind} "
                                  f"({_where(src)}) to {dst_kind} ({_where(dst)}): {put}.", owner, None)])
    return findings(ok=[f"PingFederate's cluster discovery ({dst_kind}: {_where(dst)}) is bound in {ctx.dst.label}."])


def check_cluster(ctx):
    """A PingFederate cluster (clustered nodes, or a discovery binding, in the source) needs a discovery binding in the
    target. Clustered nodes with no discovery recorded anywhere, and a target binding that is neither storage nor a
    service name, are blockers (a source binding the target lacks is the core binding check's); a different kind of
    place (S3 to a blob container, ...) is an action, the classic miss when moving, since every node's tcp.xml must
    change. A node's withheld run.properties secrets need a credential role the target binds."""
    nodes, src, dst = clustered(ctx.src), one_role(ctx.src, DISCOVERY_ROLE), one_role(ctx.dst, DISCOVERY_ROLE)
    if not nodes and src is None and dst is None:
        return findings()
    owner = responsible(ctx.d, ctx.dst.env)
    return merge_findings([_discovery(ctx, nodes, src, dst, owner),
                           findings(blockers=[b for n in nodes for b in _credentials(
                               ctx, n, f"PingFederate node `{rdn_value(n)}`", responsible(ctx.d, n, ctx.dst.env))])])
