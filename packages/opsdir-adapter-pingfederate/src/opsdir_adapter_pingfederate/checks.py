"""PingFederate planner checks: every data store can reach its system from the target (a target role and a credential
role the target binds); a data store with a fixed host, and a directory reached without TLS, are actions. Every plugin
instance, authentication policy and OIDC policy names only objects the record has, and every plugin instance's
withheld secrets come from a credential role the target binds."""

from opsdir.core.directory import children, one, rdn_value, values
from opsdir.core.environment import UNBOUND, bound_nowhere, one_role
from opsdir.core.findings import findings, merge_findings, responsible
from opsdir.core.jsondata import held_json
from opsdir.domains.infrastructure.external import external_host_fix
from opsdir.domains.pki.credentials import credential_role_fix
from .datastores import store_host, store_hosts
from .discovery import CHOICES, RENDERED, binding_protocol, clustered, discovery_fix, lacks, where
from .generic import held_resources, resource_label
from .naming import DATA_STORES, DEFAULT_POLICY, DISCOVERY_ROLE, FRAGMENTS, OIDC_POLICIES
from .oauth import oidc_policy_refs
from .objects import NOT_RECORDED, claim_fix, missing, why_unresolved
from .plugins import KINDS, plugin_refs
from .policies import fragment_refs, node_refs


def _config(e, attr="pingfedConfig"):
    return held_json(e, attr)


def _credentials(ctx, e, what, owner):
    """Blockers: withheld values nothing names a secret for (with the fix choosing the secret role), and roles the
    target doesn't bind."""
    credential = one(e, "pingfedCredentialRole")
    unbound = bound_nowhere((one(e, "pingfedTargetRole"), credential), ctx.dst)
    unnamed = bool(values(e, "pingfedWithheld")) and not credential
    fix = credential_role_fix(ctx.src, ctx.dst, e, "pingfedCredentialRole", what,
                              f"credential-role:{e.dn.split(',')[1].split('=', 1)[1]}/{rdn_value(e)}",
                              (rdn_value(e), one(e, "pingfedPluginKind") or "")) if unnamed else None
    return findings(blockers=(
        *((("PingFederate", f"{what} has withheld credentials but no credential role: nothing says which secret "
            f"{ctx.dst.label} gives it. Set pingfedCredentialRole.", owner),) if unnamed else ()),
        *(("PingFederate", f"{what} needs role `{r}`, which {ctx.dst.label} doesn't bind.", owner) for r in unbound)),
        fixes=(fix,) if fix else ())


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
    host = store_host({"type": kind, **config}) if fixed else None
    fix = external_host_fix(ctx.src, host, f"data store `{name}`", f"external-host:data-stores/{name}",
                            "pingfederate/bulk") if host and not host.startswith(UNBOUND) else None
    return merge_findings([_credentials(ctx, s, f"Data store `{name}`", owner),
                           findings(actions=actions, fixes=(fix,) if fix else ())])


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
    """Blockers for the objects an entry names that the record doesn't have (or several entries claim), with the fix
    giving a claimed id to one entry."""
    owner = responsible(ctx.d, e, ctx.dst.env)
    absent = missing(ctx.d, refs)
    return findings(blockers=[("PingFederate", f"{what} names {why_unresolved(ctx.d, k, i, NOT_RECORDED)}.", owner)
                              for k, i in absent],
                    fixes=[x for k, i in absent for x in (claim_fix(ctx.d, k, i),) if x])


def _plugin(ctx, p):
    kind = one(p, "pingfedPluginKind")
    label = KINDS[kind].label
    what = f"{label[0].upper()}{label[1:]} `{rdn_value(p)}`"
    return merge_findings([_named(ctx, p, what, plugin_refs(kind, _config(p))),
                           _credentials(ctx, p, what, responsible(ctx.d, p, ctx.dst.env))])


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
        *(_named(ctx, t, f"Authentication policy `{rdn_value(t)}`", node_refs(_config(t, "pingfedPolicyTree")))
          for t in trees),
        *(_named(ctx, f, f"Policy fragment `{rdn_value(f)}`",
                 fragment_refs({**_config(f), "rootNode": _config(f, "pingfedPolicyTree")})) for f in fragments),
        *(_named(ctx, o, f"OIDC policy `{rdn_value(o)}`", oidc_policy_refs(_config(o))) for o in oidc),
        *(_credentials(ctx, r, resource_label(r), responsible(ctx.d, r, ctx.dst.env)) for r in held)])
    if parts.blockers:
        return parts
    return parts._replace(ok=(*parts.ok, f"PingFederate's {len(plugins)} plugin instance(s), {len(trees)} authentication "
                                         f"policy tree(s) and {len(oidc)} OIDC policy(-ies) name only what the record "
                                         "has."))


def _running(nodes):
    """The protocols to offer binding the source's discovery with: the one its nodes all report using, when the
    adapter renders it, else every one it renders."""
    running = {p for n in nodes for p in values(n, "pingfedDiscovery")}
    return tuple(running) if len(running) == 1 and running <= set(CHOICES) else CHOICES


def _discovery(ctx, nodes, src, dst, owner):
    src_p, dst_p = (binding_protocol(b) if b is not None else None for b in (src, dst))
    choose = f"choose pingfedDiscoveryProtocol ({', '.join(CHOICES)})"
    if dst is None and src is not None:
        return findings()          # a role the source binds and the target doesn't: the core's binding check says so
    if dst is None:
        return findings(blockers=[("PingFederate", f"PingFederate's cluster ({len(nodes)} clustered node(s) in "
                                   f"{ctx.src.label}) has no recorded discovery, so nothing says how its members "
                                   f"find each other in {ctx.dst.label}: bind role `{DISCOVERY_ROLE}` in both and "
                                   f"{choose}.", owner)],
                        fixes=[discovery_fix(ctx.src, None, _running(nodes)), discovery_fix(ctx.dst, None, CHOICES)])
    if dst_p is None or dst_p.support != RENDERED:
        why = f"{dst_p.name}, {dst_p.about}" if dst_p else "no protocol and nothing that implies one"
        return findings(blockers=[("PingFederate", f"{ctx.dst.label}'s `{DISCOVERY_ROLE}` binding uses {why}: "
                                   f"{choose}.", owner)], fixes=[discovery_fix(ctx.dst, dst, CHOICES)])
    lack = lacks(dst_p, dst)
    if lack:
        return findings(blockers=[("PingFederate", f"{ctx.dst.label}'s `{DISCOVERY_ROLE}` binding uses {dst_p.name}, "
                                   f"which needs {lack}.", owner)],
                        fixes=[discovery_fix(ctx.dst, dst, (dst_p.name,))])
    if src_p and src_p.name != dst_p.name:
        return findings(actions=[("PingFederate", f"PingFederate's cluster discovery changes from {src_p.name} "
                                  f"({where(src)}) to {dst_p.name} ({where(dst)}): put the lines of "
                                  "pingfederate/cluster/jgroups.properties in each node's bin/jgroups.properties.",
                                  owner, None)])
    return findings(ok=[f"PingFederate's cluster discovery ({dst_p.name}: {where(dst)}) is bound in {ctx.dst.label}."])


def check_cluster(ctx):
    """A PingFederate cluster (clustered nodes, or a discovery binding, in the source) needs a discovery binding in the
    target. Clustered nodes with no discovery recorded anywhere, and a target binding whose protocol the adapter
    doesn't render (AZURE_PING, ...) or that lacks what its protocol needs, are blockers (a source binding the target
    lacks is the core binding check's); a different protocol (NATIVE_S3_PING to DNS_PING, ...) is an action, the
    classic miss when moving, since every node's jgroups.properties must change. A node's withheld run.properties
    secrets need a credential role the target binds."""
    nodes, src, dst = clustered(ctx.src), one_role(ctx.src, DISCOVERY_ROLE), one_role(ctx.dst, DISCOVERY_ROLE)
    if not nodes and src is None and dst is None:
        return findings()
    owner = responsible(ctx.d, ctx.dst.env)
    return merge_findings([_discovery(ctx, nodes, src, dst, owner),
                           *(_credentials(ctx, n, f"PingFederate node `{rdn_value(n)}`",
                                          responsible(ctx.d, n, ctx.dst.env)) for n in nodes)])
