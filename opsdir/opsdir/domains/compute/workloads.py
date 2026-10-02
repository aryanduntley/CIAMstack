"""Workloads: server roles run as containers. The workloads report and the planner's check. Pure.

A workload realizes a server role (ciamTargetRole) in the cluster an environment binds for it (ciamClusterRole), and
may assume a cloud identity (ciamIdentityRole: workload identity) that each environment binds. The check asks of the
target what the source has: somewhere to run the role (a cluster for the workload, or servers of the role) and the
roles it uses. A privileged workload is an action: what it can reach on its node isn't in the record.
"""
from ...core.directory import children, one, rdn_value, values
from ...core.environment import bound_nowhere, one_role, servers_with_role
from ...core.findings import findings, merge_findings, responsible
from .naming import WORKLOADS

WORKLOAD_HEADERS = ("workload", "kind", "role", "cluster", "namespace", "replicas", "images", "storage", "identity",
                    "pod security", "network policies", "secrets", "hosts")


def workloads(d):
    return children(d, WORKLOADS, "ciamWorkload")


def _storage(w):
    size, cls = one(w, "ciamStorageSize"), one(w, "ciamStorageClass")
    return " ".join(x for x in (size, f"({cls})" if cls else None) if x)


def workload_rows(d, dn=None):
    """One row per workload: how it runs, where, with which storage, identity, security and secrets."""
    return [(rdn_value(w), one(w, "ciamWorkloadKind"), one(w, "ciamTargetRole"), one(w, "ciamClusterRole") or "",
             one(w, "ciamNamespace") or "", one(w, "ciamReplicaCount") or "", ", ".join(values(w, "ciamContainerImage")),
             _storage(w), " ".join(x for x in (one(w, "ciamIdentityRole"), one(w, "ciamServiceAccount") and
                                                f"(as {one(w, 'ciamServiceAccount')})") if x),
             ", ".join(values(w, "ciamPodSecurity")), "; ".join(values(w, "ciamNetworkPolicy")),
             ", ".join(values(w, "ciamSecretName")), ", ".join(values(w, "ciamIngressHost")))
            for w in workloads(d)]


def runs_in(m, w):
    """Whether an environment binds the cluster a workload runs in."""
    return bool(one(w, "ciamClusterRole")) and one_role(m, one(w, "ciamClusterRole")) is not None


def _workload(ctx, w):
    name, role, owner = rdn_value(w), one(w, "ciamTargetRole"), responsible(ctx.d, w, ctx.dst.env)
    identity = one(w, "ciamIdentityRole")
    blockers = (
        *((("Workload", f"Workload `{name}` runs role `{role}` in {ctx.src.label}'s cluster "
            f"(`{one(w, 'ciamClusterRole')}`); {ctx.dst.label} binds no cluster for it and has no servers of the "
            "role.", owner),)
          if runs_in(ctx.src, w) and not runs_in(ctx.dst, w) and not servers_with_role(ctx.dst, role) else ()),
        *((("Workload", f"Workload `{name}` assumes the identity of role `{identity}`, which neither "
            f"{ctx.src.label} nor {ctx.dst.label} binds: record the identity each environment gives it.", owner),)
          if bound_nowhere((identity,), ctx.src, ctx.dst) else ()))
    actions = ((("Workload", f"Workload `{name}` runs privileged containers: what they can reach on their nodes isn't "
                 "in the record. Drop the privilege or record why it is needed.", owner, None),)
               if "privileged" in values(w, "ciamPodSecurity") else ())
    return findings(blockers=blockers, actions=actions)


def check_workloads(ctx):
    """Workloads the target has nowhere to run, or whose identity nobody binds, are blockers; privileged ones are
    actions."""
    held = workloads(ctx.d)
    if not held:
        return findings()
    parts = merge_findings([_workload(ctx, w) for w in held])
    if parts.blockers or parts.actions:
        return parts
    return parts._replace(ok=(*parts.ok, f"The {len(held)} workload(s) have somewhere to run in {ctx.dst.label}."))
