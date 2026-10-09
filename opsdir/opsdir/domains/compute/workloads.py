"""Workloads: server roles run as containers. The workloads report, the workload rows of the compute report and the
planner's check. Pure.

A workload (intent) realizes a server role (ciamTargetRole) in the cluster an environment binds for it
(ciamClusterRole), and may assume a cloud identity (ciamIdentityRole: workload identity) and read Kubernetes Secret
keys filled from secret roles (ciamWorkloadSecret) that each environment binds. How an environment runs it (images,
replicas, resources, storage) is its workload binding: the binding of the workload's ciamWorkloadRole. An environment
that binds it runs the server role on Kubernetes; one that doesn't runs it on servers, or not at all. A workload
without a workload role (recorded before workload bindings) runs wherever its cluster is bound.

Workload bindings are local to their environment (the domain declares them local): the core's role check doesn't ask
the target to bind them, because the target may run the role on servers instead. This check asks of the target what
the source has: somewhere to run the role (a workload binding with its cluster, or servers of the role), the roles
the workload uses, and what a move between servers and Kubernetes leaves behind. A privileged workload is an action:
what it can reach on its node isn't in the record.
"""
import re

from ...core.directory import children, is_a, one, rdn_value, values
from ...core.environment import bound_nowhere, environment_of, one_role, servers_with_role
from ...core.findings import findings, merge_findings, responsible
from ...core.naming import env_label
from .hosts import baseline_for, compute_rows
from .naming import WORKLOAD_SECRET, WORKLOADS

WORKLOAD_HEADERS = ("workload", "kind", "role", "cluster", "namespace", "workload role", "identity", "pod security",
                    "network policies", "secrets", "hosts")


def workloads(d):
    return children(d, WORKLOADS, "ciamWorkload")


def _secret(v):
    secret_key, role = v.split(" <- ", 1)
    secret, key = secret_key.split("/", 1)
    return secret, key, role


def workload_secrets(w):
    """The Secret keys a workload reads and the secret roles that fill them: ((secret, key, role), ...)."""
    return tuple(_secret(v) for v in values(w, "ciamWorkloadSecret") if re.match(WORKLOAD_SECRET, v))


def _secrets(w):
    return ", ".join((*(f"{s}/{k} <- {r}" for s, k, r in workload_secrets(w)), *values(w, "ciamSecretName")))


def workload_rows(d, dn=None):
    """One row per workload: how it runs, where, with which identity, security and secrets (what each environment
    runs, the compute report lists)."""
    return [(rdn_value(w), one(w, "ciamWorkloadKind"), one(w, "ciamTargetRole"), one(w, "ciamClusterRole") or "",
             one(w, "ciamNamespace") or "", one(w, "ciamWorkloadRole") or "",
             " ".join(x for x in (one(w, "ciamIdentityRole"), one(w, "ciamServiceAccount") and
                                  f"(as {one(w, 'ciamServiceAccount')})") if x),
             ", ".join(values(w, "ciamPodSecurity")), "; ".join(values(w, "ciamNetworkPolicy")), _secrets(w),
             ", ".join(values(w, "ciamIngressHost")))
            for w in workloads(d)]


def namespace_of(w):
    """A workload's Kubernetes namespace: its ciamNamespace, else default."""
    return one(w, "ciamNamespace") or "default"


def service_account_of(w):
    """The Kubernetes service account a workload runs as: its ciamServiceAccount, else its name."""
    return one(w, "ciamServiceAccount") or rdn_value(w)


def workload_binding(m, w):
    """Environment m's workload binding of a workload (how it runs it on Kubernetes), or None."""
    b = one_role(m, one(w, "ciamWorkloadRole")) if one(w, "ciamWorkloadRole") else None
    return b if b is not None and is_a(b, "ciamWorkloadBinding") else None


def runs_in(m, w):
    """Whether an environment binds the cluster a workload runs in."""
    return bool(one(w, "ciamClusterRole")) and one_role(m, one(w, "ciamClusterRole")) is not None


def runs_on_kubernetes(m, w):
    """Whether environment m runs a workload on Kubernetes: it binds the workload's role, or (a workload without
    one) the cluster it runs in."""
    return workload_binding(m, w) is not None if one(w, "ciamWorkloadRole") else runs_in(m, w)


def product_versions(m):
    """The product versions environment m runs (ciamProductVersion, e.g. "PingAM 7.5.1"): its servers', then its
    workload bindings' (what their images run on Kubernetes), without repeats."""
    found = (*(one(s, "ciamProductVersion") for s in m.servers),
             *(one(workload_binding(m, w), "ciamProductVersion") for w in workloads(m.d)
               if workload_binding(m, w) is not None))
    return tuple(dict.fromkeys(v for v in found if v))


def version_holders(m):
    """((what, product version), ...) of everything environment m records a product version on: each server
    ("server <name>") and each workload it runs on Kubernetes ("workload <name> on Kubernetes", its binding's
    version), in the record's order; those recording none left out."""
    found = (*((f"server {rdn_value(s)}", one(s, "ciamProductVersion")) for s in m.servers),
             *((f"workload {rdn_value(w)} on Kubernetes", one(workload_binding(m, w), "ciamProductVersion"))
               for w in workloads(m.d) if workload_binding(m, w) is not None))
    return tuple((what, v) for what, v in found if v)


def role_versions(m, roles):
    """((name, product version), ...) of what runs environment m's server roles: each of its servers of these roles
    and each workload of them it runs on Kubernetes (its binding's version), by name; those recording none left
    out."""
    found = (*((rdn_value(s), one(s, "ciamProductVersion")) for s in m.servers if one(s, "ciamServerRole") in roles),
             *((rdn_value(w), one(workload_binding(m, w), "ciamProductVersion")) for w in workloads(m.d)
               if one(w, "ciamTargetRole") in roles and workload_binding(m, w) is not None))
    return tuple(sorted((n, v) for n, v in found if v))


def runs_product(m, prefixes):
    """Whether environment m runs a product whose version starts with one of these prefixes (product names), on
    servers or on Kubernetes."""
    return any(v.startswith(prefixes) for v in product_versions(m))


def kubernetes_roles(m):
    """The server roles environment m runs on Kubernetes (its workloads there), in the record's order."""
    return tuple(dict.fromkeys(one(w, "ciamTargetRole") for w in workloads(m.d) if runs_on_kubernetes(m, w)))


def runs_here(m, role):
    """Whether environment m runs a server role at all: on servers, or on Kubernetes (its workloads there)."""
    return bool(servers_with_role(m, role)) or role in kubernetes_roles(m)


def only_on_kubernetes(m, role):
    """Whether environment m runs a server role on Kubernetes and on no server: what reaches it there is the
    cluster's (its ingress, its network policies), not a load balancer's pool or a firewall rule on servers."""
    return role in kubernetes_roles(m) and not servers_with_role(m, role)


def kubernetes_note(m, what, role):
    """The comment a cloud renderer writes instead of `what` for a role environment m runs only on Kubernetes."""
    return (f"# NOTE: {what} reaches role `{role}`, which runs only on Kubernetes in {env_label(m.env.dn)}: the "
            "cluster's ingress and network policies serve it there; not rendered")


def placed_on_kubernetes(m, b):
    """Whether a binding places servers of a role (a compute group's ciamTargetRole) that environment m runs on
    Kubernetes instead: m needs no counterpart of it."""
    return is_a(b, "ciamComputeGroup") and one(b, "ciamTargetRole") in kubernetes_roles(m)


def cluster_subnets(m, role):
    """The subnets (bindings) the nodes of the clusters environment m runs a server role's workloads in sit in (the
    clusters' ciamSubnetRole), without repeats: where its pods' traffic comes from outside the cluster."""
    clusters = (one_role(m, one(w, "ciamClusterRole")) for w in workloads(m.d)
                if one(w, "ciamTargetRole") == role and one(w, "ciamClusterRole") and runs_on_kubernetes(m, w))
    found = (one_role(m, r) for c in clusters if c is not None for r in values(c, "ciamSubnetRole"))
    return tuple({s.dn: s for s in found if s is not None}.values())


def _for_binding(d, b):
    return next((w for w in workloads(d) if one(w, "ciamWorkloadRole") == one(b, "ciamBindingRole")), None)


def _resources(b):
    pairs = (("cpu", "ciamCpuRequest", "ciamCpuLimit"), ("memory", "ciamMemoryRequest", "ciamMemoryLimit"))
    return ", ".join(f"{what} {one(b, req) or '-'}/{one(b, lim) or '-'}" for what, req, lim in pairs
                     if one(b, req) or one(b, lim))


def _storage(b):
    size, cls = one(b, "ciamStorageSize"), one(b, "ciamStorageClass")
    return " ".join(x for x in (size, f"({cls})" if cls else None) if x)


def _binding_row(d, b):
    w = _for_binding(d, b)
    runs = f"workload {rdn_value(w)} ({one(w, 'ciamTargetRole')})" if w else "workload: none records this role"
    return (env_label(environment_of(b)), rdn_value(b), one(b, "ciamBindingRole"), runs,
            ", ".join(values(b, "ciamContainerImage")), " ".join(x for x in (_resources(b), _storage(b)) if x),
            one(b, "ciamWorkloadReplicas") or "", "", "")


def all_compute_rows(d, dn=None):
    """The compute report: every environment's compute groups and clusters, then its workload bindings (environments
    in the order they first appear)."""
    held = sorted((e for e in d.entries.values() if is_a(e, "ciamWorkloadBinding")),
                  key=lambda e: (environment_of(e), rdn_value(e)))
    rows = [*compute_rows(d), *(_binding_row(d, b) for b in held)]
    order = {label: i for i, label in reversed(list(enumerate(r[0] for r in rows)))}
    return sorted(rows, key=lambda r: order[r[0]])


# ------------------------------------------------------------------ the planner's check
def _nowhere(ctx, w, name, role, owner):
    """The target has nowhere to run a workload the source runs on Kubernetes, or binds it without its cluster."""
    if runs_on_kubernetes(ctx.src, w) and not runs_on_kubernetes(ctx.dst, w) \
            and not servers_with_role(ctx.dst, role):
        return (("Workload", f"Workload `{name}` runs role `{role}` on Kubernetes in {ctx.src.label}; "
                 f"{ctx.dst.label} neither runs it there (workload role `{one(w, 'ciamWorkloadRole') or '-'}`, "
                 f"cluster `{one(w, 'ciamClusterRole') or '-'}`) nor has servers of the role.", owner),)
    if workload_binding(ctx.dst, w) is not None and not runs_in(ctx.dst, w):
        return (("Workload", f"{ctx.dst.label} runs workload `{name}` on Kubernetes but binds no cluster for it "
                 f"(cluster role `{one(w, 'ciamClusterRole') or '-'}`).", owner),)
    return ()


def _moves(ctx, w, name, role, owner):
    """A role moving between servers and Kubernetes: what its servers carry beyond the product must move too."""
    to_k8s = servers_with_role(ctx.src, role) and not runs_on_kubernetes(ctx.src, w) \
        and runs_on_kubernetes(ctx.dst, w)
    to_servers = runs_on_kubernetes(ctx.src, w) and not runs_on_kubernetes(ctx.dst, w) \
        and servers_with_role(ctx.dst, role)
    baseline = baseline_for(ctx.d, role)
    if to_k8s:
        return (("Workload", f"Role `{role}` moves from servers in {ctx.src.label} to Kubernetes in {ctx.dst.label} "
                 f"(workload `{name}`): "
                 + ("what its host baseline adds (truststore, limits, kernel settings, agents) must be built into "
                    "the image or the pod spec." if baseline else "no host baseline records what its servers run "
                    "beyond the product, so nothing checks that the image carries it."), owner, None),)
    if to_servers:
        return (("Workload", f"Role `{role}` moves from Kubernetes in {ctx.src.label} to servers in "
                 f"{ctx.dst.label} (workload `{name}`): its image, resources and secrets must be rebuilt as a host "
                 + ("baseline and service units." if not baseline else "baseline: compare the recorded one with "
                    "the image."), owner, None),)
    return ()


def _workload(ctx, w):
    name, role, owner = rdn_value(w), one(w, "ciamTargetRole"), responsible(ctx.d, w, ctx.dst.env)
    identity = one(w, "ciamIdentityRole")
    unfilled = bound_nowhere(tuple(r for _, _, r in workload_secrets(w)), ctx.src, ctx.dst)
    blockers = (
        *_nowhere(ctx, w, name, role, owner),
        *((("Workload", f"Workload `{name}` assumes the identity of role `{identity}`, which neither "
            f"{ctx.src.label} nor {ctx.dst.label} binds: record the identity each environment gives it.", owner),)
          if bound_nowhere((identity,), ctx.src, ctx.dst) else ()),
        *((("Workload", f"Workload `{name}` reads Secret keys filled from role(s) {', '.join(map(repr, unfilled))}, "
            f"which neither {ctx.src.label} nor {ctx.dst.label} binds: record where each secret is kept.", owner),)
          if unfilled else ()))
    actions = (*_moves(ctx, w, name, role, owner),
               *((("Workload", f"Workload `{name}` runs privileged containers: what they can reach on their nodes "
                   "isn't in the record. Drop the privilege or record why it is needed.", owner, None),)
                 if "privileged" in values(w, "ciamPodSecurity") else ()))
    return findings(blockers=blockers, actions=actions)


def check_workloads(ctx):
    """Workloads the target has nowhere to run, or whose identity or secrets nobody binds, are blockers; moves between
    servers and Kubernetes and privileged workloads are actions."""
    held = workloads(ctx.d)
    if not held:
        return findings()
    parts = merge_findings([_workload(ctx, w) for w in held])
    if parts.blockers or parts.actions:
        return parts
    return parts._replace(ok=(*parts.ok, f"The {len(held)} workload(s) have somewhere to run in {ctx.dst.label}."))
