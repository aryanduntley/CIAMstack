"""The identities an environment's renderers write, and what the cloud adapters' renderers share. Pure.

Workloads: each workload principal some server of the environment runs as (its ciamTargetRole), or that its
workloads on Kubernetes assume (their ciamIdentityRole: the Kubernetes service accounts the cloud trusts through the
cluster's OIDC issuer, workload identity federation). One identity per identity role: the workload principals that
share one (an engine and its admin console on one role) act as that one cloud identity, with their permits merged. For
the landing zone
(terraform/landing-zone/, applied by whoever keeps it): each deployer principal whose identity the environment binds
with an OIDC trust (ciamTrustedBy '<issuer URL> <subject>': a CI pipeline), and each operator principal whose identity
binding names the group it is granted to (its provider ref). For each: the cloud identity's name, and for each permit
the binding and the cloud's table row that grant it there. A permit whose role the environment doesn't bind, or that
the cloud's table has no row for, can't be granted: it is a note the renderer writes as a comment, so nothing is
silently left out.
"""
from collections import namedtuple

from ...core.directory import get, one, rdn_value, values
from ...core.environment import of_class, one_role
from ...core.findings import responsible
from ...core.notes import RECORD, note
from ..compute.hosts import runs_role
from ..compute.workloads import namespace_of, runs_on_kubernetes, service_account_of, workloads
from .grants import rows_for
from .principals import permits, principals

# principals: the names of the principals acting as it (one, but every workload principal sharing an identity role);
# server_roles: the roles whose servers run as it (theirs, once each; () for a principal with none); grants: (permit,
# binding, row) per permit, once each, sorted; notes: a RenderNote (subject 'principal <name>') per permit that can't
# be granted;
# kind: the principals' kind; trust: (issuer, subject) of a deployer's OIDC trust; group: an operator's group (the
# identity binding's provider ref); conditions: the principals' (jit: granted eligible, not active); pods: the
# Kubernetes service accounts that assume it (Pod, one per workload run on Kubernetes here with its identity role);
# servers: whether servers of its roles run here (and assume it as their own identity)
WorkloadIdentity = namedtuple("WorkloadIdentity", ("principals", "identity_role", "server_roles", "name", "grants",
                                                   "notes", "kind", "trust", "group", "conditions", "pods", "servers"),
                              defaults=("workload", None, None, (), (), True))

# A Kubernetes service account that assumes a cloud identity: its namespace and name, and the cluster binding
# (ciamCluster) of the cluster it runs in (None when the environment doesn't bind it): the cluster's OIDC issuer is
# what the cloud trusts.
Pod = namedtuple("Pod", ("namespace", "service_account", "cluster"))


def identity_name(m, role, default):
    """The name of the cloud identity a role names in environment m: the last part of its binding's provider ref (an
    IAM role's name, a resource ID's last segment, a service account's account id), else default."""
    b = one_role(m, role)
    ref = one(b, "ciamProviderRef") if b is not None else None
    return ref.rsplit("/", 1)[-1].split("@", 1)[0] if ref else default


def _grant(m, model, permit):
    """((permit, binding, row), None) when the cloud can grant a permit in m, else (None, (why not, severity, how)):
    a role not bound here a plain note (the planner's binding checks raise it), a permit the cloud has no mapping for
    an action (grant it by hand)."""
    verb, _, role = permit.partition(" ")
    b = one_role(m, role)
    rows = rows_for(m.d, model, b, verb) if b is not None else ()
    if b is None:
        return None, (f"{permit}: role `{role}` has no binding in this environment", "note",
                      (f"Bind role `{role}` in this environment, {RECORD}",))
    return ((permit, b, rows[0]), None) if rows else (None, (f"{permit}: this cloud has no mapping for it", "action", (
        f"Grant `{permit}` to the principal's identity by hand (a custom role or policy)",
        f"Or remove the permit from the principal's permission set, {RECORD}")))


def oidc_trust(binding):
    """(issuer URL, subject) of an identity binding's OIDC trust ('<issuer URL> <subject>'), or None."""
    trust = next((v for v in values(binding, "ciamTrustedBy") if v.startswith("https://") and " " in v), None)
    return tuple(trust.split(" ", 1)) if trust else None


def _identity(m, model, p, default, named=True, **extra):
    done = [_grant(m, model, x) for x in permits(m.d, p)]
    name, role, target = rdn_value(p), one(p, "ciamIdentityRole"), one(p, "ciamTargetRole")
    return WorkloadIdentity((name,), role, (target,) if target else (),
                            identity_name(m, role, default) if named else default,
                            tuple(g for g, _ in done if g),
                            tuple(note("Access", severity, f"principal {name}", why, how, p.dn, m.label)
                                  for _, n in done if n for why, severity, how in (n,)),
                            one(p, "ciamPrincipalKind"), conditions=tuple(values(p, "ciamCondition")), **extra)


def principal_label(w):
    """The principals a workload identity acts for, as words (their names joined by 'and')."""
    return " and ".join(w.principals)


def pod_notes(w):
    """The render notes (blockers) of a workload identity's Kubernetes service accounts that run in a cluster its
    environment doesn't bind: nothing trusts them (each cloud's renderer writes their comments)."""
    return tuple(note("Access", "blocker", f"principal {principal_label(w)}", f"service account "
                      f"{p.namespace}/{p.service_account} runs in a cluster this environment doesn't bind, so nothing "
                      "trusts it", (f"Bind the cluster the service account runs in (its workload's ciamClusterRole), "
                                    f"{RECORD}",))
                 for p in w.pods if p.cluster is None)


def _merged(ws):
    """One identity for the workload principals sharing an identity role (ws, in record order): the first's name and
    pods (the role's), every principal and server role, the grants, notes and conditions of all, once each."""
    once = lambda xs: tuple(dict.fromkeys(xs))                                              # noqa: E731
    return ws[0]._replace(principals=once(x for w in ws for x in w.principals),
                          server_roles=once(r for w in ws for r in w.server_roles),
                          grants=tuple(sorted({g[0]: g for w in ws for g in w.grants}.values(), key=lambda g: g[0])),
                          notes=once(n for w in ws for n in w.notes),
                          conditions=once(c for w in ws for c in w.conditions),
                          servers=any(w.servers for w in ws))


def identity_pods(m, identity_role):
    """The Kubernetes service accounts that assume an identity role in environment m: one Pod per workload run on
    Kubernetes here that names it (ciamIdentityRole), without repeats."""
    if not identity_role:
        return ()
    found = (Pod(namespace_of(w), service_account_of(w),
                 one_role(m, one(w, "ciamClusterRole")) if one(w, "ciamClusterRole") else None)
             for w in workloads(m.d) if one(w, "ciamIdentityRole") == identity_role and runs_on_kubernetes(m, w))
    return tuple({(p.namespace, p.service_account, p.cluster.dn if p.cluster is not None else None): p
                  for p in found}.values())


def workload_identities(m, model):
    """The cloud identities environment m's workload principals run as, one per identity role, each with what its
    principals' permits need there: those whose role has servers here, its own or a compute group's (the servers'
    identity), and those its workloads on Kubernetes assume (pods: the service accounts the cloud must trust through
    their cluster's OIDC issuer). Principals sharing an identity role are one identity (named as the first in record
    order would be)."""
    def found(p):
        role, pods = one(p, "ciamTargetRole"), identity_pods(m, one(p, "ciamIdentityRole"))
        servers = runs_role(m, role)
        return (_identity(m, model, p, f"ciam-{rdn_value(m.env)}-{role}", pods=pods, servers=servers),) \
            if servers or pods else ()
    each = tuple(w for p in principals(m.d) if one(p, "ciamPrincipalKind") == "workload" and one(p, "ciamTargetRole")
                 for w in found(p))
    key = lambda w: w.identity_role or ("principal", w.principals[0])                       # noqa: E731
    return tuple(_merged(tuple(w for w in each if key(w) == k)) for k in dict.fromkeys(map(key, each)))


def landing_identities(m, model):
    """(deployers, operators) environment m's landing zone grants: deployer principals whose identity m binds with an
    OIDC trust, operator principals whose identity binding names their group."""
    def bound(p):
        return one_role(m, one(p, "ciamIdentityRole"))
    deployers = tuple(_identity(m, model, p, f"ciam-{rdn_value(m.env)}-{rdn_value(p)}", trust=oidc_trust(bound(p)))
                      for p in principals(m.d) if one(p, "ciamPrincipalKind") == "deployer"
                      and bound(p) is not None and oidc_trust(bound(p)))
    operators = tuple(_identity(m, model, p, f"ciam-{rdn_value(m.env)}-{rdn_value(p)}", named=False,
                                group=one(bound(p), "ciamProviderRef"))         # the provider ref is the group
                      for p in principals(m.d) if one(p, "ciamPrincipalKind") in ("operator", "break-glass")
                      and bound(p) is not None and one(bound(p), "ciamIdentityKind") in ("group", "permission-set"))
    return deployers, operators


def identity_notes(m, model):
    """The render notes of environment m's identities as a cloud with access model renders them, each once: the
    workload identities' and the landing zone's (deployers, operators) grant notes, and the pods' (pod_notes)."""
    deployers, operators = landing_identities(m, model)
    every = (*workload_identities(m, model), *deployers, *operators)
    return tuple(dict.fromkeys(n for w in every for n in (*w.notes, *pod_notes(w))))


def landing_zone_owner(m):
    """Who keeps environment m's landing zone: the owners of its guardrails, else of its cloud, else of m."""
    return responsible(m.d, *of_class(m, "ciamGuardrail"), m.cloud, m.env)


def landing_zone_party(m):
    """The party entry that keeps environment m's landing zone (as landing_zone_owner finds it), or None."""
    owned = next((e for e in (*of_class(m, "ciamGuardrail"), m.cloud, m.env) if values(e, "ciamOwner")), None)
    return get(m.d, values(owned, "ciamOwner")[0]) if owned is not None else None


def identity_of(identities, server_role):
    """The workload identity servers of a role run as, or None."""
    return next((w for w in identities if server_role in w.server_roles), None)
