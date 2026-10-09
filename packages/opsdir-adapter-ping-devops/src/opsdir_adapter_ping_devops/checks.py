"""ping-devops' planner check on the target environment. Pure.

What the rendered values can't settle on their own, as actions: a PingFederate workload with no license recorded
(a license file key, or Ping's DevOps credentials for its license server), an admin console with no
PING_IDENTITY_PASSWORD recorded (the image's default is published), more than one admin console replica, engines
with no admin console in their namespace (the chart clusters them through it), workloads beyond the one per
product the chart runs, and a cluster discovery the record doesn't bind as DNS_PING through the chart's cluster service
(with the fix binding it).
"""
from opsdir.core.directory import rdn_value
from opsdir.core.findings import findings, responsible
from opsdir_adapter_kubernetes.kits import replicas_of
from .discovery import discovery_gap
from .products import placements, secret_keys, unplaced, workload_of
from .release import ADMIN_PASSWORD, DEVOPS_KEYS, LICENSE_KEY

AREA = "PingFederate on Kubernetes"
ADMIN, ENGINE = "pingfederate-admin", "pingfederate-engine"


def licensed(w):
    """Whether a workload records a PingFederate license: the license file key, or both DevOps credential keys."""
    keys = {k for _, k, _ in secret_keys(w)}
    return LICENSE_KEY in keys or set(DEVOPS_KEYS) <= keys


def _texts(m, p):
    admin, where = workload_of(p, ADMIN), f"{m.label} (namespace `{p.namespace}`)"
    yield from (f"PingFederate workload `{rdn_value(w)}` in {where} has no license recorded: record the Secret key "
                f"`{LICENSE_KEY}` (mounted as the license file) or `{DEVOPS_KEYS[0]}` and `{DEVOPS_KEYS[1]}` "
                f"(ciamWorkloadSecret <secret>/<key> <- <role>)." for _, w in p.placed if not licensed(w))
    if admin is not None and ADMIN_PASSWORD not in {k for _, k, _ in secret_keys(admin)}:
        yield (f"PingFederate's admin console `{rdn_value(admin)}` in {where} records no `{ADMIN_PASSWORD}`: the "
               f"image's default administrator password is published. Record the role that fills it "
               f"(ciamWorkloadSecret <secret>/{ADMIN_PASSWORD} <- <role>).")
    if admin is not None and (replicas_of(m, admin) or 1) > 1:
        yield (f"PingFederate's admin console `{rdn_value(admin)}` in {where} records {replicas_of(m, admin)} "
               f"replicas: a PingFederate cluster has one admin console node.")
    if admin is None and workload_of(p, ENGINE) is not None:
        yield (f"PingFederate engines run in {where} with no admin console there: the chart clusters engines with the "
               f"admin console of their release, so run `pf-admin` in the namespace too.")


def check_ping_devops(ctx):
    """Actions on the target: PingFederate licenses, the admin password, admin console replicas, engines without
    their admin console, workloads beyond one per product, cluster discovery (with its fix)."""
    m = ctx.dst
    spaces = placements(m)
    if not spaces:
        return findings()
    owner = responsible(ctx.d, m.env)
    texts = (*(t for p in spaces for t in _texts(m, p)),
             *(f"Workload `{rdn_value(w)}` runs `{name}` in {m.label} (namespace `{ns}`) beside another: the chart "
               f"runs one per release, so it isn't deployed. Scale the first (ciamWorkloadReplicas) or give it its own "
               f"namespace." for ns, name, w in unplaced(m)))
    gaps = tuple(g for p in spaces for g in (discovery_gap(m, p),) if g is not None)
    actions = tuple((AREA, t, owner, None) for t in (*texts, *(t for t, _ in gaps)))
    ok = () if actions else (f"PingFederate on Kubernetes in {m.label} has its licenses, admin password and cluster "
                             "discovery recorded.",)
    return findings(actions=actions, ok=ok, fixes=tuple(f for _, f in gaps))
