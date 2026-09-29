"""DS-lineage replication: bootstrap peers for new replicas, and the planner checks every product of the lineage
shares (a routed path to the source, the replication port open to each new replica). Whether the target joins the
source's replication deployment or topology is product knowledge: each product adds that check."""
from opsdir.core.directory import children, follow, one, rdn_value, values
from opsdir.core.environment import joins, of_class, one_role, servers_with_role
from opsdir.core.findings import findings, merge_findings, responsible
from opsdir.core.network import covers
from opsdir.domains.directory.naming import DIRECTORY_SERVER_ROLE

REPLICATION_PORT = "8989"      # the lineage's default replication port


def joined_ds_hosts(d, m):
    """Hostnames of the directory servers of the environment this one joins (none when it joins none)."""
    joined = joins(m)
    return tuple(one(s, "ciamHostname") for s in children(d, joined.dn, "ciamServer")
                 if one(s, "ciamServerRole") == DIRECTORY_SERVER_ROLE) if joined else ()


def peer_ds_hosts(d, m):
    """Replication bootstrap servers: this environment's DS servers, plus the DS servers of
    the environment it joins (so target replicas join the *existing* deployment)."""
    return (*(one(s, "ciamHostname") for s in servers_with_role(m, DIRECTORY_SERVER_ROLE)), *joined_ds_hosts(d, m))


def check_joins(d, src, dst, joined_text, missing_text):
    """The target declares that it joins the source's replication (ciamJoinsDeploymentOf). The product words the
    finding: what joining keeps (joined_text), what a target that doesn't join loses (missing_text)."""
    joined = joins(dst)
    if joined and joined.dn.lower() == src.dn.lower():
        return findings(ok=[joined_text])
    return findings(blockers=[("Replication", missing_text, responsible(d, dst.env))])


def _check_interconnect(d, src, dst):
    link = [ic for ic in of_class(dst, "ciamInterconnect")
            if follow(d, ic, "ciamPeerEnvironment").dn.lower() == src.dn.lower()]
    if link:
        return findings(ok=[f"Interconnect `{rdn_value(link[0])}` ({one(link[0], 'ciamInterconnectKind')}) "
                            "links the environments."])
    return findings(blockers=[("Replication", "No interconnect from the target to the source for replication "
                               "traffic.", responsible(d, one_role(dst, "network"), dst.env))])


def _check_replication_port(d, src, dst):
    rules = [f for f in of_class(src, "ciamFirewallRule") if REPLICATION_PORT in values(f, "ciamPort")]
    servers = servers_with_role(dst, DIRECTORY_SERVER_ROLE)
    replicas = [(s, one(s, "ciamPrivateIp") + "/32") for s in servers if one(s, "ciamPrivateIp")]
    unknown = [s for s in servers if not one(s, "ciamPrivateIp")]
    closed = [(s, ip) for s, ip in replicas if not any(covers(values(f, "ciamSourceCidr"), ip) for f in rules)]
    owner = responsible(d, one_role(src, "network"), src.env)
    admitted = (f"{src.label} already admits every {dst.label} replica on the replication port." if servers else
                f"{dst.label} records no directory replicas: no replication traffic to admit.")
    return findings(
        blockers=[*(("Replication", f"{src.label} doesn't admit {dst.label} replica {rdn_value(s)} ({ip}) on "
                     f"port {REPLICATION_PORT}.", owner) for s, ip in closed),
                  *(("Replication", f"{dst.label} replica {rdn_value(s)} records no private IP, so whether "
                     f"{src.label} admits it on port {REPLICATION_PORT} can't be checked.", responsible(d, s, dst.env))
                    for s in unknown)],
        ok=[] if closed or unknown else [admitted])


def check_replication_path(ctx):
    """A routed, open path for replication: an interconnect to the source, the replication port admitted."""
    return merge_findings([_check_interconnect(ctx.d, ctx.src, ctx.dst),
                           _check_replication_port(ctx.d, ctx.src, ctx.dst)])
