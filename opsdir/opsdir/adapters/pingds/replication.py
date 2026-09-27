"""PingDS replication: bootstrap peers for new replicas, and the planner checks that keep a migration inside the
existing replication deployment (same deployment ID, so encrypted data and backups stay readable)."""
from ...core.directory import children, follow, one, rdn_value, values
from ...core.environment import joins, of_class, one_role, servers_with_role
from ...core.findings import findings, merge_findings, responsible
from ...core.network import covers
from ...domains.directory.naming import DIRECTORY_SERVER_ROLE

REPLICATION_PORT = "8989"      # PingDS default replication port


def peer_ds_hosts(d, m):
    """Replication bootstrap servers: this environment's DS servers, plus the DS servers of
    the environment it joins (so target replicas join the *existing* deployment)."""
    joined = joins(m)
    theirs = tuple(one(s, "ciamHostname") for s in children(d, joined.dn, "ciamServer")
                   if one(s, "ciamServerRole") == DIRECTORY_SERVER_ROLE) if joined else ()
    return (*(one(s, "ciamHostname") for s in servers_with_role(m, DIRECTORY_SERVER_ROLE)), *theirs)


def _check_deployment(d, src, dst):
    joined = joins(dst)
    if joined and joined.dn.lower() == src.dn.lower():
        return findings(ok=[f"{dst.label} joins the DS replication deployment of {src.label} "
                            "(same deployment ID; keys and encrypted data stay readable)."])
    return findings(blockers=[("Replication", f"{dst.label} does not declare that it joins {src.label}'s "
                               "deployment. A fresh deployment can't decrypt existing encrypted data or backups.",
                               responsible(d, dst.env))])


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
    replicas = [(s, one(s, "ciamPrivateIp") + "/32") for s in servers_with_role(dst, DIRECTORY_SERVER_ROLE)]
    closed = [(s, ip) for s, ip in replicas if not any(covers(values(f, "ciamSourceCidr"), ip) for f in rules)]
    return findings(
        blockers=[("Replication", f"{src.label} doesn't admit {dst.label} replica {rdn_value(s)} ({ip}) on "
                   f"port {REPLICATION_PORT}.", responsible(d, one_role(src, "network"), src.env)) for s, ip in closed],
        ok=[] if closed else [f"{src.label} already admits every {dst.label} replica on the replication port."])


def check_replication(ctx):
    """Replication continuity: target replicas must join the existing deployment over a routed, open path."""
    return merge_findings([_check_deployment(ctx.d, ctx.src, ctx.dst), _check_interconnect(ctx.d, ctx.src, ctx.dst),
                           _check_replication_port(ctx.d, ctx.src, ctx.dst)])
