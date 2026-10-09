"""Sensitive endpoints on public services: where a service name answers the internet, the sign-in, token, password
reset and registration endpoints its products declare (or its policies place elsewhere) are where credential stuffing
and brute force land. Each needs a rate limit, which needs something inspecting requests in front. A connector: the
endpoints come from the installed product adapters of both environments, which the planner gives it. Pure.

The policies are intent, so a gap is the same in both environments: one action per service role, naming the
environments where it is public.
"""
from ..core.directory import one, rdn_value, values
from ..core.environment import of_class
from ..core.findings import findings, responsible
from ..core.network import is_private
from ..domains.edge.naming import SENSITIVE
from ..domains.edge.policies import inspects, policy_for
from ..domains.edge.resolve import declared_endpoints


def endpoints(adapters, server_role, *policies):
    """{endpoint kind: (paths, ...)} the servers of a role serve: what the adapters declare, each kind replaced where
    the policies place it elsewhere."""
    return declared_endpoints(tuple(e for a in adapters for e in a.endpoints), server_role, *policies)


def public(m):
    """Environment m's service names that answer the internet (a frontend address outside private-use space)."""
    return tuple(s for s in of_class(m, "ciamServiceName")
                 if one(s, "ciamFrontendIp") and not is_private(one(s, "ciamFrontendIp")))


def _limited(p):
    """The endpoint kinds a protection policy rate-limits."""
    return {v.split(" ", 1)[0] for v in values(p, "ciamRateLimit")} if p is not None else set()


def edge_check(src_adapters, dst_adapters):
    """The planner check for unprotected sensitive endpoints on public services, given each environment's installed
    adapters."""
    def check_endpoints(ctx):
        d, exposed = ctx.d, {}
        for m, adapters in ((ctx.src, src_adapters), (ctx.dst, dst_adapters)):
            for s in public(m):
                role = one(s, "ciamBindingRole")
                t, p = policy_for(d, "ciamTrafficPolicy", role), policy_for(d, "ciamProtectionPolicy", role)
                served = endpoints(adapters, one(s, "ciamTargetRole"), t, p)
                kinds = {k: served[k] for k in SENSITIVE if k in served}
                if kinds:
                    seen = exposed.setdefault(role, [s, t, p, {}, []])
                    seen[3].update(kinds)
                    seen[4].append(m.label)
        actions = []
        for role, (s, t, p, kinds, where) in sorted(exposed.items()):
            open_kinds = sorted(set(kinds) - _limited(p), key=SENSITIVE.index)
            if not open_kinds:
                continue
            name, owner = one(s, "ciamFqdn"), responsible(d, p, s, ctx.dst.env)
            paths = "; ".join(f"{k} {', '.join(kinds[k])}" for k in open_kinds)
            if p is None:
                behind = "" if inspects(t, p) else ", behind a TLS-terminating load balancer or a CDN"
                actions.append(("Edge", f"`{name}` (`{role}`) answers the internet in {' and '.join(where)} and serves "
                                f"sensitive endpoints ({paths}) that no protection policy covers: give it one with "
                                f"rate limits on them{behind}.", owner, None))
            else:
                actions.append(("Edge", f"`{name}` (`{role}`) answers the internet in {' and '.join(where)}; "
                                f"protection policy `{rdn_value(p)}` sets no rate limit on {paths}: add one per kind.",
                                owner, None))
        return findings(actions=actions)
    return check_endpoints
