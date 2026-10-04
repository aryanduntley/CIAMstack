"""The ports matrix across a move: the ports the installed products listen on in each environment, who must reach
them, and whether the firewall rules and network ACLs let that traffic through. A connector: the listeners come from
the installed product adapters of each environment, which the planner and the report catalogue give it. Pure.

In the target a gap between server roles blocks the cutover (replication, clustering and the products' own calls
fail); in the source it is a question for the record (the rule may exist and not be recorded). Firewall rules that
open a port no installed product listens on are named for review.
"""
from ..core.contract import directory_report
from ..core.directory import one, rdn_value, values
from ..core.findings import findings, merge_findings, responsible
from ..domains.network.ports import (BLOCKED, OPEN, PORTS_HEADERS, UNCOVERED, flow_status, flows, ports_rows,
                                     stray_rules)
from .registry import ADAPTERS, environment, environment_specs


def listeners(m, adapters):
    """The listeners the adapters declare for environment m."""
    return tuple(lst for a in adapters if a.listeners for lst in a.listeners(m))


def _gaps(m, declared):
    """(flow, status, reasons) for each flow of environment m that doesn't get through."""
    return [(f, status, reasons) for f in flows(m, declared)
            for status, _, reasons in (flow_status(m, f),) if status in (UNCOVERED, BLOCKED)]


def _by_listener(gaps):
    """((listener, (source, ...), (reason, ...)), ...): the gaps of each listener together, in order."""
    listeners = tuple(dict.fromkeys(f.listener for f, _, _ in gaps))
    return tuple((lst, tuple(f.source for f, _, _ in gaps if f.listener == lst),
                  tuple(dict.fromkeys(r for f, _, rs in gaps if f.listener == lst for r in rs))) for lst in listeners)


def _gap_text(m, lst, sources, reasons):
    who = " and ".join("clients" if s == "clients" else ("its peers" if s == lst.server_role else f"`{s}`")
                       for s in sources)
    return (f"{m.label}: `{lst.server_role}` listens on {lst.protocol} {lst.port} ({lst.purpose}) for {who}, but "
            f"{'; '.join(reasons)}.")


def _environment(ctx, m, declared, target):
    gaps = _gaps(m, declared)
    owner = responsible(ctx.d, m.env)
    between_roles = _by_listener([g for g in gaps if g[0].source != "clients"])
    for_clients = _by_listener([g for g in gaps if g[0].source == "clients"])
    if target:
        blockers = [("Ports", _gap_text(m, *g), owner) for g in between_roles]
        actions = [("Ports", _gap_text(m, *g) + " Consumers can't connect until a rule admits them.", owner, None)
                   for g in for_clients]
    else:
        blockers = []
        actions = [("Ports", _gap_text(m, *g) + " Record the rule if it exists, or confirm the traffic doesn't flow.",
                    owner, None) for g in (*between_roles, *for_clients)]
    stray = stray_rules(m, declared)
    if stray and target:
        named = ", ".join(f"`{rdn_value(fw)}` ({one(fw, 'ciamTargetRole')} {'/'.join(values(fw, 'ciamPort'))})"
                          for fw in stray)
        actions.append(("Ports", f"{m.label}: firewall rules open ports no installed product listens on: {named}. "
                        "Close them, or record what listens there.", owner, None))
    flowing = sum(1 for f in flows(m, declared) if flow_status(m, f)[0] == OPEN)
    ok = [f"{m.label}: {flowing} flow(s) of the ports matrix get through."] if flowing and not gaps else []
    return findings(blockers=blockers, actions=actions, ok=ok)


def network_check(src_adapters, dst_adapters):
    """The planner check for the ports matrix, given each environment's installed adapters."""
    def check_ports(ctx):
        src, dst = listeners(ctx.src, src_adapters), listeners(ctx.dst, dst_adapters)
        if not (src or dst):
            return findings()                       # no installed product declares its ports: nothing to check
        return merge_findings([_environment(ctx, ctx.src, src, False), _environment(ctx, ctx.dst, dst, True)])
    return check_ports


def ports_report(installed=ADAPTERS):
    """The `ports` report: every environment's ports matrix (or one environment's, given its DN)."""
    def rows(d, dn=None):
        specs = [s for s in environment_specs(d) if not dn or environment(d, s, installed)[0].dn.lower() == dn.lower()]
        return [row for s in specs for m, adapters in (environment(d, s, installed),)
                for row in ports_rows(m, listeners(m, adapters))]
    return directory_report(PORTS_HEADERS, rows)
