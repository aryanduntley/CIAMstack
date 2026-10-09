"""The ports matrix across a move: the ports the installed products listen on in each environment, who must reach
them, and whether the firewall rules and network ACLs let that traffic through. A connector: the listeners come from
the installed product adapters of each environment, which the planner and the report catalogue give it. Pure.

In the target a gap between server roles blocks the cutover (replication, clustering and the products' own calls
fail); in the source it is a question for the record (the rule may exist and not be recorded). Firewall rules that
open a port no installed product listens on are named for review.
"""
from ..core.changeset import add_values, delete_entry, delete_values, new_entry, set_values
from ..core.contract import directory_report
from ..core.directory import one, rdn_value, values
from ..core.findings import Fix, findings, merge_findings, responsible
from ..domains.network.ports import (BLOCKED, OPEN, PORTS_HEADERS, UNCOVERED, admitting, flow_status, flows,
                                     moved_ranges, ports_rows, stray_ports, stray_rules)
from .registry import ADAPTERS, environment, environment_specs, listeners_of as listeners


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


def ports_fix(m, flow, src=None):
    """The Fix admitting exactly the ranges of a flow between server roles that no firewall rule covers; None when
    nothing is uncovered or the flow comes from clients or admins. Where it goes: the rule that admits the port to the
    role from where the source role ran before it moved (src given: moved_ranges), its old ranges replaced by the new
    ones; else added to the rule that already admits the port to the role; else a new rule."""
    rules, uncovered = admitting(m, flow)
    if flow.source in ("clients", "admin") or not uncovered:
        return None
    lst, cidrs = flow.listener, ", ".join(uncovered)
    moved = moved_ranges(src, m, flow.source) if src is not None else ()
    own = next((fw for fw in rules if set(values(fw, "ciamSourceCidr")) & set(moved)), None)
    if own is not None:
        old = tuple(c for c in values(own, "ciamSourceCidr") if c in moved)
        return Fix(f"ports:{lst.server_role}:{lst.port}:from-{flow.source}", "Ports",
                   f"Replace {', '.join(old)} with {cidrs} (`{flow.source}`) in rule `{rdn_value(own)}` "
                   f"({lst.server_role} on {lst.protocol} {lst.port}, {lst.purpose})",
                   (set_values(own, "ciamSourceCidr",
                               (*(c for c in values(own, "ciamSourceCidr") if c not in moved), *uncovered)),),
                   (f"Apply {m.label}'s rendered firewall rules (the platform's Terraform).",),
                   (f"Admits exactly {cidrs}, where `{flow.source}` runs now, and closes {', '.join(old)}: where it "
                    f"ran in {src.label}'s layout, which nothing in {m.label} runs in.",))
    cn = f"fw-{flow.source}-to-{lst.server_role}-{lst.port}"
    record = (add_values(rules[0], "ciamSourceCidr", uncovered) if rules else
              new_entry(f"cn={cn},ou=bindings,{m.dn}", ("top", "ciamFirewallRule"), {
                  "cn": (cn,), "ciamBindingRole": (cn,), "ciamSourceCidr": uncovered, "ciamPort": (str(lst.port),),
                  "ciamTargetRole": (lst.server_role,), "ciamProtocol": (lst.protocol,)}))
    return Fix(f"ports:{lst.server_role}:{lst.port}:from-{flow.source}", "Ports",
               f"Admit {cidrs} (`{flow.source}`) to `{lst.server_role}` on {lst.protocol} {lst.port} ({lst.purpose})"
               + (f" in rule `{rdn_value(rules[0])}`" if rules else f" in a new rule `{cn}`"), (record,),
               (f"Apply {m.label}'s rendered firewall rules (the platform's Terraform).",),
               (f"Admits exactly {cidrs}, the ranges `{flow.source}`'s servers sit in; if they shouldn't reach "
                f"`{lst.server_role}` on {lst.port}, what to change is the product's listener, not the rule.",))


def stray_fix(m, listeners, fw):
    """The Fix closing what a rule opens that nothing listens on: the stray ports dropped from it, or the rule
    deleted when all of its ports are."""
    stray = stray_ports(m, listeners, fw)
    whole = len(stray) == len(values(fw, "ciamPort"))
    return Fix(f"stray-rule:{rdn_value(fw)}", "Ports",
               f"Close {'rule' if whole else 'ports ' + ', '.join(stray) + ' of rule'} `{rdn_value(fw)}` in {m.label}",
               (delete_entry(fw) if whole else delete_values(fw, "ciamPort", stray),),
               (f"Apply {m.label}'s rendered firewall rules (the platform's Terraform).",),
               ("If something the record doesn't know listens there (a product or agent no adapter declares), it "
                "loses its traffic: record that listener instead.",))


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
    fixes = [*(x for f, status, _ in gaps if target and status == UNCOVERED
               for x in (ports_fix(m, f, ctx.src),) if x),
             *(stray_fix(m, declared, fw) for fw in stray if target)]
    return findings(blockers=blockers, actions=actions, ok=ok, fixes=fixes)


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
