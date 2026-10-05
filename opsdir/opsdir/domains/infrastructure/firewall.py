"""Firewall rules as renderers write them, shared by every cloud adapter. Pure.

Providers that order rules by number (Azure network security groups, Google Cloud VPC firewall rules) take each
rule's priority from the record (ciamRulePriority), so adding a rule never renumbers the others; a rule without one
takes the next free slot, which the renderer flags so someone pins it, and the planner offers to pin (priority_check):
only after a fresh import of the environment's rules, since a slot free in the record may be taken by a live rule the
record lacks.
"""
from functools import reduce

from ...core.changeset import set_values
from ...core.directory import follow, one, rdn_value, within
from ...core.environment import of_class
from ...core.findings import Fix, Requirement, findings, responsible


def rule_priorities(rules, first, step, last):
    """{rule DN: (priority, pinned)}: pinned priorities kept, unpinned rules given the next free slot from first by
    step (up to last), in rule order."""
    pinned = frozenset(int(one(f, "ciamRulePriority")) for f in rules if one(f, "ciamRulePriority"))

    def assign(acc, fw):
        assigned, used = acc
        if one(fw, "ciamRulePriority"):
            return {**assigned, fw.dn: (int(one(fw, "ciamRulePriority")), True)}, used
        prio = next(p for p in range(first, last + 1, step) if p not in used)
        return {**assigned, fw.dn: (prio, False)}, used | {prio}

    return reduce(assign, rules, ({}, pinned))[0]


def rule_purpose(m, fw):
    """What a firewall rule is for: the consumer it admits, else its binding role."""
    consumer = follow(m.d, fw, "ciamAllowsConsumer")
    return f"consumer {rdn_value(consumer)}" if consumer else one(fw, "ciamBindingRole")


def priority_check(first, step, last):
    """A planner check for a provider that orders rules by number in [first, last] (its renderer's rule_priorities):
    the target's rules without a pinned priority are an action, with the fix pinning the slots the render assigns
    them, once an import read the environment's rules after their last change."""
    def check_priorities(ctx):
        m = ctx.dst
        rules = of_class(m, "ciamFirewallRule")
        prios = rule_priorities(rules, first, step, last)
        unpinned = [fw for fw in rules if not prios[fw.dn][1]]
        if not unpinned:
            return findings()
        own = [fw for fw in unpinned if within(fw.dn, m.dn)]
        named = ", ".join(f"`{rdn_value(fw)}` {prios[fw.dn][0]}" for fw in unpinned)
        inherited = [rdn_value(fw) for fw in unpinned if fw not in own]
        fix = Fix(f"priorities:{m.label}", "Firewall",
                  f"Pin the priorities {m.label}'s render assigns to {len(own)} firewall rule(s)",
                  tuple(set_values(fw, "ciamRulePriority", (str(prios[fw.dn][0]),)) for fw in own),
                  (f"Apply {m.label}'s rendered firewall rules.",),
                  ("Pins the slots free in the record when the import ran; a live rule added since would collide.",),
                  requires=(Requirement(tuple(fw.dn for fw in rules if within(fw.dn, m.dn)),
                                        f"{m.label}'s firewall rules as they run, so the slots are free there too"),))
        return findings(actions=[("Firewall", f"{len(unpinned)} firewall rule(s) in {m.label} have no pinned priority "
                                  f"({named}): the render assigns free slots that a live rule the record lacks may "
                                  f"already hold. Import {m.label}'s rules, then pin them."
                                  + (f" Inherited from a base environment, pinned there: {', '.join(inherited)}."
                                     if inherited else ""), responsible(ctx.d, m.env), None)],
                        fixes=[fix] if own else [])
    return check_priorities
