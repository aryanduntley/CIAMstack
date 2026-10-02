"""Firewall rules as renderers write them, shared by every cloud adapter. Pure.

Providers that order rules by number (Azure network security groups, Google Cloud VPC firewall rules) take each
rule's priority from the record (ciamRulePriority), so adding a rule never renumbers the others; a rule without one
takes the next free slot, which the renderer flags so someone pins it.
"""
from functools import reduce

from ...core.directory import follow, one, rdn_value


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
