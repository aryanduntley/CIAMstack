"""Firewall rules as a firewall manager runs them, read back (milestone 6.2c): what the importers of the
network-firewall add-ons (PAN-OS/Panorama first; a firewall manager such as AlgoSec, Tufin or FireMon later) observe in
the running configuration beyond the neutral rule's own attributes, and the planner's check and report of it.
Vendor-neutral. Pure.

An import reads the rule's sources, ports, protocol and target role into the rule itself, where a difference is the
import's conflict to take or keep. What the rule can't hold is observed: where the running configuration holds it
(ciamRunningState: committed on a manager, deployed on a firewall, disabled, missing), what it runs that the record
owns otherwise (ciamRunningFact: an action, logging, destinations that aren't the target role's servers, a description,
a source or service the import can't resolve: the next push restores the record's) and the network team's settings
that limit what it admits (negation, a schedule, another rulebase); and on the appliance, the rules it runs that the
record doesn't hold (ciamUnrecordedRule). An external allowlist whose ciamAllowlistRef names an object the import read
records the addresses it holds (ciamRecordedCidr), so the allowlist check sees whether it covers ours; its request
status stays the person's.
"""
from ...core.directory import make_entry, one, rdn_value, subtree, values, within
from ...core.environment import of_class
from ...core.findings import findings, merge_findings, responsible
from ...core.naming import env_label
from ..governance.imports import environment_of_scope, runs_covering
from .appliances import appliances
from .naming import ACCESS_FACTS, ENVIRONMENTS, EXTERNAL_ALLOWLISTS, OWNED_FACTS

NETWORK_FIREWALL = "network-firewall"
FIREWALL_RUNNING_HEADERS = ("environment", "entry", "state", "runs", "read at")


def _with(e, attr, vals):
    vals = tuple(dict.fromkeys(vals))
    return make_entry(e.dn, e.classes, {**{k: v for k, v in e.attrs.items() if k != attr},
                                        **({attr: vals} if vals else {})})


def observed_rule(e, state, facts):
    """Firewall rule e with what a read-back of its running configuration observed: its state (RUNNING_STATES) and
    facts ('<key> <value>'), each replacing what the rule held (none: removed)."""
    return _with(_with(e, "ciamRunningState", (state,) if state else ()), "ciamRunningFact", sorted(facts))


def observed_appliance(a, unrecorded):
    """Appliance a with the rules its running configuration holds that the record doesn't (none: removed)."""
    return _with(a, "ciamUnrecordedRule", sorted(unrecorded))


def allowlist_refs(d, adapter):
    """((external allowlist, path), ...): the allowlists whose ciamAllowlistRef an adapter's importer reads
    ('<adapter>:<path>'), with the path after the prefix."""
    prefix = f"{adapter}:"
    return tuple((xa, one(xa, "ciamAllowlistRef")[len(prefix):])
                 for xa in subtree(d, EXTERNAL_ALLOWLISTS, "ciamExternalAllowlist")
                 if (one(xa, "ciamAllowlistRef") or "").startswith(prefix))


def recorded_allowlist(xa, cidrs):
    """External allowlist xa with the addresses its system holds today (ciamRecordedCidr), as a read-back saw them."""
    return _with(xa, "ciamRecordedCidr", cidrs)


def _key(fact):
    return fact.split(" ", 1)[0]


def running_facts(e):
    """(owned, access): a rule's ciamRunningFact values the record owns (the next push restores them) and the network
    team's settings that limit what it admits."""
    facts = values(e, "ciamRunningFact")
    return (tuple(f for f in facts if _key(f) in OWNED_FACTS), tuple(f for f in facts if _key(f) in ACCESS_FACTS))


def _read_at(d, e):
    runs = runs_covering(d, e.dn)
    return one(runs[0], "ciamImportedAt") if runs else None


def _shown(facts):
    return ", ".join(f"`{f}`" for f in facts)


def _rule(ctx, m, fw, keepers):
    name, state = f"`{rdn_value(fw)}` in {m.label}", one(fw, "ciamRunningState")
    owned, access = running_facts(fw)
    when = f" (read {_read_at(ctx.d, fw) or 'back'})"
    team = responsible(ctx.d, *keepers, m.env)
    return [
        *([("Firewall", f"{name} isn't in its firewall's running configuration{when}: push {m.label}'s firewall rules "
            "(the add-on's play), or delete the rule if it was removed on purpose.",
            responsible(ctx.d, fw, m.env), None)] if state == "missing" else []),
        *([("Firewall", f"{name} is disabled on its firewall{when}: what it admits is blocked. Enable it there, or "
            "delete the rule if it is no longer needed.", team, None)] if state == "disabled" else []),
        *([("Firewall", f"{name} runs {_shown(owned)}, which the record doesn't say{when}: the next push restores the "
            "record's. If the change was meant, change the record (or the rule's role and servers) to say it.",
            responsible(ctx.d, fw, m.env), None)] if owned else []),
        *([("Firewall", f"{name} admits less than the record says: {_shown(access)} (the network team's settings)"
            f"{when}. Confirm they are meant.", team, None)] if access else [])]


def _environment(ctx, m):
    rules = [fw for fw in of_class(m, "ciamFirewallRule") if within(fw.dn, m.dn)
             and (one(fw, "ciamRunningState") or values(fw, "ciamRunningFact"))]
    keepers = [a for a in appliances(m, NETWORK_FIREWALL) if within(a.dn, m.dn)]
    unrecorded = [(a, text) for a in keepers for text in values(a, "ciamUnrecordedRule")]
    committed = [fw for fw in rules if one(fw, "ciamRunningState") == "committed"]
    return findings(
        actions=[*(row for fw in rules for row in _rule(ctx, m, fw, keepers)),
                 *(("Firewall", f"`{rdn_value(a)}` ({m.label}'s network firewall) runs a rule the record doesn't hold: "
                    f"{text}. Record it (a firewall rule with a role), or remove it there.",
                    responsible(ctx.d, a, m.env), None) for a, text in unrecorded)],
        ok=[f"{len(committed)} of {m.label}'s firewall rule(s) are committed on their firewall manager as the record "
            "says; their delivery to the firewalls isn't confirmed by that read."] if committed else [])


def check_firewall_running(ctx):
    """The source's and the target's firewall rules as last read back from their firewall managers: each rule
    missing, disabled, running what the record owns otherwise, or admitting less through the network team's settings,
    and each rule an appliance runs that the record doesn't hold, is an action; rules committed on a manager are fine,
    their delivery unconfirmed. An environment nothing was read back from has nothing to compare."""
    envs = {m.dn.lower(): m for m in (ctx.src, ctx.dst)}
    return merge_findings([_environment(ctx, m) for m in envs.values()])


def firewall_running_rows(d, dn=None):
    """Each environment's firewall rules as last read back (state, what each runs that the record doesn't) and each
    network firewall's rules the record doesn't hold, with when the import covering it read the live system."""
    rules = [(fw, one(fw, "ciamRunningState") or "", ", ".join(values(fw, "ciamRunningFact")))
             for fw in subtree(d, ENVIRONMENTS, "ciamFirewallRule")
             if one(fw, "ciamRunningState") or values(fw, "ciamRunningFact")]
    unrecorded = [(a, "unrecorded", text) for a in subtree(d, ENVIRONMENTS, "ciamAppliance")
                  for text in values(a, "ciamUnrecordedRule")]
    return sorted(((env_label(environment_of_scope(e.dn)), rdn_value(e), state, runs, _read_at(d, e) or "")
                   for e, state, runs in (*rules, *unrecorded)
                   if dn is None or within(e.dn, dn)), key=lambda r: (r[0], r[2] == "unrecorded", r[1], r[3]))
