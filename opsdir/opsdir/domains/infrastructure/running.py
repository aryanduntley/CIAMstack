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

Where the manager's firewalls were read too, each is a ciamManagedFirewall under the manager's appliance (connected,
in sync, software version, high-availability peer) with, per rule of the environment, a ciamRuleObservation: deployed,
disabled or missing in the policy pushed to it, and its hit counts. The rule's state is then their rollup (deployed:
every firewall runs it; partial: not every one). The planner names partial rules, firewalls disconnected or out of
sync, and rules no firewall has hit for firewall-unused-rule-days (still needed? and should a move's target get them?).
"""

from ...core.directory import children, date_of, get, make_entry, merged_attrs, one, rdn_value, subtree, values, within
from ...core.environment import of_class
from ...core.findings import findings, merge_findings, responsible
from ...core.naming import env_label
from ...core.settings import setting_value
from ..governance.imports import environment_of_scope, runs_covering
from .appliances import appliances
from .naming import ACCESS_FACTS, ENVIRONMENTS, EXTERNAL_ALLOWLISTS, OWNED_FACTS
from .settings import UNUSED_RULE_DAYS

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


FIREWALL_CLASS, OBSERVATION_CLASS = "ciamManagedFirewall", "ciamRuleObservation"
FIREWALL_ATTRS = ("cn", "ciamDeviceName", "ciamDeviceContext", "ciamApplianceScope", "ciamDeviceConnected",
                  "ciamSoftwareVersion", "ciamHaState", "ciamPolicySync")
OBSERVATION_ATTRS = ("cn", "ciamRunningState", "ciamDeviceContext", "ciamHitCount", "ciamFirstHit", "ciamLastHit",
                     "ciamCountedSince")


def _owned(facts):
    return {k: v if isinstance(v, tuple) else (v,) for k, v in facts.items()}


def managed_firewall(d, appliance, serial, facts):
    """A firewall manager appliance's managed firewall (cn: its serial) with facts {attribute of FIREWALL_ATTRS: value,
    values or None}; what the record adds kept."""
    dn = f"cn={serial},{appliance.dn}"
    return make_entry(dn, ("top", "ciamObject", FIREWALL_CLASS),
                      merged_attrs(get(d, dn), {"cn": (serial,), **_owned(facts)}, FIREWALL_ATTRS))


def rule_observation(firewall, rule, context, state, hits=None):
    """What a managed firewall runs of the environment's rule named rule in one of its virtual contexts: its state
    (OBSERVED_STATES) and hits {ciamHitCount, ciamFirstHit, ciamLastHit, ciamCountedSince: value or None}."""
    attrs = {"cn": (f"{rule}/{context}",), "ciamRunningState": (state,), "ciamDeviceContext": (context,),
             **{k: (v,) for k, v in (hits or {}).items() if v is not None}}
    return make_entry(f"cn={rule}/{context},{firewall.dn}", ("top", "ciamObject", OBSERVATION_CLASS), attrs)


def rollup(states):
    """A rule's running state from what each managed firewall runs of it: the state they share, else partial."""
    found = set(states)
    return next(iter(found)) if len(found) == 1 else "partial"


def managed_firewalls(d, appliance):
    return children(d, appliance.dn, FIREWALL_CLASS)


def observations_of(d, rule, appliances_):
    """((managed firewall, observation), ...) of a record rule across the appliances' managed firewalls."""
    cn = rdn_value(rule)
    return tuple((fw, o) for a in appliances_ for fw in managed_firewalls(d, a)
                 for o in children(d, fw.dn, OBSERVATION_CLASS) if rdn_value(o).rsplit("/", 1)[0] == cn)


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


def _where(seen):
    return ", ".join(f"{rdn_value(fw)}/{one(o, 'ciamDeviceContext')}" for fw, o in seen)


def _partial(ctx, m, fw, keepers):
    """A rule some of its manager's firewalls don't run as the manager has it."""
    seen = observations_of(ctx.d, fw, keepers)
    off = [(f, o) for f, o in seen if one(o, "ciamRunningState") != "deployed"]
    if one(fw, "ciamRunningState") != "partial" or not off:
        return []
    by = {s: [(f, o) for f, o in off if one(o, "ciamRunningState") == s] for s in ("missing", "disabled")}
    return [("Firewall", f"`{rdn_value(fw)}` in {m.label} runs on {len(seen) - len(off)} of the {len(seen)} firewalls "
             "its manager pushes to"
             + "".join(f"; {s} on {_where(by[s])}" for s in ("missing", "disabled") if by[s])
             + ": push the device group again (or reconnect the firewall), then read it back.",
             responsible(ctx.d, *keepers, m.env), None)]


def _unused(ctx, m, fw, keepers, days):
    """A rule every firewall running it counted for at least `days` without a hit (an unknown count or start: not
    judged)."""
    seen = [(f, o) for f, o in observations_of(ctx.d, fw, keepers) if one(o, "ciamRunningState") == "deployed"]
    counts = [one(o, "ciamHitCount") for _, o in seen]
    since = [date_of(o, "ciamCountedSince") for _, o in seen]
    if not seen or any(c is None for c in counts) or any(int(c) for c in counts) or any(s is None for s in since):
        return []
    start = max(since)
    if (ctx.as_of - start).days < days:
        return []
    return [("Firewall", f"`{rdn_value(fw)}` in {m.label} has no hits on any of the {len(seen)} firewall(s) running it "
             f"since "
             f"{start} ({(ctx.as_of - start).days} days): confirm it is still needed, else delete it; before a move, "
             "decide whether the target should get it at all.", responsible(ctx.d, fw, m.env), None)]


def _firewall_state(ctx, m, a):
    """A managed firewall that its manager says is disconnected or not running the policy it pushed."""
    return [("Firewall", f"`{rdn_value(f)}` ({one(f, 'ciamDeviceName') or 'firewall'} behind `{rdn_value(a)}`, "
             f"{m.label}) {why}: what its manager commits doesn't reach it as the record says.",
             responsible(ctx.d, a, m.env), None)
            for f in managed_firewalls(ctx.d, a)
            for why in ((["isn't connected to its manager"] if one(f, "ciamDeviceConnected") == "FALSE" else [])
                        + ([f"has policy {one(f, 'ciamPolicySync')}"]
                           if (one(f, "ciamPolicySync") or "in sync").replace("-", " ").lower() != "in sync"
                           else []))]


def _environment(ctx, m):
    rules = [fw for fw in of_class(m, "ciamFirewallRule") if within(fw.dn, m.dn)
             and (one(fw, "ciamRunningState") or values(fw, "ciamRunningFact"))]
    keepers = [a for a in appliances(m, NETWORK_FIREWALL) if within(a.dn, m.dn)]
    days = setting_value(ctx.d, UNUSED_RULE_DAYS)
    unrecorded = [(a, text) for a in keepers for text in values(a, "ciamUnrecordedRule")]
    committed = [fw for fw in rules if one(fw, "ciamRunningState") == "committed"]
    return findings(
        actions=[*(row for fw in rules for row in _rule(ctx, m, fw, keepers)),
                 *(row for fw in rules for row in _partial(ctx, m, fw, keepers)),
                 *(row for fw in rules for row in _unused(ctx, m, fw, keepers, days)),
                 *(row for a in keepers for row in _firewall_state(ctx, m, a)),
                 *(("Firewall", f"`{rdn_value(a)}` ({m.label}'s network firewall) runs a rule the record doesn't hold: "
                    f"{text}. Record it (a firewall rule with a role), or remove it there.",
                    responsible(ctx.d, a, m.env), None) for a, text in unrecorded)],
        ok=[f"{len(committed)} of {m.label}'s firewall rule(s) are committed on their firewall manager as the record "
            "says; their delivery to the firewalls isn't confirmed by that read."] if committed else [])


def check_firewall_running(ctx):
    """The source's and the target's firewall rules as last read back from their firewall managers: each rule
    missing, disabled, running what the record owns otherwise, or admitting less through the network team's settings,
    and each rule an appliance runs that the record doesn't hold, is an action; rules committed on a manager are fine,
    their delivery unconfirmed. Where the manager's firewalls were read: a rule some of them don't run, a firewall
    disconnected or out of sync, and a rule none of them has hit for firewall-unused-rule-days are actions. An
    environment nothing was read back from has nothing to compare."""
    envs = {m.dn.lower(): m for m in (ctx.src, ctx.dst)}
    return merge_findings([_environment(ctx, m) for m in envs.values()])


def _label(e):
    """A report row's entry: a rule or appliance by name; a managed firewall '<appliance>/<serial>'; an observation
    '<rule> @ <serial>/<context>'."""
    if OBSERVATION_CLASS in e.classes:
        rule, context = rdn_value(e).rsplit("/", 1)
        return f"{rule} @ {e.dn.split(',')[1].split('=', 1)[1]}/{context}"
    if FIREWALL_CLASS in e.classes:
        return f"{e.dn.split(',')[1].split('=', 1)[1]}/{rdn_value(e)}"
    return rdn_value(e)


def _device(f):
    connected = {"TRUE": "connected", "FALSE": "disconnected"}.get(one(f, "ciamDeviceConnected"))
    return ", ".join(v for v in (one(f, "ciamDeviceName"), connected, one(f, "ciamPolicySync"),
                                 one(f, "ciamSoftwareVersion"), one(f, "ciamHaState"),
                                 " ".join(values(f, "ciamDeviceContext"))) if v)


def _hits(o):
    count = one(o, "ciamHitCount")
    return ", ".join(v for v in (f"hits {count}" if count is not None else None,
                                 f"since {date_of(o, 'ciamCountedSince')}" if one(o, "ciamCountedSince") else None,
                                 f"last {date_of(o, 'ciamLastHit')}" if one(o, "ciamLastHit") else None) if v)


def firewall_running_rows(d, dn=None):
    """Each environment's firewall rules as last read back (state, what each runs that the record doesn't) and each
    network firewall's rules the record doesn't hold, with when the import covering it read the live system."""
    rules = [(fw, one(fw, "ciamRunningState") or "", ", ".join(values(fw, "ciamRunningFact")))
             for fw in subtree(d, ENVIRONMENTS, "ciamFirewallRule")
             if one(fw, "ciamRunningState") or values(fw, "ciamRunningFact")]
    unrecorded = [(a, "unrecorded", text) for a in subtree(d, ENVIRONMENTS, "ciamAppliance")
                  for text in values(a, "ciamUnrecordedRule")]
    firewalls = [(f, "firewall", _device(f)) for f in subtree(d, ENVIRONMENTS, FIREWALL_CLASS)]
    seen = [(o, one(o, "ciamRunningState"), _hits(o)) for o in subtree(d, ENVIRONMENTS, OBSERVATION_CLASS)]
    return sorted(((env_label(environment_of_scope(e.dn)), _label(e), state, runs, _read_at(d, e) or "")
                   for e, state, runs in (*rules, *unrecorded, *firewalls, *seen)
                   if dn is None or within(e.dn, dn)), key=lambda r: (r[0], r[2] == "unrecorded", r[1], r[3]))
