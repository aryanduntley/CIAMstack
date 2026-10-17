"""MITRE ATT&CK (Enterprise) as Elastic Security's detection rules map it (a rule's threat array), from the tactics and
techniques an alert rule records (core ciamAttackTactic, ciamAttackTechnique). Pure.

A rule's threat array holds an entry per tactic, framework "MITRE ATT&CK": the tactic's ID, name and reference (its
ATT&CK page), and the techniques detected under it, each with its ID, name and reference and its sub-techniques
(likewise), as the Kibana detection engine API documents them (each of those fields required; a sub-technique nested
in its parent technique) and Elastic's prebuilt rules write them. The record names a tactic by its short name and a
technique by its ID only: their IDs, names and tactics are the core's ATT&CK table's (observability.attack, ATT&CK
v20, generated from MITRE's STIX bundle).

A recorded technique is placed under each recorded tactic it serves in ATT&CK; one serving none of them, or not in
the core's ATT&CK version, is left out (attack.unplaced: the detection's render note names it), and so is a tactic
that version retired (attack.retired_tactics, defense-evasion: likewise a note; the planner asks for its successor).
"""
from opsdir.domains.observability.attack import TACTICS, parent, placed, reference, tactic_entry, technique_name

FRAMEWORK = "MITRE ATT&CK"


def _technique(technique):
    return {"id": technique, "name": technique_name(technique), "reference": reference(technique)}


def threat(tactics, techniques):
    """A rule's threat array: an entry per tactic (short names, the record's order) with the techniques serving it,
    each sub-technique under its parent technique; [] when no tactic is recorded."""
    def entry(tactic):
        found = placed(tactic, techniques)
        parents = dict.fromkeys(parent(t) for t in found)
        return {"framework": FRAMEWORK, "tactic": tactic_entry(tactic), **({"technique": [
            {**_technique(p), **({"subtechnique": [_technique(t) for t in subs]} if subs else {})}
            for p in parents for subs in (tuple(t for t in found if "." in t and parent(t) == p),)]}
            if parents else {})}
    return [entry(t) for t in tactics if t in TACTICS]
