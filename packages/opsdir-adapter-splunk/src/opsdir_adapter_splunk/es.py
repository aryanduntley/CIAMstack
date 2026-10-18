"""Splunk Enterprise Security (ES): what a detection's saved search adds as an ES correlation search, where the
environment's stack declares the Splunk component's offering enterprise-security (naming.enterprise_security), and
what a plain saved search can't hold. Pure.

A correlation search is a saved search in savedsearches.conf marked action.correlationsearch.enabled = 1 with a label
(the alert rule), ES's documented settings (research on milestone 109, section 1; task 587):
- its MITRE ATT&CK techniques (the alert rule's ciamAttackTechnique, sub-techniques as recorded) as the annotations
  ES stores in action.correlationsearch.annotations, JSON {"mitre_attack": ["T1110.003", ...]}: ES enriches the
  tactics from the technique IDs, so the rule's tactics alone (ciamAttackTactic) aren't rendered (a note); a
  technique the core's ATT&CK version (observability.attack, v20) doesn't hold, retired or never in ATT&CK, is left
  out (a note; the planner asks for its replacement);
- a notable (ES 8: a finding) per result: action.notable = 1, its rule_title the alert rule and its rule_description
  the rule's description (siem.described);
- for a rows detection (core ciamDetectionMode rows) mapping entities (ciamEntityMapping), the risk action:
  action.risk = 1 and the JSON list action.risk.param._risk, a risk object per account name (risk_object_type user)
  and host name (system), its column the risk_object_field and its risk_score the alert rule's severity (sev0 99, sev1
  73, sev2 47, sev3 and sev4 21; 47 when none: Elastic's scale, so both SIEMs score a rule alike), and a threat object
  per IP address (threat_object_field, threat_object_type ip_address); for an alert rule rendered from a product's
  declared detection (adopted), the same for the fields it groups by (a subject or actor as a user, a source address
  as a threat object: search_settings with risk_entries).
The entity mappings ES has no documented type for (an account's other identifiers, a host's DNS domain, a URL, an
application) are notes; the notable's severity and security domain aren't rendered (ES's stored values for them
aren't established) and are set in ES, with the check that ES 8.7 reads these settings as it saves a detection (an
action).

On the plain Splunk platform a saved search has no place for ATT&CK or entities: a detection recording them says so
(a note).

Read back (risk_mappings): a saved search's risk objects and threat objects are the entity mappings they were
rendered from.
"""
import json

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.notes import note
from opsdir.domains.observability.attack import VERSION, technique_name, unknown_techniques
from opsdir.domains.observability.siem import described, detection_mode, entity_mappings

RISK_SCORES = {"sev0": 99, "sev1": 73, "sev2": 47, "sev3": 21, "sev4": 21}
UNRATED = 47
# a core entity mapping (entity, identifier) as an ES risk object's type (ES: system, user or other)
RISK_OBJECTS = {("account", "name"): "user", ("host", "hostname"): "system"}
# ... as an ES threat object's type (ES documents ip_address)
THREAT_OBJECTS = {("ip", "address"): "ip_address"}
CORE_RISK = {v: k for k, v in RISK_OBJECTS.items()}
CORE_THREAT = {v: k for k, v in THREAT_OBJECTS.items()}


def annotations(rule):
    """The annotations (JSON text) of an alert rule's ATT&CK techniques the core's ATT&CK version holds, or None when
    it records none of them."""
    found = tuple(t for t in values(rule, "ciamAttackTechnique") if technique_name(t) is not None)
    return json.dumps({"mitre_attack": list(found)}, separators=(",", ":")) if found else None


def risk_objects(s):
    """The risk action's objects of detection spec s (a rows detection's entity mappings ES has a type for, in the
    record's order): a risk object per account or host, a threat object per IP address; () for a count detection."""
    return risk_entries(s.rule, entity_mappings(s.alarm)) if detection_mode(s.alarm) == "rows" else ()


def risk_entries(rule, mapped):
    """The risk action's objects of an alert rule's search whose results name mapped ((entity, identifier, result
    column), ...), those ES has a type for, in order: a risk object per account or host (its risk score the rule's
    severity), a threat object per IP address."""
    score = RISK_SCORES.get(one(rule, "ciamSeverity") or "", UNRATED)
    return tuple({"risk_object_field": col, "risk_object_type": RISK_OBJECTS[(e, i)], "risk_score": score}
                 if (e, i) in RISK_OBJECTS else
                 {"threat_object_field": col, "threat_object_type": THREAT_OBJECTS[(e, i)]}
                 for e, i, col in mapped if (e, i) in RISK_OBJECTS or (e, i) in THREAT_OBJECTS)


def correlation_settings(s):
    """The settings detection spec s's saved search adds as an ES correlation search (search_settings)."""
    return search_settings(s.rule, risk_objects(s))


def search_settings(alert_rule, found):
    """The settings an alert rule's saved search adds as an ES correlation search: the marker and label, its ATT&CK
    annotations, the notable, and the risk action when found (risk_entries) names risk or threat objects."""
    rule, marks = rdn_value(alert_rule), annotations(alert_rule)
    return (("action.correlationsearch.enabled", "1"), ("action.correlationsearch.label", rule),
            *((("action.correlationsearch.annotations", marks),) if marks else ()),
            ("action.notable", "1"), ("action.notable.param.rule_title", rule),
            ("action.notable.param.rule_description", described(rule)),
            *((("action.risk", "1"), ("action.risk.param._risk", json.dumps(list(found)))) if found else ()))


def risk_mappings(text):
    """The entity mappings ('<entity> <identifier>=<column>', in order) of a risk action's objects (the text of
    action.risk.param._risk): its risk objects and threat objects of the types the render writes; () when they aren't
    a JSON list."""
    try:
        found = json.loads(text or "[]")
    except ValueError:
        return ()
    def mapped(x):
        key = (CORE_RISK.get(x.get("risk_object_type")) if "risk_object_field" in x
               else CORE_THREAT.get(x.get("threat_object_type")))
        column = x.get("risk_object_field") or x.get("threat_object_field")
        return f"{key[0]} {key[1]}={column}" if key and isinstance(column, str) and column else None
    return tuple(m for m in (mapped(x) for x in (found if isinstance(found, list) else []) if isinstance(x, dict)) if m)


def attack_notes(m, rule):
    """Notes of what an alert rule's correlation search doesn't annotate of its ATT&CK: tactics recorded without
    techniques, techniques the core's ATT&CK version doesn't hold."""
    name = rdn_value(rule)
    bare = values(rule, "ciamAttackTactic") if not values(rule, "ciamAttackTechnique") else ()
    gone = unknown_techniques(values(rule, "ciamAttackTechnique"))
    return (*((note("Monitoring", "note", f"alert rule {name}", f"its ATT&CK tactics {', '.join(bare)} aren't "
                    "annotated: ES annotates a correlation search by technique (mitre_attack) and derives the "
                    "tactics, and the rule records no technique (ciamAttackTechnique)",
                    ("Record the techniques it detects (ciamAttackTechnique)",), rule.dn, m.label),)
              if bare else ()),
            *((note("Monitoring", "note", f"alert rule {name}", f"its ATT&CK techniques {', '.join(gone)} aren't "
                    f"annotated: they aren't in {VERSION} (retired, or never in ATT&CK)",
                    ("Apply the plan's fix replacing them (ciamAttackTechnique)",), rule.dn, m.label),)
              if gone else ()))


def es_notes(m, specs, rules=()):
    """Notes of the ES correlation searches of environment m's rendered detection specs and of the alert rules
    rendered from a product's declaration (rules): entity mappings ES has no type for, tactics recorded without
    techniques, techniques the core's ATT&CK version doesn't hold (notes), and what ES keeps to the Splunk team (an
    action)."""
    def of(s):
        left = tuple(f"{e} {i}" for e, i, _ in entity_mappings(s.alarm)
                     if (e, i) not in RISK_OBJECTS and (e, i) not in THREAT_OBJECTS) \
            if detection_mode(s.alarm) == "rows" else ()
        return (*((note("Monitoring", "note", f"alert rule {rdn_value(s.rule)}", f"its entity mappings "
                        f"{', '.join(left)} aren't risk or threat objects of its correlation search: opsdir renders an "
                        "account's name and a host's name as risk objects and an IP address as a threat object, the "
                        "types ES documents",
                        ("Add them to the correlation search's risk modifiers in ES if needed",), s.alarm.dn,
                        m.label),) if left else ()),
                *attack_notes(m, s.rule))
    return (*(n for s in specs for n in of(s)), *(n for r in rules for n in attack_notes(m, r)),
            *((note("Monitoring", "action", "Splunk Enterprise Security", "the detections are rendered as correlation "
                    "searches with the notable (action.notable) and risk (action.risk) settings ES documents; their "
                    "findings' severity and security domain aren't rendered (the values ES stores for them aren't "
                    "established), and that ES 8 reads these settings as it saves a detection (findings and "
                    "intermediate findings) isn't established either",
                    ("Set each correlation search's finding severity and security domain in ES",
                     "Before installing the app, compare one detection saved in ES (its savedsearches.conf stanza) "
                     "with these and report a difference to the opsdir team"), None, m.label),)
              if specs or rules else ()))


def _platform_note(m, rule, found, dn):
    return note("Monitoring", "note", f"alert rule {rdn_value(rule)}", f"{' and '.join(found)} aren't rendered: a "
                "saved search has no place for them (a Splunk Enterprise Security correlation search does)",
                ("If the environment runs Splunk Enterprise Security, declare its Splunk stack component's offering "
                 "enterprise-security (ciamOffering)",), dn, m.label)


def platform_notes(m, specs, rules=()):
    """Notes of environment m's rendered detection specs, and alert rules rendered from a product's declaration
    (rules), recording ATT&CK or entity mappings a plain saved search has no place for."""
    def attack(rule):
        return (["its ATT&CK tactics and techniques"]
                if values(rule, "ciamAttackTactic") or values(rule, "ciamAttackTechnique") else [])

    def what(s):
        return (*attack(s.rule),
                *(["its entity mappings"] if detection_mode(s.alarm) == "rows" and entity_mappings(s.alarm) else []))
    return (*(_platform_note(m, s.rule, found, s.alarm.dn) for s in specs for found in (what(s),) if found),
            *(_platform_note(m, r, attack(r), r.dn) for r in rules if attack(r)))
