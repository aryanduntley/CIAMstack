"""MITRE ATT&CK Enterprise, the version the record follows (attack_table: ATT&CK v20, generated from MITRE's STIX
bundle by scripts/gen-attack.py): what an alert rule's tactics and techniques (ciamAttackTactic by short name,
ciamAttackTechnique by ID) are, for every SIEM adapter to render its own way, and the planner's check of what the
record still holds of retired ATT&CK. Pure.

A technique serves the tactics ATT&CK lists for it: placed under a recorded tactic it serves, unplaced when it serves
none of them or isn't in this version. ATT&CK retires a technique ID by revoking it (another technique replaces it)
or deprecating it (nothing does), and a tactic's short name by renaming it (v19 split defense-evasion into stealth and
defense-impairment). Records and imports holding a retired value keep working (the vocabulary still accepts
defense-evasion), but every SIEM following the current ATT&CK maps it wrong or not at all, so the check makes each
one an action of the alert rule's owner, with a fix replacing it by what ATT&CK says replaced it (the owner's choice
where there are several), or removing a deprecated technique: never rewritten without someone approving it.
"""
from ...core.changeset import add_values, delete_values
from ...core.directory import rdn_value, values
from ...core.findings import Fix, Option, findings, merge_findings, responsible
from .alerts import alert_rules
from .attack_table import ATTACK_VERSION, RETIRED, RETIRED_TACTICS, TACTICS, TECHNIQUES

SITE = "https://attack.mitre.org"
AREA = "Alert"
VERSION = f"ATT&CK v{ATTACK_VERSION.removesuffix('.0')}"        # the version as a person names it (ATT&CK v20)


def parent(technique):
    """A sub-technique's parent technique ID (T1110.003 -> T1110); a technique's own ID."""
    return technique.split(".", 1)[0]


def reference(technique):
    """A technique's ATT&CK page: T1110 -> .../techniques/T1110/, T1110.003 -> .../techniques/T1110/003/."""
    return f"{SITE}/techniques/{technique.replace('.', '/')}/"


def tactic_entry(tactic):
    """An ATT&CK tactic (short name) as its ID, name and ATT&CK page: {id, name, reference}."""
    found, name = TACTICS[tactic]
    return {"id": found, "name": name, "reference": f"{SITE}/tactics/{found}/"}


def technique_name(technique):
    """A technique's (or sub-technique's) name in this ATT&CK version, or None when it isn't in it."""
    return TECHNIQUES[technique][0] if technique in TECHNIQUES else None


def technique_tactics(technique):
    """The tactics (short names) a technique serves in this ATT&CK version; () when it isn't in it."""
    return TECHNIQUES[technique][1] if technique in TECHNIQUES else ()


def placed(tactic, techniques):
    """The techniques (IDs, in the record's order) serving a tactic (short name) in this ATT&CK version."""
    return tuple(t for t in techniques if tactic in technique_tactics(t))


def unplaced(tactics, techniques):
    """The techniques (IDs) a mapping under tactics leaves out: not in this ATT&CK version, or serving none of the
    tactics."""
    return tuple(t for t in techniques if not any(placed(x, (t,)) for x in tactics if x in TACTICS))


def unknown_techniques(techniques):
    """The techniques (IDs, in order) this ATT&CK version doesn't hold (retired, or never in ATT&CK)."""
    return tuple(t for t in techniques if t not in TECHNIQUES)


def retired_tactics(tactics):
    """The tactics (short names, in order) this ATT&CK version retired (RETIRED_TACTICS)."""
    return tuple(t for t in tactics if t in RETIRED_TACTICS)


def _named(technique):
    return f"{technique} ({technique_name(technique)})"


def _replaced(rule, attr, old, new):
    """The modify record replacing value old of a rule's attr with new (those it doesn't hold yet)."""
    gone, added = delete_values(rule, attr, (old,)), tuple(v for v in new if v not in values(rule, attr))
    return gone._replace(mods=(*gone.mods, *add_values(rule, attr, added).mods)) if added else gone


def _tactic(ctx, rule, tactic):
    name, owner = rdn_value(rule), responsible(ctx.d, rule, ctx.dst.env)
    tid, was, new = RETIRED_TACTICS[tactic]
    now = " and ".join(f"{t} ({TACTICS[t][0]} {TACTICS[t][1]})" for t in new)
    picks = (*((t,) for t in new), *((new,) if len(new) > 1 else ()))
    return findings(
        actions=[(AREA, f"Alert rule `{name}` records ATT&CK tactic `{tactic}` ({tid} {was}), which {VERSION} "
                  f"replaced with {now}: a SIEM following {VERSION} maps it wrong or not at all. Choose the tactic it "
                  "detects (ciamAttackTactic).", owner, None)],
        fixes=[Fix(f"attack-tactic:{name}:{tactic}", AREA, f"Replace alert rule `{name}`'s ATT&CK tactic `{tactic}` "
                   f"with its {VERSION} successor", (), (), (), tuple(
                       Option("+".join(p), " and ".join(f"`{t}` ({TACTICS[t][1]})" for t in p),
                              (_replaced(rule, "ciamAttackTactic", tactic, p),), ()) for p in picks))])


def _technique(ctx, rule, technique):
    name, owner = rdn_value(rule), responsible(ctx.d, rule, ctx.dst.env)
    if technique not in RETIRED:
        return findings(actions=[(AREA, f"Alert rule `{name}` records ATT&CK technique `{technique}`, which isn't in "
                                  f"{VERSION}: no SIEM maps it. Record the technique's ID as ATT&CK has it "
                                  "(ciamAttackTechnique), or remove it.", owner, None)])
    was, how, new = RETIRED[technique]
    key, attr = f"attack-technique:{name}:{technique}", "ciamAttackTechnique"
    if not new:
        return findings(
            actions=[(AREA, f"Alert rule `{name}` records ATT&CK technique `{technique}` ({was}), which {VERSION} "
                      f"{how} with nothing replacing it: no SIEM following {VERSION} maps it. Remove it, or record "
                      "the technique that covers what the rule detects.", owner, None)],
            fixes=[Fix(key, AREA, f"Remove {how} ATT&CK technique `{technique}` from alert rule `{name}`",
                       (delete_values(rule, attr, (technique,)),),
                       ("Record the technique that covers what the rule detects, if one does",), ())])
    now = ", ".join(_named(t) for t in new)
    record = [_replaced(rule, attr, technique, (t,)) for t in new]
    return findings(
        actions=[(AREA, f"Alert rule `{name}` records ATT&CK technique `{technique}` ({was}), which {VERSION} "
                  f"revoked: {now} replaced it. A SIEM following {VERSION} doesn't map it; record its replacement "
                  "(ciamAttackTechnique).", owner, None)],
        fixes=[Fix(key, AREA, f"Replace alert rule `{name}`'s ATT&CK technique `{technique}` with {now}",
                   tuple(record), (), ())
               if len(new) == 1 else
               Fix(key, AREA, f"Replace alert rule `{name}`'s ATT&CK technique `{technique}` with its {VERSION} "
                   "replacement", (), (), (), tuple(Option(t, _named(t), (r,), ()) for t, r in zip(new, record)))])


def check_attack(ctx):
    """Alert rules recording an ATT&CK tactic or technique the current ATT&CK retired (or never held) are actions of
    the rule's owner, each with a fix replacing it by its successor (a choice when there are several) or removing a
    deprecated technique; an ok line when the rules recording ATT&CK all hold current values; nothing when none
    records ATT&CK."""
    rules = [r for r in alert_rules(ctx.d) if values(r, "ciamAttackTactic") or values(r, "ciamAttackTechnique")]
    if not rules:
        return findings()
    found = merge_findings([*(_tactic(ctx, r, t) for r in rules
                              for t in retired_tactics(values(r, "ciamAttackTactic"))),
                            *(_technique(ctx, r, t) for r in rules
                              for t in unknown_techniques(values(r, "ciamAttackTechnique")))])
    return found if found.actions else findings(
        ok=[f"Alert rules' ATT&CK tactics and techniques ({len(rules)} rule(s)) are {VERSION}'s."])
