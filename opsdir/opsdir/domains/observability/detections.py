"""Detections product adapters declare (core.contract.ProductDetection: Adapter.detections) and the alert rules that
adopt them: what a declaration means as record values, what the record's rule means as a declaration again (for every
SIEM adapter, and the Sigma export, to render), and the planner's check. Pure.

A declaration is product knowledge in vendor-neutral terms: the events to count on canonical fields (naming.
DETECTION_FIELDS: subject, source-ip, realm, outcome, action, actor, object), per what, how many within which window
(sliding or fixed), the ATT&CK it detects, how severe, and per product version where each canonical field and value is
in the product's log (its DetectionMappings). It becomes an alert rule only through a fix a person approves, never on
its own: the rule then holds everything that decides what fires (the canonical selector in ciamDetectionSelector, its
ciamGroupBy, ciamDistinctField, threshold, window and ciamWindowKind, severity, ATT&CK), so a person can tune it and a
review sees it, and names the declaration (ciamDeclaredDetection <adapter>:<id>) whose field mappings render it for
the product version an environment runs. The search text isn't recorded: each SIEM adapter writes its own from the
canonical selector and the mapping.

The check (connectors.observability.detection_check gives it the declarations): a declaration of an adapter rendering
the target that no rule adopts is an action, its fix recording the rule (the channel's role, and its owner where the
target names none, given); a rule whose declaration changed since it adopted it (ciamDeclarationDigest: a digest of
what it took then) is an action, its fix a person's choice: take the declaration's values (the values a person tuned
since named as its risk) or keep the rule's, recording the declaration as seen (a rule tuned while its declaration
stayed is left alone); one whose declaration is gone is an action, its fix removing the rule; one naming an adapter
that isn't installed is an action; a declaration that doesn't hold together (a field no mapping names, an unknown
ATT&CK ID) is an action for its adapter's maintainers, never offered.
"""
import hashlib
import json
import re

from ...core.changeset import delete_entry, new_entry
from ...core.directory import get, one, rdn_value, values
from ...core.findings import Fix, Input, Option, findings, merge_findings, responsible
from ...core.interchange.ldif import LdifRecord
from ...core.versions import holds
from ..compute.workloads import recorded_versions
from .alerts import alert_rules
from .attack_table import TACTICS, TECHNIQUES
from .naming import (ALERT_RULES, DECLARED_DETECTION, DETECTION_ACTIONS, DETECTION_FIELDS, DETECTION_OUTCOMES,
                     SELECTOR_TERM, SEVERITIES, VALIDATIONS, WINDOW_KINDS)
from .signals import parse_threshold

AREA = "Alert"
# The rule attributes a declaration gives (declared_attrs), in the order a fix lists them; the digest covers these
DECLARED_ATTRS = ("ciamSignal", "ciamTargetRole", "ciamDetectionSelector", "ciamGroupBy", "ciamDistinctField",
                  "ciamComparison", "ciamThreshold", "ciamEvaluationPeriod", "ciamWindowKind", "ciamSeverity",
                  "ciamAttackTactic", "ciamAttackTechnique")
_UNITS = (("d", 86400), ("h", 3600), ("m", 60), ("s", 1))
_ID = re.compile(r"[a-z0-9][a-z0-9.-]*")
_SAID = {"documented": "documented only: not yet seen firing in a lab or on a live system",
         "lab-verified": "verified against a lab's events", "live-verified": "seen firing on a live system"}


def declared_ref(adapter, det):
    """What an alert rule adopting a declaration names it by (ciamDeclaredDetection): <adapter>:<id>."""
    return f"{adapter}:{det.id}"


def declared(pairs, ref):
    """The ProductDetection ((adapter name, ProductDetection), ...) pairs hold under ref (<adapter>:<id>), or None."""
    return next((det for a, det in pairs if declared_ref(a, det) == ref), None)


def adopting(d):
    """The record's alert rules adopting a declared detection (ciamDeclaredDetection), in record order."""
    return tuple(r for r in alert_rules(d) if one(r, "ciamDeclaredDetection"))


def rule_name(adapter, det):
    """The name a fix gives the alert rule adopting a declaration: <adapter>-<id>."""
    return f"{adapter}-{det.id}"


def window_text(seconds):
    """A window in seconds as a duration in the largest unit dividing it (300 -> 5m, 90 -> 90s)."""
    unit, size = next((u, s) for u, s in _UNITS if seconds % s == 0)
    return f"{seconds // size}{unit}"


def duration_seconds(text):
    """A duration (30s, 5m, 1h, 7d) in seconds, or None when it isn't one."""
    found = re.fullmatch(r"([0-9]+)(s|m|h|d)", (text or "").strip())
    return int(found.group(1)) * dict(_UNITS)[found.group(2)] if found else None


def selector_values(selector):
    """A canonical selector ((field, (value, ...)), ...) as ciamDetectionSelector values (field=value|value)."""
    return tuple(f"{field}={'|'.join(vals)}" for field, vals in selector)


def parse_selector(texts):
    """ciamDetectionSelector values as a canonical selector ((field, (value, ...)), ...)."""
    return tuple((field, tuple(rest.split("|"))) for t in texts for field, _, rest in (t.partition("="),))


def declared_attrs(det):
    """{attribute: values} of what an alert rule adopting a declaration records from it (DECLARED_ATTRS): its id as the
    signal, its server role, selector, grouping and distinct field, threshold (ge), window and its kind, severity and
    ATT&CK; () where it says nothing."""
    counted = det.threshold is not None
    return {"ciamSignal": (det.id,), "ciamTargetRole": (det.server_role,),
            "ciamDetectionSelector": selector_values(det.selector), "ciamGroupBy": tuple(det.group_by),
            "ciamDistinctField": (det.distinct,) if det.distinct else (),
            "ciamComparison": ("ge",) if counted else (), "ciamThreshold": (str(det.threshold),) if counted else (),
            "ciamEvaluationPeriod": (window_text(det.window_seconds),) if counted and det.window_seconds else (),
            "ciamWindowKind": (det.window_kind,) if counted and det.window_kind else (),
            "ciamSeverity": (det.severity,), "ciamAttackTactic": tuple(det.tactics),
            "ciamAttackTechnique": tuple(det.techniques)}


def digest(det):
    """The digest of what a declaration gives an adopting rule (declared_attrs): 16 hex characters of its SHA-256."""
    text = json.dumps({k: sorted(v) for k, v in declared_attrs(det).items()}, sort_keys=True)
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def differing(rule, det):
    """The attributes (DECLARED_ATTRS order) whose values on rule differ from what the declaration gives."""
    given = declared_attrs(det)
    return tuple(a for a in DECLARED_ATTRS if sorted(values(rule, a)) != sorted(given[a]))


def recorded(rule, det):
    """(the declaration as the record's rule has it, None) or (None, why it can't be): the rule's selector, grouping,
    distinct field, threshold (ge, or gt as one more), window and its kind, severity and ATT&CK over the declaration's
    own, which keeps its mappings, products and evidence. What every SIEM adapter, and the Sigma export, renders."""
    comparison, threshold = one(rule, "ciamComparison"), parse_threshold(one(rule, "ciamThreshold"))
    window = duration_seconds(one(rule, "ciamEvaluationPeriod"))
    if threshold is not None and (threshold[1] is not None or threshold[0] != int(threshold[0])
                                  or comparison not in ("ge", "gt")):
        return None, (f"its condition `{comparison or '(no comparison)'} {one(rule, 'ciamThreshold')}` isn't a count "
                      "of events reached "
                      "(ciamComparison ge or gt, a whole ciamThreshold without a unit)")
    if threshold is not None and window is None:
        return None, "it counts events but records no window (ciamEvaluationPeriod)"
    count = None if threshold is None else int(threshold[0]) + (1 if comparison == "gt" else 0)
    return det._replace(server_role=one(rule, "ciamTargetRole") or det.server_role,
                        selector=parse_selector(values(rule, "ciamDetectionSelector")),
                        group_by=values(rule, "ciamGroupBy"), distinct=one(rule, "ciamDistinctField"),
                        threshold=count, window_seconds=window if count is not None else None,
                        window_kind=(one(rule, "ciamWindowKind") or det.window_kind) if count is not None else None,
                        severity=one(rule, "ciamSeverity") or det.severity,
                        tactics=values(rule, "ciamAttackTactic"), techniques=values(rule, "ciamAttackTechnique")), None


def mapping_for(m, det):
    """The declaration's DetectionMapping holding for the versions environment m records for its server role
    (versions.holds: the newest release when none is recorded), or None."""
    found = recorded_versions(m, det.server_role)
    return next((mp for mp in det.mappings if holds(mp.versions, found)), None)


def product_field(mapping, field):
    """Where a canonical field is in the product's events (its path), or None when the mapping doesn't name it."""
    return dict(mapping.fields).get(field)


def product_values(mapping, field, value):
    """A canonical field's value in the product's own words: the mapping's values for it, else the value itself."""
    return next((tuple(vs) for f, v, vs in mapping.values if (f, v) == (field, value)), (value,))


def _used_fields(det):
    return tuple(dict.fromkeys((*(f for f, _ in det.selector), *det.group_by,
                                *((det.distinct,) if det.distinct else ()))))


def _mapping_problems(det, mp):
    named = {p for p, _ in det.products}
    return (*((f"mapping of {mp.product}, which it doesn't name among its products",) if mp.product not in named
              else ()),
            *(f"mapping of {mp.product} {mp.versions or ''} names no field for `{f}`".replace("  ", " ")
              for f in _used_fields(det) if product_field(mp, f) is None),
            *(f"mapping of {mp.product} {mp.versions or ''} doesn't say what `{f}={v}` is".replace("  ", " ")
              for f, vals in det.selector if f in ("outcome", "action") for v in vals
              if not any((x, y) == (f, v) for x, y, _ in mp.values)))


def _window_problems(det):
    if det.threshold is None:
        return tuple(f"no threshold but a {what}" for what, has in (
            ("window", det.window_seconds is not None), ("window kind", det.window_kind is not None),
            ("grouping", bool(det.group_by)), ("distinct field", det.distinct is not None)) if has)
    return (*(("a threshold that isn't a positive whole number",)
              if not isinstance(det.threshold, int) or det.threshold < 1 else ()),
            *(("no window in whole seconds",)
              if not isinstance(det.window_seconds, int) or det.window_seconds < 1 else ()),
            *((f"window kind {det.window_kind!r}, not {' or '.join(WINDOW_KINDS)}",)
              if det.window_kind not in WINDOW_KINDS else ()))


def _selector_problems(det):
    return (*(("no selector",) if not det.selector else ()),
            *(f"selector value `{t}` isn't canonical ({', '.join(DETECTION_FIELDS)}; outcome "
              f"{'|'.join(DETECTION_OUTCOMES)}; action {'|'.join(DETECTION_ACTIONS)})"
              for (f, vals), t in zip(det.selector, selector_values(det.selector))
              if not vals or not re.fullmatch(SELECTOR_TERM, t)
              or (f == "outcome" and set(vals) - set(DETECTION_OUTCOMES))
              or (f == "action" and set(vals) - set(DETECTION_ACTIONS))),
            *(f"grouping or distinct field `{f}` isn't canonical" for f in (*det.group_by, det.distinct)
              if f is not None and f not in DETECTION_FIELDS))


def detection_problems(adapter, det):
    """What keeps a declaration from being offered as an alert rule, in words (() when it holds together): an id or
    adapter name that can't name it, no products or mappings, a selector, grouping or distinct field off the canonical
    vocabulary, a threshold without a window (or a window without a threshold), a field a mapping doesn't name, an
    outcome or action a mapping doesn't translate, ATT&CK the core's version doesn't hold, a severity or validation
    off their vocabularies, no https evidence. For adapter tests and the planner."""
    return (*((f"reference `{declared_ref(adapter, det)}` isn't <adapter>:<id> in lower case",)
              if not re.fullmatch(DECLARED_DETECTION, declared_ref(adapter, det)) or not _ID.fullmatch(det.id)
              else ()),
            *(("no products",) if not det.products else ()), *(("no mappings",) if not det.mappings else ()),
            *(("no server role",) if not det.server_role else ()), *(("no log source",) if not det.log_source else ()),
            *_selector_problems(det), *_window_problems(det),
            *(p for mp in det.mappings for p in _mapping_problems(det, mp)),
            *(f"ATT&CK tactic `{t}` isn't one of the current ATT&CK's" for t in det.tactics if t not in TACTICS),
            *(f"ATT&CK technique `{t}` isn't in the current ATT&CK" for t in det.techniques if t not in TECHNIQUES),
            *((f"severity {det.severity!r}, not one of {', '.join(SEVERITIES)}",)
              if det.severity not in SEVERITIES else ()),
            *((f"validation {det.validation!r}, not one of {', '.join(VALIDATIONS)}",)
              if det.validation not in VALIDATIONS else ()),
            *(("no https evidence (the documentation it rests on)",)
              if not det.evidence or not all(u.startswith("https://") for u in det.evidence) else ()))


def _products(det):
    return ", ".join(f"{p} {r}" if r else p for p, r in det.products)


def adopt_record(adapter, det, alert_roles, owners):
    """The add record of the alert rule adopting a declaration (rule_name): what it declares (declared_attrs), its
    description, the reference and digest, its channel's role (an Input: alert_roles, the record's, as examples) and
    owners (their DNs; an Input when none)."""
    attrs = {k: v for k, v in declared_attrs(det).items() if v}
    return new_entry(f"cn={rule_name(adapter, det)},{ALERT_RULES}", ("top", "ciamObject", "ciamAlertRule"), {
        "cn": (rule_name(adapter, det),), **attrs, "description": (f"{det.title}: {det.description}",),
        "ciamDeclaredDetection": (declared_ref(adapter, det),), "ciamDeclarationDigest": (digest(det),),
        "ciamAlertRole": (Input("ciamAlertRole", "the binding role of the channel delivering it (a topic, an action "
                                "group, a paging service each environment binds)", (), tuple(alert_roles)),),
        "ciamOwner": tuple(owners) or (Input("ciamOwner", "who owns the alert rule (a party's DN)"),)})


def _adopt(ctx, adapter, det):
    ref, name = declared_ref(adapter, det), rule_name(adapter, det)
    roles = tuple(dict.fromkeys(one(r, "ciamAlertRole") for r in alert_rules(ctx.d)))
    container = () if get(ctx.d, ALERT_RULES) is not None else (
        new_entry(ALERT_RULES, ("top", "organizationalUnit"), {"ou": ("alert-rules",)}),)
    return findings(
        actions=[(AREA, f"{adapter} declares detection `{det.id}` ({det.title}; {_products(det)}; "
                  f"{_SAID[det.validation]}); no alert rule adopts it, so no SIEM runs it. Adopt it (the fix records "
                  f"alert rule `{name}`, its channel's role given) or leave it.", responsible(ctx.d, ctx.dst.env),
                  None)],
        fixes=[Fix(f"detection:{ref}", AREA, f"Record alert rule `{name}` adopting {adapter}'s detection `{det.id}` "
                   f"({det.title})", (*container, adopt_record(adapter, det, roles, values(ctx.dst.env, "ciamOwner"))),
                   tuple(f"Make sure: {p}" for p in det.prerequisites),
                   (f"The detection is {_SAID[det.validation]}: it may miss or over-count until its events are "
                    "checked against the product's",) if det.validation == "documented" else ())])


def _update(ctx, rule, adapter, det):
    name, owner, gone, given = (rdn_value(rule), responsible(ctx.d, rule, ctx.dst.env), differing(rule, det),
                                declared_attrs(det))
    seen = ("replace", "ciamDeclarationDigest", (digest(det),))
    take = LdifRecord(rule.dn, "modify", {}, (*((("replace", a, given[a]) if given[a] else ("delete", a, ()))
                                                 for a in gone), seen))
    keep = LdifRecord(rule.dn, "modify", {}, (seen,))
    said = ", ".join(f"{a} {'|'.join(values(rule, a)) or '(none)'} -> {'|'.join(given[a]) or '(none)'}" for a in gone)
    key, title = f"detection-update:{name}", f"Bring alert rule `{name}` up to {adapter}'s declaration of `{det.id}`"
    return findings(
        actions=[(AREA, f"Alert rule `{name}` adopted {adapter}'s detection `{det.id}`, whose declaration changed "
                  "since: " + (f"the rule differs from it in {said}. Take the declaration's values, or keep the "
                               "rule's (values a person tuned) and record the declaration as seen."
                               if gone else "the rule already holds its values; record the declaration as seen."),
                  owner, None)],
        fixes=[Fix(key, AREA, title, (), (), (), (
                   Option("take", "take the declaration's values", (take,),
                          (f"Values a person tuned on `{name}` since it adopted the declaration are replaced: "
                           f"{said}",)),
                   Option("keep", "keep the rule's values, recording the declaration as seen", (keep,), ())))
               if gone else Fix(key, AREA, title, (keep,), (), ())])


def _removed(ctx, rule, adapter, ref):
    name = rdn_value(rule)
    return findings(
        actions=[(AREA, f"Alert rule `{name}` adopted detection `{ref}`, which {adapter} no longer declares: nothing "
                  "maps its fields to the product's log, so no SIEM renders it. Remove it (the fix), or adopt the "
                  "detection that replaced it.", responsible(ctx.d, rule, ctx.dst.env), None)],
        fixes=[Fix(f"detection-remove:{name}", AREA, f"Remove alert rule `{name}` (its declaration `{ref}` is gone)",
                   (delete_entry(rule),), (),
                   (f"Alarms and detections realizing `{name}` (ciamRealizes) are left realizing nothing: remove them "
                    "too.",))])


def _adopted(ctx, rule, installed):
    ref = one(rule, "ciamDeclaredDetection")
    adapter = ref.split(":", 1)[0]
    if adapter not in installed:
        return findings(actions=[(AREA, f"Alert rule `{rdn_value(rule)}` adopted detection `{ref}`, but adapter "
                                  f"`{adapter}` isn't installed: nothing maps its fields to the product's log. Install "
                                  "it, or remove the rule.", responsible(ctx.d, rule, ctx.dst.env), None)])
    det = declared(tuple((adapter, x) for x in installed[adapter]), ref)
    if det is None:
        return _removed(ctx, rule, adapter, ref)
    return _update(ctx, rule, adapter, det) if one(rule, "ciamDeclarationDigest") != digest(det) else findings()


def check_detections(ctx, declarations, installed):
    """The planner's check of declared detections. declarations: ((adapter name, ProductDetection), ...) the
    adapters rendering the target declare; installed: {adapter name: ProductDetections} of every installed adapter
    (where an adopted rule's declaration is looked up). A declaration that doesn't hold together, one no rule adopts
    (with the fix recording it), a rule whose declaration changed (with the fix taking or keeping), is gone (the fix
    removing it) or names an adapter not installed, are actions; an ok line when every declaration is adopted and
    current; nothing when nothing declares or adopts one."""
    rules = adopting(ctx.d)
    if not declarations and not rules:
        return findings()
    taken = {one(r, "ciamDeclaredDetection") for r in rules}
    broken = tuple((a, det, detection_problems(a, det)) for a, det in declarations)
    found = merge_findings([
        findings(actions=[(AREA, f"{a} declares detection `{det.id}`, which can't be offered as an alert rule: "
                           f"{'; '.join(why)}. Its adapter's maintainers correct the declaration.",
                           responsible(ctx.d, ctx.dst.env), None) for a, det, why in broken if why]),
        *(_adopt(ctx, a, det) for a, det, why in broken if not why and declared_ref(a, det) not in taken),
        *(_adopted(ctx, r, installed) for r in rules)])
    return found if found.actions else found._replace(ok=(
        *found.ok, f"Every detection the target's products declare ({len(declarations)}) is adopted, and the alert "
                   f"rules adopting one ({len(rules)}) hold what their declarations say now."))
