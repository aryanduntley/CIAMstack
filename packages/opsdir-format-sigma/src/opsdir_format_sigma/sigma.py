"""The record's adopted detections as Sigma rules (specification 2.1.0): for each alert rule adopting a product's
declared detection (ciamDeclaredDetection), one base rule (logsource: the product and its log by name; detection: the
rule's canonical selector in the product's field names and values, for the version the environment runs) and, when it
counts (a threshold), a correlation rule over it (event_count, or value_count of its distinct field; group-by, the
timespan of its window, gte its threshold). Sigma is an export, never the source: the declaration and the record are.
Pure.

What Sigma needs that the record doesn't say is opsdir's own, the same every time: ids are UUID version 5 of the rule's
name (the specification asks for random version 4 ones: these stay put across renders), the product and service are
the declaration's names (custom ones: SigmaHQ's taxonomy has none for these products), status follows the
declaration's validation (documented experimental, lab-verified test, live-verified stable), level its severity (sev1
critical to sev4 low). A detection Sigma can't say as recorded is left out with a note: one counting in fixed windows
(a correlation's timespan isn't bound to clock boundaries), one whose fields the product's mapping doesn't name, or
for whose versions no mapping holds.
"""
import uuid

from opsdir.core.directory import one, rdn_value
from opsdir.core.notes import note
from opsdir.domains.observability.detections import (adopting, declared, mapping_for, product_field, product_values,
                                                     recorded, window_text)

SPEC = "2.1.0"
AREA = "Monitoring"
LEVELS = {"sev1": "critical", "sev2": "high", "sev3": "medium", "sev4": "low"}
STATUSES = {"documented": "experimental", "lab-verified": "test", "live-verified": "stable"}
AUTHOR = "opsdir"
FOLDER = "sigma"


def rule_id(name):
    """A Sigma rule's id: the UUID version 5 of its name (stable across renders)."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"urn:opsdir:sigma:{name}"))


def logsource_name(text):
    """A logsource product or service name as Sigma writes them: lower case, spaces as underscores."""
    return text.strip().lower().replace(" ", "_")


def tags(det):
    """The ATT&CK tags of a detection: attack.<tactic short name>, attack.<technique ID in lower case>."""
    return (*(f"attack.{t}" for t in det.tactics), *(f"attack.{t.lower()}" for t in det.techniques))


def _one_or_list(vals):
    return vals[0] if len(vals) == 1 else list(vals)


def selection(det, mapping):
    """(the base rule's selection map in the product's field names and values, None) or (None, why it can't be)."""
    fields = tuple((f, product_field(mapping, f)) for f, _ in det.selector)
    missing = tuple(f for f, p in fields if p is None)
    if missing:
        return None, f"the product's mapping names no field for {', '.join(missing)}"
    if len({p for _, p in fields}) < len(fields):
        return None, "two of its selector's canonical fields are one field of the product's"
    return {p: _one_or_list(tuple(dict.fromkeys(v for c in vals for v in product_values(mapping, f, c))))
            for (f, vals), (_, p) in zip(det.selector, fields)}, None


def _meta(name, det, rule):
    return {"title": det.title, "id": rule_id(name), "name": name, "status": STATUSES[det.validation],
            "description": f"{det.description} (opsdir alert rule {rdn_value(rule)}, adopting "
                           f"{one(rule, 'ciamDeclaredDetection')})",
            "references": list(det.evidence), "author": AUTHOR}


def base_rule(rule, det, mapping, chosen):
    """The base rule (a dict in the specification's order) of an adopting alert rule: det as the record has it, mapping
    the product's for the environment's version, chosen its selection map."""
    name = rdn_value(rule)
    group = tuple(p for p in (product_field(mapping, f) for f in (*det.group_by, *(
        (det.distinct,) if det.distinct else ()))) if p)
    versions = f"{mapping.product} {mapping.versions}" if mapping.versions else mapping.product
    return {**_meta(f"{name}-events", det, rule),
            "logsource": {"product": logsource_name(mapping.product), "service": logsource_name(det.log_source),
                          "definition": f"{versions}, its {det.log_source} log"
                          + (f"; requires: {'; '.join(det.prerequisites)}" if det.prerequisites else "")},
            "detection": {"selection": chosen, "condition": "selection"},
            **({"fields": list(group)} if group else {}),
            "level": LEVELS[det.severity], "tags": list(tags(det))}


def correlation_rule(rule, det, mapping):
    """The correlation rule (a dict) counting an adopting alert rule's base rule: event_count, or value_count of its
    distinct field, per its group-by fields over the window, reaching its threshold."""
    name = rdn_value(rule)
    condition = {"gte": det.threshold, **({"field": product_field(mapping, det.distinct)} if det.distinct else {})}
    return {**_meta(name, det, rule),
            "correlation": {"type": "value_count" if det.distinct else "event_count", "rules": [f"{name}-events"],
                            **({"group-by": [product_field(mapping, f) for f in det.group_by]} if det.group_by
                               else {}),
                            "timespan": window_text(det.window_seconds), "condition": condition},
            "level": LEVELS[det.severity], "tags": list(tags(det))}


def exported(m, pairs, rule):
    """(the Sigma documents of an adopting alert rule in environment m, given the declarations of the adapters
    rendering it ((adapter, ProductDetection), ...), None) or (None, why it isn't exported, how) or None when no
    adapter rendering m declares it (the product isn't there)."""
    ref = one(rule, "ciamDeclaredDetection")
    det = declared(pairs, ref)
    if det is None:
        return None
    det, why = recorded(rule, det)
    if why:
        return None, why, f"Correct alert rule {rdn_value(rule)}'s condition and window under an approved change"
    mapping = mapping_for(m, det)
    if mapping is None:
        return None, (f"{ref} maps no version of its product {m.label} records for role {det.server_role} "
                      f"({', '.join(x.versions or 'every version' for x in det.mappings)})"), (
            f"Record the product version role {det.server_role} runs (ciamProductVersion), or ask "
            f"{ref.split(':')[0]}'s maintainers for the mapping of that version")
    if det.threshold is not None and det.window_kind == "fixed":
        return None, ("it counts in fixed (clock-aligned) windows, and a Sigma correlation's timespan isn't bound to "
                      "clock boundaries"), ("Render it natively with the SIEM's adapter, or make the window sliding "
                                            "(ciamWindowKind) if that is what is meant")
    chosen, why = selection(det, mapping)
    counted = tuple(f for f in (*det.group_by, *((det.distinct,) if det.distinct else ()))
                    if product_field(mapping, f) is None)
    if why or counted:
        return None, why or f"the product's mapping names no field for {', '.join(counted)}", (
            f"Change alert rule {rdn_value(rule)}'s canonical fields to ones {ref} maps, or ask its adapter's "
            "maintainers to map them")
    base = base_rule(rule, det, mapping, chosen)
    return ((base, correlation_rule(rule, det, mapping)) if det.threshold is not None else (base,)), None, None


def sigma_exports(m, pairs):
    """((alert rule, documents or None, why, how), ...) of environment m's adopting alert rules some adapter rendering
    it declares, in record order."""
    return tuple((r, *found) for r in adopting(m.d) for found in (exported(m, pairs, r),) if found is not None)


def sigma_notes(m, pairs):
    """The render notes: each adopting rule not exported (why, and how to get it exported), each exported one whose
    declaration is documented only, and where any is exported, what a converter needs (a pipeline for the custom
    product and service names, and the logs parsed into the product's fields)."""
    found = sigma_exports(m, pairs)
    done = tuple(r for r, docs, _, _ in found if docs)
    return (*(note(AREA, "action", f"alert rule {rdn_value(r)}", f"not exported as Sigma: {why}", (how,), r.dn,
                   m.label) for r, docs, why, how in found if not docs),
            *(note(AREA, "note", f"alert rule {rdn_value(r)}", "exported as Sigma with status experimental: its "
                   "declaration is documented only, not yet seen firing in a lab or on a live system",
                   ("Replay the product's events against it once converted, before relying on it",), r.dn, m.label)
              for r, docs, _, _ in found if docs and docs[0]["status"] == "experimental"),
            *((note(AREA, "note", "Sigma rules", "their logsource product and service names are opsdir's own (the "
                    "products' names and their logs'), which no SIEM's Sigma pipeline knows yet",
                    ("Whoever converts them (the SIEM team) gives the converter a pipeline mapping each product and "
                     "service to the index or table holding those logs",
                     "Make sure the SIEM parses those logs into the product's fields the rules name: conversion "
                     "doesn't parse"), None, m.label),) if done else ()))


def sigma_files(m, pairs, write, top=""):
    """{path: text} of environment m's Sigma rules: sigma/<alert rule>.yml per exported rule, its base rule and its
    correlation rule as two YAML documents after top (a header comment); write: (dict) -> YAML text."""
    return {f"{FOLDER}/{rdn_value(r)}.yml": top + "---\n".join(write(doc) for doc in docs)
            for r, docs, _, _ in sigma_exports(m, pairs) if docs}
