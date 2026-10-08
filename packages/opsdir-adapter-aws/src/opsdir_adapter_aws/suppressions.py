"""Suppressions of findings on AWS (core estate: ciamSuppression, carrying out an exception). Pure.

Rendered in the platform's own root, for each suppression the platform team keeps (one someone else keeps is named in
a comment), named after its exception (exc-<exception>):

  aws:securityhub:<control>   an aws_securityhub_automation_rule matching the controls (compliance_security_control_id
                              EQUALS each) that sets their findings' workflow status SUPPRESSED and notes the exception
  aws:guardduty:<type>        an aws_guardduty_filter that archives findings of the types (criterion type equals)

Neither has an expiry: a comment says until when the exception stands (remove the suppression then). In GovCloud,
Security Hub's automation rules for integrations aren't available (AWS GovCloud (US) user guide): a comment. Another
provider's or kind's refs are named in a comment.

Read back from Terraform state: automation rules setting workflow SUPPRESSED and GuardDuty filters archiving, merged
per name into one suppression (kind suppression) covering their controls and finding types, its exception the name's
(exc-<cn>).
"""
from opsdir.core.directory import date_of, get, one, rdn_value, values
from opsdir.core.environment import of_class
from opsdir.core.inventory import of_types, resource
from opsdir.domains.estate.poam import exception_of, suppression_name
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .budgets import govcloud

RULE, FILTER = "aws_securityhub_automation_rule", "aws_guardduty_filter"
DETECTOR = "data.aws_guardduty_detector.suppressions"
SUPPRESSION = "ciamSuppression"


def _refs(s, kind):
    """The ids of a suppression's aws:<kind>:<id> finding refs."""
    return [r.split(":", 2)[2] for r in values(s, "ciamFindingRef") if r.split(":", 2)[:2] == ["aws", kind]]


def _others(s):
    return [r for r in values(s, "ciamFindingRef") if r.split(":", 2)[:2] not in (["aws", "securityhub"],
                                                                                ["aws", "guardduty"])]


def _note(m, s):
    exc = get(m.d, one(s, "ciamExceptionRef")) if one(s, "ciamExceptionRef") else None
    until = date_of(s, "ciamExpiresAt") or (date_of(exc, "ciamExpiresAt") if exc is not None else None)
    return f"exception {rdn_value(exc) if exc is not None else '(none recorded)'}" + (f", until {until}" if until
                                                                                       else ""), until


def _rule(m, s, order):
    name, (note, until) = suppression_name(s), _note(m, s)
    controls = _refs(s, "securityhub")
    if not controls:
        return ()
    criteria = Block(tuple(("compliance_security_control_id", Block((("comparison", "EQUALS"), ("value", c))))
                           for c in controls))
    update = Block((("workflow", Block((("status", "SUPPRESSED"),))),
                    ("note", Block((("text", note), ("updated_by", "opsdir"))))))
    return (*((f"# {name}: Security Hub automation rules have no expiry: remove this rule on {until}",) if until
              else ()),
            *((f"# {name}: AWS GovCloud (US): automation rules for integrations aren't available (AWS GovCloud (US) "
               "user guide); this rule matches Security Hub's own controls",) if govcloud(m) else ()),
            block("resource", [RULE, tf_name(name)], [
                ("rule_name", name), ("rule_order", order), ("description", f"Suppress {', '.join(controls)}: {note}"),
                ("criteria", criteria),
                ("actions", Block((("type", "FINDING_FIELDS_UPDATE"), ("finding_fields_update", update))))]))


def _filter(m, s, rank):
    name, (note, until) = suppression_name(s), _note(m, s)
    types = _refs(s, "guardduty")
    if not types:
        return ()
    return (*((f"# {name}: GuardDuty filters have no expiry: remove this filter on {until}",) if until else ()),
            block("resource", [FILTER, tf_name(f"{name}_guardduty")], [
                ("name", name), ("description", note), ("detector_id", ref(f"{DETECTOR}.id")), ("action", "ARCHIVE"),
                ("rank", rank),
                ("finding_criteria", Block((("criterion", Block((("field", "type"), ("equals", types)))),)))]))


def render_suppressions(m):
    """HCL (and comments) for environment m's suppressions."""
    kept = [s for s in of_class(m, SUPPRESSION) if not one(s, "ciamManagedBy")]
    held = [s for s in of_class(m, SUPPRESSION) if one(s, "ciamManagedBy")]
    data = (block("data", ["aws_guardduty_detector", "suppressions"], []),) if any(_refs(s, "guardduty")
                                                                                    for s in kept) else ()
    return (*data,
            *(x for i, s in enumerate(kept, 1) for x in (*_rule(m, s, i), *_filter(m, s, i),
                                                          *((f"# {suppression_name(s)}: not AWS's (not rendered here): "
                                                             f"{', '.join(_others(s))}",) if _others(s) else ()))),
            *(f"# Suppression {suppression_name(s)}: kept by {rdn_value(get(m.d, one(s, 'ciamManagedBy')))}, not "
              "rendered here" for s in held if get(m.d, one(s, "ciamManagedBy")) is not None))


# ------------------------------------------------------------------ read back
def _first(v):
    return v[0] if isinstance(v, list) and v else v if isinstance(v, dict) else {}


def _suppressing(a):
    """Whether an automation rule's actions set its findings' workflow status SUPPRESSED."""
    return any(_first(_first(x.get("finding_fields_update")).get("workflow")).get("status") == "SUPPRESSED"
               for x in a.get("actions") or ())


def _controls(a):
    return [f"aws:securityhub:{c.get('value')}" for crit in a.get("criteria") or ()
            for c in crit.get("compliance_security_control_id") or () if c.get("comparison") == "EQUALS"]


def _types(a):
    return [f"aws:guardduty:{v}" for fc in a.get("finding_criteria") or () for c in fc.get("criterion") or ()
            if c.get("field") == "type" for v in c.get("equals") or ()]


def suppression_resources(pairs):
    """Suppressions of (Terraform resource type, attributes) pairs, one per name."""
    found = [(a.get("rule_name"), a.get("arn"), _controls(a)) for a in of_types(pairs, RULE)
             if a.get("rule_name") and _suppressing(a)] + \
            [(a.get("name"), a.get("arn") or a.get("id"), _types(a)) for a in of_types(pairs, FILTER)
             if a.get("name") and (a.get("action") or "").upper() == "ARCHIVE"]
    names = list(dict.fromkeys(n for n, _, _ in found))
    return tuple(resource("suppression", next(r for n, r, _ in found if n == name and r), {
        "ciamFindingRef": tuple(dict.fromkeys(x for n, _, refs in found if n == name for x in refs)),
        "ciamExceptionRef": exception_of(name)}, name=name)
        for name in names if any(r for n, r, _ in found if n == name))
