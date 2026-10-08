"""Suppressions of findings on Azure (core estate: ciamSuppression, carrying out an exception). Pure.

Rendered in the stack's main.tf for each suppression the platform team keeps (one someone else keeps is named in a
comment), after its exception (exc-<exception>):

  azure:policy:<framework>[/<reference id>]   an azurerm_subscription_policy_exemption per framework, of the
                                              subscription's assignment of the framework's initiative (ciam-<framework>,
                                              as the security services' posture renders it), for the policy
                                              definitions its reference ids name (the whole initiative without):
                                              category Mitigated for a compensating control, Waiver otherwise, expiring
                                              with the exception, its exception in the metadata
  azure:alerts:<alert type>                   a Defender for Cloud alert suppression rule
                                              (Microsoft.Security/alertsSuppressionRules@2019-01-01-preview, reason
                                              FalsePositive for a false positive, Other otherwise, expiring with the
                                              exception): azurerm has no resource for it, so it is rendered through
                                              Microsoft's azapi provider only when the cloud allows that add-on
                                              (ciamProviderAddOn azapi); otherwise a comment names the rule to create

Another provider's or kind's refs are named in a comment.

Read back from Terraform state: subscription policy exemptions (the framework from the assignment's name, the reference
ids, the exception from the metadata) and azapi alert suppression rules (the alert type, the exception from the name),
merged per exception into one suppression (kind suppression).
"""
import json

from opsdir.core.directory import date_of, get, one, rdn_value, values
from opsdir.core.environment import of_class
from opsdir.core.inventory import of_types, resource
from opsdir.domains.estate.poam import exception_of, suppression_name
from opsdir_format_terraform.hcl import block, jsonencoded, ref, tf_name

EXEMPTION = "azurerm_subscription_policy_exemption"
AZAPI = "azapi_resource"
ALERT_RULES = "Microsoft.Security/alertsSuppressionRules"
ALERT_RULES_API = f"{ALERT_RULES}@2019-01-01-preview"
ADD_ON = "azapi"
SUBSCRIPTION = "data.azurerm_subscription.current"
ASSIGNMENT_PREFIX = "ciam-"           # the posture renderer's assignment names: ciam-<framework>
SUPPRESSION = "ciamSuppression"


def _refs(s, kind):
    return [r.split(":", 2)[2] for r in values(s, "ciamFindingRef") if r.split(":", 2)[:2] == ["azure", kind]]


def _others(s):
    return [r for r in values(s, "ciamFindingRef")
            if r.split(":", 2)[:2] not in (["azure", "policy"], ["azure", "alerts"])]


def _exception(m, s):
    ref_ = one(s, "ciamExceptionRef")
    return get(m.d, ref_) if ref_ else None


def _expiry(m, s):
    exc = _exception(m, s)
    day = date_of(s, "ciamExpiresAt") or (date_of(exc, "ciamExpiresAt") if exc is not None else None)
    return f"{day}T00:00:00Z" if day else None


def _kind(m, s):
    exc = _exception(m, s)
    return one(exc, "ciamExceptionKind") if exc is not None else None


def _frameworks(s):
    """{framework: (reference ids, ...)} of a suppression's azure:policy refs (() for the whole initiative)."""
    pairs = [r.partition("/") for r in _refs(s, "policy")]
    return {fw: tuple(x for f, _, x in pairs if f == fw and x) for fw in dict.fromkeys(f for f, _, _ in pairs)}


def _exemptions(m, s):
    name, exc = suppression_name(s), _exception(m, s)
    category = "Mitigated" if _kind(m, s) == "compensating-control" else "Waiver"
    return tuple(block("resource", [EXEMPTION, tf_name(f"{name}_{fw}")], [
        ("name", f"{name}-{fw}"), ("subscription_id", ref(f"{SUBSCRIPTION}.id")),
        ("policy_assignment_id",
         f"${{{SUBSCRIPTION}.id}}/providers/Microsoft.Authorization/policyAssignments/{ASSIGNMENT_PREFIX}{fw}"),
        ("exemption_category", category),
        *((("policy_definition_reference_ids", list(ids)),) if ids else ()),
        *((("expires_on", _expiry(m, s)),) if _expiry(m, s) else ()),
        ("description", f"exception {rdn_value(exc) if exc is not None else '(none recorded)'}"),
        ("metadata", jsonencoded({"exception": rdn_value(exc) if exc is not None else None}))])
        for fw, ids in _frameworks(s).items())


def _add_on(m):
    return ADD_ON in values(m.cloud, "ciamProviderAddOn")


def _alert_rules(m, s):
    name, types = suppression_name(s), _refs(s, "alerts")
    if not types:
        return ()
    if not _add_on(m):
        return (f"# {name}: Defender for Cloud alert suppression rules for {', '.join(types)} until "
                f"{_expiry(m, s) or 'no date'}: azurerm has no resource for them; create them in Defender for Cloud "
                "(or allow the azapi add-on: ciamProviderAddOn azapi)",)
    exc = _exception(m, s)
    return tuple(block("resource", [AZAPI, tf_name(f"{name}_{t}")], [
        ("type", ALERT_RULES_API), ("name", f"{name}-{t}" if len(types) > 1 else name),
        ("parent_id", ref(f"{SUBSCRIPTION}.id")),
        ("body", {"properties": {"alertType": t, "state": "Enabled",
                                 "reason": "FalsePositive" if _kind(m, s) == "false-positive" else "Other",
                                 "comment": f"exception {rdn_value(exc) if exc is not None else '(none recorded)'}",
                                 **({"expirationDateUtc": _expiry(m, s)} if _expiry(m, s) else {})}})])
        for t in types)


def _kept(m):
    return [s for s in of_class(m, SUPPRESSION) if not one(s, "ciamManagedBy")]


def uses_azapi(m):
    """Whether environment m's root renders azapi resources."""
    return _add_on(m) and any(_refs(s, "alerts") for s in _kept(m))


def azapi_provider(m):
    """The azapi provider block of a root of environment m."""
    gov = (("environment", "usgovernment"),) if one(m.cloud, "ciamCloudEnvironment") == "usgovernment" else ()
    return block("provider", ["azapi"], [("subscription_id", ref("var.subscription_id")), *gov])


def render_suppressions(m):
    """HCL (and comments) for environment m's suppressions."""
    kept, held = _kept(m), [s for s in of_class(m, SUPPRESSION) if one(s, "ciamManagedBy")]
    out = tuple(x for s in kept for x in (*_exemptions(m, s), *_alert_rules(m, s),
                                          *((f"# {suppression_name(s)}: not Azure's (not rendered here): "
                                             f"{', '.join(_others(s))}",) if _others(s) else ())))
    return ((block("data", ["azurerm_subscription", "current"], []),) if any(SUBSCRIPTION in x for x in out) else ()) \
        + out + tuple(f"# Suppression {suppression_name(s)}: kept by {rdn_value(get(m.d, one(s, 'ciamManagedBy')))}, "
                      "not rendered here" for s in held if get(m.d, one(s, "ciamManagedBy")) is not None)


# ------------------------------------------------------------------ read back
def _metadata(a):
    try:
        v = json.loads(a.get("metadata") or "{}")
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


def _body(a):
    b = a.get("body")
    try:
        b = json.loads(b) if isinstance(b, str) else b
    except ValueError:
        return {}
    return b if isinstance(b, dict) else {}


def _commented(body):
    """The exception a rule's comment names ("exception <cn>"), or None."""
    comment = (body.get("properties") or {}).get("comment") or ""
    return comment.split(" ", 1)[1] if comment.startswith("exception ") and " " in comment else None


def _framework(assignment_id):
    name = (assignment_id or "").rsplit("/", 1)[-1]
    return name[len(ASSIGNMENT_PREFIX):] if name.startswith(ASSIGNMENT_PREFIX) else name


def suppression_resources(pairs):
    """Suppressions of (azurerm/azapi type, attributes) pairs, one per exception (or name)."""
    exemptions = [(_metadata(a).get("exception") or exception_of(a.get("name")), a.get("id"),
                   [f"azure:policy:{_framework(a.get('policy_assignment_id'))}" + (f"/{x}" if x else "")
                    for x in (a.get("policy_definition_reference_ids") or [None])])
                  for a in of_types(pairs, EXEMPTION) if a.get("id")]
    rules = [(_commented(_body(a)) or exception_of(a.get("name")), a.get("id"),
              [f"azure:alerts:{(_body(a).get('properties') or {}).get('alertType')}"])
             for a in of_types(pairs, AZAPI) if (a.get("type") or "").startswith(ALERT_RULES) and a.get("id")]
    found = [(exc, rid, refs) for exc, rid, refs in (*exemptions, *rules) if exc]
    names = list(dict.fromkeys(exc for exc, _, _ in found))
    return tuple(resource("suppression", next(r for e, r, _ in found if e == exc), {
        "ciamFindingRef": tuple(dict.fromkeys(x for e, _, refs in found if e == exc for x in refs)),
        "ciamExceptionRef": exc}, name=f"exc-{exc}") for exc in names)
