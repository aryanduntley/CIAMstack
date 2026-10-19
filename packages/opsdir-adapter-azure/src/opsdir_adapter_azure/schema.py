"""Azure schema fragment, under this package's own OID arc: choices only Microsoft Sentinel has, which the core's
vendor-neutral detections don't name (milestone 129, decision 3538). A SIEM detection on a Sentinel workspace (an alarm
binding naming it in ciamLogDestinationRole) may add the auxiliary class azSentinelRule: how its analytics rule runs
(scheduled, or near-real-time), its alerts' details taken from its results (alert details override) and how long
Sentinel stops running it after an alert (suppression). Without the class, the rule is scheduled, with Sentinel's own
alert details and no suppression. Pure data."""
from opsdir.core.standard import AttributeDef, ClassDef, fragment
from opsdir.domains.observability.naming import DURATION

ARC = "1.3.6.1.4.1.32473.3.7"      # packages in this repository: .3.<n> of the documentation PEN (SPEC 2.1)
ORIGIN = "azure"
KINDS = ("scheduled", "nrt")
# The alert properties a rule's results may set (alert details override's dynamic properties): what azurerm 5.10.0
# accepts (terraform validate lists them); the alertRules API 2025-09-01 types the name as any string
ALERT_PROPERTIES = ("AlertLink", "ConfidenceLevel", "ConfidenceScore", "ExtendedLinks", "ProductComponentName",
                    "ProductName", "ProviderName", "RemediationSteps", "SubTechniques", "Techniques")
_COLUMN = r"[A-Za-z_][A-Za-z0-9_]*"

ATTRIBUTES = (
    AttributeDef(1, 'azSentinelRuleKind', 'enum:' + '|'.join(KINDS), 'binding', True,
                 "How Sentinel runs a detection's analytics rule: scheduled (the default: every evaluation period, "
                 "over it) or nrt (near-real-time: every minute, over what arrived since its last run; a rows "
                 "detection only)"),
    AttributeDef(2, 'azSentinelAlertName', 'string', 'binding', True,
                 "The name of a detection's alerts, its results' columns as {{Column}} (alert details override; "
                 "none: the analytics rule's name)"),
    AttributeDef(3, 'azSentinelAlertDescription', 'string', 'binding', True,
                 "The description of a detection's alerts, its results' columns as {{Column}} (alert details "
                 "override; none: the analytics rule's description)"),
    AttributeDef(4, 'azSentinelSeverityColumn', 'string', 'binding', True,
                 "The result column whose value is an alert's severity (none: the alert rule's severity)",
                 (("X-PATTERN", f"^{_COLUMN}$"),)),
    AttributeDef(5, 'azSentinelTacticsColumn', 'string', 'binding', True,
                 "The result column whose value is an alert's ATT&CK tactics (none: the alert rule's tactics)",
                 (("X-PATTERN", f"^{_COLUMN}$"),)),
    AttributeDef(6, 'azSentinelAlertProperty', 'string', 'binding', False,
                 "An alert property a result column sets: '<property>=<column>', property one of "
                 + ", ".join(ALERT_PROPERTIES),
                 (("X-PATTERN", "^(" + "|".join(ALERT_PROPERTIES) + f")={_COLUMN}$"),)),
    AttributeDef(7, 'azSentinelSuppression', 'string', 'binding', True,
                 "How long Sentinel stops running a detection's analytics rule after it raises an alert (5m to 24h, "
                 "whole minutes; none: never)", (("X-PATTERN", DURATION),)),
)
CHOICES = tuple(a.name for a in ATTRIBUTES)
CLASSES = (
    ClassDef(1, 'azSentinelRule', 'top', 'AUXILIARY', (), CHOICES,
             "Microsoft Sentinel's choices for a SIEM detection (on its alarm binding): how its analytics rule runs, "
             "its alerts' details and its suppression"),
)
SENTINEL_RULE = CLASSES[0].name

FRAGMENT = fragment(ATTRIBUTES, CLASSES, ARC, ORIGIN)
