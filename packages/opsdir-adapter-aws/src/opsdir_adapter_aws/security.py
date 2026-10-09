"""Cloud security services on AWS (core estate: ciamSecurityService) as GuardDuty, Inspector, AWS Config and Security
Hub. Pure.

Rendered in the platform's own root, for each service the platform team keeps (no ciamManagedBy; one someone else
keeps is named in a comment):

  threat-detection        aws_guardduty_detector (its foundational sources, CloudTrail management events, VPC flow
                          logs and DNS logs, watch control-plane, identity and network) and an
                          aws_guardduty_detector_feature per further area: storage S3_DATA_EVENTS, containers
                          EKS_AUDIT_LOGS + RUNTIME_MONITORING (EKS add-on, Fargate agent), compute
                          EBS_MALWARE_PROTECTION + RUNTIME_MONITORING (EC2 agent), databases RDS_LOGIN_EVENTS,
                          applications LAMBDA_NETWORK_LOGS; key-vaults has no GuardDuty plan (a comment)
  vulnerability-scanning  aws_inspector2_enabler for the account: EC2 (compute), ECR (containers), LAMBDA and
                          LAMBDA_CODE (applications); EC2 and ECR when the record names no area
  config-recording        aws_config_configuration_recorder through AWS Config's service-linked role, recording every
                          supported resource type, its aws_config_delivery_channel to the S3 bucket of the object
                          store its ciamFindingsRole names (AWS Config needs one: without it, not rendered), an
                          aws_config_retention_configuration for ciamRetentionDays (30 to 2557 days) and the
                          recorder's status
  posture                 aws_securityhub_account (consolidated control findings, no default standards) and an
                          aws_securityhub_standards_subscription per framework Security Hub has (cis, nist-800-53-r5,
                          nist-800-171-r2, pci-dss) and per AWS baseline (aws-foundational, aws-resource-tagging);
                          frameworks it has no standard for (FedRAMP, CMMC, ...) and other clouds' baselines are named
                          in a comment

Findings of GuardDuty, Inspector and Security Hub go where ciamFindingsRole says through an EventBridge rule: to an
alert channel's SNS topic or a log destination's CloudWatch log group (their ciamProviderRef ARNs; the topic's or log
group's resource policy must let EventBridge deliver, said in a comment); an object store isn't an EventBridge target
(a comment). An organization-wide service (ciamAuditScope organization) is enabled for the organization from its
management account or delegated administrator, and a service in every region (ciamAllRegions) needs a detector, hub
or recorder in each region: both said in a comment, this root renders its own account and region.

Findings at or above a service's ciamIncidentSeverity also go to the incident process (its ciamIncidentRole) through a
second EventBridge rule filtering on the finding's severity: GuardDuty's numeric detail.severity (low 1.0, medium 4.0,
high 7.0, critical 9.0 and up), Security Hub's detail.findings.Severity.Label and Inspector's detail.severity (the
labels at or above it); AWS Config has no finding severity (a comment).

Read back from Terraform state: aws_guardduty_detector (+ aws_guardduty_detector_feature, its legacy datasources;
aws_guardduty_organization_configuration: organization scope), aws_inspector2_enabler,
aws_config_configuration_recorder (+ its delivery channel's bucket as the findings destination,
aws_config_retention_configuration), aws_securityhub_account (+ aws_securityhub_standards_subscription,
aws_securityhub_organization_configuration) -> security services (kind
security), the SNS topic or log group an EventBridge rule for the service's findings targets as their destination,
and the one a rule filtering them on severity targets as their incident route (with the least severity it lets
through).
"""
import json

from opsdir.core.directory import get, is_kind, one, rdn_value, values
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.estate.incidents import incident_routes
from opsdir.domains.estate.naming import SEVERITIES
from opsdir.domains.estate.security import findings_destination, security_services
from opsdir.domains.observability.audit import INDEFINITE
from opsdir_format_terraform.hcl import Block, block, jsonencoded, ref, tf_name
from .storage import bucket_of
from .tags import state_tags

DETECTOR = "aws_guardduty_detector"
FEATURE = "aws_guardduty_detector_feature"
ENABLER = "aws_inspector2_enabler"
RECORDER = "aws_config_configuration_recorder"
CHANNEL = "aws_config_delivery_channel"
RETENTION = "aws_config_retention_configuration"
HUB = "aws_securityhub_account"
SUBSCRIPTION = "aws_securityhub_standards_subscription"
RULE, TARGET = "aws_cloudwatch_event_rule", "aws_cloudwatch_event_target"
FOUNDATIONAL = ("control-plane", "identity", "network")    # what a detector's own sources watch
# area -> GuardDuty features (name, additional configurations) that watch it
AREA_FEATURES = {"storage": (("S3_DATA_EVENTS", ()),),
                 "containers": (("EKS_AUDIT_LOGS", ()),
                                ("RUNTIME_MONITORING", ("EKS_ADDON_MANAGEMENT", "ECS_FARGATE_AGENT_MANAGEMENT"))),
                 "compute": (("EBS_MALWARE_PROTECTION", ()), ("RUNTIME_MONITORING", ("EC2_AGENT_MANAGEMENT",))),
                 "databases": (("RDS_LOGIN_EVENTS", ()),),
                 "applications": (("LAMBDA_NETWORK_LOGS", ()),)}
# GuardDuty feature or additional configuration -> the area it watches (read back)
FEATURE_AREAS = {"S3_DATA_EVENTS": "storage", "EKS_AUDIT_LOGS": "containers", "EKS_RUNTIME_MONITORING": "containers",
                 "EKS_ADDON_MANAGEMENT": "containers", "ECS_FARGATE_AGENT_MANAGEMENT": "containers",
                 "EC2_AGENT_MANAGEMENT": "compute", "EBS_MALWARE_PROTECTION": "compute",
                 "RDS_LOGIN_EVENTS": "databases", "LAMBDA_NETWORK_LOGS": "applications"}
INSPECTED = {"compute": ("EC2",), "containers": ("ECR",), "applications": ("LAMBDA", "LAMBDA_CODE")}
SCANNED = {"EC2": "compute", "ECR": "containers", "LAMBDA": "applications", "LAMBDA_CODE": "applications"}
# Security Hub standards: framework or AWS baseline -> its ARN after "securityhub:<region>::" (AWS's reference pages
# and sample findings: standards/nist-800-171/v/2.0.0 and pci-dss/v/4.0.1 appear as findings' StandardsId)
STANDARDS = {"cis": "standards/cis-aws-foundations-benchmark/v/5.0.0",
             "nist-800-53-r5": "standards/nist-800-53/v/5.0.0",
             "nist-800-171-r2": "standards/nist-800-171/v/2.0.0",
             "pci-dss": "standards/pci-dss/v/4.0.1"}
BASELINES = {"aws-foundational": "standards/aws-foundational-security-best-practices/v/1.0.0",
             "aws-resource-tagging": "standards/aws-resource-tagging-standard/v/1.0.0"}
# a standard's ARN path (version aside) -> (framework or baseline id, whether it is a baseline)
_KNOWN = (("cis-aws-foundations-benchmark/", "cis", False), ("nist-800-53/", "nist-800-53-r5", False),
          ("nist-800-171/", "nist-800-171-r2", False), ("pci-dss/", "pci-dss", False),
          ("aws-foundational-security-best-practices/", "aws-foundational", True),
          ("aws-resource-tagging-standard/", "aws-resource-tagging", True))
SOURCES = {"threat-detection": ("aws.guardduty", "GuardDuty Finding"),
           "vulnerability-scanning": ("aws.inspector2", "Inspector2 Finding"),
           "posture": ("aws.securityhub", "Security Hub Findings - Imported"),
           "data-discovery": ("aws.macie", "Macie Finding")}             # Macie (opsdir_adapter_aws.discovery)
_HUB = "arn:${data.aws_partition.current.partition}:securityhub:${data.aws_region.current.name}::"
# the least GuardDuty severity value of each level (GuardDuty's severity levels: low 1.0-3.9 .. critical 9.0-10.0)
GUARDDUTY_FLOOR = {"low": 1, "medium": 4, "high": 7, "critical": 9}


def _notes(m, s):
    """Comments every kept service carries: organization scope, every region."""
    cn = rdn_value(s)
    return (*((f"# {cn}: organization-wide: enable it for the organization from its management account or delegated "
               "administrator (not rendered here)",) if one(s, "ciamAuditScope") == "organization" else ()),
            *((f"# {cn}: runs in every region: each region needs its own (this root renders "
               f"{one(m.cloud, 'ciamRegion')})",) if one(s, "ciamAllRegions") == "TRUE" else ()))


def _features(areas):
    """((feature, additional configurations), ...) watching areas, RUNTIME_MONITORING's configurations merged."""
    found = [(f, extra) for a in areas for f, extra in AREA_FEATURES.get(a, ())]
    names = list(dict.fromkeys(f for f, _ in found))
    return tuple((f, tuple(dict.fromkeys(x for g, extra in found if g == f for x in extra))) for f in names)


def _detector(m, s):
    n, areas = tf_name(rdn_value(s)), values(s, "ciamSecurityCoverage")
    return (block("resource", [DETECTOR, n], [("enable", True), ("finding_publishing_frequency", "FIFTEEN_MINUTES")]),
            *(block("resource", [FEATURE, f"{n}_{tf_name(f.lower())}"], [
                ("detector_id", ref(f"{DETECTOR}.{n}.id")), ("name", f), ("status", "ENABLED"),
                *(("additional_configuration", Block((("name", x), ("status", "ENABLED")))) for x in extra)])
              for f, extra in _features(areas)),
            *((f"# {rdn_value(s)}: GuardDuty has no plan for key vaults: its CloudTrail analysis sees KMS API use "
               "(control-plane)",) if "key-vaults" in areas else ()))


def _scanner(m, s):
    areas = values(s, "ciamSecurityCoverage")
    kinds = tuple(dict.fromkeys(t for a in areas for t in INSPECTED.get(a, ()))) or ("EC2", "ECR")
    return (block("resource", [ENABLER, tf_name(rdn_value(s))], [
        ("account_ids", [ref("data.aws_caller_identity.current.account_id")]), ("resource_types", list(kinds))]),)


def _retention(s, n):
    days = one(s, "ciamRetentionDays")
    if days is None or int(days) == INDEFINITE:
        return ()
    kept = min(max(int(days), 30), 2557)
    return ((f"# {rdn_value(s)}: AWS Config keeps history 30 to 2557 days: {days} kept as {kept}",)
            if kept != int(days) else ()) + (block("resource", [RETENTION, n], [("retention_period_in_days", kept)]),)


def _recorder(m, s):
    cn, n, dest = rdn_value(s), tf_name(rdn_value(s)), findings_destination(m, s)
    bucket = bucket_of(one(dest, "ciamStorageRef")) if dest is not None and is_kind(m.d, dest, "ciamObjectStore") \
        else None
    if bucket is None:
        return (f"# NOTE: security service {cn} (config-recording): not rendered: AWS Config delivers to an S3 "
                "bucket and no object store here is its ciamFindingsRole",)
    return (block("resource", ["aws_iam_service_linked_role", f"{n}_config"],
                  [("aws_service_name", "config.amazonaws.com")]),
            block("resource", [RECORDER, n], [
                ("name", cn), ("role_arn", ref(f"aws_iam_service_linked_role.{n}_config.arn")),
                ("recording_group", Block((("all_supported", True), ("include_global_resource_types", True))))]),
            block("resource", [CHANNEL, n], [("name", cn), ("s3_bucket_name", bucket),
                                             ("depends_on", [ref(f"{RECORDER}.{n}")])]),
            *_retention(s, n),
            block("resource", ["aws_config_configuration_recorder_status", n], [
                ("name", ref(f"{RECORDER}.{n}.name")), ("is_enabled", True),
                ("depends_on", [ref(f"{CHANNEL}.{n}")])]))


def _hub(m, s):
    n = tf_name(rdn_value(s))
    wanted = [*((k, STANDARDS.get(k)) for k in values(s, "ciamComplianceStandard")),
              *((k, BASELINES.get(k)) for k in values(s, "ciamSecurityBaseline"))]
    missing = [k for k, path in wanted if path is None]
    return (block("resource", [HUB, n], [("enable_default_standards", False), ("auto_enable_controls", True),
                                         ("control_finding_generator", "SECURITY_CONTROL")]),
            *(block("resource", [SUBSCRIPTION, f"{n}_{tf_name(k)}"], [
                ("standards_arn", _HUB + path), ("depends_on", [ref(f"{HUB}.{n}")])])
              for k, path in wanted if path is not None),
            *((f"# {rdn_value(s)}: Security Hub has no standard for {', '.join(missing)}: assess it another way "
               "(an AWS Audit Manager framework, a Config conformance pack), not rendered",) if missing else ()))


def findings_routing(m, s, kind):
    """The EventBridge rule and target sending a service's findings where its ciamFindingsRole says, or a note."""
    cn, dest = rdn_value(s), findings_destination(m, s)
    if dest is None or kind not in SOURCES:
        return ()
    target = one(dest, "ciamProviderRef") if not is_kind(m.d, dest, "ciamObjectStore") else None
    if not target:
        why = ("an object store isn't an EventBridge target (deliver through a Firehose stream)"
               if is_kind(m.d, dest, "ciamObjectStore") else f"{rdn_value(dest)} names no ARN (ciamProviderRef)")
        return (f"# NOTE: {cn}'s findings to {one(s, 'ciamFindingsRole')}: not rendered: {why}",)
    n, (source, detail) = tf_name(f"{cn}_findings"), SOURCES[kind]
    return (block("resource", [RULE, n], [
                ("name", f"{cn}-findings"), ("description", f"{cn}'s findings to {one(s, 'ciamFindingsRole')}"),
                ("event_pattern", jsonencoded({"source": [source], "detail-type": [detail]}))]),
            block("resource", [TARGET, n], [
                ("#", "its resource policy must let events.amazonaws.com deliver to it"),
                ("rule", ref(f"{RULE}.{n}.name")), ("arn", target)]))


def _labels(severity):
    """The severity labels (upper case) at or above a neutral severity."""
    return [x.upper() for x in SEVERITIES[SEVERITIES.index(severity):]]


def severity_filter(source, severity):
    """The EventBridge pattern's detail filter letting a security service's findings at or above a severity through."""
    if source == "aws.guardduty":
        return {"severity": [{"numeric": [">=", GUARDDUTY_FLOOR[severity]]}]}
    if source == "aws.securityhub":
        return {"findings": {"Severity": {"Label": _labels(severity)}}}
    return {"severity": _labels(severity)}


def _incident_routing(m, s, kind):
    """The EventBridge rule and target sending a service's findings at or above its incident severity to the incident
    process (its ciamIncidentRole), or a note."""
    route = next((r for r in incident_routes(m) if r.service.dn == s.dn), None)
    if route is None:
        return ()
    cn, dest = rdn_value(s), route.binding
    if kind not in SOURCES:
        return (f"# NOTE: {cn}'s incidents to {route.role}: not rendered: AWS Config's findings have no severity "
                "(route its compliance changes through a Config rule's EventBridge event)",)
    if dest is None:
        return ()
    target = one(dest, "ciamProviderRef") if not is_kind(m.d, dest, "ciamObjectStore") else None
    if not target:
        why = ("an object store isn't an EventBridge target" if is_kind(m.d, dest, "ciamObjectStore") else
               f"{rdn_value(dest)} names no ARN (ciamProviderRef)")
        return (f"# NOTE: {cn}'s incidents to {route.role}: not rendered: {why}",)
    n, (source, detail) = tf_name(f"{cn}_incidents"), SOURCES[kind]
    return (block("resource", [RULE, n], [
                ("name", f"{cn}-incidents"),
                ("description", f"{cn}'s {route.severity} and worse findings to {route.role} (incident process)"),
                ("event_pattern", jsonencoded({"source": [source], "detail-type": [detail],
                                               "detail": severity_filter(source, route.severity)}))]),
            block("resource", [TARGET, n], [
                ("#", "its resource policy must let events.amazonaws.com deliver to it"),
                ("rule", ref(f"{RULE}.{n}.name")), ("arn", target)]))


_RENDER = {"threat-detection": _detector, "vulnerability-scanning": _scanner, "config-recording": _recorder,
           "posture": _hub}


def _service(m, s):
    kind, keeper = one(s, "ciamSecurityKind"), one(s, "ciamManagedBy")
    if keeper:
        holder = get(m.d, keeper)
        return (f"# Security service {rdn_value(s)} ({kind}): kept by "
                f"{rdn_value(holder) if holder is not None else keeper}, not rendered here",)
    return (*_RENDER[kind](m, s), *findings_routing(m, s, kind), *_incident_routing(m, s, kind), *_notes(m, s))


def render_security(m):
    """HCL (and comments) for environment m's security services."""
    services = security_services(m)
    data = (block("data", ["aws_partition", "current"], []), block("data", ["aws_region", "current"], [])) \
        if any(one(s, "ciamSecurityKind") == "posture" and not one(s, "ciamManagedBy") for s in services) else ()
    caller = (block("data", ["aws_caller_identity", "current"], []),) \
        if any(one(s, "ciamSecurityKind") == "vulnerability-scanning" and not one(s, "ciamManagedBy")
               for s in services) else ()
    return (*data, *caller, *(x for s in services for x in _service(m, s)))


def _enabled(v):
    return (v or "").upper() == "ENABLED"


def _first(v):
    return v[0] if isinstance(v, list) and v else v if isinstance(v, dict) else {}


def _legacy(a):
    """Areas a detector's legacy datasources block turns on."""
    ds = _first(a.get("datasources"))
    s3 = _first(ds.get("s3_logs")).get("enable")
    k8s = _first(_first(ds.get("kubernetes")).get("audit_logs")).get("enable")
    ebs = _first(_first(_first(ds.get("malware_protection")).get("scan_ec2_instance_with_findings"))
                 .get("ebs_volumes")).get("enable")
    return (*(("storage",) if s3 else ()), *(("containers",) if k8s else ()), *(("compute",) if ebs else ()))


def _detector_areas(a, features):
    found = {FEATURE_AREAS.get(x) for f in features if _enabled(f.get("status"))
             for x in (f.get("name"), *(c.get("name") for c in f.get("additional_configuration") or ()
                                        if _enabled(c.get("status"))))} | set(_legacy(a))
    return tuple(x for x in ("control-plane", "identity", "network", "compute", "containers", "storage",
                             "databases", "key-vaults", "applications")
                 if x in FOUNDATIONAL or x in found)


def _least(source, detail):
    """The least neutral severity an EventBridge pattern's detail filter lets through, or None when it filters none."""
    if source == "aws.guardduty":
        floors = [num[i + 1] for c in (detail.get("severity") or ()) if isinstance(c, dict)
                  for num in (c.get("numeric") or [],) for i in range(0, len(num) - 1, 2) if num[i] in (">=", ">")]
        return max((s for s, f in GUARDDUTY_FLOOR.items() if floors and f <= min(floors)),
                   key=SEVERITIES.index, default="low" if floors else None)
    labels = (((detail.get("findings") or {}).get("Severity") or {}).get("Label") if source == "aws.securityhub"
              else detail.get("severity")) or ()
    known = [x.lower() for x in labels if isinstance(x, str) and x.lower() in SEVERITIES]
    return min(known, key=SEVERITIES.index) if known else None


def _rules(pairs):
    """{rule name: ((event source, least severity or None), ...)} of the EventBridge rules for security findings."""
    def parsed(r):
        try:
            return json.loads(r.get("event_pattern") or "{}")
        except ValueError:
            return {}
    return {r.get("name"): tuple((src, _least(src, p.get("detail") or {})) for src in p.get("source") or ())
            for r in of_types(pairs, RULE) for p in (parsed(r),)}


def _targets(pairs):
    """((event source, least severity or None, target ARN), ...) of the rules' targets."""
    rules = _rules(pairs)
    return tuple((src, least, t.get("arn")) for t in of_types(pairs, TARGET) if t.get("arn")
                 for src, least in rules.get(t.get("rule"), ()))


def findings_routes(pairs):
    """{event source: the ARN its findings rule (no severity filter) targets}."""
    return {src: arn for src, least, arn in _targets(pairs) if least is None}


def _incidents(pairs):
    """{event source: (the ARN a rule filtering its findings on severity targets, the least severity it lets
    through)}."""
    return {src: (arn, least) for src, least, arn in _targets(pairs) if least is not None}


def findings_topics(pairs):
    """ARNs of SNS topics EventBridge rules send security findings to (all of them, or the incident process's)."""
    wanted = {src for src, _ in SOURCES.values()}
    return frozenset(arn for src, _, arn in _targets(pairs) if src in wanted and ":sns:" in arn)


def _standard(arn):
    """(id, is a baseline) of a Security Hub standards ARN; an unknown one by its name, as a baseline."""
    path = (arn or "").split("::", 1)[-1]
    for part, key, baseline in _KNOWN:
        if part in path:
            return key, baseline
    name = path.split("/")[1] if path.count("/") >= 1 else path
    return name.lower(), True


def _scope(pairs, kind):
    return "organization" if of_types(pairs, kind) else "account"


def _incident_link(incidents, source):
    """The incident role link (and nothing when none routes the source's findings on severity)."""
    return {"ciamIncidentRole": incidents[source][0]} if source in incidents else {}


def _incident_severity(incidents, source):
    return {"ciamIncidentSeverity": incidents[source][1]} if source in incidents else {}


def security_resources(pairs):
    """Security services of (Terraform resource type, attributes) pairs."""
    routes, incidents = findings_routes(pairs), _incidents(pairs)
    found = of_types(pairs, FEATURE)
    features = {i: [f for f in found if f.get("detector_id") == i] for i in {f.get("detector_id") for f in found}}
    buckets = {c.get("name"): c.get("s3_bucket_name") for c in of_types(pairs, CHANNEL)}
    retention = next((c.get("retention_period_in_days") for c in of_types(pairs, RETENTION)), None)
    standards = [_standard(s.get("standards_arn")) for s in of_types(pairs, SUBSCRIPTION)]
    detectors = tuple(resource("security", a.get("arn") or a.get("id"), {
        "ciamSecurityKind": "threat-detection",
        "ciamSecurityCoverage": _detector_areas(a, features.get(a.get("id"), ())),
        "ciamAuditScope": _scope(pairs, "aws_guardduty_organization_configuration"),
        **_incident_severity(incidents, "aws.guardduty")},
        links={"ciamFindingsRole": routes.get("aws.guardduty"), **_incident_link(incidents, "aws.guardduty")},
        name=f"guardduty-{a.get('id')}", role=tagged_role(state_tags(a)), tags=state_tags(a))
        for a in of_types(pairs, DETECTOR) if a.get("enable", True) and (a.get("arn") or a.get("id")))
    scanners = tuple(resource("security", f"inspector2:{a.get('id')}", {
        "ciamSecurityKind": "vulnerability-scanning",
        "ciamSecurityCoverage": tuple(dict.fromkeys(SCANNED[t] for t in a.get("resource_types") or ()
                                                    if t in SCANNED)),
        "ciamAuditScope": _scope(pairs, "aws_inspector2_organization_configuration"),
        **_incident_severity(incidents, "aws.inspector2")},
        links={"ciamFindingsRole": routes.get("aws.inspector2"), **_incident_link(incidents, "aws.inspector2")},
        name="inspector")
        for a in of_types(pairs, ENABLER) if a.get("id"))
    recorders = tuple(resource("security", f"config-recorder:{a.get('name')}", {
        "ciamSecurityKind": "config-recording", "ciamAuditScope": "account",
        "ciamRetentionDays": retention},
        links={"ciamFindingsRole": f"arn:aws:s3:::{buckets[a.get('name')]}" if buckets.get(a.get("name")) else None},
        name=a.get("name"))
        for a in of_types(pairs, RECORDER) if a.get("name"))
    hubs = tuple(resource("security", a.get("arn") or a.get("id"), {
        "ciamSecurityKind": "posture",
        "ciamComplianceStandard": tuple(sorted(k for k, base in standards if not base)),
        "ciamSecurityBaseline": tuple(sorted(k for k, base in standards if base)),
        "ciamAuditScope": _scope(pairs, "aws_securityhub_organization_configuration"),
        **_incident_severity(incidents, "aws.securityhub")},
        links={"ciamFindingsRole": routes.get("aws.securityhub"), **_incident_link(incidents, "aws.securityhub")},
        name="security-hub")
        for a in of_types(pairs, HUB) if a.get("arn") or a.get("id"))
    return (*detectors, *scanners, *recorders, *hubs)
