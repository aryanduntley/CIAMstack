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
(a comment).

An organization-wide service (ciamAuditScope organization, milestone 5.7b, decision 2777) is enabled by the
organization, its part stamped with the entry's organization origin (kept by ciamManagedBy, else the landing zone's
keeper): the management account (provider aws.management) registers the security services' delegated administrator
(ciamSecurityAdminRef), whose account (provider aws.security_admin) holds the organization configuration:
  threat-detection        its own detector and features, aws_guardduty_organization_configuration enabling every member
                          (auto_enable_organization_members ALL) and an aws_guardduty_organization_configuration_feature
                          per feature its areas need
  vulnerability-scanning  its own enabler, aws_inspector2_organization_configuration enabling the scans of its areas for
                          every member
  posture                 its own hub, a finding aggregator, aws_securityhub_organization_configuration in central
                          configuration, an aws_securityhub_configuration_policy enabling the standards for every
                          account, associated with the organization's root
  config-recording        AWS Config's delegated administrator (aws_organizations_delegated_administrator) and an
                          organization aggregator through a role with AWSConfigRoleForOrganizations; an organization
                          can't turn members' recorders on this way, so the environment's own recorder stays
The environment's own root keeps the findings and incident routing and a line saying who enables it; in every region
(ciamAllRegions) the GuardDuty and Inspector parts are made in each region (management_<region>, security_admin_<region>
providers). Without the accounts the record must name (ciamManagementRef, ciamSecurityAdminRef), not rendered.

What isn't rendered, or is left to a person, is a render note (security_notes, flow 43), written as its comment.

A service in every region (ciamAllRegions, milestone 5.7b) renders its detector, enabler, hub or recorder in each region
it may run in (security_regions): the region catalog's available regions of the cloud's partition, less those the
environment's region guardrail denies (no action runs there, so nothing to watch; the detector couldn't be made).
Opt-in regions are named, not rendered: the catalog doesn't say whether the account opted in. Each region's copy goes
through an aws provider of its own (region_<region>: Terraform providers have no for_each), named after the region; IAM
roles are global and made once; AWS Config records global resource types in the cloud's region only. Security Hub
aggregates every region's findings in the cloud's region (a finding aggregator), where the findings routing is; without
it, the other regions' findings stay there (said in a comment).

Findings at or above a service's ciamIncidentSeverity also go to the incident process (its ciamIncidentRole) through a
second EventBridge rule filtering on the finding's severity: GuardDuty's numeric detail.severity (low 1.0, medium 4.0,
high 7.0, critical 9.0 and up), Security Hub's detail.findings.Severity.Label and Inspector's detail.severity (the
labels at or above it); AWS Config has no finding severity (a comment).

Read back from Terraform state (and from the CLI and CloudFormation, normalized to the same names: cli_security.py,
cloudformation_security.py): aws_guardduty_detector (+ aws_guardduty_detector_feature, its legacy datasources;
aws_guardduty_organization_configuration: organization scope), aws_inspector2_enabler,
aws_config_configuration_recorder (+ its delivery channel's bucket as the findings destination,
aws_config_retention_configuration), aws_securityhub_account (+ aws_securityhub_standards_subscription,
aws_securityhub_organization_configuration) -> security services (kind
security), the SNS topic or log group an EventBridge rule for the service's findings targets as their destination,
and the one a rule filtering them on severity targets as their incident route (with the least severity it lets
through). Coverage is in one order (AREA_ORDER), whatever order the source lists features or resource types in.
"""
import json
import re
from collections import namedtuple

from opsdir.core.directory import get, is_kind, one, rdn_value, values
from opsdir.core.environment import of_class
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.estate.incidents import incident_routes
from opsdir.domains.estate.naming import SEVERITIES
from opsdir.domains.estate.regions import catalog_regions
from opsdir.domains.estate.residency import permitted_regions
from opsdir.domains.estate.security import findings_destination, security_services
from opsdir.domains.governance.keepers import organization_line, organization_origin, organization_wide
from opsdir.domains.observability.audit import INDEFINITE
from opsdir_format_terraform.hcl import Block, TfBlock, comment, from_entry, jsonencoded, ref, tf_block, tf_name
from .account import MANAGEMENT, SECURITY_ADMIN, management_account, partition, security_admin_account
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
AGGREGATOR = "aws_securityhub_finding_aggregator"
STATUS = "aws_config_configuration_recorder_status"
GD_ADMIN, GD_ORG = "aws_guardduty_organization_admin_account", "aws_guardduty_organization_configuration"
GD_ORG_FEATURE = "aws_guardduty_organization_configuration_feature"
INSPECTOR_ADMIN, INSPECTOR_ORG = "aws_inspector2_delegated_admin_account", "aws_inspector2_organization_configuration"
HUB_ADMIN, HUB_ORG = "aws_securityhub_organization_admin_account", "aws_securityhub_organization_configuration"
HUB_POLICY, HUB_ASSOCIATION = "aws_securityhub_configuration_policy", "aws_securityhub_configuration_policy_association"
DELEGATED, CONFIG_AGGREGATOR = "aws_organizations_delegated_administrator", "aws_config_configuration_aggregator"
# what a region of its own holds (IAM is global: made once; EventBridge routing stays in the cloud's region; Security
# Hub's central configuration and AWS Config's aggregator span every region from the cloud's)
REGIONAL = (DETECTOR, FEATURE, ENABLER, RECORDER, CHANNEL, RETENTION, STATUS, HUB, SUBSCRIPTION, GD_ADMIN, GD_ORG,
            GD_ORG_FEATURE, INSPECTOR_ADMIN, INSPECTOR_ORG)
_ADDRESS = re.compile(r"\b(aws_[a-z0-9_]+)\.([A-Za-z0-9_-]+)")
FOUNDATIONAL = ("control-plane", "identity", "network")    # what a detector's own sources watch
AREA_ORDER = ("control-plane", "identity", "network", "compute", "containers", "storage", "databases", "key-vaults",
              "applications")
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
_HUB = "arn:${data.aws_partition.current.partition}:securityhub:${data.aws_region.current.region}::"
# the least GuardDuty severity value of each level (GuardDuty's severity levels: low 1.0-3.9 .. critical 9.0-10.0)
GUARDDUTY_FLOOR = {"low": 1, "medium": 4, "high": 7, "critical": 9}
AREA = "Security"


def region_alias(region):
    """The aws provider alias a security service's copy in region is made through."""
    return f"region_{tf_name(region)}"


def _guardrail(m):
    """The environment's guardrail denying every region but those it may use (ciamDenies region-escape), or None."""
    return next((g for g in of_class(m, "ciamGuardrail") if "region-escape" in values(g, "ciamDenies")), None)


# regions: the other regions a service in every region runs in; denied: those the region guardrail denies; opt_in:
# those open only to accounts that opt in; listed: whether the catalog holds any region of the cloud's partition
Regions = namedtuple("Regions", ("regions", "denied", "opt_in", "listed"))


def security_regions(m):
    """The regions besides its own a security service of environment m in every region runs in (Regions): the region
    catalog's available regions of the cloud's partition (GovCloud's or the others), less those its region guardrail
    denies; opt-in regions apart (the catalog doesn't say whether the account opted in)."""
    home = one(m.cloud, "ciamRegion") or ""
    gov = home.startswith("us-gov-")
    listed = [r for r in catalog_regions(m.d, "aws") if rdn_value(r).startswith("us-gov-") == gov]
    allowed = set(permitted_regions(m)) if _guardrail(m) is not None else None
    available = [rdn_value(r) for r in listed if one(r, "ciamRegionStatus") == "available" and rdn_value(r) != home]
    return Regions(tuple(r for r in available if allowed is None or r in allowed),
                   tuple(r for r in available if allowed is not None and r not in allowed),
                   tuple(rdn_value(r) for r in listed if one(r, "ciamRegionStatus") == "opt-in"), bool(listed))


def every_region(m):
    """The regions environment m's security services in every region need a provider for (region_alias)."""
    wanted = any(one(s, "ciamAllRegions") == "TRUE" for s in security_services(m))
    return security_regions(m).regions if wanted else ()


def _rewrite(v, renamed, region):
    """A body value with references to renamed resources pointing at their copies and the region lookup's value
    the region itself."""
    if isinstance(v, str):
        v = _ADDRESS.sub(lambda x: f"{x.group(0)}_{tf_name(region)}" if x.group(0) in renamed else x.group(0), v)
        return v.replace("${data.aws_region.current.region}", region)
    if isinstance(v, Block):
        return Block(tuple((k, _rewrite(x, renamed, region)) for k, x in v.body))
    if isinstance(v, (list, tuple)):
        return type(v)(_rewrite(x, renamed, region) for x in v)
    if isinstance(v, dict):
        return {k: _rewrite(x, renamed, region) for k, x in v.items()}
    return v


def _local_only(b):
    """A regional AWS Config recorder: global resource types are recorded in the cloud's region only."""
    if b.labels[0] != RECORDER:
        return b
    return b._replace(body=tuple((k, Block(tuple((kk, False if kk == "include_global_resource_types" else vv)
                                                 for kk, vv in v.body))) if k == "recording_group" else (k, v)
                                 for k, v in b.body))


def _provider_in(b, region):
    """The provider a block's copy in region is made through: its own account's in that region (an aliased provider
    <alias>_<region>), else the environment's (region_alias)."""
    given = next((v for k, v in b.body if k == "provider"), None)
    alias = given[len("${aws."):-1] if given else None
    return ref(f"aws.{alias}_{tf_name(region)}" if alias else f"aws.{region_alias(region)}")


def in_region(items, region):
    """The copy of a service's regional resources (REGIONAL) for region: each named <name>_<region>, made through
    that region's provider for its account (_provider_in), references among them following; comments and global
    resources left to the original."""
    blocks = [x for x in items if isinstance(x, TfBlock) and x.kind == "resource" and x.labels[0] in REGIONAL]
    renamed = {f"{b.labels[0]}.{b.labels[1]}" for b in blocks}
    return tuple(_local_only(b._replace(
        labels=(b.labels[0], f"{b.labels[1]}_{tf_name(region)}"),
        body=(("provider", _provider_in(b, region)),
              *((k, _rewrite(v, renamed, region)) for k, v in b.body if k not in ("#", "provider"))))) for b in blocks)


def regions_note(m, s):
    """The render note of a service in every region when the region catalog holds no aws regions (a blocker: only
    the cloud's own region renders), or None."""
    if security_regions(m).listed:
        return None
    home = one(m.cloud, "ciamRegion")
    return note(AREA, "blocker", rdn_value(s), "runs in every region, but the region catalog holds no aws regions "
                f"(`opsdir prerequisites`): only {home} renders",
                ("Fetch the region catalog (`opsdir prerequisites`), then re-render",), s.dn,
                f"every region of {m.label} but {home}")


def _everywhere(m, s, own):
    """What a service in every region adds to its own region's resources: their copy in each other region, Security
    Hub's finding aggregator (for the environment's own hub), and comments naming where it runs and where it doesn't."""
    cn, home, found = rdn_value(s), one(m.cloud, "ciamRegion"), security_regions(m)
    aggregate = not organization_wide(s)
    if not found.listed:
        return (comment(note_comment(regions_note(m, s))),)
    kind, n = one(s, "ciamSecurityKind"), tf_name(cn)
    guardrail = _guardrail(m)
    return (comment(f"{cn}: in every region: {', '.join((home, *found.regions))}"),
            *((comment(f"{cn}: not in {', '.join(found.denied)}: guardrail {rdn_value(guardrail)} denies every "
                       "action there"),) if found.denied else ()),
            *((comment(f"{cn}: not in opt-in regions {', '.join(found.opt_in)}: the record doesn't say the account "
                       "opted in (enable it there once it does)"),) if found.opt_in else ()),
            *((tf_block("resource", [AGGREGATOR, n], [("linking_mode", "ALL_REGIONS"),
                                                      ("depends_on", [ref(f"{HUB}.{n}")])]),)
              if kind == "posture" and found.regions and aggregate else ()),
            *((comment(f"{cn}: its findings in the other regions stay there unless Security Hub aggregates them (a "
                       "posture service in every region)"),)
              if kind != "posture" and found.regions and findings_destination(m, s) is not None and aggregate
              else ()),
            *(x for r in found.regions for x in in_region(own, r)))


# ------------------------------------------------------------------ organization-wide (5.7b)
def _as_admin(items):
    """A service's own resources as its delegated administrator's: named <name>_admin, made through
    aws.security_admin, references among them following (IAM, routing and comments left out)."""
    blocks = [x for x in items if isinstance(x, TfBlock) and x.kind == "resource" and x.labels[0] in REGIONAL]
    renamed = {f"{b.labels[0]}.{b.labels[1]}" for b in blocks}

    def admin(v):
        return _ADDRESS.sub(lambda x: f"{x.group(0)}_admin" if x.group(0) in renamed else x.group(0), v) \
            if isinstance(v, str) else Block(tuple((k, admin(x)) for k, x in v.body)) if isinstance(v, Block) else \
            type(v)(admin(x) for x in v) if isinstance(v, (list, tuple)) else v
    return tuple(b._replace(labels=(b.labels[0], f"{b.labels[1]}_admin"),
                            body=(("provider", ref(f"aws.{SECURITY_ADMIN}")),
                                  *((k, admin(v)) for k, v in b.body if k != "#"))) for b in blocks)


def _org_detection(m, s, n, mgmt, adm, admin):
    features = _features(values(s, "ciamSecurityCoverage"))
    return (tf_block("resource", [GD_ADMIN, n], [mgmt, ("admin_account_id", admin)]),
            *_as_admin(_detector(m, s)),
            tf_block("resource", [GD_ORG, n], [
                adm, ("detector_id", ref(f"{DETECTOR}.{n}_admin.id")), ("auto_enable_organization_members", "ALL"),
                ("depends_on", [ref(f"{GD_ADMIN}.{n}")])]),
            *(tf_block("resource", [GD_ORG_FEATURE, f"{n}_{tf_name(f.lower())}"], [
                adm, ("detector_id", ref(f"{DETECTOR}.{n}_admin.id")), ("name", f), ("auto_enable", "ALL"),
                *(("additional_configuration", Block((("name", x), ("auto_enable", "ALL")))) for x in extra),
                ("depends_on", [ref(f"{GD_ORG}.{n}")])]) for f, extra in features))


def _org_scanning(m, s, n, mgmt, adm, admin):
    kinds = list(_scan_kinds(s))
    return (tf_block("resource", [INSPECTOR_ADMIN, n], [mgmt, ("account_id", admin)]),
            tf_block("resource", [ENABLER, f"{n}_admin"], [adm, ("account_ids", [admin]), ("resource_types", kinds),
                                                           ("depends_on", [ref(f"{INSPECTOR_ADMIN}.{n}")])]),
            tf_block("resource", [INSPECTOR_ORG, n], [
                adm, ("auto_enable", Block(tuple((k.lower(), k in kinds) for k in ("EC2", "ECR", "LAMBDA",
                                                                                    "LAMBDA_CODE")))),
                ("depends_on", [ref(f"{ENABLER}.{n}_admin")])]))


def _org_posture(m, s, n, mgmt, adm, admin):
    arns = [_HUB + path for path in (*(STANDARDS.get(k) for k in values(s, "ciamComplianceStandard")),
                                     *(BASELINES.get(k) for k in values(s, "ciamSecurityBaseline"))) if path]
    return (tf_block("resource", [HUB_ADMIN, n], [mgmt, ("admin_account_id", admin)]),
            tf_block("resource", [HUB, f"{n}_admin"], [
                adm, ("enable_default_standards", False), ("auto_enable_controls", True),
                ("control_finding_generator", "SECURITY_CONTROL"), ("depends_on", [ref(f"{HUB_ADMIN}.{n}")])]),
            tf_block("resource", [AGGREGATOR, f"{n}_admin"], [adm, ("linking_mode", "ALL_REGIONS"),
                                                              ("depends_on", [ref(f"{HUB}.{n}_admin")])]),
            tf_block("resource", [HUB_ORG, n], [
                adm, ("auto_enable", False), ("auto_enable_standards", "NONE"),
                ("organization_configuration", Block((("configuration_type", "CENTRAL"),))),
                ("depends_on", [ref(f"{AGGREGATOR}.{n}_admin")])]),
            tf_block("resource", [HUB_POLICY, n], [
                adm, ("name", rdn_value(s)), ("description", f"{rdn_value(s)}: Security Hub for every account"),
                ("configuration_policy", Block((
                    ("service_enabled", True), ("enabled_standard_arns", arns),
                    ("security_controls_configuration", Block((("disabled_control_identifiers", []),)))))),
                ("depends_on", [ref(f"{HUB_ORG}.{n}")])]),
            tf_block("data", ["aws_organizations_organization", SECURITY_ADMIN], [adm]),
            tf_block("resource", [HUB_ASSOCIATION, n], [
                adm, ("target_id", ref(f"data.aws_organizations_organization.{SECURITY_ADMIN}.roots[0].id")),
                ("policy_id", ref(f"{HUB_POLICY}.{n}.id"))]),
            *((comment(note_comment(standards_note(m, s))),) if standards_note(m, s) else ()))


def _org_recording(m, s, n, mgmt, adm, admin):
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    return (tf_block("resource", [DELEGATED, f"{n}_config"], [mgmt, ("account_id", admin),
                                                              ("service_principal", "config.amazonaws.com")]),
            tf_block("resource", ["aws_iam_role", f"{n}_aggregator"], [
                adm, ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(s)}-aggregator"[:64]),
                ("assume_role_policy", json.dumps(trust, separators=(",", ":")))]),
            tf_block("resource", ["aws_iam_role_policy_attachment", f"{n}_aggregator"], [
                adm, ("role", ref(f"aws_iam_role.{n}_aggregator.name")),
                ("policy_arn", f"arn:{partition(m)}:iam::aws:policy/service-role/AWSConfigRoleForOrganizations")]),
            tf_block("resource", [CONFIG_AGGREGATOR, n], [
                adm, ("name", rdn_value(s)),
                ("organization_aggregation_source", Block((("all_regions", True),
                                                           ("role_arn", ref(f"aws_iam_role.{n}_aggregator.arn"))))),
                ("depends_on", [ref(f"aws_iam_role_policy_attachment.{n}_aggregator"),
                                ref(f"{DELEGATED}.{n}_config")])]))


_ORGANIZATION = {"threat-detection": _org_detection, "vulnerability-scanning": _org_scanning,
                 "posture": _org_posture, "config-recording": _org_recording}


def organization_note(m, s):
    """The render note of an organization-wide service without the accounts its organization part is made from (a
    blocker), or None."""
    missing = [a for a, v in (("ciamManagementRef", management_account(m)),
                              ("ciamSecurityAdminRef", security_admin_account(m))) if not v]
    if not missing:
        return None
    return note(AREA, "blocker", rdn_value(s), f"organization-wide, but not rendered: the record doesn't name "
                f"{' and '.join(missing)} (the organization's management account, its security services' delegated "
                "administrator)",
                (f"Record {' and '.join(missing)} on {rdn_value(m.cloud)}, {RECORD}",), s.dn, "the organization")


def organization_part(m, s):
    """(the organization part of an organization-wide service, the comment of its note (organization_note) for the
    environment's own part or None): what the management account and the security services' delegated administrator
    make for every member account."""
    missing = organization_note(m, s)
    if missing is not None:
        return (), comment(note_comment(missing))
    kind, n = one(s, "ciamSecurityKind"), tf_name(rdn_value(s))
    mgmt, adm = ("provider", ref(f"aws.{MANAGEMENT}")), ("provider", ref(f"aws.{SECURITY_ADMIN}"))
    return _ORGANIZATION[kind](m, s, n, mgmt, adm, security_admin_account(m)), None


def _features(areas):
    """((feature, additional configurations), ...) watching areas, RUNTIME_MONITORING's configurations merged."""
    found = [(f, extra) for a in areas for f, extra in AREA_FEATURES.get(a, ())]
    names = list(dict.fromkeys(f for f, _ in found))
    return tuple((f, tuple(dict.fromkeys(x for g, extra in found if g == f for x in extra))) for f in names)


def _detector(m, s):
    n, areas = tf_name(rdn_value(s)), values(s, "ciamSecurityCoverage")
    return (tf_block("resource", [DETECTOR, n],
                     [("enable", True), ("finding_publishing_frequency", "FIFTEEN_MINUTES")]),
            *(tf_block("resource", [FEATURE, f"{n}_{tf_name(f.lower())}"], [
                ("detector_id", ref(f"{DETECTOR}.{n}.id")), ("name", f), ("status", "ENABLED"),
                *(("additional_configuration", Block((("name", x), ("status", "ENABLED")))) for x in extra)])
              for f, extra in _features(areas)),
            *((comment(f"{rdn_value(s)}: GuardDuty has no plan for key vaults: its CloudTrail analysis sees KMS API "
                       "use (control-plane)"),) if "key-vaults" in areas else ()))


def _scan_kinds(s):
    """The resource types Inspector scans for a service's areas (EC2 and ECR when it names none)."""
    return tuple(dict.fromkeys(t for a in values(s, "ciamSecurityCoverage") for t in INSPECTED.get(a, ()))) or \
        ("EC2", "ECR")


def _scanner(m, s):
    kinds = _scan_kinds(s)
    return (tf_block("resource", [ENABLER, tf_name(rdn_value(s))], [
        ("account_ids", [ref("data.aws_caller_identity.current.account_id")]), ("resource_types", list(kinds))]),)


def _retention(s, n):
    days = one(s, "ciamRetentionDays")
    if days is None or int(days) == INDEFINITE:
        return ()
    kept = min(max(int(days), 30), 2557)
    return ((comment(f"{rdn_value(s)}: AWS Config keeps history 30 to 2557 days: {days} kept as {kept}"),)
            if kept != int(days) else ()) + \
        (tf_block("resource", [RETENTION, n], [("retention_period_in_days", kept)]),)


def _config_bucket(m, s):
    dest = findings_destination(m, s)
    return bucket_of(one(dest, "ciamStorageRef")) if dest is not None and is_kind(m.d, dest, "ciamObjectStore") \
        else None


def recorder_note(m, s):
    """The render note of a config-recording service AWS Config has no S3 bucket to deliver to (a blocker: no
    recorder), or None."""
    if _config_bucket(m, s) is not None:
        return None
    return note(AREA, "blocker", f"security service {rdn_value(s)} (config-recording)", "not rendered: AWS Config "
                "delivers to an S3 bucket and no object store here is its ciamFindingsRole",
                (f"Record the object store of the S3 bucket AWS Config delivers to as the service's ciamFindingsRole, "
                 f"{RECORD}",), s.dn, m.label)


def _recorder(m, s):
    cn, n, bucket = rdn_value(s), tf_name(rdn_value(s)), _config_bucket(m, s)
    if bucket is None:
        return (comment(note_comment(recorder_note(m, s))),)
    return (tf_block("resource", ["aws_iam_service_linked_role", f"{n}_config"],
                     [("aws_service_name", "config.amazonaws.com")]),
            tf_block("resource", [RECORDER, n], [
                ("name", cn), ("role_arn", ref(f"aws_iam_service_linked_role.{n}_config.arn")),
                ("recording_group", Block((("all_supported", True), ("include_global_resource_types", True))))]),
            tf_block("resource", [CHANNEL, n], [("name", cn), ("s3_bucket_name", bucket),
                                                ("depends_on", [ref(f"{RECORDER}.{n}")])]),
            *_retention(s, n),
            tf_block("resource", ["aws_config_configuration_recorder_status", n], [
                ("name", ref(f"{RECORDER}.{n}.name")), ("is_enabled", True),
                ("depends_on", [ref(f"{CHANNEL}.{n}")])]))


def _hub(m, s):
    n = tf_name(rdn_value(s))
    wanted = [*((k, STANDARDS.get(k)) for k in values(s, "ciamComplianceStandard")),
              *((k, BASELINES.get(k)) for k in values(s, "ciamSecurityBaseline"))]
    return (tf_block("resource", [HUB, n], [("enable_default_standards", False), ("auto_enable_controls", True),
                                            ("control_finding_generator", "SECURITY_CONTROL")]),
            *(tf_block("resource", [SUBSCRIPTION, f"{n}_{tf_name(k)}"], [
                ("standards_arn", _HUB + path), ("depends_on", [ref(f"{HUB}.{n}")])])
              for k, path in wanted if path is not None),
            *((comment(note_comment(standards_note(m, s))),) if standards_note(m, s) else ()))


def _target(m, dest):
    return one(dest, "ciamProviderRef") if not is_kind(m.d, dest, "ciamObjectStore") else None


def _route_note(m, s, dest, role, what, store_why):
    """The blocker of a service's findings or incidents (what) to role, whose binding dest is no EventBridge target."""
    store = is_kind(m.d, dest, "ciamObjectStore")
    return note(AREA, "blocker", f"{rdn_value(s)}'s {what} to {role}",
                f"not rendered: {store_why if store else f'{rdn_value(dest)} names no ARN (ciamProviderRef)'}",
                (f"Bind {role} to an alert channel (its SNS topic's ARN as ciamProviderRef) or a log destination (its "
                 f"CloudWatch log group's ARN), {RECORD}",) if store else
                (f"Record the ARN of {rdn_value(dest)}'s SNS topic or CloudWatch log group (ciamProviderRef), "
                 f"{RECORD}",), s.dn, m.label)


def standards_note(m, s):
    """The render note of a posture service's frameworks Security Hub has no standard for (an action: assess them
    another way), or None."""
    missing = [*(k for k in values(s, "ciamComplianceStandard") if k not in STANDARDS),
               *(k for k in values(s, "ciamSecurityBaseline") if k not in BASELINES)]
    if not missing:
        return None
    return note(AREA, "action", rdn_value(s), f"Security Hub has no standard for {', '.join(missing)}: assess it "
                "another way (an AWS Audit Manager framework, a Config conformance pack), not rendered",
                (f"Assess {', '.join(missing)} with an AWS Audit Manager framework or a Config conformance pack, by "
                 "hand",), s.dn, m.label)


def delivery_note(m, s, role, what, target):
    """The render note (an action) of a rendered findings or incident route (what) to target, an SNS topic or a
    CloudWatch log group whose resource policy someone else keeps: it must let EventBridge deliver to it."""
    topic = ":sns:" in target
    return note(AREA, "action", f"{rdn_value(s)}'s {what} to {role}", "its resource policy must let "
                "events.amazonaws.com deliver to it",
                (f"Allow events.amazonaws.com sns:Publish in topic {target}'s access policy (aws:SourceArn the rule's "
                 "ARN)",) if topic else
                (f"Add a CloudWatch Logs resource policy letting events.amazonaws.com and delivery.logs.amazonaws.com "
                 f"create log streams and put events in {target}",), s.dn, m.label)


def findings_delivery_notes(m, s, kind):
    """The delivery_note of service s's findings route when this render makes it (findings_routing; Macie's too)."""
    dest = findings_destination(m, s)
    return (delivery_note(m, s, one(s, "ciamFindingsRole"), "findings", _target(m, dest)),) \
        if dest is not None and kind in SOURCES and _target(m, dest) else ()


def delivery_notes(m, s, kind):
    """The delivery_note of each route of service s this render makes: its findings' and its incidents'."""
    route = _route(m, s)
    incidents = (delivery_note(m, s, route.role, "incidents", _target(m, route.binding)),) \
        if route is not None and kind in SOURCES and route.binding is not None and _target(m, route.binding) else ()
    return (*findings_delivery_notes(m, s, kind), *incidents)


def findings_note(m, s, kind):
    """The render note of a service's findings route EventBridge can't deliver (a blocker: the findings go nowhere),
    or None."""
    dest = findings_destination(m, s)
    if dest is None or kind not in SOURCES or _target(m, dest):
        return None
    return _route_note(m, s, dest, one(s, "ciamFindingsRole"), "findings",
                       "an object store isn't an EventBridge target (deliver through a Firehose stream)")


def findings_routing(m, s, kind):
    """The EventBridge rule and target sending a service's findings where its ciamFindingsRole says, or its note's
    comment (findings_note)."""
    cn, dest = rdn_value(s), findings_destination(m, s)
    if dest is None or kind not in SOURCES:
        return ()
    target, found = _target(m, dest), findings_note(m, s, kind)
    if found is not None:
        return (comment(note_comment(found)),)
    n, (source, detail) = tf_name(f"{cn}_findings"), SOURCES[kind]
    return (tf_block("resource", [RULE, n], [
                ("name", f"{cn}-findings"), ("description", f"{cn}'s findings to {one(s, 'ciamFindingsRole')}"),
                ("event_pattern", jsonencoded({"source": [source], "detail-type": [detail]}))]),
            tf_block("resource", [TARGET, n], [
                ("#", note_comment(delivery_note(m, s, one(s, "ciamFindingsRole"), "findings", target))),
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


def _route(m, s):
    return next((r for r in incident_routes(m) if r.service.dn == s.dn), None)


def incident_note(m, s, kind):
    """The render note of a service's incident route this render doesn't make, or None: AWS Config's findings have
    no severity to filter on (an action: route its compliance changes by hand), or the route's binding is no
    EventBridge target (a blocker)."""
    route = _route(m, s)
    if route is None:
        return None
    if kind not in SOURCES:
        return note(AREA, "action", f"{rdn_value(s)}'s incidents to {route.role}", "not rendered: AWS Config's "
                    "findings have no severity (route its compliance changes through a Config rule's EventBridge "
                    "event)",
                    (f"Make an EventBridge rule on AWS Config's \"Config Rules Compliance Change\" events, for the "
                     f"rules that matter, targeting {route.role}'s SNS topic or log group",
                     f"Or remove the service's ciamIncidentRole, {RECORD}"), s.dn, m.label)
    if route.binding is None or _target(m, route.binding):
        return None
    return _route_note(m, s, route.binding, route.role, "incidents", "an object store isn't an EventBridge target")


def _incident_routing(m, s, kind):
    """The EventBridge rule and target sending a service's findings at or above its incident severity to the incident
    process (its ciamIncidentRole), or its note's comment (incident_note)."""
    route, found = _route(m, s), incident_note(m, s, kind)
    if route is None:
        return ()
    if found is not None:
        return (comment(note_comment(found)),)
    cn, dest = rdn_value(s), route.binding
    if dest is None:
        return ()
    target = _target(m, dest)
    n, (source, detail) = tf_name(f"{cn}_incidents"), SOURCES[kind]
    return (tf_block("resource", [RULE, n], [
                ("name", f"{cn}-incidents"),
                ("description", f"{cn}'s {route.severity} and worse findings to {route.role} (incident process)"),
                ("event_pattern", jsonencoded({"source": [source], "detail-type": [detail],
                                               "detail": severity_filter(source, route.severity)}))]),
            tf_block("resource", [TARGET, n], [
                ("#", note_comment(delivery_note(m, s, route.role, "incidents", target))),
                ("rule", ref(f"{RULE}.{n}.name")), ("arn", target)]))


_RENDER = {"threat-detection": _detector, "vulnerability-scanning": _scanner, "config-recording": _recorder,
           "posture": _hub}


def _service(m, s):
    """(a service's items in the environment's render, its organization part): an organization-wide one keeps only
    its routing here (AWS Config its recorder too: the organization can't turn members' recorders on) and a line saying
    who enables it."""
    kind = one(s, "ciamSecurityKind")
    everywhere = one(s, "ciamAllRegions") == "TRUE"
    routing = (*findings_routing(m, s, kind), *_incident_routing(m, s, kind))
    if not organization_wide(s):
        own = _RENDER[kind](m, s)
        return (*own, *routing, *(_everywhere(m, s, own) if everywhere else ())), ()
    org, missing = organization_part(m, s)
    own = _RENDER[kind](m, s) if kind == "config-recording" else ()
    return ((*own, *routing, *(_everywhere(m, s, own) if everywhere and own else ()),
             *((missing,) if missing else (comment(organization_line(m, s)),)),
             *((comment(f"{rdn_value(s)}: an organization can't turn members' AWS Config recorders on: this account "
                        "records its own"),) if own else ())),
            (*org, *((x for r in security_regions(m).regions for x in in_region(org, r)) if everywhere else ())))


def security_notes(m):
    """The render notes of environment m's security services (render_security writes their comments), in the order
    _service writes them: its own part's (AWS Config's recorder, every region), its routes', its organization part's."""
    def of(s):
        kind, org = one(s, "ciamSecurityKind"), organization_wide(s)
        own = kind == "config-recording" or not org
        return (recorder_note(m, s) if kind == "config-recording" else None,
                standards_note(m, s) if kind == "posture" else None,
                findings_note(m, s, kind), incident_note(m, s, kind), *delivery_notes(m, s, kind),
                regions_note(m, s) if own and one(s, "ciamAllRegions") == "TRUE" else None,
                organization_note(m, s) if org else None)
    return tuple(n for s in security_services(m) for n in of(s) if n is not None)


def render_security(m):
    """HCL (and comments) for environment m's security services (whoever keeps each), each stamped with its entry
    (the render places it by its keeper; the lookups go wherever they are read)."""
    services = security_services(m)
    data = (tf_block("data", ["aws_partition", "current"], []), tf_block("data", ["aws_region", "current"], [])) \
        if any(one(s, "ciamSecurityKind") == "posture" for s in services) else ()
    caller = (tf_block("data", ["aws_caller_identity", "current"], []),) \
        if any(one(s, "ciamSecurityKind") == "vulnerability-scanning" for s in services) else ()
    parts = tuple((s, _service(m, s)) for s in services)
    return (*data, *caller, *(x for s, (own, org) in parts
                              for x in (*from_entry(s.dn, own), *from_entry(organization_origin(s.dn), org))))


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


def _in_order(areas):
    """Areas in one order, whatever order the source lists them in."""
    return tuple(x for x in AREA_ORDER if x in areas)


def _detector_areas(a, features):
    found = {FEATURE_AREAS.get(x) for f in features if _enabled(f.get("status"))
             for x in (f.get("name"), *(c.get("name") for c in f.get("additional_configuration") or ()
                                        if _enabled(c.get("status"))))} | set(_legacy(a))
    return _in_order(found | set(FOUNDATIONAL))


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
        "ciamSecurityCoverage": _in_order({SCANNED[t] for t in a.get("resource_types") or () if t in SCANNED}),
        "ciamAuditScope": _scope(pairs, "aws_inspector2_organization_configuration"),
        **_incident_severity(incidents, "aws.inspector2")},
        links={"ciamFindingsRole": routes.get("aws.inspector2"), **_incident_link(incidents, "aws.inspector2")},
        name="inspector")
        for a in of_types(pairs, ENABLER) if a.get("id"))
    recorders = tuple(resource("security", f"config-recorder:{a.get('name')}", {
        "ciamSecurityKind": "config-recording",
        "ciamAuditScope": "organization" if any(a.get("organization_aggregation_source")
                                                for a in of_types(pairs, CONFIG_AGGREGATOR)) else "account",
        "ciamRetentionDays": retention},
        links={"ciamFindingsRole": f"arn:aws:s3:::{buckets[a.get('name')]}" if buckets.get(a.get("name")) else None},
        name=a.get("name"))
        for a in of_types(pairs, RECORDER) if a.get("name"))
    hubs = tuple(resource("security", a.get("arn") or a.get("id"), {
        "ciamSecurityKind": "posture",
        "ciamComplianceStandard": tuple(sorted({k for k, base in standards if not base})),   # once, whatever the
        "ciamSecurityBaseline": tuple(sorted({k for k, base in standards if base})),         # regions subscribing
        "ciamAuditScope": _scope(pairs, "aws_securityhub_organization_configuration"),
        **_incident_severity(incidents, "aws.securityhub")},
        links={"ciamFindingsRole": routes.get("aws.securityhub"), **_incident_link(incidents, "aws.securityhub")},
        name="security-hub")
        for a in of_types(pairs, HUB) if a.get("arn") or a.get("id"))
    return (*_folded(detectors), *_folded(scanners), *_folded(recorders), *_folded(hubs))


def _folded(found):
    """A kind's services as one: the copies a service in every region has (one detector, enabler, recorder or hub per
    region, an account holds no more) read as one of them, in every region (ciamAllRegions): the one first by its
    reference, whatever order the source lists them in."""
    if len(found) < 2:
        return found
    first = min(found, key=lambda r: (r.ref or "", r.name or ""))
    return (first._replace(attrs={**first.attrs, "ciamAllRegions": ("TRUE",)}),)
