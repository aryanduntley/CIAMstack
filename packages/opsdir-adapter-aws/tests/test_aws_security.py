"""Cloud security services on AWS: GuardDuty with a feature per area it watches, Inspector for the resource types its
areas name, AWS Config into its object store's bucket with its retention, Security Hub with a subscription per
standard it has (standards it lacks said in a comment), findings sent to an SNS topic by an
EventBridge rule, organization scope, other regions and services kept by someone else in comments; all of them read back
from Terraform state, with the topic, bucket or log group their findings go to as the role of that binding; the AWS
CLI's outputs of the same services read as the same record (organization scope only from the delegated administrator's
saved answer)."""
import json
import re

from opsdir.core.inventory import environment_groups, resource
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.inventory import pairs_resources
from opsdir_adapter_aws.security import render_security, security_resources
from network_fixtures import ALPHA, entry, model

PARTY = "cn=landing-zone,ou=owners,dc=ciam-ops"
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
          f"dn: {PARTY}\nobjectClass: top\nobjectClass: ciamParty\ncn: landing-zone\nciamOwnerKind: team\n")
TOPIC_ARN = "arn:aws:sns:us-east-1:111122223333:security-alerts"
BUCKET = entry(ALPHA, "config-history", "ciamObjectStore", ciamBindingRole="config-history",
               ciamStorageRef="s3://example-ciam-config")
TOPIC = entry(ALPHA, "security-alerts", "ciamAlertChannel", ciamBindingRole="security-alerts",
              ciamChannelKind="topic", ciamProviderRef=TOPIC_ARN)


def svc(cn, kind, **more):
    return entry(ALPHA, cn, "ciamSecurityService", ciamBindingRole=cn, ciamSecurityKind=kind, **more)


def _render(*services):
    _, alpha, _ = model(alpha=(BUCKET, TOPIC, *services), tree=OWNERS)
    return "\n\n".join(as_text(render_security(alpha)))


def test_guardduty_turns_on_a_feature_per_area_and_sends_findings_to_the_topic():
    out = _render(svc("guardduty", "threat-detection", ciamFindingsRole="security-alerts", ciamAllRegions="TRUE",
                      ciamSecurityCoverage=("control-plane", "network", "containers", "compute", "key-vaults")))
    assert 'resource "aws_guardduty_detector" "guardduty" {\n  enable                       = true\n' in out
    assert [f for f in ("S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "RUNTIME_MONITORING", "EBS_MALWARE_PROTECTION",
                        "RDS_LOGIN_EVENTS") if f'name        = "{f}"' in out] == [
        "EKS_AUDIT_LOGS", "RUNTIME_MONITORING", "EBS_MALWARE_PROTECTION"]
    assert out.count("additional_configuration {") == 3 and '"EC2_AGENT_MANAGEMENT"' in out
    assert "# guardduty: GuardDuty has no plan for key vaults" in out
    assert '"aws.guardduty"' in out and f'arn  = "{TOPIC_ARN}"' in out
    assert "# NOTE: guardduty: runs in every region, but the region catalog holds no aws regions" in out


def test_inspector_scans_the_resource_types_of_its_areas():
    out = _render(svc("inspector", "vulnerability-scanning", ciamSecurityCoverage=("compute", "applications")))
    assert 'data "aws_caller_identity" "current"' in out
    assert 'resource_types = ["EC2", "LAMBDA", "LAMBDA_CODE"]' in out
    assert 'resource_types = ["EC2", "ECR"]' in _render(svc("inspector", "vulnerability-scanning"))


def test_aws_config_records_into_its_object_store_s_bucket_or_isn_t_rendered():
    out = _render(svc("config", "config-recording", ciamFindingsRole="config-history", ciamRetentionDays="3650"))
    assert 's3_bucket_name = "example-ciam-config"' in out
    assert "role_arn = aws_iam_service_linked_role.config_config.arn" in out
    assert "# config: AWS Config keeps history 30 to 2557 days: 3650 kept as 2557" in out
    assert "retention_period_in_days = 2557" in out and "is_enabled = true" in out
    assert _render(svc("config", "config-recording", ciamFindingsRole="security-alerts")) == (
        "# NOTE: security service config (config-recording): not rendered: AWS Config delivers to an S3 bucket and "
        "no object store here is its ciamFindingsRole")


def test_security_hub_subscribes_to_the_standards_it_has_and_names_the_rest():
    out = _render(svc("hub", "posture", ciamSecurityBaseline=("aws-foundational",),
                      ciamComplianceStandard=("nist-800-53-r5", "nist-800-171-r2", "cmmc-l2")))
    assert 'data "aws_partition" "current"' in out and 'control_finding_generator = "SECURITY_CONTROL"' in out
    assert ("arn:${data.aws_partition.current.partition}:securityhub:${data.aws_region.current.region}::standards/"
            "nist-800-53/v/5.0.0") in out
    assert "aws-foundational-security-best-practices/v/1.0.0" in out
    assert "standards/nist-800-171/v/2.0.0" in out and "describe-standards" not in out
    assert "# NOTE: hub: Security Hub has no standard for cmmc-l2: assess it another way" in out


def test_a_service_someone_else_keeps_renders_too_for_its_keeper():
    assert 'resource "aws_guardduty_detector" "org_guardduty"' in _render(
        svc("org-guardduty", "threat-detection", ciamManagedBy=PARTY))      # placed by its keeper (render_files)


DETECTOR = {"id": "12abc", "arn": "arn:aws:guardduty:us-east-1:111122223333:detector/12abc", "enable": True,
            "tags_all": {"Role": "guardduty"}}
STATE = [("aws_guardduty_detector", DETECTOR),
         ("aws_guardduty_detector_feature", {"detector_id": "12abc", "name": "S3_DATA_EVENTS", "status": "ENABLED"}),
         ("aws_guardduty_detector_feature", {"detector_id": "12abc", "name": "RUNTIME_MONITORING", "status": "ENABLED",
                                             "additional_configuration": [{"name": "EKS_ADDON_MANAGEMENT",
                                                                           "status": "ENABLED"}]}),
         ("aws_guardduty_detector_feature", {"detector_id": "12abc", "name": "RDS_LOGIN_EVENTS", "status": "DISABLED"}),
         ("aws_guardduty_organization_configuration", {"detector_id": "12abc", "auto_enable": True}),
         ("aws_inspector2_enabler", {"id": "111122223333-EC2:ECR", "resource_types": ["ECR", "EC2"]}),
         ("aws_config_configuration_recorder", {"id": "config", "name": "config"}),
         ("aws_config_delivery_channel", {"name": "config", "s3_bucket_name": "example-ciam-config"}),
         ("aws_config_retention_configuration", {"retention_period_in_days": 2557}),
         ("aws_securityhub_account", {"id": "111122223333",
                                      "arn": "arn:aws:securityhub:us-east-1:111122223333:hub/default"}),
         ("aws_securityhub_standards_subscription", {
             "standards_arn": "arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0"}),
         ("aws_securityhub_standards_subscription", {"standards_arn": "arn:aws:securityhub:us-east-1::standards/"
                                                     "aws-foundational-security-best-practices/v/1.0.0"}),
         ("aws_securityhub_standards_subscription", {
             "standards_arn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"}),
         ("aws_cloudwatch_event_rule", {"name": "guardduty-findings", "event_pattern":
                                        '{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"]}'}),
         ("aws_cloudwatch_event_target", {"rule": "guardduty-findings", "arn": TOPIC_ARN}),
         ("aws_sns_topic", {"arn": TOPIC_ARN, "name": "security-alerts", "tags_all": {"Role": "security-alerts"}})]


def test_the_services_are_read_back_from_state():
    found = {r.attrs["ciamSecurityKind"][0]: (dict(r.attrs), dict(r.links)) for r in security_resources(STATE)}
    assert found["threat-detection"] == ({
        "ciamSecurityKind": ("threat-detection",),
        "ciamSecurityCoverage": ("control-plane", "identity", "network", "containers", "storage"),
        "ciamAuditScope": ("organization",)}, {"ciamFindingsRole": TOPIC_ARN})
    assert found["vulnerability-scanning"][0]["ciamSecurityCoverage"] == ("compute", "containers")   # one order
    assert found["config-recording"] == ({
        "ciamSecurityKind": ("config-recording",), "ciamAuditScope": ("account",), "ciamRetentionDays": ("2557",)},
        {"ciamFindingsRole": "arn:aws:s3:::example-ciam-config"})
    assert {k: v for k, v in found["posture"][0].items() if k != "ciamAuditScope"} == {
        "ciamSecurityKind": ("posture",), "ciamComplianceStandard": ("cis", "nist-800-53-r5"),
        "ciamSecurityBaseline": ("aws-foundational",)}


def test_the_findings_topic_is_an_alert_channel_and_the_detector_finds_its_role():
    d, *_ = model(alpha=())
    resources, _ = pairs_resources(STATE)
    assert [(r.kind, r.ref) for r in resources if r.ref == TOPIC_ARN] == [("channel", TOPIC_ARN)]
    store = resource("storage", "arn:aws:s3:::example-ciam-config", {"ciamStorageRef": "s3://example-ciam-config"},
                     name="example-ciam-config", role="config-history")
    groups, _ = environment_groups(d, "alpha/prod", (store, *resources))
    placed = {e.dn.split(",")[0]: dict(e.attrs) for _, entries in groups for e in entries
              if "ciamSecurityService" in e.classes}
    assert placed["cn=guardduty-12abc"]["ciamBindingRole"] == ("guardduty",)
    assert placed["cn=guardduty-12abc"]["ciamFindingsRole"] == ("security-alerts",)
    assert placed["cn=config"]["ciamBindingRole"] == ("config-recording",)
    assert placed["cn=config"]["ciamFindingsRole"] == ("config-history",)



# ------------------------------------------------------------------ incident routes (severity-filtered rules)
INCIDENT_ARN = "arn:aws:sns:us-east-1:111122223333:security-incidents"
INCIDENTS = entry(ALPHA, "security-incidents", "ciamAlertChannel", ciamBindingRole="security-incidents",
                  ciamChannelKind="topic", ciamProviderRef=INCIDENT_ARN)


def test_findings_at_or_above_the_incident_severity_go_to_the_incident_topic():
    import json
    from opsdir_adapter_aws.security import severity_filter
    _, alpha, _ = model(alpha=(BUCKET, TOPIC, INCIDENTS,
                               svc("guardduty", "threat-detection", ciamFindingsRole="security-alerts",
                                   ciamIncidentRole="security-incidents"),
                               svc("hub", "posture", ciamIncidentRole="security-incidents",
                                   ciamIncidentSeverity="critical"),
                               svc("config", "config-recording", ciamFindingsRole="config-history",
                                   ciamIncidentRole="security-incidents")), tree=OWNERS)
    out = "\n\n".join(as_text(render_security(alpha)))
    assert 'resource "aws_cloudwatch_event_rule" "guardduty_incidents"' in out
    assert '"guardduty\'s high and worse findings to security-incidents (incident process)"' in out
    compact = "".join(out.split())
    assert '"detail":{"severity":[{"numeric":[">=",7]}]}' in compact and out.count(f'arn  = "{INCIDENT_ARN}"') == 2
    assert '"detail":{"findings":{"Severity":{"Label":["CRITICAL"]}}}' in compact
    assert ("# NOTE: config's incidents to security-incidents: not rendered: AWS Config's findings have no "
            "severity") in out
    assert severity_filter("aws.inspector2", "medium") == {"severity": ["MEDIUM", "HIGH", "CRITICAL"]}
    assert json.loads(json.dumps(severity_filter("aws.guardduty", "low"))) == {"severity": [{"numeric": [">=", 1]}]}


def test_an_unbound_incident_role_renders_nothing_the_planner_blocks_it():
    out = _render(svc("guardduty", "threat-detection", ciamIncidentRole="nowhere"))
    assert "incidents" not in out


def test_incident_routes_are_read_back_with_their_least_severity():
    state = (*STATE,
             ("aws_cloudwatch_event_rule", {"name": "guardduty-incidents", "event_pattern":
                 '{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"],'
                 '"detail":{"severity":[{"numeric":[">=",7]}]}}'}),
             ("aws_cloudwatch_event_target", {"rule": "guardduty-incidents", "arn": INCIDENT_ARN}),
             ("aws_cloudwatch_event_rule", {"name": "hub-incidents", "event_pattern":
                 '{"source":["aws.securityhub"],"detail-type":["Security Hub Findings - Imported"],'
                 '"detail":{"findings":{"Severity":{"Label":["HIGH","CRITICAL"]}}}}'}),
             ("aws_cloudwatch_event_target", {"rule": "hub-incidents", "arn": INCIDENT_ARN}))
    found = {r.attrs["ciamSecurityKind"][0]: r for r in security_resources(state)}
    assert dict(found["threat-detection"].links) == {"ciamFindingsRole": TOPIC_ARN, "ciamIncidentRole": INCIDENT_ARN}
    assert found["threat-detection"].attrs["ciamIncidentSeverity"] == ("high",)
    assert found["posture"].attrs["ciamIncidentSeverity"] == ("high",)
    assert "ciamIncidentRole" not in found["vulnerability-scanning"].links
    from opsdir_adapter_aws.security import findings_topics
    assert findings_topics(state) == frozenset({TOPIC_ARN, INCIDENT_ARN})



# ------------------------------------------------------------------ the same services from the AWS CLI
CLI = {
    "subnets.json": {"Subnets": [{"SubnetId": "subnet-a", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24",
                                  "SubnetArn": "arn:aws:ec2:us-east-1:111122223333:subnet/subnet-a"}]},
    "guardduty/12abc.json": {"Status": "ENABLED", "Tags": {"Role": "guardduty"}, "Features": [
        {"Name": "CLOUD_TRAIL", "Status": "ENABLED"}, {"Name": "S3_DATA_EVENTS", "Status": "ENABLED"},
        {"Name": "RUNTIME_MONITORING", "Status": "ENABLED",
         "AdditionalConfiguration": [{"Name": "EKS_ADDON_MANAGEMENT", "Status": "ENABLED"}]},
        {"Name": "RDS_LOGIN_EVENTS", "Status": "DISABLED"}]},
    "organization-configuration/guardduty-12abc.json": {"AutoEnable": True, "MemberAccountLimitReached": False},
    "inspector2.json": {"accounts": [{"accountId": "111122223333", "state": {"status": "ENABLED"}, "resourceState": {
        "ec2": {"status": "ENABLED"}, "ecr": {"status": "ENABLED"}, "lambda": {"status": "DISABLED"}}}],
        "failedAccounts": []},
    "config-recorders.json": {"ConfigurationRecorders": [
        {"name": "config", "roleARN": "arn:aws:iam::111122223333:role/aws-service-role/config.amazonaws.com/x"},
        {"name": "AWSConfigurationRecorderForSecurityHub", "servicePrincipal": "securityhub.amazonaws.com"}]},
    "config-channels.json": {"DeliveryChannels": [{"name": "config", "s3BucketName": "example-ciam-config"}]},
    "config-retention.json": {"RetentionConfigurations": [{"Name": "default", "RetentionPeriodInDays": 2557}]},
    "securityhub-hub.json": {"HubArn": "arn:aws:securityhub:us-east-1:111122223333:hub/default",
                             "AutoEnableControls": True, "ControlFindingGenerator": "SECURITY_CONTROL"},
    "securityhub-standards.json": {"StandardsSubscriptions": [
        {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0", "StandardsStatus": "READY"},
        {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0",
         "StandardsStatus": "READY"},
        {"StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
         "StandardsStatus": "INCOMPLETE"},
        {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/pci-dss/v/4.0.1", "StandardsStatus": "DELETING"}]},
    "rules.json": {"Rules": [{"Name": "guardduty-findings", "State": "ENABLED",
                              "Arn": "arn:aws:events:us-east-1:111122223333:rule/guardduty-findings",
                              "EventPattern": '{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"]}'}]},
    "event-targets/guardduty-findings.json": {"Targets": [{"Id": "topic", "Arn": TOPIC_ARN}]},
    "topics.json": {"Topics": [{"TopicArn": TOPIC_ARN}]},
    "topic-tags/security-alerts.json": {"Tags": [{"Key": "Role", "Value": "security-alerts"}]}}


def _cli(outputs):
    return cli_resources({p: json.dumps(doc) for p, doc in outputs.items()})


def test_the_cli_reads_the_same_services_and_findings_routes_as_state():
    resources, notices = _cli(CLI)
    kinds = ("security", "channel")
    state = {r.ref: r for r in pairs_resources(STATE)[0] if r.kind in kinds}
    assert {r.ref: r for r in resources if r.kind in kinds} == state
    named = "describe-organization-configuration saved (only the delegated administrator's account answers it)"
    assert set(notices) >= {"config: service-linked recorder(s) AWSConfigurationRecorderForSecurityHub (kept by "
                            "another AWS service) not read",
                            f"inspector2: no {named}: read as the account's own",
                            f"securityhub: no {named}: read as the account's own"}


def test_incident_routes_read_the_same_from_the_cli():
    rules = {"Rules": [*CLI["rules.json"]["Rules"],
                       {"Name": "hub-incidents", "State": "ENABLED", "EventPattern": json.dumps({
                           "source": ["aws.securityhub"], "detail-type": ["Security Hub Findings - Imported"],
                           "detail": {"findings": {"Severity": {"Label": ["HIGH", "CRITICAL"]}}}})}]}
    found = {r.attrs["ciamSecurityKind"][0]: r for r in _cli({**CLI, "rules.json": rules,
                                                              "event-targets/hub-incidents.json": {"Targets": [
                                                                  {"Id": "t", "Arn": INCIDENT_ARN}]}})[0]
             if r.kind == "security"}
    assert (found["posture"].attrs["ciamIncidentSeverity"], found["posture"].links["ciamIncidentRole"]) == (
        ("high",), INCIDENT_ARN)


def test_without_an_own_arn_a_detector_is_read_by_its_id_and_named():
    resources, notices = _cli({p: d for p, d in CLI.items() if p not in ("subnets.json", "securityhub-hub.json",
                                                                         "rules.json")})
    assert "12abc" in {r.ref for r in resources if r.kind == "security"}
    assert ("guardduty: no output names the account and region (describe-subnets, describe-hub, ...): 1 detector(s) "
            "read by ID") in notices


# ------------------------------------------------------------------ every region (5.7b)
CATALOG = "cn=aws,ou=regions,dc=ciam-ops"
OU = "dn: ou={0},dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: {0}\n"
REGIONS = (OU.format("regions"), OU.format("residencies"),
           f"dn: {CATALOG}\nobjectClass: top\nobjectClass: ciamRegionCatalog\ncn: aws\nciamCloudProvider: aws\n",
           *(entry(CATALOG, code, "ciamCloudRegion", ciamRegionStatus=status)
             for code, status in (("region-1", "available"), ("region-2", "available"), ("region-3", "available"),
                                  ("region-4", "opt-in"))))
FENCE = entry(ALPHA, "fence", "ciamGuardrail", ciamBindingRole="fence", ciamDenies="region-escape")


def _everywhere(*services, fenced=False):
    from opsdir.core.interchange.ldif import LdifRecord
    residency = entry("ou=residencies,dc=ciam-ops", "two", "ciamResidency",
                      ciamAllowedRegion=(f"cn=region-1,{CATALOG}", f"cn=region-2,{CATALOG}"))
    held = LdifRecord(ALPHA, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                             ("replace", "ciamResidencyRef", ("cn=two,ou=residencies,dc=ciam-ops",))))
    aws = LdifRecord("cloud=alpha,ou=environments,dc=ciam-ops", "modify", {},
                     (("replace", "ciamCloudProvider", ("aws",)),))
    _, alpha, _ = model(alpha=(BUCKET, TOPIC, *((FENCE,) if fenced else ()), *services),
                        tree=(*OWNERS, *REGIONS, residency), changes=(held, aws))
    return alpha


def test_a_service_in_every_region_is_copied_to_each_region_its_guardrail_allows_through_a_provider_of_its_own():
    from opsdir_adapter_aws.security import every_region, region_alias, security_regions
    hub = svc("security-hub", "posture", ciamAllRegions="TRUE", ciamComplianceStandard="nist-800-53-r5",
              ciamFindingsRole="security-alerts")
    config = svc("config", "config-recording", ciamAllRegions="TRUE", ciamFindingsRole="config-history")
    m = _everywhere(hub, config, fenced=True)
    found = security_regions(m)
    assert (found.regions, found.denied, found.opt_in) == (("region-2",), ("region-3",), ("region-4",))
    assert every_region(m) == ("region-2",) and region_alias("us-gov-west-1") == "region_us_gov_west_1"
    out = "\n\n".join(as_text(render_security(m)))
    assert "# security-hub: in every region: region-1, region-2" in out
    assert "# security-hub: not in region-3: guardrail fence denies every action there" in out
    assert "# security-hub: not in opt-in regions region-4: the record doesn't say the account opted in" in out
    assert 'resource "aws_securityhub_account" "security_hub_region_2" {\n  provider' in out
    assert "= aws.region_region_2" in out
    assert "securityhub:region-2::standards/nist-800-53" in out                      # the region's own standard
    assert "depends_on    = [aws_securityhub_account.security_hub_region_2]" in out
    assert 'resource "aws_securityhub_finding_aggregator" "security_hub"' in out
    assert out.count('resource "aws_iam_service_linked_role"') == 1                 # IAM: once
    regional = out.split('resource "aws_config_configuration_recorder" "config_region_2"', 1)[1].split("\n}", 1)[0]
    assert "include_global_resource_types = false" in regional
    assert re.search(r"role_arn +\= aws_iam_service_linked_role\.config_config\.arn", regional)
    assert out.count('resource "aws_cloudwatch_event_rule"') == 1                    # routing: the cloud's region


def test_without_a_guardrail_every_available_region_and_other_regions_findings_are_said_to_stay_there():
    from opsdir_adapter_aws.security import security_regions
    m = _everywhere(svc("guardduty", "threat-detection", ciamAllRegions="TRUE", ciamFindingsRole="security-alerts"))
    assert security_regions(m).regions == ("region-2", "region-3")
    out = "\n\n".join(as_text(render_security(m)))
    assert 'resource "aws_guardduty_detector" "guardduty_region_3"' in out
    assert "# guardduty: its findings in the other regions stay there unless Security Hub aggregates them" in out


def test_regional_copies_read_back_as_one_service_in_every_region():
    second = {**DETECTOR, "id": "34def", "arn": "arn:aws:guardduty:us-west-2:111122223333:detector/34def"}
    found = [r for r in security_resources([("aws_guardduty_detector", DETECTOR), ("aws_guardduty_detector", second)])
             if r.attrs.get("ciamSecurityKind") == ("threat-detection",)]
    assert len(found) == 1 and found[0].attrs["ciamAllRegions"] == ("TRUE",)
    (one_region,) = security_resources([("aws_guardduty_detector", DETECTOR)])
    assert "ciamAllRegions" not in one_region.attrs


# ------------------------------------------------------------------ organization-wide (5.7b, decision 2777)
def _organization(*services, regions=False, **cloud):
    from opsdir.core.interchange.ldif import LdifRecord
    accounts = LdifRecord("cloud=alpha,ou=environments,dc=ciam-ops", "modify", {}, (
        ("add", "objectClass", ("ciamCloudAccount",)), ("replace", "ciamCloudProvider", ("aws",)),
        *(("replace", k, (v,)) for k, v in {"ciamAccountRef": "111122223333", "ciamManagementRef": "999988887777",
                                            "ciamSecurityAdminRef": "555566667777", **cloud}.items() if v)))
    _, alpha, _ = model(alpha=(BUCKET, TOPIC, *services), tree=(*OWNERS, *(REGIONS if regions else ())),
                        changes=(accounts,))
    return alpha


def _parts(m):
    from opsdir.domains.governance.keepers import ORGANIZATION
    items = render_security(m)
    org = [x for x in items if getattr(x, "origin", None) and x.origin.startswith(ORGANIZATION)]
    return "\n\n".join(as_text(tuple(x for x in items if x not in org))), "\n\n".join(as_text(tuple(org)))


def test_an_organization_wide_detector_is_the_delegated_administrator_s_enabling_every_member():
    detector = svc("guardduty", "threat-detection", ciamAuditScope="organization", ciamFindingsRole="security-alerts",
                   ciamSecurityCoverage=("control-plane", "compute"))
    own, org = _parts(_organization(detector))
    assert "aws_guardduty_detector" not in own and '"aws.guardduty"' in own                   # routing only
    assert "# guardduty: organization-wide: enabled for every account by" in own
    assert re.search(r'resource "aws_guardduty_organization_admin_account" "guardduty" \{\n  provider +'
                     r'= aws.management\n  admin_account_id = "555566667777"', org)
    assert 'resource "aws_guardduty_detector" "guardduty_admin"' in org and "= aws.security_admin" in org
    assert re.search(r'auto_enable_organization_members = "ALL"', org)
    assert 'resource "aws_guardduty_organization_configuration_feature" "guardduty_runtime_monitoring"' in org
    assert re.search(r"detector_id += aws_guardduty_detector\.guardduty_admin\.id", org)


def test_an_organization_wide_scanner_hub_and_recorder():
    scanner = svc("inspector", "vulnerability-scanning", ciamAuditScope="organization",
                  ciamSecurityCoverage=("containers",))
    hub = svc("hub", "posture", ciamAuditScope="organization", ciamComplianceStandard="nist-800-53-r5")
    config = svc("config", "config-recording", ciamAuditScope="organization", ciamFindingsRole="config-history")
    own, org = _parts(_organization(scanner, hub, config))
    assert re.search(r"auto_enable \{\n    ec2 += false\n    ecr += true", org)
    assert 'account_ids    = ["555566667777"]' in org or re.search(r'account_ids += \["555566667777"\]', org)
    assert re.search(r'configuration_type = "CENTRAL"', org) and 'linking_mode = "ALL_REGIONS"' in org
    assert "standards/nist-800-53/v/5.0.0" in org
    assert "data.aws_organizations_organization.security_admin.roots[0].id" in org
    assert re.search(r'service_principal += "config.amazonaws.com"', org) and "AWSConfigRoleForOrganizations" in org
    assert 'resource "aws_config_configuration_recorder" "config"' in own                  # its own recorder stays
    assert "# config: an organization can't turn members' AWS Config recorders on" in own


def test_without_the_organization_s_accounts_an_organization_wide_service_is_said_so():
    own, org = _parts(_organization(svc("guardduty", "threat-detection", ciamAuditScope="organization"),
                                    ciamSecurityAdminRef=None))
    assert org == "" and "# NOTE: guardduty: organization-wide, but not rendered: the record doesn't name " \
                         "ciamSecurityAdminRef" in own


def test_an_organization_wide_service_in_every_region_is_registered_and_configured_in_each():
    from opsdir_adapter_aws.account import organization_providers
    m = _organization(svc("guardduty", "threat-detection", ciamAuditScope="organization", ciamAllRegions="TRUE"),
                      regions=True)
    _, org = _parts(m)
    assert 'resource "aws_guardduty_organization_admin_account" "guardduty_region_2"' in org
    assert "= aws.management_region_2" in org and "= aws.security_admin_region_2" in org
    assert re.search(r"detector_id += aws_guardduty_detector\.guardduty_admin_region_2\.id", org)
    aliases = [b.body[1][1] for b in organization_providers(m, ("region-2",))]
    assert aliases == ["management", "management_region_2", "security_admin", "security_admin_region_2"]


def _noted(notes, items):
    """Whether each note's comment is in the rendered items and every NOTE comment there is a note's (flow 43)."""
    from opsdir.core.notes import note_comment
    lines = [x.strip() for t in as_text(items) if isinstance(t, str) for x in t.splitlines()]
    return {f"# {note_comment(n)}" for n in notes} == {x for x in lines if x.startswith("# NOTE:")}


def test_what_a_service_s_render_leaves_out_is_a_render_note_written_as_its_comment():
    from opsdir_adapter_aws.security import security_notes
    _, alpha, _ = model(alpha=(BUCKET, TOPIC, INCIDENTS,
                               svc("guardduty", "threat-detection", ciamFindingsRole="config-history",
                                   ciamAllRegions="TRUE"),
                               svc("config", "config-recording", ciamFindingsRole="security-alerts",
                                   ciamIncidentRole="security-incidents")), tree=OWNERS)
    notes = {n.subject: n for n in security_notes(alpha)}
    assert _noted(notes.values(), render_security(alpha))
    assert {k: n.severity for k, n in notes.items()} == {
        "guardduty's findings to config-history": "blocker", "guardduty": "blocker",
        "security service config (config-recording)": "blocker", "config's incidents to security-incidents": "action"}
    findings = notes["guardduty's findings to config-history"]
    assert {n.area for n in notes.values()} == {"Security"} and findings.entry == f"cn=guardduty,ou=bindings,{ALPHA}"
    assert findings.how[0].startswith("Bind config-history to an alert channel (its SNS topic's ARN")
    assert notes["guardduty"].how == ("Fetch the region catalog (`opsdir prerequisites`), then re-render",)
    assert notes["config's incidents to security-incidents"].how[0].startswith(
        "Make an EventBridge rule on AWS Config's \"Config Rules Compliance Change\"")
    m = _organization(svc("guardduty", "threat-detection", ciamAuditScope="organization"), ciamSecurityAdminRef=None)
    (org,) = security_notes(m)
    assert _noted((org,), render_security(m)) and (org.severity, org.scope) == ("blocker", "the organization")
    assert org.how == ("Record ciamSecurityAdminRef on alpha, under an approved change, and re-render",)


def test_a_route_this_render_makes_is_an_action_for_its_target_s_policy():
    from opsdir_adapter_aws.security import security_notes
    _, alpha, _ = model(alpha=(BUCKET, TOPIC, svc("guardduty", "threat-detection", ciamFindingsRole="security-alerts"),
                               svc("hub", "posture", ciamComplianceStandard="cmmc-l2")), tree=OWNERS)
    notes = {n.subject: n for n in security_notes(alpha)}
    assert _noted(notes.values(), render_security(alpha))
    delivery = notes["guardduty's findings to security-alerts"]
    assert delivery.severity == "action" and delivery.how[0].startswith(f"Allow events.amazonaws.com sns:Publish in "
                                                                       f"topic {TOPIC_ARN}'s access policy")
    assert notes["hub"].severity == "action"
