"""Cloud security services on AWS: GuardDuty with a feature per area it watches, Inspector for the resource types its
areas name, AWS Config into its object store's bucket with its retention, Security Hub with a subscription per
standard it has (standards it lacks said in a comment), findings sent to an SNS topic by an
EventBridge rule, organization scope, other regions and services kept by someone else in comments; all of them read back
from Terraform state, with the topic, bucket or log group their findings go to as the role of that binding."""
from opsdir.core.inventory import environment_groups, resource
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
    return "\n\n".join(render_security(alpha))


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
    assert "# guardduty: runs in every region: each region needs its own (this root renders region-1)" in out


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
    out = _render(svc("hub", "posture", ciamAuditScope="organization", ciamSecurityBaseline=("aws-foundational",),
                      ciamComplianceStandard=("nist-800-53-r5", "nist-800-171-r2", "cmmc-l2")))
    assert 'data "aws_partition" "current"' in out and 'control_finding_generator = "SECURITY_CONTROL"' in out
    assert ("arn:${data.aws_partition.current.partition}:securityhub:${data.aws_region.current.name}::standards/"
            "nist-800-53/v/5.0.0") in out
    assert "aws-foundational-security-best-practices/v/1.0.0" in out
    assert "standards/nist-800-171/v/2.0.0" in out and "describe-standards" not in out
    assert "# hub: Security Hub has no standard for cmmc-l2: assess it another way" in out
    assert "# hub: organization-wide: enable it for the organization from its management account" in out


def test_a_service_someone_else_keeps_is_named_not_rendered():
    assert _render(svc("org-guardduty", "threat-detection", ciamManagedBy=PARTY)) == (
        "# Security service org-guardduty (threat-detection): kept by landing-zone, not rendered here")


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
    assert found["vulnerability-scanning"][0]["ciamSecurityCoverage"] == ("containers", "compute")
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
    out = "\n\n".join(render_security(alpha))
    assert 'resource "aws_cloudwatch_event_rule" "guardduty_incidents"' in out
    assert '"guardduty\'s high and worse findings to security-incidents (incident process)"' in out
    compact = "".join(out.split())
    assert '"detail":{"severity":[{"numeric":[">=",7]}]}' in compact and out.count(f'arn  = "{INCIDENT_ARN}"') == 2
    assert '"detail":{"findings":{"Severity":{"Label":["CRITICAL"]}}}' in compact
    assert "# NOTE: config's incidents to security-incidents: not rendered: AWS Config's findings have no severity" in out
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
