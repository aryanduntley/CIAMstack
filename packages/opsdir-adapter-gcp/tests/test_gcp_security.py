"""Cloud security services on Google Cloud: Security Command Center's activation, services and frameworks named as a
request to the organization's administrators; findings streamed to a Pub/Sub topic by an SCC notification config per
finding class; the scanning APIs enabled once; a project asset feed exporting configuration changes; other bindings,
other clouds' baselines and services kept by someone else in comments; all read back from Terraform state."""
from opsdir.core.inventory import environment_groups, resource
from opsdir_adapter_gcp.security import render_security, security_resources
from network_fixtures import ALPHA, entry, model

PARTY = "cn=landing-zone,ou=owners,dc=ciam-ops"
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
          f"dn: {PARTY}\nobjectClass: top\nobjectClass: ciamParty\ncn: landing-zone\nciamOwnerKind: team\n")
TOPIC = "projects/example-sec/topics/security-findings"
STREAM = entry(ALPHA, "security-findings", "ciamStreamBinding", ciamBindingRole="security-findings",
               ciamStreamKind="topic", ciamProviderRef=TOPIC)
LOGS = entry(ALPHA, "app-logs", "ciamLogDestination", ciamBindingRole="app-logs", ciamDestinationKind="bucket")


def svc(cn, kind, **more):
    return entry(ALPHA, cn, "ciamSecurityService", ciamBindingRole=cn, ciamSecurityKind=kind, **more)


def _render(*services):
    _, alpha, _ = model(alpha=(STREAM, LOGS, *services), tree=OWNERS)
    return "\n\n".join(render_security(alpha))


def test_threat_detection_is_a_request_and_its_findings_stream_to_the_topic():
    out = _render(svc("scc", "threat-detection", ciamFindingsRole="security-findings", ciamAuditScope="organization",
                      ciamSecurityCoverage=("control-plane", "containers", "compute", "key-vaults")))
    assert ("# scc: Security Command Center (Premium or Enterprise) activated with Event Threat Detection, Container "
            "Threat Detection, VM Threat Detection: a request to the organization's administrators (not "
            "rendered)") in out
    assert "# scc: no Security Command Center service watches key vaults on their own" in out
    assert 'resource "google_scc_v2_project_notification_config" "scc_findings"' in out
    assert f'pubsub_topic = "{TOPIC}"' in out and 'filter = "finding_class=\\"THREAT\\" AND state=\\"ACTIVE\\""' in out
    assert "# scc: organization-wide (Security Command Center and its notification at the organization)" in out
    assert "# NOTE: scc's findings to app-logs: not rendered: app-logs names no Pub/Sub topic" in _render(
        svc("scc", "threat-detection", ciamFindingsRole="app-logs"))


def test_scanning_apis_are_enabled_once_across_services():
    out = _render(svc("scan-a", "vulnerability-scanning", ciamSecurityCoverage=("containers", "compute")),
                  svc("scan-b", "vulnerability-scanning", ciamSecurityCoverage=("containers", "applications")))
    assert out.count('service            = "containerscanning.googleapis.com"') == 1
    assert out.count('"osconfig.googleapis.com"') == 1
    assert "# scan-a: VM Manager reports vulnerabilities once the instances carry metadata enable-osconfig=TRUE" in out
    assert "# scan-b: Web Security Scanner (Security Command Center) for applications: a request" in out


def test_configuration_changes_are_exported_by_an_asset_feed():
    out = _render(svc("assets", "config-recording", ciamFindingsRole="security-findings"))
    assert "# assets: Cloud Asset Inventory keeps 35 days of resource history itself" in out
    assert 'resource "google_cloud_asset_project_feed" "assets"' in out and f'topic = "{TOPIC}"' in out
    assert _render(svc("assets", "config-recording")) == (
        "# assets: Cloud Asset Inventory keeps 35 days of resource history itself")


def test_posture_frameworks_are_a_request_and_other_clouds_baselines_are_named():
    out = _render(svc("sha", "posture", ciamComplianceStandard=("nist-800-171-r2", "fedramp-high"),
                      ciamSecurityBaseline=("gcp-default", "aws-foundational")))
    assert ("# sha: nist-800-171-r2, fedramp-high assessed by Compliance Manager framework deployments (FedRAMP, IL "
            "and ITAR regimes held by an Assured Workloads folder): a request") in out
    assert "# sha: aws-foundational: another cloud's baseline, not Google Cloud's (not rendered)" in out
    assert _render(svc("org-scc", "threat-detection", ciamManagedBy=PARTY)) == (
        "# Security service org-scc (threat-detection): kept by landing-zone, not rendered here")


STATE = [("google_scc_v2_project_notification_config", {
             "name": "projects/example/locations/global/notificationConfigs/scc-findings", "config_id": "scc-findings",
             "pubsub_topic": TOPIC, "streaming_config": [{"filter": 'finding_class="THREAT" AND state="ACTIVE"'}]}),
         ("google_scc_notification_config", {"name": "organizations/123/notificationConfigs/all", "config_id": "all",
                                             "pubsub_topic": TOPIC,
                                             "streaming_config": [{"filter": 'state="ACTIVE"'}]}),
         ("google_project_service", {"id": "example/containerscanning.googleapis.com",
                                     "service": "containerscanning.googleapis.com"}),
         ("google_project_service", {"id": "example/compute.googleapis.com", "service": "compute.googleapis.com"}),
         ("google_cloud_asset_project_feed", {"name": "projects/123/feeds/assets", "feed_id": "assets",
                                              "feed_output_config": [{"pubsub_destination": [{"topic": TOPIC}]}]})]


def test_the_services_are_read_back_from_state():
    found = [(r.attrs["ciamSecurityKind"][0], r.attrs.get("ciamAuditScope"), r.attrs.get("ciamSecurityCoverage"),
              r.attrs.get("ciamRetentionDays"), dict(r.links)) for r in security_resources(STATE)]
    assert found == [
        ("threat-detection", ("account",), None, None, {"ciamFindingsRole": TOPIC}),
        ("threat-detection", ("organization",), None, None, {"ciamFindingsRole": TOPIC}),
        ("vulnerability-scanning", ("account",), ("containers",), None, {}),
        ("config-recording", ("account",), None, ("35",), {"ciamFindingsRole": TOPIC})]


def test_the_topic_s_role_is_where_findings_go():
    d, *_ = model(alpha=())
    topic = resource("stream", TOPIC, {"ciamStreamKind": "topic"}, name="security-findings", role="security-findings")
    groups, _ = environment_groups(d, "alpha/prod", (topic, *security_resources(STATE[:1])))
    placed = {e.dn.split(",")[0]: dict(e.attrs) for _, entries in groups for e in entries
              if "ciamSecurityService" in e.classes}
    assert placed["cn=scc-findings"]["ciamFindingsRole"] == ("security-findings",)


# ------------------------------------------------------------------ incident routes
INCIDENT_TOPIC = "projects/example-sec/topics/security-incidents"
INCIDENTS = entry(ALPHA, "security-incidents", "ciamStreamBinding", ciamBindingRole="security-incidents",
                  ciamStreamKind="topic", ciamProviderRef=INCIDENT_TOPIC)


def test_findings_at_or_above_the_incident_severity_go_to_the_incident_topic():
    out = _render(INCIDENTS,
                  svc("scc", "threat-detection", ciamFindingsRole="security-findings",
                      ciamIncidentRole="security-incidents"),
                  svc("posture", "posture", ciamIncidentRole="security-incidents", ciamIncidentSeverity="medium"),
                  svc("assets", "config-recording", ciamFindingsRole="security-findings",
                      ciamIncidentRole="security-incidents"),
                  svc("shared", "posture", ciamIncidentRole="app-logs"))
    assert 'resource "google_scc_v2_project_notification_config" "scc_incidents"' in out
    assert ('filter = "finding_class=\\"THREAT\\" AND state=\\"ACTIVE\\" AND (severity=\\"CRITICAL\\" OR '
            'severity=\\"HIGH\\")"') in out
    assert ('(severity=\\"CRITICAL\\" OR severity=\\"HIGH\\" OR severity=\\"MEDIUM\\")' in out
            and out.count(f'pubsub_topic = "{INCIDENT_TOPIC}"') == 2)
    assert ("# NOTE: assets's incidents to security-incidents: not rendered: "
            "an asset feed's changes have no severity") in out
    assert "# NOTE: shared's incidents to app-logs: not rendered: app-logs names no Pub/Sub topic" in out


def test_incident_routes_are_read_back():
    state = [*STATE,
             ("google_scc_v2_project_notification_config", {
                 "name": "projects/example/locations/global/notificationConfigs/scc-incidents",
                 "config_id": "scc-incidents", "pubsub_topic": INCIDENT_TOPIC, "streaming_config": [{
                     "filter": 'finding_class="THREAT" AND state="ACTIVE" '
                               'AND (severity="CRITICAL" OR severity="HIGH")'}]}),
             ("google_scc_v2_project_notification_config", {
                 "name": "projects/example/locations/global/notificationConfigs/posture-incidents",
                 "config_id": "posture-incidents", "pubsub_topic": INCIDENT_TOPIC, "streaming_config": [{
                     "filter": 'finding_class="MISCONFIGURATION" AND severity="CRITICAL"'}]})]
    found = [(r.attrs["ciamSecurityKind"][0], r.attrs.get("ciamIncidentSeverity"), dict(r.links), r.name)
             for r in security_resources(state)]
    assert found[0] == ("threat-detection", ("high",), {"ciamFindingsRole": TOPIC, "ciamIncidentRole": INCIDENT_TOPIC},
                        "scc-findings")
    assert ("posture", ("critical",), {"ciamIncidentRole": INCIDENT_TOPIC}, "posture-incidents") in found
    assert found[1] == ("threat-detection", None, {"ciamFindingsRole": TOPIC}, "all")      # the organization's
    assert len(found) == len(security_resources(STATE)) + 1
