"""Control-plane audit trails on AWS: an account trail the platform keeps rendered as aws_cloudtrail into its bucket
(all regions with global services' events, integrity validation; data events noted), trails kept by someone else or
delivered to CloudWatch Logs named, not rendered; aws_cloudtrail read back from Terraform state with the activity its
event selectors record and its bucket's role as where its records go."""
from opsdir.core.inventory import environment_groups, resource
from opsdir_adapter_aws.audit import render_trails, trail_events, trail_resources
from network_fixtures import ALPHA, entry, model

PARTY = "cn=landing-zone,ou=owners,dc=ciam-ops"
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
          f"dn: {PARTY}\nobjectClass: top\nobjectClass: ciamParty\ncn: landing-zone\nciamOwnerKind: team\n")
BUCKET = entry(ALPHA, "audit-logs", "ciamObjectStore", ciamBindingRole="audit-logs",
               ciamStorageRef="s3://example-ciam-audit")
GROUP = entry(ALPHA, "app-logs", "ciamLogDestination", ciamBindingRole="app-logs", ciamDestinationKind="log-group")


def _trail(cn, destination, **more):
    return entry(ALPHA, cn, "ciamAuditTrail", ciamBindingRole=cn, ciamAuditScope="account",
                 ciamLogDestinationRole=destination, **more)


def test_an_account_trail_the_platform_keeps_is_rendered_into_its_bucket():
    trails = (_trail("cloudtrail", "audit-logs", ciamAuditEvents=("control-plane", "data-write"), ciamAllRegions="TRUE",
                     ciamIntegrityValidation="TRUE",
                     ciamProviderRef="arn:aws:cloudtrail:us-east-1:111122223333:trail/ciam-prod"),
              _trail("org-trail", "audit-logs", ciamManagedBy=PARTY),
              _trail("to-logs", "app-logs"))
    _, alpha, _ = model(alpha=(BUCKET, GROUP, *trails), tree=OWNERS)
    assert render_trails(alpha) == ('''resource "aws_cloudtrail" "cloudtrail" {
  # data-write events: log them with event selectors naming the resources (not rendered)
  name                          = "ciam-prod"
  s3_bucket_name                = "example-ciam-audit"
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
}''', "# Audit trail org-trail (account): kept by landing-zone, not rendered here",
        "# NOTE: audit trail to-logs: not rendered: its records go to a CloudWatch log group, a delivery that also "
        "needs a role CloudTrail assumes")


def test_the_activity_a_trail_records_comes_from_its_event_selectors():
    assert trail_events({}) == ("control-plane",)
    assert trail_events({"event_selector": [{"read_write_type": "WriteOnly", "include_management_events": True,
                                             "data_resource": [{"type": "AWS::S3::Object"}]}]}) == (
        "control-plane", "data-write")
    assert trail_events({"advanced_event_selector": [
        {"field_selector": [{"field": "eventCategory", "equals": ["Data"]}, {"field": "readOnly", "equals": ["true"]}]},
        {"field_selector": [{"field": "eventCategory", "equals": ["Management"]}]}]}) == ("control-plane", "data-read")


def test_a_trail_is_read_back_with_its_bucket_s_role_as_where_its_records_go():
    d, *_ = model(alpha=(BUCKET,))
    trail = {"arn": "arn:aws:cloudtrail:us-east-1:111122223333:trail/ciam-prod", "name": "ciam-prod",
             "s3_bucket_name": "example-ciam-audit", "is_multi_region_trail": True, "enable_log_file_validation": False,
             "is_organization_trail": False, "tags_all": {}}
    store = resource("storage", "arn:aws:s3:::example-ciam-audit", {"ciamStorageRef": "s3://example-ciam-audit"},
                     name="example-ciam-audit")
    groups, _ = environment_groups(d, "alpha/prod", (store, *trail_resources([("aws_cloudtrail", trail)])))
    placed = [e for _, entries in groups for e in entries if "ciamAuditTrail" in e.classes]
    assert [(e.dn.split(",")[0], dict(e.attrs)) for e in placed] == [("cn=ciam-prod", {
        "cn": ("ciam-prod",), "ciamBindingRole": ("audit-trail",), "ciamProviderRef": (trail["arn"],),
        "ciamAuditScope": ("account",), "ciamAuditEvents": ("control-plane",), "ciamAllRegions": ("TRUE",),
        "ciamIntegrityValidation": ("FALSE",), "ciamLogDestinationRole": ("audit-logs",)})]
