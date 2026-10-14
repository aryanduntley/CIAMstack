"""Control-plane audit trails on AWS: an account trail the platform keeps rendered as aws_cloudtrail into its bucket
(all regions with global services' events, integrity validation; data events noted), trails kept by someone else or
delivered to CloudWatch Logs named, not rendered; aws_cloudtrail read back from Terraform state with the activity its
event selectors record and its bucket's role as where its records go; the same from the CLI's describe-trails,
get-event-selectors and list-tags, and from a CloudFormation AWS::CloudTrail::Trail."""
import json

from opsdir.core.inventory import environment_groups, resource
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_aws.audit import render_trails, trail_events, trail_resources
from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.cloudformation import cloudformation_resources
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
              _trail("to-logs", "app-logs"))
    _, alpha, _ = model(alpha=(BUCKET, GROUP, *trails), tree=OWNERS)
    note, trail, logs = as_text(render_trails(alpha))
    assert note.startswith("# NOTE: audit trail cloudtrail: bucket example-ciam-audit (audit-logs) must let "
                           "cloudtrail.amazonaws.com s3:GetBucketAcl on arn:aws:s3:::example-ciam-audit; s3:PutObject "
                           "on arn:aws:s3:::example-ciam-audit/AWSLogs/111122223333/* (s3:x-amz-acl ")
    assert note.endswith("aws:SourceArn arn:aws:cloudtrail:us-east-1:111122223333:trail/ciam-prod): its policy isn't "
                         "rendered: the record doesn't describe the bucket")
    assert trail == '''resource "aws_cloudtrail" "cloudtrail" {
  # data-write events: no data resource to log but the trail's own bucket (logging its writes would log themselves)
  name                          = "ciam-prod"
  s3_bucket_name                = "example-ciam-audit"
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
}'''
    assert logs.startswith("# NOTE: audit trail to-logs: not rendered: its records go to a CloudWatch log group, but "
                           "CloudTrail keeps them in an S3 bucket")


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


ARN = "arn:aws:cloudtrail:us-east-1:111122223333:trail/ciam-prod"


def _trails(resources):
    return [(r.ref, dict(r.attrs), dict(r.links), r.role) for r in resources if r.kind == "audit"]


def test_the_cli_s_trails_are_read_with_their_selectors_and_tags():
    trail = {"Name": "ciam-prod", "TrailARN": ARN, "S3BucketName": "example-ciam-audit", "IsMultiRegionTrail": True,
             "IncludeGlobalServiceEvents": True, "LogFileValidationEnabled": True, "IsOrganizationTrail": False,
             "HomeRegion": "us-east-1"}
    texts = {"trails.json": json.dumps({"trailList": [trail, trail]}),        # listed again from another region
             "trail-selectors.json": json.dumps({"TrailARN": ARN, "EventSelectors": [
                 {"ReadWriteType": "All", "IncludeManagementEvents": True,
                  "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}]}]}),
             "trail-tags.json": json.dumps({"ResourceTagList": [
                 {"ResourceId": ARN, "TagsList": [{"Key": "Role", "Value": "cloudtrail"}]}]})}
    resources, _ = cli_resources(texts)
    assert _trails(resources) == [(ARN, {
        "ciamAuditScope": ("account",), "ciamAuditEvents": ("control-plane", "data-read", "data-write"),
        "ciamAllRegions": ("TRUE",), "ciamIntegrityValidation": ("TRUE",)},
        {"ciamLogDestinationRole": "arn:aws:s3:::example-ciam-audit"}, "cloudtrail")]


def test_a_cloudformation_trail_is_read_with_its_arn_from_the_stack():
    template = {"Resources": {"Trail": {"Type": "AWS::CloudTrail::Trail", "Properties": {
        "TrailName": "ciam-prod", "IsLogging": True, "S3BucketName": "example-ciam-audit",
        "IsMultiRegionTrail": False, "EnableLogFileValidation": True,
        "AdvancedEventSelectors": [{"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}],
        "Tags": [{"Key": "Role", "Value": "cloudtrail"}]}}}}
    stack = {"Stacks": [{"StackId": "arn:aws:cloudformation:us-east-1:111122223333:stack/ciam-audit/0a1b",
                         "StackName": "ciam-audit", "StackStatus": "CREATE_COMPLETE"}]}
    created = {"StackResourceSummaries": [{"LogicalResourceId": "Trail", "PhysicalResourceId": "ciam-prod",
                                           "ResourceType": "AWS::CloudTrail::Trail",
                                           "ResourceStatus": "CREATE_COMPLETE"}]}
    texts = {f"audit/{p}": json.dumps(t) for p, t in (("stack.json", stack), ("resources.json", created),
                                                      ("template.json", template))}
    resources, _ = cloudformation_resources(texts)
    assert _trails(resources) == [(ARN, {
        "ciamAuditScope": ("account",), "ciamAuditEvents": ("control-plane",), "ciamAllRegions": ("FALSE",),
        "ciamIntegrityValidation": ("TRUE",)}, {"ciamLogDestinationRole": "arn:aws:s3:::example-ciam-audit"},
        "cloudtrail")]


# ------------------------------------------------------------------ organization trails, streaming, data events (5.7b)
def _cloud(**attrs):
    from opsdir.core.interchange.ldif import LdifRecord
    return LdifRecord("cloud=alpha,ou=environments,dc=ciam-ops", "modify", {}, (
        ("add", "objectClass", ("ciamCloudAccount",)), *(("replace", k, (v,)) for k, v in attrs.items())))


ACCOUNT = _cloud(ciamAccountRef="111122223333", ciamManagementRef="999988887777",
                 ciamOrganizationRef="o-exampleorg")
FILES = entry(ALPHA, "files", "ciamObjectStore", ciamBindingRole="files", ciamStorageRef="s3://example-ciam-files")
NEW_BUCKET = entry(ALPHA, "audit-logs", "ciamObjectStore", ciamBindingRole="audit-logs",
                   ciamStorageRef="s3://example-ciam-audit", ciamStorageVersioning="TRUE")
SECRET = entry(ALPHA, "db-password", "ciamSecretRef", ciamBindingRole="db-password",
               ciamRefUri="aws-sm://arn:aws:secretsmanager:us-east-1:111122223333:secret:db")
STREAM = entry(ALPHA, "trail-logs", "ciamLogDestination", ciamBindingRole="trail-logs", ciamDestinationKind="log-group",
               ciamProviderRef="arn:aws:logs:us-east-1:111122223333:log-group:/ciam/trail:*", ciamRetentionDays="30")


def _org_trail(cn, destination, **more):
    return entry(ALPHA, cn, "ciamAuditTrail", ciamBindingRole=cn, ciamAuditScope="organization",
                 ciamLogDestinationRole=destination, **more)


def _render(*records):
    return as_text(render_trails(model(alpha=records, tree=OWNERS, changes=(ACCOUNT,))[1]))


def test_data_events_select_the_environment_s_own_buckets_and_keep_management_events_by_a_selector():
    trail = _trail("cloudtrail", "audit-logs", ciamAuditEvents=("control-plane", "data-write"))
    policy, block = _render(NEW_BUCKET, FILES, SECRET, trail)
    assert block.count("advanced_event_selector {") == 2
    assert 'name = "Management events"' in block and 'equals = ["Management"]' in block
    assert 'name = "data-write on S3 objects"' in block and 'equals = ["AWS::S3::Object"]' in block
    assert 'equals = ["false"]' in block and 'starts_with = ["arn:aws:s3:::example-ciam-files/"]' in block
    assert "example-ciam-audit/" not in block                             # its own bucket: never selected
    assert "# data-write events: reading the 1 secret is a Secrets Manager management event" in block
    assert "depends_on = [aws_s3_bucket_policy.cloudtrail_delivery]" in block
    statements = json.loads(json.loads(policy.split("policy = ", 1)[1].rsplit("\n", 1)[0]))["Statement"]
    assert [s["Action"] for s in statements] == ["s3:GetBucketAcl", "s3:PutObject"]
    assert statements[1]["Resource"] == "arn:aws:s3:::example-ciam-audit/AWSLogs/111122223333/*"
    assert statements[1]["Condition"]["StringEquals"] == {
        "aws:SourceArn": "arn:aws:cloudtrail:region-1:111122223333:trail/cloudtrail",
        "s3:x-amz-acl": "bucket-owner-full-control"}


def test_a_trail_naming_its_data_resources_logs_those_reads_only():
    trail = _trail("reads", "audit-logs", ciamAuditEvents="data-read", ciamAuditResourceRole="files")
    block = _render(BUCKET, FILES, NEW_BUCKET, trail)[-1]
    assert 'equals = ["true"]' in block and "Management" not in block and "example-ciam-files/" in block


def test_an_organization_trail_is_made_from_the_management_account_writes_the_organization_s_logs_and_streams():
    trail = _org_trail("org-trail", "audit-logs", ciamAuditStreamRole="trail-logs")
    policy, role, role_policy, block, line = _render(NEW_BUCKET, STREAM, trail)
    assert "provider                      = aws.management" in block and "is_organization_trail         = true" in block
    assert "cloud_watch_logs_group_arn    = \"${aws_cloudwatch_log_group.trail_logs.arn}:*\"" in block
    assert "cloud_watch_logs_role_arn     = aws_iam_role.org_trail_logs.arn" in block
    assert "provider           = aws.management" in role and "cloudtrail.amazonaws.com" in role
    streams = json.loads(json.loads(role_policy.split("policy   = ", 1)[1].rsplit("\n", 1)[0]))["Statement"][0]
    assert streams["Resource"] == [
        "arn:aws:logs:us-east-1:111122223333:log-group:/ciam/trail:log-stream:999988887777_CloudTrail_*",
        "arn:aws:logs:us-east-1:111122223333:log-group:/ciam/trail:log-stream:o-exampleorg_*"]
    assert "AWSLogs/o-exampleorg/*" in policy and "999988887777:trail/org-trail" in policy
    assert line == ("# org-trail: organization-wide: enabled for every account by **NO OWNER** (in their root "
                    "terraform/landing-zone)")                     # no landing zone party to ask: its root renders


def test_an_organization_trail_without_a_management_account_or_a_stream_that_isn_t_a_log_group_is_said_so():
    from opsdir.core.environment import env_model
    trail = _org_trail("org-trail", "audit-logs")
    d, _, _ = model(alpha=(NEW_BUCKET, trail), tree=OWNERS, changes=(_cloud(ciamAccountRef="111122223333"),))
    note, _ = as_text(render_trails(env_model(d, "alpha/prod")))
    assert note.endswith("which the record doesn't name (ciamManagementRef)")
    odd = _trail("cloudtrail", "audit-logs", ciamAuditStreamRole="files")
    assert any("streams only to a CloudWatch log group" in x for x in _render(NEW_BUCKET, FILES, odd))


def test_cloudformation_writes_the_trail_s_selectors_stream_role_and_bucket_policy_natively():
    from types import SimpleNamespace
    from opsdir_format_terraform.hcl import TfBlock, TfFile, tf_block
    from opsdir_adapter_aws.cfn_types import cloudformation_translation
    from opsdir_adapter_aws.observability import render_log_groups
    from opsdir_adapter_aws.storage import render_object_stores
    trail = _trail("cloudtrail", "audit-logs", ciamAuditEvents=("control-plane", "data-write"),
                   ciamAuditStreamRole="trail-logs")
    m = model(alpha=(NEW_BUCKET, FILES, STREAM, trail), tree=OWNERS, changes=(ACCOUNT,))[1]
    items = tuple(x for x in (*render_object_stores(m), *render_log_groups(m), *render_trails(m))
                  if isinstance(x, TfBlock))
    files = {"terraform/main.tf": TfFile("", (tf_block("provider", ["aws"], [("region", "us-east-1")]), *items))}
    done = cloudformation_translation(SimpleNamespace(dn=m.dn, label="alpha/prod"), files, "AWS infrastructure")
    (template,) = done.templates.values()
    found = {r.logical_id: r for r in template.resources}
    props = found["CloudtrailCloudtrail"].properties
    assert [s["Name"] for s in props["AdvancedEventSelectors"]] == ["Management events", "data-write on S3 objects"]
    assert {"Field": "resources.ARN", "StartsWith": ["arn:aws:s3:::example-ciam-files/"]} in \
        props["AdvancedEventSelectors"][1]["FieldSelectors"]
    assert "CloudWatchLogsLogGroupArn" in props and "CloudWatchLogsRoleArn" in props
    policy = found["S3BucketPolicyCloudtrailDelivery"].properties
    assert json.loads(policy["PolicyDocument"])["Statement"][0]["Action"] == "s3:GetBucketAcl"   # as the role's
    assert found["IamRoleCloudtrailLogs"].properties["Policies"][0]["PolicyName"] == "cloudtrail-logs"


def test_a_trail_read_back_names_the_log_group_it_streams_to_beside_its_bucket():
    (r,) = trail_resources([("aws_cloudtrail", {
        "arn": "arn:aws:cloudtrail:us-east-1:111122223333:trail/t", "name": "t", "s3_bucket_name": "b",
        "cloud_watch_logs_group_arn": "arn:aws:logs:us-east-1:111122223333:log-group:/ciam/trail:*",
        "advanced_event_selector": [{"field_selector": [{"field": "eventCategory", "equals": ["Data"]},
                                                        {"field": "readOnly", "equals": ["false"]}]}]})])
    assert r.links == {"ciamLogDestinationRole": "arn:aws:s3:::b",
                       "ciamAuditStreamRole": "arn:aws:logs:us-east-1:111122223333:log-group:/ciam/trail"}
    assert r.attrs["ciamAuditEvents"] == ("data-write",)


def test_what_a_trail_s_render_leaves_out_is_a_render_note_written_as_its_comment():
    from opsdir.core.notes import note_comment
    from opsdir_adapter_aws.audit import audit_notes
    trails = (_trail("cloudtrail", "audit-logs", ciamAuditStreamRole="app-logs",
                     ciamProviderRef="arn:aws:cloudtrail:us-east-1:111122223333:trail/ciam-prod"),
              _trail("to-logs", "app-logs"))
    _, alpha, _ = model(alpha=(BUCKET, GROUP, *trails), tree=OWNERS)
    notes = audit_notes(alpha)
    assert sorted(f"# {note_comment(n)}" for n in notes) == sorted(
        x for x in as_text(render_trails(alpha)) if x.startswith("# NOTE:"))
    policy, stream, logs = notes
    assert (policy.severity, policy.entry, policy.scope) == (
        "action", f"cn=audit-logs,ou=bindings,{ALPHA}", "bucket example-ciam-audit")
    statements = json.loads(policy.how[0].split("policy: ", 1)[1])
    assert [s["Sid"] for s in statements] == ["AWSCloudTrailAclCheck", "AWSCloudTrailWrite"]
    assert stream.severity == logs.severity == "blocker" and {n.area for n in notes} == {"Audit"}
    assert stream.text.startswith("streams only to a CloudWatch log group (its ciamAuditStreamRole app-logs")
    assert logs.how[0].startswith("Record the object store of the S3 bucket keeping the trail's records as its "
                                  "ciamLogDestinationRole and app-logs as its ciamAuditStreamRole")
