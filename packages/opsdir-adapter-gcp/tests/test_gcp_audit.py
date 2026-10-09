"""Control-plane audit trails on Google Cloud: a trail the platform keeps rendered as a log sink exporting Cloud Audit
Logs to its bucket (with the writer identity's grant) or log bucket, data events as an audit config for every service,
an organization trail as an organization sink; integrity without a locked bucket noted; trails kept by someone else
and other destinations named. Read back from Terraform state, Cloud Asset Inventory and gcloud: sinks exporting audit
logs (built-in and disabled ones skipped), data events from their parent's audit configs, the bucket's role as where
records go."""
import json

from opsdir.core.inventory import environment_groups, resource
from opsdir_adapter_gcp.audit import audit_configs, render_trails, sink_parent, trail_events, trail_resources
from opsdir_adapter_gcp.cli import cli_resources
from network_fixtures import ALPHA, entry, model

PARTY = "cn=landing-zone,ou=owners,dc=ciam-ops"
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
          f"dn: {PARTY}\nobjectClass: top\nobjectClass: ciamParty\ncn: landing-zone\nciamOwnerKind: team\n")
LOG_BUCKET = "projects/ciam-prod/locations/global/buckets/audit"


def _bucket(mode=None, **more):
    return entry(ALPHA, "audit-logs", "ciamObjectStore", ciamBindingRole="audit-logs",
                 ciamStorageRef="gs://example-ciam-audit",
                 **({"ciamStorageImmutability": mode, "ciamStorageLockDays": "365"} if mode else {}), **more)


def _trail(cn, destination, **more):
    return entry(ALPHA, cn, "ciamAuditTrail", **{"ciamBindingRole": cn, "ciamAuditScope": "account",
                                                 "ciamLogDestinationRole": destination, **more})


def test_a_project_trail_the_platform_keeps_is_a_sink_with_its_grant_and_audit_config():
    trails = (_trail("audit-sink", "audit-logs", ciamAuditEvents=("control-plane", "data-read", "data-write"),
                     ciamIntegrityValidation="TRUE", ciamProviderRef="projects/ciam-prod/sinks/ciam-audit"),
              _trail("org-trail", "audit-logs", ciamManagedBy=PARTY))
    _, alpha, _ = model(alpha=(_bucket(), *trails), tree=OWNERS)
    assert render_trails(alpha) == ('''resource "google_logging_project_sink" "audit_sink" {
  # integrity: Google keeps no digest of audit logs; keep them in a bucket whose retention policy is locked '''
                                    '''(ciamStorageImmutability compliance)
  name                   = "ciam-audit"
  destination            = "storage.googleapis.com/example-ciam-audit"
  filter                 = "logName:\\"cloudaudit.googleapis.com\\""
  unique_writer_identity = true
}''', '''resource "google_storage_bucket_iam_member" "audit_sink" {
  bucket = "example-ciam-audit"
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.audit_sink.writer_identity
}''', '''resource "google_project_iam_audit_config" "audit_sink" {
  project = var.project_id
  service = "allServices"
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}''', "# Audit trail org-trail (account): kept by landing-zone, not rendered here")


def test_an_organization_trail_into_a_locked_bucket_or_a_log_bucket():
    logs = entry(ALPHA, "audit-bucket", "ciamLogDestination", ciamBindingRole="audit-bucket",
                 ciamDestinationKind="log-group", ciamProviderRef=LOG_BUCKET)
    siem = entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index")
    _, alpha, _ = model(alpha=(_bucket("compliance"), logs, siem,
                               _trail("org", "audit-logs", ciamAuditScope="organization",
                                      ciamIntegrityValidation="TRUE"),
                               _trail("to-log-bucket", "audit-bucket"), _trail("to-siem", "siem")))
    out = render_trails(alpha)
    assert out[0].startswith('variable "organization_id"')
    org = next(x for x in out if x.startswith('resource "google_logging_organization_sink"'))
    assert "org_id                 = var.organization_id" in org and "include_children       = true" in org
    assert "integrity" not in org and "bucket = google_storage_bucket.audit_logs.name" in "\n".join(out)
    assert any(f'destination            = "logging.googleapis.com/{LOG_BUCKET}"' in x for x in out)
    assert "# NOTE: audit trail to-siem: not rendered: a sink exports to a bucket, a log bucket, BigQuery or " \
           "Pub/Sub, and siem is none of those" in out


def test_the_activity_a_sink_exports_comes_from_its_filter_and_its_parent_s_audit_configs():
    configs = audit_configs([("google_project_iam_audit_config", {
        "project": "ciam-prod", "service": "allServices", "audit_log_config": [{"log_type": "DATA_WRITE"}]})])
    assert configs == {"projects/ciam-prod": {"DATA_WRITE"}}
    sink = {"id": "projects/ciam-prod/sinks/s", "filter": 'logName:"cloudaudit.googleapis.com"'}
    assert trail_events(sink, configs) == ("control-plane", "data-write")
    assert trail_events({**sink, "filter": 'logName="projects/ciam-prod/logs/cloudaudit.googleapis.com%2Factivity"'},
                        configs) == ("control-plane",)
    assert trail_events({**sink, "id": "projects/other/sinks/s"}, configs) == ("control-plane",)
    policy = {"resource": "//cloudresourcemanager.googleapis.com/projects/ciam-prod", "policy_data": json.dumps(
        {"auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "DATA_READ"}]}]})}
    assert audit_configs([("google_cai_iam_policy", policy)]) == {"projects/ciam-prod": {"DATA_READ"}}


def test_sinks_are_read_back_with_their_bucket_s_role_and_others_are_skipped():
    sinks = [("google_logging_project_sink", {"id": "projects/ciam-prod/sinks/ciam-audit", "name": "ciam-audit",
                                              "destination": "storage.googleapis.com/example-ciam-audit",
                                              "filter": 'logName:"cloudaudit.googleapis.com"'}),
             ("google_logging_project_sink", {"id": "projects/ciam-prod/sinks/_Required", "name": "_Required",
                                              "destination": "logging.googleapis.com/projects/ciam-prod/locations/"
                                                             "global/buckets/_Required", "filter": ""}),
             ("google_logging_project_sink", {"id": "projects/ciam-prod/sinks/off", "name": "off", "disabled": True,
                                              "destination": "storage.googleapis.com/x", "filter": ""}),
             ("google_logging_project_sink", {"id": "projects/ciam-prod/sinks/app", "name": "app",
                                              "destination": "storage.googleapis.com/x",
                                              "filter": 'resource.type="gce_instance"'})]
    trail, = trail_resources(sinks)
    d, *_ = model(alpha=(_bucket(),))
    store = resource("storage", "example-ciam-audit", {"ciamStorageRef": "gs://example-ciam-audit"},
                     name="example-ciam-audit")
    groups, _ = environment_groups(d, "alpha/prod", (store, trail))
    placed = [(e.dn.split(",")[0], dict(e.attrs)) for _, entries in groups for e in entries
              if "ciamAuditTrail" in e.classes]
    assert placed == [("cn=ciam-audit", {
        "cn": ("ciam-audit",), "ciamBindingRole": ("audit-trail",),
        "ciamProviderRef": ("projects/ciam-prod/sinks/ciam-audit",), "ciamAuditScope": ("account",),
        "ciamAuditEvents": ("control-plane",), "ciamAllRegions": ("TRUE",),
        "ciamLogDestinationRole": ("audit-logs",)})]


def test_gcloud_and_inventory_sinks_are_read_under_their_parent():
    assert sink_parent("log-sinks/ciam-prod.json") == "projects/ciam-prod"
    assert sink_parent("log-sinks/organizations-1234.json") == "organizations/1234"
    listed = [{"name": "ciam-audit", "destination": "storage.googleapis.com/example-ciam-audit",
               "filter": 'logName:"cloudaudit.googleapis.com"',
               "writerIdentity": "serviceAccount:service-1@gcp-sa-logging.iam.gserviceaccount.com"}]
    asset = {"name": "//logging.googleapis.com/organizations/1234/sinks/org-audit",
             "assetType": "logging.googleapis.com/LogSink",
             "resource": {"data": {"name": "org-audit", "destination": f"logging.googleapis.com/{LOG_BUCKET}",
                                   "includeChildren": True, "filter": ""}}}
    resources, _ = cli_resources({"log-sinks/ciam-prod.json": json.dumps(listed), "assets.json": json.dumps([asset])})
    assert sorted((r.ref, r.attrs["ciamAuditScope"], r.links["ciamLogDestinationRole"])
                  for r in resources if r.kind == "audit") == [
        ("organizations/1234/sinks/org-audit", ("organization",), LOG_BUCKET),
        ("projects/ciam-prod/sinks/ciam-audit", ("account",), "example-ciam-audit")]
