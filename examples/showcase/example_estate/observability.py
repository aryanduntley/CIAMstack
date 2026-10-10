"""Observability fixture data (79-observability): what the platform is watched for, where its logs go and for how
long, and the synthetic sign-in that checks it works. Each environment's alert channels, log destinations, the alarms
and checks its cloud runs, and its control-plane audit trail with the object store that keeps its records, are
bindings (MONITORING below, used by infrastructure: SOURCE / TARGET / STANDBY).

The audit trails: the source's CloudTrail (management events and S3 data writes, every region, log file validation)
into a bucket under Object Lock in compliance mode; the target's Activity Log export (a subscription diagnostic
setting) into its storage account's insights-activity-logs container; the standby's Cloud Audit Logs sink (Data
Access logs on) into a bucket whose retention policy is locked.

Planted for the planner to find:
  - the target's audit workspace keeps logs 90 days; the audit route must keep them 400 (and they are under legal hold)
  - the source runs an alarm on disk space that realizes no recorded rule, and the target doesn't run it
  - the login-failures rule names no runbook
  - the target's audit trail records control-plane activity only (the source's records data writes too), and its
    container's immutability policy is unlocked: a privileged user can lift it, so its records are less protected
    than the source's validated ones
"""
from .common import RB, R, ou, owner, spec

FILE = "79-observability"
RULES, ROUTES, CANARIES = f"ou=alert-rules,{R}", f"ou=log-routes,{R}", f"ou=canaries,{R}"
AWS_ACCOUNT = "arn:aws:{}:us-east-1:111122223333:{}"
AZ_INSIGHTS = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers/"
               "Microsoft.Insights/{}")
AZ_WORKSPACES = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers/"
                 "Microsoft.OperationalInsights/workspaces/{}")


def entries():
    return (ou(FILE, "alert-rules"),
            spec(FILE, f"cn=replication-lag,{RULES}", ["top", "ciamObject", "ciamAlertRule"], cn="replication-lag",
                 ciamSignal="replication-delay", ciamTargetRole="ds", ciamComparison="gt", ciamThreshold="5000 ms",
                 ciamEvaluationPeriod="5m", ciamSeverity="sev2", ciamAlertRole="alerts-page",
                 ciamRunbookRef=f"cn=WI-CIAM-007,{RB}", ciamOwner=owner("ciam-platform")),
            spec(FILE, f"cn=login-failures,{RULES}", ["top", "ciamObject", "ciamAlertRule"], cn="login-failures",
                 ciamSignal="login-failures", ciamTargetRole="pf-engine", ciamComparison="gt", ciamThreshold="50 /min",
                 ciamEvaluationPeriod="5m", ciamSeverity="sev2", ciamAlertRole="alerts-page",
                 ciamOwner=owner("ciam-platform")),
            ou(FILE, "log-routes"),
            spec(FILE, f"cn=audit-logs,{ROUTES}", ["top", "ciamObject", "ciamLogRoute"], cn="audit-logs",
                 ciamLogKind=["audit", "admin"], ciamPublishedBy=["ds", "pf-engine", "pf-admin"],
                 ciamLogDestinationRole="audit-logs", ciamRetentionDays=400, ciamLegalHold="TRUE",
                 ciamOwner=owner("ciam-platform")),
            spec(FILE, f"cn=access-logs,{ROUTES}", ["top", "ciamObject", "ciamLogRoute"], cn="access-logs",
                 ciamLogKind="access", ciamPublishedBy=["ds", "pf-engine"], ciamLogDestinationRole="ops-logs",
                 ciamRetentionDays=30, ciamOwner=owner("ciam-platform")),
            ou(FILE, "canaries"),
            spec(FILE, f"cn=sso-login,{CANARIES}", ["top", "ciamObject", "ciamCanary"], cn="sso-login",
                 ciamCheckedService="pf-sso-service", ciamCanaryFlow="oidc-token", ciamInterval="5m",
                 ciamUsesRole="canary-client", ciamFeedsAlert=f"cn=login-failures,{RULES}",
                 ciamOwner=owner("ciam-platform")))


GCP_PROJECT = "projects/example-aero-ciam-standby"
SUBSCRIPTION = "/subscriptions/00000000-0000-0000-0000-000000000000"
AZ_AUDIT_ACCOUNT = (f"{SUBSCRIPTION}/resourceGroups/rg-ciam-prod/providers/Microsoft.Storage/storageAccounts/"
                    "stciamprodaudit")
CLOUDTRAIL_BUCKET = "example-aero-ciam-prod-cloudtrail"


def _aws(service, rest):
    return AWS_ACCOUNT.format(service, rest)


# Each environment's monitoring bindings: (class, name, binding role, attributes).
PAGE_TOPIC = _aws("sns", "ciam-prod-page")
MONITORING = {
    "source": (
        ("ciamAlertChannel", "alerts-page", "alerts-page", {"ciamChannelKind": "topic", "ciamProviderRef": PAGE_TOPIC}),
        ("ciamLogDestination", "audit-logs", "audit-logs",
         {"ciamDestinationKind": "log-group", "ciamRetentionDays": 400,
          "ciamProviderRef": _aws("logs", "log-group:/ciam/prod/audit")}),
        ("ciamLogDestination", "ops-logs", "ops-logs",
         {"ciamDestinationKind": "log-group", "ciamRetentionDays": 30,
          "ciamProviderRef": _aws("logs", "log-group:/ciam/prod/access")}),
        ("ciamAlarmBinding", "ds-replication-lag", "alarm-replication-lag",
         {"ciamProviderRef": _aws("cloudwatch", "alarm:ds-replication-lag"), "ciamRealizes": "replication-lag",
          "ciamMetric": "CIAM/DS ReplicationDelay", "ciamNotifies": PAGE_TOPIC}),
        ("ciamAlarmBinding", "pf-login-failures", "alarm-login-failures",
         {"ciamProviderRef": _aws("cloudwatch", "alarm:pf-login-failures"), "ciamRealizes": "login-failures",
          "ciamMetric": "CIAM/PingFederate LoginFailures", "ciamNotifies": PAGE_TOPIC}),
        # planted: an alarm nobody described (no rule named disk-free), which the target doesn't run either
        ("ciamAlarmBinding", "ds-disk-free", "alarm-disk-free",
         {"ciamProviderRef": _aws("cloudwatch", "alarm:ds-disk-free"), "ciamRealizes": "disk-free",
          "ciamMetric": "CWAgent disk_used_percent", "ciamNotifies": PAGE_TOPIC}),
        # its artifacts in the source's own bucket (CloudWatch Synthetics asks for a place; the other clouds don't)
        ("ciamCanaryBinding", "sso-login", "canary-sso-login",
         {"ciamProviderRef": _aws("synthetics", "canary:sso-login"), "ciamRealizes": "sso-login",
          "ciamInterval": "5m", "ciamStorageRef": "s3://example-aero-ciam-prod-canaries/sso-login"}),
        ("ciamObjectStore", "audit-archive", "audit-archive",
         {"ciamStorageRef": f"s3://{CLOUDTRAIL_BUCKET}", "ciamProviderRef": f"arn:aws:s3:::{CLOUDTRAIL_BUCKET}",
          "ciamStorageVersioning": "TRUE", "ciamStorageImmutability": "compliance", "ciamStorageLockDays": "400"}),
        ("ciamAuditTrail", "cloudtrail", "audit-trail",
         {"ciamAuditScope": "account", "ciamAuditEvents": ["control-plane", "data-write"], "ciamAllRegions": "TRUE",
          "ciamIntegrityValidation": "TRUE", "ciamLogDestinationRole": "audit-archive",
          "ciamProviderRef": _aws("cloudtrail", "trail/ciam-prod")})),
    "target": (
        ("ciamAlertChannel", "alerts-page", "alerts-page",
         {"ciamChannelKind": "action-group", "ciamProviderRef": AZ_INSIGHTS.format("actionGroups/ag-ciam-page")}),
        # planted: the target's audit workspace keeps logs 90 days; the audit route must keep them 400
        ("ciamLogDestination", "audit-logs", "audit-logs",
         {"ciamDestinationKind": "workspace", "ciamRetentionDays": 90,
          "ciamProviderRef": AZ_WORKSPACES.format("law-ciam-prod-audit")}),
        ("ciamLogDestination", "ops-logs", "ops-logs",
         {"ciamDestinationKind": "workspace", "ciamRetentionDays": 30,
          "ciamProviderRef": AZ_WORKSPACES.format("law-ciam-prod-ops")}),
        ("ciamAlarmBinding", "ds-replication-lag", "alarm-replication-lag",
         {"ciamProviderRef": AZ_INSIGHTS.format("metricAlerts/ds-replication-lag"), "ciamRealizes": "replication-lag",
          "ciamMetric": "Microsoft.Compute/virtualMachines ReplicationDelay"}),
        ("ciamAlarmBinding", "pf-login-failures", "alarm-login-failures",
         {"ciamProviderRef": AZ_INSIGHTS.format("scheduledQueryRules/pf-login-failures"),
          "ciamRealizes": "login-failures", "ciamMetric": "log query"}),
        ("ciamCanaryBinding", "sso-login", "canary-sso-login",
         {"ciamProviderRef": AZ_INSIGHTS.format("webtests/sso-login"), "ciamRealizes": "sso-login",
          "ciamInterval": "5m"}),
        # planted: an unlocked immutability policy (governance), and control-plane activity only
        ("ciamObjectStore", "activity-logs", "audit-archive",
         {"ciamStorageRef": "azblob://stciamprodaudit/insights-activity-logs",
          "ciamProviderRef": f"{AZ_AUDIT_ACCOUNT}/blobServices/default/containers/insights-activity-logs",
          "ciamStorageVersioning": "TRUE", "ciamStorageImmutability": "governance", "ciamStorageLockDays": "400"}),
        ("ciamAuditTrail", "activity-log", "audit-trail",
         {"ciamAuditScope": "account", "ciamAuditEvents": "control-plane", "ciamAllRegions": "TRUE",
          "ciamLogDestinationRole": "audit-archive",
          "ciamProviderRef": f"{SUBSCRIPTION}/providers/Microsoft.Insights/diagnosticSettings/ciam-activity-log"})),
    "standby": (
        ("ciamAlertChannel", "alerts-page", "alerts-page",
         {"ciamChannelKind": "paging-service", "ciamProviderRef": f"{GCP_PROJECT}/notificationChannels/1001"}),
        ("ciamLogDestination", "audit-logs", "audit-logs",
         {"ciamDestinationKind": "log-group", "ciamRetentionDays": 400,
          "ciamProviderRef": f"{GCP_PROJECT}/locations/global/buckets/ciam-audit"}),
        ("ciamLogDestination", "ops-logs", "ops-logs",
         {"ciamDestinationKind": "log-group", "ciamRetentionDays": 30,
          "ciamProviderRef": f"{GCP_PROJECT}/locations/global/buckets/ciam-ops"}),
        ("ciamAlarmBinding", "ds-replication-lag", "alarm-replication-lag",
         {"ciamProviderRef": f"{GCP_PROJECT}/alertPolicies/2001", "ciamRealizes": "replication-lag",
          "ciamMetric": "custom.googleapis.com/ds/replication_delay",
          "ciamNotifies": f"{GCP_PROJECT}/notificationChannels/1001"}),
        ("ciamAlarmBinding", "pf-login-failures", "alarm-login-failures",
         {"ciamProviderRef": f"{GCP_PROJECT}/alertPolicies/2002", "ciamRealizes": "login-failures",
          "ciamMetric": "log query", "ciamNotifies": f"{GCP_PROJECT}/notificationChannels/1001"}),
        ("ciamCanaryBinding", "sso-login", "canary-sso-login",
         {"ciamProviderRef": f"{GCP_PROJECT}/uptimeCheckConfigs/sso-login", "ciamRealizes": "sso-login",
          "ciamInterval": "5m"}),
        ("ciamObjectStore", "audit-archive", "audit-archive",
         {"ciamStorageRef": "gs://example-aero-ciam-standby-audit",
          "ciamProviderRef": "example-aero-ciam-standby-audit", "ciamStorageImmutability": "compliance",
          "ciamStorageLockDays": "400"}),
        ("ciamAuditTrail", "audit-sink", "audit-trail",
         {"ciamAuditScope": "account", "ciamAuditEvents": ["control-plane", "data-write"], "ciamAllRegions": "TRUE",
          "ciamLogDestinationRole": "audit-archive", "ciamProviderRef": f"{GCP_PROJECT}/sinks/ciam-audit"})),
}

