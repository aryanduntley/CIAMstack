"""Observability fixture data (79-observability): what the platform is watched for, where its logs go and for how
long, and the synthetic checks that it works: a client-credentials token from PingFederate (sso-login), a SAML
sign-in started for the customer portal (portal-sso: the IdP's start reaches the sign-in page), and an LDAPS bind to
the internal directory service as the check's own account (directory-bind). Each environment's alert channels, log
destinations, the alarms and checks its cloud runs, and its control-plane audit trail with the object store that keeps
its records, are bindings (MONITORING below, used by infrastructure: SOURCE / TARGET / STANDBY).

The audit trails: the source's CloudTrail (management events and S3 data writes, every region, log file validation)
into a bucket under Object Lock in compliance mode; the target's Activity Log export (a subscription diagnostic
setting) into its storage account's insights-activity-logs container; the standby's Cloud Audit Logs sink (Data
Access logs on) into a bucket whose retention policy is locked.

Security events (milestone 6.2e): the PingFederate engines' audit logs and the admin console's logs go to the security
team's SIEM, kept 365 days. Production's is Splunk (its stack declares the Splunk add-on: the render writes the
opsdir_ciam app and the forwarders' inputs), the index's retention and the detection the security team runs read in from
Splunk's management API under CHG-2049 (exports/splunk); the target's is Microsoft Sentinel on its own workspace, 90
days searchable and 365 in all, with the admin-login detection as a scheduled analytics rule.

Planted for the planner to find:
  - the target's audit workspace keeps logs 90 days; the audit route must keep them 400 (and they are under legal hold)
  - the source runs an alarm on disk space that realizes no recorded rule, and the target doesn't run it
  - the login-failures rule names no runbook
  - Splunk keeps production's security events 180 days, short of the 365 the route needs (read in under CHG-2049)
  - the target's Sentinel keeps them searchable 90 days only: older events must be restored from its archive
  - nothing in production runs the admin-login detection until CHG-2049 reads in the one Splunk runs
  - the target's audit trail records control-plane activity only (the source's records data writes too), and its
    container's immutability policy is unlocked: a privileged user can lift it, so its records are less protected
    than the source's validated ones
"""
from .common import RB, R, ou, owner, spec

PORTAL = f"cn=customer-portal,ou=integrations,{R}"

FILE = "79-observability"
RULES, ROUTES, CANARIES = f"ou=alert-rules,{R}", f"ou=log-routes,{R}", f"ou=canaries,{R}"
AWS_ACCOUNT = "arn:aws:{}:us-east-1:111122223333:{}"
AZ_INSIGHTS = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers/"
               "Microsoft.Insights/{}")
AZ_WORKSPACES = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers/"
                 "Microsoft.OperationalInsights/workspaces/{}")
AZ_JOBS = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers/"
           "Microsoft.App/jobs/{}")
# the check image Example Aero's pipeline built, signed and pushed from the render's images/ciam-check/ (by digest)
AZ_CHECK_IMAGE = ("check=crexampleaerociam.azurecr.io/ciam/check@sha256:"
                  "574144c3681fe0e10565a329003298f27890e7589c4e5aa6ea7eb102ce0e9c1e")


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
            spec(FILE, f"cn=admin-login-failures,{RULES}", ["top", "ciamObject", "ciamAlertRule"],
                 cn="admin-login-failures", ciamSignal="admin-login-failures", ciamTargetRole="pf-admin",
                 ciamComparison="gt", ciamThreshold="10 /min", ciamEvaluationPeriod="5m", ciamSeverity="sev2",
                 ciamAlertRole="soc-alerts", ciamRunbookRef=f"cn=WI-CIAM-012,{RB}",
                 ciamOwner=owner("security-operations")),
            ou(FILE, "log-routes"),
            spec(FILE, f"cn=audit-logs,{ROUTES}", ["top", "ciamObject", "ciamLogRoute"], cn="audit-logs",
                 ciamLogKind=["audit", "admin"], ciamPublishedBy=["ds", "pf-engine", "pf-admin"],
                 ciamLogDestinationRole="audit-logs", ciamRetentionDays=400, ciamLegalHold="TRUE",
                 ciamOwner=owner("ciam-platform")),
            spec(FILE, f"cn=access-logs,{ROUTES}", ["top", "ciamObject", "ciamLogRoute"], cn="access-logs",
                 ciamLogKind="access", ciamPublishedBy=["ds", "pf-engine"], ciamLogDestinationRole="ops-logs",
                 ciamRetentionDays=30, ciamOwner=owner("ciam-platform")),
            spec(FILE, f"cn=security-events,{ROUTES}", ["top", "ciamObject", "ciamLogRoute"], cn="security-events",
                 ciamLogKind=["audit", "admin"], ciamPublishedBy=["pf-engine", "pf-admin"],
                 ciamLogDestinationRole="siem", ciamRetentionDays=365, ciamOwner=owner("security-operations")),
            ou(FILE, "canaries"),
            spec(FILE, f"cn=sso-login,{CANARIES}", ["top", "ciamObject", "ciamCanary"], cn="sso-login",
                 ciamCheckedService="pf-sso-service", ciamCanaryFlow="oidc-token", ciamInterval="5m",
                 ciamUsesRole="canary-client", ciamFeedsAlert=f"cn=login-failures,{RULES}",
                 ciamOwner=owner("ciam-platform")),
            spec(FILE, f"cn=portal-sso,{CANARIES}", ["top", "ciamObject", "ciamCanary"], cn="portal-sso",
                 ciamCheckedService="pf-sso-service", ciamCanaryFlow="saml-sso", ciamStartsFrom=PORTAL,
                 ciamInterval="10m", ciamFeedsAlert=f"cn=login-failures,{RULES}", ciamOwner=owner("ciam-platform")),
            spec(FILE, f"cn=directory-bind,{CANARIES}", ["top", "ciamObject", "ciamCanary"], cn="directory-bind",
                 ciamCheckedService="ds-ldaps-service", ciamCanaryFlow="ldap-bind", ciamInterval="5m",
                 ciamUsesRole="canary-bind", ciamOwner=owner("ciam-platform"),
                 # sign-ins bind to the directory (PingFederate's and PingAM's stores): a failed bind is a failed login
                 ciamFeedsAlert=f"cn=login-failures,{RULES}"))


GCP_PROJECT = "projects/example-aero-ciam-standby"
SUBSCRIPTION = "/subscriptions/00000000-0000-0000-0000-000000000000"
AZ_AUDIT_ACCOUNT = (f"{SUBSCRIPTION}/resourceGroups/rg-ciam-prod/providers/Microsoft.Storage/storageAccounts/"
                    "stciamprodaudit")
CLOUDTRAIL_BUCKET = "example-aero-ciam-prod-cloudtrail"


def _aws(service, rest):
    return AWS_ACCOUNT.format(service, rest)


# Each environment's monitoring bindings: (class, name, binding role, attributes).
PAGE_TOPIC = _aws("sns", "ciam-prod-page")
SENTINEL = AZ_WORKSPACES.format("law-ciam-prod-sentinel")
# the target's admin-login detection: admin console sign-ins that fail, in the containers' output Sentinel keeps
ADMIN_LOGINS = 'ContainerLogV2 | where ContainerName startswith "pf-log-admin" and LogMessage has "Login failed"'
MONITORING = {
    "source": (
        ("ciamAlertChannel", "alerts-page", "alerts-page", {"ciamChannelKind": "topic", "ciamProviderRef": PAGE_TOPIC}),
        ("ciamAlertChannel", "soc-alerts", "soc-alerts",
         {"ciamChannelKind": "email", "ciamProviderRef": "mailto:soc@example-aero.test"}),
        # the security team's Splunk index; what it keeps is read in from Splunk (CHG-2049)
        ("ciamLogDestination", "siem", "siem",
         {"ciamDestinationKind": "siem-index", "ciamProviderRef": "ciam_security"}),
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
        ("ciamCanaryBinding", "portal-sso", "canary-portal-sso",
         {"ciamProviderRef": _aws("synthetics", "canary:portal-sso"), "ciamRealizes": "portal-sso",
          "ciamInterval": "10m", "ciamStorageRef": "s3://example-aero-ciam-prod-canaries/portal-sso"}),
        # the internal directory's check runs in the VPC, from the first subnet role the firewall admits to it on its
        # port (record order: IDM's, which fw-idm-sync admits)
        ("ciamCanaryBinding", "directory-bind", "canary-directory-bind",
         {"ciamProviderRef": _aws("synthetics", "canary:directory-bind"), "ciamRealizes": "directory-bind",
          "ciamInterval": "5m", "ciamStorageRef": "s3://example-aero-ciam-prod-canaries/directory-bind"}),
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
        ("ciamAlertChannel", "soc-alerts", "soc-alerts",
         {"ciamChannelKind": "action-group", "ciamProviderRef": AZ_INSIGHTS.format("actionGroups/ag-ciam-soc")}),
        # planted: Sentinel keeps the security events searchable 90 days (365 in all)
        ("ciamLogDestination", "siem", "siem",
         {"ciamDestinationKind": "siem-index", "ciamRetentionDays": 90, "ciamTotalRetentionDays": 365,
          "ciamProviderRef": SENTINEL}),
        ("ciamAlarmBinding", "pf-admin-login-failures", "alarm-admin-login-failures",
         {"ciamProviderRef": f"{SENTINEL}/providers/Microsoft.SecurityInsights/alertRules/ciam-admin-login-failures",
          "ciamRealizes": "admin-login-failures", "ciamMetric": ADMIN_LOGINS, "ciamLogDestinationRole": "siem"}),
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
        # the token and bind checks are Container Apps jobs (a standard web test can't read a secret or bind), running
        # the check image the organization built and recorded; the SAML sign-in's GET a standard web test
        ("ciamCanaryBinding", "sso-login", "canary-sso-login",
         {"ciamProviderRef": AZ_JOBS.format("sso-login"), "ciamRealizes": "sso-login", "ciamInterval": "5m",
          "ciamContainerImage": AZ_CHECK_IMAGE}),
        ("ciamCanaryBinding", "portal-sso", "canary-portal-sso",
         {"ciamProviderRef": AZ_INSIGHTS.format("webtests/portal-sso"), "ciamRealizes": "portal-sso",
          "ciamInterval": "10m"}),
        ("ciamCanaryBinding", "directory-bind", "canary-directory-bind",
         {"ciamProviderRef": AZ_JOBS.format("directory-bind"), "ciamRealizes": "directory-bind",
          "ciamInterval": "5m", "ciamSubnetRole": "subnet-checks", "ciamContainerImage": AZ_CHECK_IMAGE}),
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
        # the standby is an Assured Workloads workload (FedRAMP Moderate): Google supports neither uptime checks nor
        # synthetic monitors there, so its render names each check it can't run
        ("ciamCanaryBinding", "sso-login", "canary-sso-login",
         {"ciamProviderRef": f"{GCP_PROJECT}/uptimeCheckConfigs/sso-login", "ciamRealizes": "sso-login",
          "ciamInterval": "5m"}),
        ("ciamCanaryBinding", "portal-sso", "canary-portal-sso",
         {"ciamProviderRef": f"{GCP_PROJECT}/uptimeCheckConfigs/portal-sso", "ciamRealizes": "portal-sso",
          "ciamInterval": "10m"}),
        ("ciamCanaryBinding", "directory-bind", "canary-directory-bind",
         {"ciamProviderRef": f"{GCP_PROJECT}/uptimeCheckConfigs/directory-bind", "ciamRealizes": "directory-bind",
          "ciamInterval": "5m"}),
        ("ciamObjectStore", "audit-archive", "audit-archive",
         {"ciamStorageRef": "gs://example-aero-ciam-standby-audit",
          "ciamProviderRef": "example-aero-ciam-standby-audit", "ciamStorageImmutability": "compliance",
          "ciamStorageLockDays": "400"}),
        ("ciamAuditTrail", "audit-sink", "audit-trail",
         {"ciamAuditScope": "account", "ciamAuditEvents": ["control-plane", "data-write"], "ciamAllRegions": "TRUE",
          "ciamLogDestinationRole": "audit-archive", "ciamProviderRef": f"{GCP_PROJECT}/sinks/ciam-audit"})),
}

