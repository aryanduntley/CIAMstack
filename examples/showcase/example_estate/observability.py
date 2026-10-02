"""Observability fixture data (79-observability): what the platform is watched for, where its logs go and for how
long, and the synthetic sign-in that checks it works. Each environment's alert channels, log destinations, and the
alarms and checks its cloud runs, are bindings (MONITORING below, used by infrastructure: SOURCE / TARGET /
STANDBY).

Planted for the planner to find:
  - the target's audit workspace keeps logs 90 days; the audit route must keep them 400 (and they are under legal hold)
  - the source runs an alarm on disk space that realizes no recorded rule, and the target doesn't run it
  - the login-failures rule names no runbook
"""
from .common import RB, R, owner, spec

FILE = "79-observability"
RULES, ROUTES, CANARIES = f"ou=alert-rules,{R}", f"ou=log-routes,{R}", f"ou=canaries,{R}"
AWS_ACCOUNT = "arn:aws:{}:us-east-1:111122223333:{}"
AZ_INSIGHTS = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers/"
               "Microsoft.Insights/{}")
AZ_WORKSPACES = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers/"
                 "Microsoft.OperationalInsights/workspaces/{}")


def _ou(dn, name):
    return spec(FILE, dn, ["top", "organizationalUnit"], ou=name)


def entries():
    return (_ou(RULES, "alert-rules"),
            spec(FILE, f"cn=replication-lag,{RULES}", ["top", "ciamObject", "ciamAlertRule"], cn="replication-lag",
                 ciamSignal="replication-delay", ciamTargetRole="ds", ciamComparison="gt", ciamThreshold="5000 ms",
                 ciamEvaluationPeriod="5m", ciamSeverity="sev2", ciamAlertRole="alerts-page",
                 ciamRunbookRef=f"cn=WI-CIAM-007,{RB}", ciamOwner=owner("ciam-platform")),
            spec(FILE, f"cn=login-failures,{RULES}", ["top", "ciamObject", "ciamAlertRule"], cn="login-failures",
                 ciamSignal="login-failures", ciamTargetRole="pf-engine", ciamComparison="gt", ciamThreshold="50 /min",
                 ciamEvaluationPeriod="5m", ciamSeverity="sev2", ciamAlertRole="alerts-page",
                 ciamOwner=owner("ciam-platform")),
            _ou(ROUTES, "log-routes"),
            spec(FILE, f"cn=audit-logs,{ROUTES}", ["top", "ciamObject", "ciamLogRoute"], cn="audit-logs",
                 ciamLogKind=["audit", "admin"], ciamPublishedBy=["ds", "pf-engine", "pf-admin"],
                 ciamLogDestinationRole="audit-logs", ciamRetentionDays=400, ciamLegalHold="TRUE",
                 ciamOwner=owner("ciam-platform")),
            spec(FILE, f"cn=access-logs,{ROUTES}", ["top", "ciamObject", "ciamLogRoute"], cn="access-logs",
                 ciamLogKind="access", ciamPublishedBy=["ds", "pf-engine"], ciamLogDestinationRole="ops-logs",
                 ciamRetentionDays=30, ciamOwner=owner("ciam-platform")),
            _ou(CANARIES, "canaries"),
            spec(FILE, f"cn=sso-login,{CANARIES}", ["top", "ciamObject", "ciamCanary"], cn="sso-login",
                 ciamCheckedService="pf-sso-service", ciamCanaryFlow="oidc-token", ciamInterval="5m",
                 ciamFeedsAlert=f"cn=login-failures,{RULES}", ciamOwner=owner("ciam-platform")))


GCP_PROJECT = "projects/example-aero-ciam-standby"


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
        ("ciamCanaryBinding", "sso-login", "canary-sso-login",
         {"ciamProviderRef": _aws("synthetics", "canary:ciam-sso-login"), "ciamRealizes": "sso-login",
          "ciamInterval": "5m"})),
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
          "ciamInterval": "5m"})),
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
          "ciamInterval": "5m"})),
}

