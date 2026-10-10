"""Observability domain schema: what the platform is watched for, where its logs go and for how long, the synthetic
checks that sign in as a user would, and the control-plane audit trail that records who did what to the cloud. Alert
rules, log routes and canaries are intent, the same in every environment; what delivers an alert (a topic, an action
group, a paging service), what keeps logs (a log group, a workspace, a SIEM index) and the audit trail (CloudTrail, the
Activity Log's diagnostic setting, Cloud Audit Logs' sinks) are bindings each environment gives a role."""
from ...core.standard import AttributeDef, ClassDef, enum_type, fragment
from .naming import (AUDIT_EVENTS, AUDIT_SCOPES, CANARY_FLOWS, CHANNEL_KINDS, COMPARISONS, DESTINATION_KINDS, DURATION,
                     LOG_KINDS)

PERIOD = (("X-PATTERN", DURATION),)


ATTRIBUTES = (
    # ------------------------------------------------------------------ alert rules
    AttributeDef(309, 'ciamSignal', 'string', 'intent', True,
                 'What an alert rule watches, named neutrally (replication-delay, ldaps-errors, login-failures, '
                 'cert-expiry, disk-free, heap-used, ...): each provider renders its own metric or query'),
    AttributeDef(310, 'ciamComparison', enum_type(COMPARISONS), 'intent', True,
                 "How an alert rule's signal is compared with its threshold"),
    AttributeDef(311, 'ciamThreshold', 'string', 'intent', True,
                 'The value an alert rule compares its signal with, with its unit (5000 ms, 90 %, 10 /min)',
                 (("X-PATTERN", "^-?[0-9]+(\\.[0-9]+)?( ?[A-Za-z%/]+)?$"),)),
    AttributeDef(312, 'ciamEvaluationPeriod', 'string', 'intent', True,
                 'How long the condition must hold before an alert fires (5m)', PERIOD),
    AttributeDef(313, 'ciamAlertRole', 'string', 'intent', True,
                 'The binding role of the channel that delivers an alert in each environment (a topic, an action '
                 'group, a paging service)'),
    # ------------------------------------------------------------------ log routes
    AttributeDef(314, 'ciamLogKind', enum_type(LOG_KINDS), 'intent', False,
                 'Which logs a route carries: access, audit, error, admin, ...'),
    AttributeDef(315, 'ciamLogDestinationRole', 'string', 'intent', True,
                 'The binding role of what keeps a route\'s logs in each environment (a log group, a workspace, a '
                 'SIEM index)'),
    AttributeDef(316, 'ciamLegalHold', 'bool', 'meta', True,
                 'Whether logs are under legal hold: the source keeps them after a move, whatever their retention'),
    # ------------------------------------------------------------------ canaries
    AttributeDef(317, 'ciamCheckedService', 'string', 'intent', True,
                 'The binding role of the service name a synthetic check exercises (each environment its own name)'),
    AttributeDef(318, 'ciamCanaryFlow', enum_type(CANARY_FLOWS), 'intent', True,
                 'What a synthetic check does: load the login page, get a token, a SAML sign-in, an LDAP bind, a '
                 'health probe'),
    AttributeDef(319, 'ciamInterval', 'string', 'intent', True, 'How often a synthetic check runs (5m)', PERIOD),
    AttributeDef(320, 'ciamFeedsAlert', 'dn', 'intent', True, 'The alert rule a failing synthetic check fires'),
    # ------------------------------------------------------------------ bindings
    AttributeDef(321, 'ciamChannelKind', enum_type(CHANNEL_KINDS), 'binding', True,
                 'What delivers alerts in an environment: a topic, an action group, a paging service, ...'),
    AttributeDef(322, 'ciamDestinationKind', enum_type(DESTINATION_KINDS), 'binding', True,
                 'What keeps logs in an environment: a log group, a workspace, a SIEM index, a bucket'),
    # ------------------------------------------------------------------ what a cloud runs
    AttributeDef(323, 'ciamRealizes', 'string', 'binding', True,
                 'The alert rule or canary (its name) an alarm or synthetic check a cloud runs realizes'),
    AttributeDef(324, 'ciamNotifies', 'string', 'binding', False,
                 'What an alarm a cloud runs notifies (the provider refs of its channels: topics, action groups)'),
    AttributeDef(325, 'ciamMetric', 'string', 'binding', True,
                 'The metric or query an alarm a cloud runs evaluates, as the provider names it (AWS/EC2 '
                 'CPUUtilization)'),
    # ------------------------------------------------------------------ control-plane audit trails
    AttributeDef(495, 'ciamAuditScope', enum_type(AUDIT_SCOPES), 'binding', True,
                 "What an audit trail records: one account (an AWS account, an Azure subscription, a Google Cloud "
                 "project) or every account of the organization"),
    AttributeDef(496, 'ciamAuditEvents', enum_type(AUDIT_EVENTS), 'binding', False,
                 "Which activity an audit trail records: control-plane (management API calls), data-read, data-write"),
    AttributeDef(497, 'ciamAllRegions', 'bool', 'binding', True,
                 "Whether an audit trail records activity in every region (and global services), not one region"),
    AttributeDef(498, 'ciamIntegrityValidation', 'bool', 'binding', True,
                 "Whether the cloud cryptographically validates an audit trail's records (CloudTrail's signed digest "
                 "files); a locked immutable store keeping them is graded through its ciamStorageImmutability"),
)
CLASSES = (
    ClassDef(62, 'ciamAlertRule', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamSignal', 'ciamAlertRole'),
             ('ciamTargetRole', 'ciamComparison', 'ciamThreshold', 'ciamEvaluationPeriod', 'ciamSeverity',
              'ciamRunbookRef'),
             'What the platform is watched for: a signal on a server role, the condition that fires, how severe, '
             'who it goes to, what to do'),
    ClassDef(63, 'ciamLogRoute', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamLogKind', 'ciamLogDestinationRole'),
             ('ciamPublishedBy', 'ciamRetentionDays', 'ciamLegalHold'),
             "Where a server role's logs go and how long they must be kept (an obligation: audit logs survive a "
             "move and the source's decommissioning)"),
    ClassDef(64, 'ciamCanary', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamCheckedService', 'ciamCanaryFlow'),
             ('ciamInterval', 'ciamUsesRole', 'ciamFeedsAlert'),
             'A synthetic check that signs in as a user would: what it exercises, how often, the secret role of its '
             'test credentials, the alert it fires'),
    ClassDef(65, 'ciamAlertChannel', 'ciamBinding', 'STRUCTURAL', ('ciamChannelKind',), ('ciamProviderRef',),
             'What delivers alerts of a role in an environment (a topic, an action group, a paging service)'),
    ClassDef(66, 'ciamLogDestination', 'ciamBinding', 'STRUCTURAL', ('ciamDestinationKind',),
             ('ciamProviderRef', 'ciamRetentionDays'),
             'What keeps logs of a role in an environment, and for how many days (0: kept indefinitely)'),
    ClassDef(67, 'ciamAlarmBinding', 'ciamBinding', 'STRUCTURAL', ('ciamProviderRef',),
             ('ciamRealizes', 'ciamNotifies', 'ciamMetric'),
             'An alarm a cloud runs in an environment: the alert rule it realizes, what it evaluates, what it '
             'notifies'),
    ClassDef(68, 'ciamCanaryBinding', 'ciamBinding', 'STRUCTURAL', ('ciamProviderRef',),
             ('ciamRealizes', 'ciamInterval', 'ciamStorageRef'),
             'A synthetic check a cloud runs in an environment: the canary it realizes, how often, and where it keeps '
             'its results when the cloud asks for a place (ciamStorageRef: CloudWatch Synthetics\' S3 artifact '
             'location)'),
    ClassDef(111, 'ciamAuditTrail', 'ciamBinding', 'STRUCTURAL', ('ciamAuditScope',),
             ('ciamAuditEvents', 'ciamAllRegions', 'ciamIntegrityValidation', 'ciamLogDestinationRole',
              'ciamProviderRef', 'ciamManagedBy'),
             "An environment's control-plane audit trail (CloudTrail, the Activity Log's diagnostic setting, Cloud "
             "Audit Logs' sinks): what it records, where its records go (a log destination's or object store's "
             "role), and who keeps it when it isn't the platform team (an organization trail the landing zone keeps)"),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
