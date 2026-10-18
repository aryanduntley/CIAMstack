"""Observability domain schema: what the platform is watched for, where its logs go and for how long, the synthetic
checks that sign in as a user would, and the control-plane audit trail that records who did what to the cloud. Alert
rules, log routes and canaries are intent, the same in every environment; what delivers an alert (a topic, an action
group, a paging service), what keeps logs (a log group, a workspace, a SIEM index) and the audit trail (CloudTrail, the
Activity Log's diagnostic setting, Cloud Audit Logs' sinks) are bindings each environment gives a role."""
from ...core.standard import AttributeDef, ClassDef, enum_type, fragment
from .naming import (ATTACK_TACTICS, AUDIT_EVENTS, AUDIT_SCOPES, CANARY_FLOWS, CHANNEL_KINDS, COMPARISONS,
                     DECLARED_DETECTION, DESTINATION_KINDS, DETECTION_FIELDS, DURATION, ENTITY_MAPPING, LOG_KINDS,
                     SELECTOR_TERM, WINDOW_KINDS)

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
    AttributeDef(658, 'ciamStartsFrom', 'dn', 'intent', True,
                 'The SAML integration (a service provider) a SAML sign-in check starts from: the identity provider '
                 'is asked to sign in to it'),
    # ------------------------------------------------------------------ bindings
    AttributeDef(321, 'ciamChannelKind', enum_type(CHANNEL_KINDS), 'binding', True,
                 'What delivers alerts in an environment: a topic, an action group, a paging service, ...'),
    AttributeDef(322, 'ciamDestinationKind', enum_type(DESTINATION_KINDS), 'binding', True,
                 'What keeps logs in an environment: a log group, a workspace, a SIEM index, a bucket'),
    AttributeDef(710, 'ciamTotalRetentionDays', 'int', 'binding', True,
                 "How many days a log destination keeps logs in all, searchable and archived (a SIEM's archive, a "
                 "Log Analytics table's long-term retention); its ciamRetentionDays are the days they stay "
                 "searchable. Not recorded: nothing is kept beyond those"),
    AttributeDef(843, 'ciamArchiveRef', 'string', 'binding', True,
                 "Where a log destination keeps its archive, the copies it holds past its searchable days that must "
                 "be restored to be searched, as its SIEM names the place (an Elasticsearch snapshot repository)"),
    # ------------------------------------------------------------------ what a cloud runs
    AttributeDef(323, 'ciamRealizes', 'string', 'binding', True,
                 'The alert rule or canary (its name) an alarm or synthetic check a cloud runs realizes'),
    AttributeDef(324, 'ciamNotifies', 'string', 'binding', False,
                 'What an alarm a cloud runs notifies (the provider refs of its channels: topics, action groups)'),
    AttributeDef(325, 'ciamMetric', 'string', 'binding', True,
                 'The metric or query an alarm a cloud runs evaluates, as the provider names it (AWS/EC2 '
                 'CPUUtilization)'),
    # MITRE ATT&CK and what a detection's results name (milestone 109, decision 3299): vendor-neutral, every SIEM
    # adapter renders them its own way
    AttributeDef(958, 'ciamAttackTactic', 'enum:' + '|'.join(ATTACK_TACTICS), 'intent', False,
                 "A MITRE ATT&CK (Enterprise) tactic an alert rule detects, by ATT&CK's short name "
                 "(credential-access), as the current ATT&CK (v20) names it; a short name it retired "
                 "(defense-evasion) is still accepted, and the planner asks for its successor"),
    AttributeDef(959, 'ciamAttackTechnique', 'string', 'intent', False,
                 'A MITRE ATT&CK technique or sub-technique an alert rule detects, by ID (T1110, T1078.004)',
                 (("X-PATTERN", r"^T[0-9]{4}(\.[0-9]{3})?$"),)),
    AttributeDef(960, 'ciamDetectionMode', 'enum:count|rows', 'binding', True,
                 "How a SIEM detection's search (ciamMetric) is used: count (the default: its matching events counted "
                 "per window against the alert rule's threshold) or rows (the search itself returns one row per "
                 "finding, its own threshold included, so each row can name what it is about)"),
    AttributeDef(961, 'ciamEntityMapping', 'string', 'binding', False,
                 "What a rows detection's results are about: '<entity> <identifier>=<result column>', entity account, "
                 "ip, host, url or application; identifier name, upn-suffix, nt-domain, sid, object-id (account), "
                 "address (ip), hostname, dns-domain (host), url (url), app-id, name (application)",
                 (("X-PATTERN", ENTITY_MAPPING),)),
    # an alert rule adopting a detection a product adapter declares (core.contract.ProductDetection; milestone 109,
    # task 594): what it counts, per what, over which window, and the declaration it came from
    AttributeDef(968, 'ciamDetectionSelector', 'string', 'intent', False,
                 "The events an alert rule counts, on the canonical fields every product's log is mapped to: "
                 "'<field>=<value>[|<value>...]' (outcome=failure, action=login|admin-login), every value of the "
                 "attribute holding. Each SIEM adapter renders it in the product's own field names and values, from "
                 "the declaration the rule adopts (ciamDeclaredDetection)",
                 (("X-PATTERN", SELECTOR_TERM),)),
    AttributeDef(969, 'ciamGroupBy', enum_type(DETECTION_FIELDS), 'intent', False,
                 "The canonical fields an alert rule counts per (subject, source-ip, realm, ...): a finding is about "
                 "one value of each"),
    AttributeDef(970, 'ciamDistinctField', enum_type(DETECTION_FIELDS), 'intent', True,
                 "A canonical field whose distinct values an alert rule counts instead of its events (the subjects one "
                 "source address tried: a password spray)"),
    AttributeDef(971, 'ciamWindowKind', enum_type(WINDOW_KINDS), 'intent', True,
                 "How an alert rule's window (its ciamEvaluationPeriod) is counted over: sliding (any span of that "
                 "length) or fixed (clock-aligned buckets, which can miss what straddles two). A SIEM that can't "
                 "count it so refuses the rule rather than render another"),
    AttributeDef(972, 'ciamDeclaredDetection', 'string', 'intent', True,
                 "The product detection an alert rule adopted, as '<adapter>:<id>' (an adapter's brute-force): its "
                 "product field names and values per version come from that declaration",
                 (("X-PATTERN", DECLARED_DETECTION),)),
    AttributeDef(973, 'ciamDeclarationDigest', 'string', 'meta', True,
                 "A digest of what an alert rule took from the declaration it adopted, when it last did: the planner "
                 "offers the declaration's changes once it changes, and leaves the values a person tuned since",
                 (("X-PATTERN", "^[0-9a-f]{16}$"),)),
    # forwarding a cloud log service's logs on to a SIEM (milestone 109, decision 3301)
    AttributeDef(962, 'ciamForwardsToRole', 'string', 'binding', True,
                 "The binding role of the SIEM index (a log destination of kind siem-index) a cloud log destination's "
                 "logs are forwarded on to (a CloudWatch log group through a delivery stream, a Log Analytics "
                 "workspace through an event stream)"),
    AttributeDef(963, 'ciamIntakeUrl', 'string', 'binding', True,
                 "Where a SIEM index takes logs pushed to it (a Splunk HTTP Event Collector, an Elastic intake "
                 "endpoint): https URL; its credential is the secret reference its ciamCredentialRole names"),
    AttributeDef(842, 'ciamSearchLanguage', 'vocab', 'binding', True,
                 "The language a SIEM detection's search (its ciamMetric) is written in, from the vocabulary the SIEM "
                 "adapters declare (spl, kusto, esql, kuery, ...). Not recorded: the native language of the SIEM "
                 "keeping the index it searches"),
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
    AttributeDef(647, 'ciamAuditResourceRole', 'string', 'intent', False,
                 "The binding role of a data resource (an object store, a function, a table, a secret) whose data "
                 "access an audit trail records (ciamAuditEvents data-read / data-write); none named: the "
                 "environment's own data resources"),
    AttributeDef(648, 'ciamAuditStreamRole', 'string', 'intent', True,
                 "The binding role of a log destination an audit trail also streams its records to, beside the store "
                 "keeping them (CloudTrail to CloudWatch Logs)"),
)
CLASSES = (
    ClassDef(62, 'ciamAlertRule', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamSignal', 'ciamAlertRole'),
             ('ciamTargetRole', 'ciamComparison', 'ciamThreshold', 'ciamEvaluationPeriod', 'ciamSeverity',
              'ciamRunbookRef', 'ciamAttackTactic', 'ciamAttackTechnique', 'ciamDetectionSelector', 'ciamGroupBy',
              'ciamDistinctField', 'ciamWindowKind', 'ciamDeclaredDetection', 'ciamDeclarationDigest'),
             'What the platform is watched for: a signal on a server role, the condition that fires, how severe, '
             'who it goes to, what to do; one adopting a product\'s declared detection also says which events it '
             'counts, per what and over which window'),
    ClassDef(63, 'ciamLogRoute', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamLogKind', 'ciamLogDestinationRole'),
             ('ciamPublishedBy', 'ciamRetentionDays', 'ciamLegalHold'),
             "Where a server role's logs go and how long they must be kept (an obligation: audit logs survive a "
             "move and the source's decommissioning)"),
    ClassDef(64, 'ciamCanary', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamCheckedService', 'ciamCanaryFlow'),
             ('ciamInterval', 'ciamUsesRole', 'ciamFeedsAlert', 'ciamStartsFrom'),
             'A synthetic check that signs in as a user would: what it exercises, how often, the secret role of its '
             'test credentials, the alert it fires, the SAML integration a SAML sign-in starts from'),
    ClassDef(65, 'ciamAlertChannel', 'ciamBinding', 'STRUCTURAL', ('ciamChannelKind',), ('ciamProviderRef',),
             'What delivers alerts of a role in an environment (a topic, an action group, a paging service)'),
    ClassDef(66, 'ciamLogDestination', 'ciamBinding', 'STRUCTURAL', ('ciamDestinationKind',),
             ('ciamProviderRef', 'ciamRetentionDays', 'ciamTotalRetentionDays', 'ciamManagedBy', 'ciamArchiveRef',
              'ciamForwardsToRole', 'ciamIntakeUrl', 'ciamCredentialRole', 'ciamStreamRole', 'ciamStorageRef'),
             'What keeps logs of a role in an environment, and for how many days (0: kept indefinitely): searchable '
             '(ciamRetentionDays), and in all when it archives them (ciamTotalRetentionDays), the archive kept where '
             'ciamArchiveRef says; a cloud log destination may forward its logs on to a SIEM index '
             '(ciamForwardsToRole: through the event stream ciamStreamRole names, events it can\'t deliver kept '
             'where ciamStorageRef says), and a SIEM index takes pushed logs at ciamIntakeUrl with the credential '
             'ciamCredentialRole references'),
    ClassDef(67, 'ciamAlarmBinding', 'ciamBinding', 'STRUCTURAL', ('ciamProviderRef',),
             ('ciamRealizes', 'ciamNotifies', 'ciamMetric', 'ciamManagedBy', 'ciamLogDestinationRole',
              'ciamSearchLanguage', 'ciamDetectionMode', 'ciamEntityMapping'),
             'An alarm a cloud runs in an environment: the alert rule it realizes, what it evaluates, what it '
             'notifies; a SIEM detection names the log destination (a SIEM index) its search runs on '
             '(ciamLogDestinationRole) and holds the search in ciamMetric, written in ciamSearchLanguage'),
    ClassDef(68, 'ciamCanaryBinding', 'ciamBinding', 'STRUCTURAL', ('ciamProviderRef',),
             ('ciamRealizes', 'ciamInterval', 'ciamStorageRef', 'ciamSubnetRole', 'ciamManagedBy',
              'ciamContainerImage'),
             'A synthetic check a cloud runs in an environment: the canary it realizes, how often, where it keeps '
             'its results when the cloud asks for a place (ciamStorageRef: CloudWatch Synthetics\' S3 artifact '
             'location), and the subnets a check of an internal service name runs from (ciamSubnetRole; else those '
             'the firewall rules admit to the service); the image its job runs where the cloud runs one the '
             'organization builds (ciamContainerImage check=<registry>/<repository>@sha256:<digest>)'),
    ClassDef(111, 'ciamAuditTrail', 'ciamBinding', 'STRUCTURAL', ('ciamAuditScope',),
             ('ciamAuditEvents', 'ciamAllRegions', 'ciamIntegrityValidation', 'ciamLogDestinationRole',
              'ciamAuditResourceRole', 'ciamAuditStreamRole', 'ciamProviderRef', 'ciamManagedBy'),
             "An environment's control-plane audit trail (CloudTrail, the Activity Log's diagnostic setting, Cloud "
             "Audit Logs' sinks): what it records, where its records go (a log destination's or object store's "
             "role), and who keeps it when it isn't the platform team (an organization trail the landing zone keeps)"),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
