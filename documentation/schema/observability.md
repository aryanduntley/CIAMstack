# Observability

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 8 object classes · 40 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

Observability domain schema: what the platform is watched for, where its logs go and for how long, the synthetic checks that sign in as a user would, and the control-plane audit trail that records who did what to the cloud. Alert rules, log routes and canaries are intent, the same in every environment; what delivers an alert (a topic, an action group, a paging service), what keeps logs (a log group, a workspace, a SIEM index) and the audit trail (CloudTrail, the Activity Log's diagnostic setting, Cloud Audit Logs' sinks) are bindings each environment gives a role.

**Branches:** `ou=alert-rules,dc=ciam-ops`, `ou=canaries,dc=ciam-ops`, `ou=log-routes,dc=ciam-ops`

## Object classes

<a id="c-ciamalarmbinding"></a>
### ciamAlarmBinding

An alarm a cloud runs in an environment: the alert rule it realizes, what it evaluates, what it notifies; a SIEM detection names the log destination (a SIEM index) its search runs on (ciamLogDestinationRole) and holds the search in ciamMetric, written in ciamSearchLanguage

OID `1.3.6.1.4.1.32473.1.2.67` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) | yes | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamRealizes`](#a-ciamrealizes) |  | `string` | single | The alert rule or canary (its name) an alarm or synthetic check a cloud runs realizes |
| [`ciamNotifies`](#a-ciamnotifies) |  | `string` | multi | What an alarm a cloud runs notifies (the provider refs of its channels: topics, action groups) |
| [`ciamMetric`](#a-ciammetric) |  | `string` | single | The metric or query an alarm a cloud runs evaluates, as the provider names it (AWS/EC2 CPUUtilization) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |
| [`ciamLogDestinationRole`](#a-ciamlogdestinationrole) |  | `string` | single | The binding role of what keeps a route's logs in each environment (a log group, a workspace, a SIEM index) |
| [`ciamSearchLanguage`](#a-ciamsearchlanguage) |  | `vocab` | single | The language a SIEM detection's search (its ciamMetric) is written in, from the vocabulary the SIEM adapters declare (spl, kusto, esql, kuery, ...). Not recorded: the native language of the SIEM keeping the index it searches |
| [`ciamDetectionMode`](#a-ciamdetectionmode) |  | `enum` | single | How a SIEM detection's search (ciamMetric) is used: count (the default: its matching events counted per window against the alert rule's threshold) or rows (the search itself returns one row per finding, its own threshold included, so each row can name what it is about) |
| [`ciamEntityMapping`](#a-ciamentitymapping) |  | `string` | multi | What a rows detection's results are about: '<entity> <identifier>=<result column>', entity account, ip, host, url or application; identifier name, upn-suffix, nt-domain, sid, object-id (account), address (ip), hostname, dns-domain (host), url (url), app-id, name (application) |

<a id="c-ciamalertchannel"></a>
### ciamAlertChannel

What delivers alerts of a role in an environment (a topic, an action group, a paging service)

OID `1.3.6.1.4.1.32473.1.2.65` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamChannelKind`](#a-ciamchannelkind) | yes | `enum` | single | What delivers alerts in an environment: a topic, an action group, a paging service, ... |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |

<a id="c-ciamalertrule"></a>
### ciamAlertRule

What the platform is watched for: a signal on a server role, the condition that fires, how severe, who it goes to, what to do; one adopting a product's declared detection also says which events it counts, per what and over which window

OID `1.3.6.1.4.1.32473.1.2.62` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamSignal`](#a-ciamsignal) | yes | `string` | single | What an alert rule watches, named neutrally (replication-delay, ldaps-errors, login-failures, cert-expiry, disk-free, heap-used, ...): each provider renders its own metric or query |
| [`ciamAlertRole`](#a-ciamalertrole) | yes | `string` | single | The binding role of the channel that delivers an alert in each environment (a topic, an action group, a paging service) |
| [`ciamTargetRole`](infrastructure.md#a-ciamtargetrole) |  | `vocab` | single | Server role a service or rule targets |
| [`ciamComparison`](#a-ciamcomparison) |  | `enum` | single | How an alert rule's signal is compared with its threshold |
| [`ciamThreshold`](#a-ciamthreshold) |  | `string` | single | The value an alert rule compares its signal with, with its unit (5000 ms, 90 %, 10 /min) |
| [`ciamEvaluationPeriod`](#a-ciamevaluationperiod) |  | `string` | single | How long the condition must hold before an alert fires (5m) |
| [`ciamSeverity`](governance.md#a-ciamseverity) |  | `enum` | single | Incident severity |
| [`ciamRunbookRef`](custom.md#a-ciamrunbookref) |  | `dn` | multi | Runbooks about it |
| [`ciamAttackTactic`](#a-ciamattacktactic) |  | `enum` | multi | A MITRE ATT&CK (Enterprise) tactic an alert rule detects, by ATT&CK's short name (credential-access), as the current ATT&CK (v20) names it; a short name it retired (defense-evasion) is still accepted, and the planner asks for its successor |
| [`ciamAttackTechnique`](#a-ciamattacktechnique) |  | `string` | multi | A MITRE ATT&CK technique or sub-technique an alert rule detects, by ID (T1110, T1078.004) |
| [`ciamDetectionSelector`](#a-ciamdetectionselector) |  | `string` | multi | The events an alert rule counts, on the canonical fields every product's log is mapped to: '<field>=<value>[\|<value>...]' (outcome=failure, action=login\|admin-login), every value of the attribute holding. Each SIEM adapter renders it in the product's own field names and values, from the declaration the rule adopts (ciamDeclaredDetection) |
| [`ciamGroupBy`](#a-ciamgroupby) |  | `enum` | multi | The canonical fields an alert rule counts per (subject, source-ip, realm, ...): a finding is about one value of each |
| [`ciamDistinctField`](#a-ciamdistinctfield) |  | `enum` | single | A canonical field whose distinct values an alert rule counts instead of its events (the subjects one source address tried: a password spray) |
| [`ciamWindowKind`](#a-ciamwindowkind) |  | `enum` | single | How an alert rule's window (its ciamEvaluationPeriod) is counted over: sliding (any span of that length) or fixed (clock-aligned buckets, which can miss what straddles two). A SIEM that can't count it so refuses the rule rather than render another |
| [`ciamDeclaredDetection`](#a-ciamdeclareddetection) |  | `string` | single | The product detection an alert rule adopted, as '<adapter>:<id>' (an adapter's brute-force): its product field names and values per version come from that declaration |
| [`ciamDeclarationDigest`](#a-ciamdeclarationdigest) |  | `string` | single | A digest of what an alert rule took from the declaration it adopted, when it last did: the planner offers the declaration's changes once it changes, and leaves the values a person tuned since |

<a id="c-ciamaudittrail"></a>
### ciamAuditTrail

An environment's control-plane audit trail (CloudTrail, the Activity Log's diagnostic setting, Cloud Audit Logs' sinks): what it records, where its records go (a log destination's or object store's role), and who keeps it when it isn't the platform team (an organization trail the landing zone keeps)

OID `1.3.6.1.4.1.32473.1.2.111` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamAuditScope`](#a-ciamauditscope) | yes | `enum` | single | What an audit trail records: one account (an AWS account, an Azure subscription, a Google Cloud project) or every account of the organization |
| [`ciamAuditEvents`](#a-ciamauditevents) |  | `enum` | multi | Which activity an audit trail records: control-plane (management API calls), data-read, data-write |
| [`ciamAllRegions`](#a-ciamallregions) |  | `bool` | single | Whether an audit trail records activity in every region (and global services), not one region |
| [`ciamIntegrityValidation`](#a-ciamintegrityvalidation) |  | `bool` | single | Whether the cloud cryptographically validates an audit trail's records (CloudTrail's signed digest files); a locked immutable store keeping them is graded through its ciamStorageImmutability |
| [`ciamLogDestinationRole`](#a-ciamlogdestinationrole) |  | `string` | single | The binding role of what keeps a route's logs in each environment (a log group, a workspace, a SIEM index) |
| [`ciamAuditResourceRole`](#a-ciamauditresourcerole) |  | `string` | multi | The binding role of a data resource (an object store, a function, a table, a secret) whose data access an audit trail records (ciamAuditEvents data-read / data-write); none named: the environment's own data resources |
| [`ciamAuditStreamRole`](#a-ciamauditstreamrole) |  | `string` | single | The binding role of a log destination an audit trail also streams its records to, beside the store keeping them (CloudTrail to CloudWatch Logs) |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamcanary"></a>
### ciamCanary

A synthetic check that signs in as a user would: what it exercises, how often, the secret role of its test credentials, the alert it fires, the SAML integration a SAML sign-in starts from

OID `1.3.6.1.4.1.32473.1.2.64` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamCheckedService`](#a-ciamcheckedservice) | yes | `string` | single | The binding role of the service name a synthetic check exercises (each environment its own name) |
| [`ciamCanaryFlow`](#a-ciamcanaryflow) | yes | `enum` | single | What a synthetic check does: load the login page, get a token, a SAML sign-in, an LDAP bind, a health probe |
| [`ciamInterval`](#a-ciaminterval) |  | `string` | single | How often a synthetic check runs (5m) |
| [`ciamUsesRole`](automation.md#a-ciamusesrole) |  | `string` | multi | A binding role the job uses (a secret, a service name, a storage location): each environment binds it |
| [`ciamFeedsAlert`](#a-ciamfeedsalert) |  | `dn` | single | The alert rule a failing synthetic check fires |
| [`ciamStartsFrom`](#a-ciamstartsfrom) |  | `dn` | single | The SAML integration (a service provider) a SAML sign-in check starts from: the identity provider is asked to sign in to it |

<a id="c-ciamcanarybinding"></a>
### ciamCanaryBinding

A synthetic check a cloud runs in an environment: the canary it realizes, how often, where it keeps its results when the cloud asks for a place (ciamStorageRef: CloudWatch Synthetics' S3 artifact location), and the subnets a check of an internal service name runs from (ciamSubnetRole; else those the firewall rules admit to the service); the image its job runs where the cloud runs one the organization builds (ciamContainerImage check=<registry>/<repository>@sha256:<digest>)

OID `1.3.6.1.4.1.32473.1.2.68` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) | yes | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamRealizes`](#a-ciamrealizes) |  | `string` | single | The alert rule or canary (its name) an alarm or synthetic check a cloud runs realizes |
| [`ciamInterval`](#a-ciaminterval) |  | `string` | single | How often a synthetic check runs (5m) |
| [`ciamStorageRef`](infrastructure.md#a-ciamstorageref) |  | `string` | single | Object storage location (bucket or container URI, e.g. s3://bucket, azblob://account/container, gs://bucket) |
| [`ciamSubnetRole`](network.md#a-ciamsubnetrole) |  | `string` | multi | Binding role of a subnet this applies to |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |
| [`ciamContainerImage`](compute.md#a-ciamcontainerimage) |  | `string` | multi | A container image an environment runs for a workload: container=repository:tag or container=repository@sha256:digest (sidecars included) |

<a id="c-ciamlogdestination"></a>
### ciamLogDestination

What keeps logs of a role in an environment, and for how many days (0: kept indefinitely): searchable (ciamRetentionDays), and in all when it archives them (ciamTotalRetentionDays), the archive kept where ciamArchiveRef says; a cloud log destination may forward its logs on to a SIEM index (ciamForwardsToRole: through the event stream ciamStreamRole names, events it can't deliver kept where ciamStorageRef says), and a SIEM index takes pushed logs at ciamIntakeUrl with the credential ciamCredentialRole references (a cloud delivery stream's at ciamStreamIntakeUrl, when it differs)

OID `1.3.6.1.4.1.32473.1.2.66` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamDestinationKind`](#a-ciamdestinationkind) | yes | `enum` | single | What keeps logs in an environment: a log group, a workspace, a SIEM index, a bucket |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamRetentionDays`](infrastructure.md#a-ciamretentiondays) |  | `int` | single | Retention period in days |
| [`ciamTotalRetentionDays`](#a-ciamtotalretentiondays) |  | `int` | single | How many days a log destination keeps logs in all, searchable and archived (a SIEM's archive, a Log Analytics table's long-term retention); its ciamRetentionDays are the days they stay searchable. Not recorded: nothing is kept beyond those |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |
| [`ciamArchiveRef`](#a-ciamarchiveref) |  | `string` | single | Where a log destination keeps its archive, the copies it holds past its searchable days that must be restored to be searched, as its SIEM names the place (an Elasticsearch snapshot repository) |
| [`ciamForwardsToRole`](#a-ciamforwardstorole) |  | `string` | single | The binding role of the SIEM index (a log destination of kind siem-index) a cloud log destination's logs are forwarded on to (a CloudWatch log group through a delivery stream, a Log Analytics workspace through an event stream) |
| [`ciamIntakeUrl`](#a-ciamintakeurl) |  | `string` | single | Where a SIEM index takes logs pushed to it (a Splunk HTTP Event Collector, an Elastic intake endpoint): https URL; its credential is the secret reference its ciamCredentialRole names |
| [`ciamCredentialRole`](governance.md#a-ciamcredentialrole) |  | `string` | single | The role of the binding holding the reference to the credential a collection source is read with (resolved when collecting, held in memory for the call, never stored) |
| [`ciamStreamRole`](messaging.md#a-ciamstreamrole) |  | `string` | single | The binding role of the queue, topic or bus that carries a stream in each environment |
| [`ciamStorageRef`](infrastructure.md#a-ciamstorageref) |  | `string` | single | Object storage location (bucket or container URI, e.g. s3://bucket, azblob://account/container, gs://bucket) |
| [`ciamStreamIntakeUrl`](#a-ciamstreamintakeurl) |  | `string` | single | Where a SIEM index takes the logs a cloud's delivery stream pushes to it, when that differs from its ciamIntakeUrl (a host of its own for the stream): https URL, used as recorded; the credential is the same |

<a id="c-ciamlogroute"></a>
### ciamLogRoute

Where a server role's logs go and how long they must be kept (an obligation: audit logs survive a move and the source's decommissioning)

OID `1.3.6.1.4.1.32473.1.2.63` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamLogKind`](#a-ciamlogkind) | yes | `enum` | multi | Which logs a route carries: access, audit, error, admin, ... |
| [`ciamLogDestinationRole`](#a-ciamlogdestinationrole) | yes | `string` | single | The binding role of what keeps a route's logs in each environment (a log group, a workspace, a SIEM index) |
| [`ciamPublishedBy`](messaging.md#a-ciampublishedby) |  | `string` | multi | A server role that publishes to a stream |
| [`ciamRetentionDays`](infrastructure.md#a-ciamretentiondays) |  | `int` | single | Retention period in days |
| [`ciamLegalHold`](#a-ciamlegalhold) |  | `bool` | single | Whether logs are under legal hold: the source keeps them after a move, whatever their retention |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamalertrole"></a>`ciamAlertRole` | `1.3.6.1.4.1.32473.1.1.313` | `string` | intent | single |  | The binding role of the channel that delivers an alert in each environment (a topic, an action group, a paging service) |
| <a id="a-ciamallregions"></a>`ciamAllRegions` | `1.3.6.1.4.1.32473.1.1.497` | `bool` | binding | single |  | Whether an audit trail records activity in every region (and global services), not one region |
| <a id="a-ciamarchiveref"></a>`ciamArchiveRef` | `1.3.6.1.4.1.32473.1.1.843` | `string` | binding | single |  | Where a log destination keeps its archive, the copies it holds past its searchable days that must be restored to be searched, as its SIEM names the place (an Elasticsearch snapshot repository) |
| <a id="a-ciamattacktactic"></a>`ciamAttackTactic` | `1.3.6.1.4.1.32473.1.1.958` | enum: `reconnaissance`, `resource-development`, `initial-access`, `execution`, `persistence`, `privilege-escalation`, `stealth`, `defense-impairment`, `credential-access`, `discovery`, `lateral-movement`, `collection`, `command-and-control`, `exfiltration`, `impact`, `defense-evasion` | intent | multi |  | A MITRE ATT&CK (Enterprise) tactic an alert rule detects, by ATT&CK's short name (credential-access), as the current ATT&CK (v20) names it; a short name it retired (defense-evasion) is still accepted, and the planner asks for its successor |
| <a id="a-ciamattacktechnique"></a>`ciamAttackTechnique` | `1.3.6.1.4.1.32473.1.1.959` | `string` | intent | multi | X-PATTERN `^T[0-9]{4}(\.[0-9]{3})?$` | A MITRE ATT&CK technique or sub-technique an alert rule detects, by ID (T1110, T1078.004) |
| <a id="a-ciamauditevents"></a>`ciamAuditEvents` | `1.3.6.1.4.1.32473.1.1.496` | enum: `control-plane`, `data-read`, `data-write` | binding | multi |  | Which activity an audit trail records: control-plane (management API calls), data-read, data-write |
| <a id="a-ciamauditresourcerole"></a>`ciamAuditResourceRole` | `1.3.6.1.4.1.32473.1.1.647` | `string` | intent | multi |  | The binding role of a data resource (an object store, a function, a table, a secret) whose data access an audit trail records (ciamAuditEvents data-read / data-write); none named: the environment's own data resources |
| <a id="a-ciamauditscope"></a>`ciamAuditScope` | `1.3.6.1.4.1.32473.1.1.495` | enum: `account`, `organization` | binding | single |  | What an audit trail records: one account (an AWS account, an Azure subscription, a Google Cloud project) or every account of the organization |
| <a id="a-ciamauditstreamrole"></a>`ciamAuditStreamRole` | `1.3.6.1.4.1.32473.1.1.648` | `string` | intent | single |  | The binding role of a log destination an audit trail also streams its records to, beside the store keeping them (CloudTrail to CloudWatch Logs) |
| <a id="a-ciamcanaryflow"></a>`ciamCanaryFlow` | `1.3.6.1.4.1.32473.1.1.318` | enum: `login-page`, `oidc-token`, `saml-sso`, `ldap-bind`, `health`, `other` | intent | single |  | What a synthetic check does: load the login page, get a token, a SAML sign-in, an LDAP bind, a health probe |
| <a id="a-ciamchannelkind"></a>`ciamChannelKind` | `1.3.6.1.4.1.32473.1.1.321` | enum: `topic`, `action-group`, `paging-service`, `email`, `webhook`, `ticket`, `other` | binding | single |  | What delivers alerts in an environment: a topic, an action group, a paging service, ... |
| <a id="a-ciamcheckedservice"></a>`ciamCheckedService` | `1.3.6.1.4.1.32473.1.1.317` | `string` | intent | single |  | The binding role of the service name a synthetic check exercises (each environment its own name) |
| <a id="a-ciamcomparison"></a>`ciamComparison` | `1.3.6.1.4.1.32473.1.1.310` | enum: `gt`, `ge`, `lt`, `le`, `eq`, `ne` | intent | single |  | How an alert rule's signal is compared with its threshold |
| <a id="a-ciamdeclarationdigest"></a>`ciamDeclarationDigest` | `1.3.6.1.4.1.32473.1.1.973` | `string` | meta | single | X-PATTERN `^[0-9a-f]{16}$` | A digest of what an alert rule took from the declaration it adopted, when it last did: the planner offers the declaration's changes once it changes, and leaves the values a person tuned since |
| <a id="a-ciamdeclareddetection"></a>`ciamDeclaredDetection` | `1.3.6.1.4.1.32473.1.1.972` | `string` | intent | single | X-PATTERN `^[a-z0-9][a-z0-9-]*:[a-z0-9][a-z0-9.-]*$` | The product detection an alert rule adopted, as '<adapter>:<id>' (an adapter's brute-force): its product field names and values per version come from that declaration |
| <a id="a-ciamdestinationkind"></a>`ciamDestinationKind` | `1.3.6.1.4.1.32473.1.1.322` | enum: `log-group`, `workspace`, `siem-index`, `bucket`, `other` | binding | single |  | What keeps logs in an environment: a log group, a workspace, a SIEM index, a bucket |
| <a id="a-ciamdetectionmode"></a>`ciamDetectionMode` | `1.3.6.1.4.1.32473.1.1.960` | enum: `count`, `rows` | binding | single |  | How a SIEM detection's search (ciamMetric) is used: count (the default: its matching events counted per window against the alert rule's threshold) or rows (the search itself returns one row per finding, its own threshold included, so each row can name what it is about) |
| <a id="a-ciamdetectionselector"></a>`ciamDetectionSelector` | `1.3.6.1.4.1.32473.1.1.968` | `string` | intent | multi | X-PATTERN `^(subject\|source-ip\|realm\|outcome\|action\|actor\|object\|step\|step-outcome)=[A-Za-z0-9_.:@/-]+(\\|[A-Za-z0-9_.:@/-]+)*$` | The events an alert rule counts, on the canonical fields every product's log is mapped to: '<field>=<value>[\|<value>...]' (outcome=failure, action=login\|admin-login), every value of the attribute holding. Each SIEM adapter renders it in the product's own field names and values, from the declaration the rule adopts (ciamDeclaredDetection) |
| <a id="a-ciamdistinctfield"></a>`ciamDistinctField` | `1.3.6.1.4.1.32473.1.1.970` | enum: `subject`, `source-ip`, `realm`, `outcome`, `action`, `actor`, `object`, `step`, `step-outcome` | intent | single |  | A canonical field whose distinct values an alert rule counts instead of its events (the subjects one source address tried: a password spray) |
| <a id="a-ciamentitymapping"></a>`ciamEntityMapping` | `1.3.6.1.4.1.32473.1.1.961` | `string` | binding | multi | X-PATTERN `^(account\|ip\|host\|url\|application) [a-z-]+=[A-Za-z_][A-Za-z0-9_]*$` | What a rows detection's results are about: '<entity> <identifier>=<result column>', entity account, ip, host, url or application; identifier name, upn-suffix, nt-domain, sid, object-id (account), address (ip), hostname, dns-domain (host), url (url), app-id, name (application) |
| <a id="a-ciamevaluationperiod"></a>`ciamEvaluationPeriod` | `1.3.6.1.4.1.32473.1.1.312` | `string` | intent | single | X-PATTERN `^[0-9]+(s\|m\|h\|d)$` | How long the condition must hold before an alert fires (5m) |
| <a id="a-ciamfeedsalert"></a>`ciamFeedsAlert` | `1.3.6.1.4.1.32473.1.1.320` | `dn` | intent | single |  | The alert rule a failing synthetic check fires |
| <a id="a-ciamforwardstorole"></a>`ciamForwardsToRole` | `1.3.6.1.4.1.32473.1.1.962` | `string` | binding | single |  | The binding role of the SIEM index (a log destination of kind siem-index) a cloud log destination's logs are forwarded on to (a CloudWatch log group through a delivery stream, a Log Analytics workspace through an event stream) |
| <a id="a-ciamgroupby"></a>`ciamGroupBy` | `1.3.6.1.4.1.32473.1.1.969` | enum: `subject`, `source-ip`, `realm`, `outcome`, `action`, `actor`, `object`, `step`, `step-outcome` | intent | multi |  | The canonical fields an alert rule counts per (subject, source-ip, realm, ...): a finding is about one value of each |
| <a id="a-ciamintakeurl"></a>`ciamIntakeUrl` | `1.3.6.1.4.1.32473.1.1.963` | `string` | binding | single |  | Where a SIEM index takes logs pushed to it (a Splunk HTTP Event Collector, an Elastic intake endpoint): https URL; its credential is the secret reference its ciamCredentialRole names |
| <a id="a-ciamintegrityvalidation"></a>`ciamIntegrityValidation` | `1.3.6.1.4.1.32473.1.1.498` | `bool` | binding | single |  | Whether the cloud cryptographically validates an audit trail's records (CloudTrail's signed digest files); a locked immutable store keeping them is graded through its ciamStorageImmutability |
| <a id="a-ciaminterval"></a>`ciamInterval` | `1.3.6.1.4.1.32473.1.1.319` | `string` | intent | single | X-PATTERN `^[0-9]+(s\|m\|h\|d)$` | How often a synthetic check runs (5m) |
| <a id="a-ciamlegalhold"></a>`ciamLegalHold` | `1.3.6.1.4.1.32473.1.1.316` | `bool` | meta | single |  | Whether logs are under legal hold: the source keeps them after a move, whatever their retention |
| <a id="a-ciamlogdestinationrole"></a>`ciamLogDestinationRole` | `1.3.6.1.4.1.32473.1.1.315` | `string` | intent | single |  | The binding role of what keeps a route's logs in each environment (a log group, a workspace, a SIEM index) |
| <a id="a-ciamlogkind"></a>`ciamLogKind` | `1.3.6.1.4.1.32473.1.1.314` | enum: `access`, `audit`, `error`, `admin`, `debug`, `replication`, `transaction`, `other` | intent | multi |  | Which logs a route carries: access, audit, error, admin, ... |
| <a id="a-ciammetric"></a>`ciamMetric` | `1.3.6.1.4.1.32473.1.1.325` | `string` | binding | single |  | The metric or query an alarm a cloud runs evaluates, as the provider names it (AWS/EC2 CPUUtilization) |
| <a id="a-ciamnotifies"></a>`ciamNotifies` | `1.3.6.1.4.1.32473.1.1.324` | `string` | binding | multi |  | What an alarm a cloud runs notifies (the provider refs of its channels: topics, action groups) |
| <a id="a-ciamrealizes"></a>`ciamRealizes` | `1.3.6.1.4.1.32473.1.1.323` | `string` | binding | single |  | The alert rule or canary (its name) an alarm or synthetic check a cloud runs realizes |
| <a id="a-ciamsearchlanguage"></a>`ciamSearchLanguage` | `1.3.6.1.4.1.32473.1.1.842` | vocab: `kusto` (azure), `esql` (elastic), `kuery` (elastic), `lucene` (elastic), `eql` (elastic), `spl` (splunk) | binding | single |  | The language a SIEM detection's search (its ciamMetric) is written in, from the vocabulary the SIEM adapters declare (spl, kusto, esql, kuery, ...). Not recorded: the native language of the SIEM keeping the index it searches |
| <a id="a-ciamsignal"></a>`ciamSignal` | `1.3.6.1.4.1.32473.1.1.309` | `string` | intent | single |  | What an alert rule watches, named neutrally (replication-delay, ldaps-errors, login-failures, cert-expiry, disk-free, heap-used, ...): each provider renders its own metric or query |
| <a id="a-ciamstartsfrom"></a>`ciamStartsFrom` | `1.3.6.1.4.1.32473.1.1.658` | `dn` | intent | single |  | The SAML integration (a service provider) a SAML sign-in check starts from: the identity provider is asked to sign in to it |
| <a id="a-ciamstreamintakeurl"></a>`ciamStreamIntakeUrl` | `1.3.6.1.4.1.32473.1.1.974` | `string` | binding | single | X-PATTERN `^https://[^\s/?#]+(/[^\s]*)?$` | Where a SIEM index takes the logs a cloud's delivery stream pushes to it, when that differs from its ciamIntakeUrl (a host of its own for the stream): https URL, used as recorded; the credential is the same |
| <a id="a-ciamthreshold"></a>`ciamThreshold` | `1.3.6.1.4.1.32473.1.1.311` | `string` | intent | single | X-PATTERN `^-?[0-9]+(\.[0-9]+)?( ?[A-Za-z%/]+)?$` | The value an alert rule compares its signal with, with its unit (5000 ms, 90 %, 10 /min) |
| <a id="a-ciamtotalretentiondays"></a>`ciamTotalRetentionDays` | `1.3.6.1.4.1.32473.1.1.710` | `int` | binding | single |  | How many days a log destination keeps logs in all, searchable and archived (a SIEM's archive, a Log Analytics table's long-term retention); its ciamRetentionDays are the days they stay searchable. Not recorded: nothing is kept beyond those |
| <a id="a-ciamwindowkind"></a>`ciamWindowKind` | `1.3.6.1.4.1.32473.1.1.971` | enum: `sliding`, `fixed` | intent | single |  | How an alert rule's window (its ciamEvaluationPeriod) is counted over: sliding (any span of that length) or fixed (clock-aligned buckets, which can miss what straddles two). A SIEM that can't count it so refuses the rule rather than render another |
