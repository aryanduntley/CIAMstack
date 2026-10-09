"""Estate domain schema: the cloud accounts the environments run in and how the estate's resources are marked. A cloud
(infrastructure's ciamCloud) may name its account (an AWS account, an Azure subscription, a Google Cloud project) and
the organization above it (the auxiliary class ciamCloudAccount); an environment its resource group and how sensitive
its data is and the residency it is held to (ciamEnvironmentPlacement); a party the cost center its spending is charged
to (ciamChargedParty). The tag policy (under ou=tag-policy) says which tags every resource rendered for an environment
carries and where each value comes from, so the renderers tag and the importers can say what the cloud has untagged.
The region catalog (under ou=regions) holds each provider's regions as the provider lists them, fetched with the
provider's own command (an adapter's prerequisite) and managed from then on like any other record; a residency (under
ou=residencies) is the estate's own classification of where data may be held, listing the catalog regions it allows,
so residency values are the estate's to define yet every environment names one that exists. A cloud may say its
clients use FIPS 140 validated endpoints (ciamCloudEndpoints). The cloud security services an environment runs
(ciamSecurityService: threat detection, vulnerability scanning, configuration recording, posture assessment) are
bindings: what each watches or assesses, where its findings go and how long it keeps its records; so are the data
discovery services (ciamDataDiscovery: the stores each examines for sensitive data, the organization's own data types it
looks for, how often, where its findings go and where it keeps its results). What an environment
needs of a provider limit (ciamQuotaNeed: virtual CPUs, public addresses, networks, ...) is a binding too, with the
operator's decision when the provider grants less; the limits themselves are fetched from the provider into the quota
catalog (under ou=quotas, one ciamQuotaCatalog per account and region, a ciamQuotaLimit per quota). A budget
(ciamBudget) caps an environment's spending per period and says at which shares of it, spent or forecast, whom to
alert; the account billing is managed from is the cloud's ciamBillingAccountRef. The reporting obligations (under
ou=reporting-obligations: a regime's clock from discovery to report, the authority reports go to, who files them, the
certificate they are filed with, how long evidence is preserved, the contracts that impose it) are the estate's to
define, and an environment names the ones it is held to; a security service says which of its findings (at or above a
severity) also go to the incident process; an incident (governance) may carry what its reporting needs (ciamReportable
Incident: when it was discovered and reported, the authority's report number, malware submitted, media preserved). The
plan of action and milestones (under ou=poam: each known weakness, the controls it concerns, how and when it
is fixed), the approved deviations (under ou=exceptions: accepted risks, false positives, operational requirements, each
approved by a risk authority until a date, for named environments) and the compliance assessments (under
ou=assessments: score, status) are the estate's record of its compliance; a cloud's suppression of findings
(ciamSuppression) is a binding of the environment it runs in, named after the exception it carries out."""
from ...core.standard import AttributeDef, ClassDef, enum_type, fragment
from .naming import (AMOUNT, ASSESSMENT_KINDS, AUTHORIZATION_STATUSES, CONFIGURATIONS, LEVELS, RESPONSIBILITY,
                     ASSESSMENT_STATUSES, BUDGET_PERIODS, CAGE_CODE, CLASSIFICATIONS,
                     CONTROL_REF, CURRENCY, DISCOVERY_SOURCES, EXCEPTION_KINDS, EXCEPTION_STATUSES, FINDING_REF,
                     MEDIA_REQUESTS, POAM_STATUSES, QUOTA_DECISIONS, QUOTA_KINDS, REGION_STATUSES, RISK_RATINGS,
                     SECURITY_AREAS, SECURITY_KINDS, SEVERITIES, STANDARD_ID, TAG_SOURCES, UEI, CUSTOM_IDENTIFIER)

ATTRIBUTES = (
    AttributeDef(482, 'ciamAccountRef', 'string', 'binding', True,
                 "The cloud account a cloud's environments run in: an AWS account ID, an Azure subscription ID, a "
                 "Google Cloud project ID"),
    AttributeDef(483, 'ciamOrganizationRef', 'string', 'binding', True,
                 'The organization the account belongs to: an AWS organization, an Azure tenant, a Google Cloud '
                 'organization or folder'),
    AttributeDef(484, 'ciamCostCenter', 'string', 'meta', True,
                 "The cost center a party's spending is charged to (resources of environments it owns are tagged "
                 "with it where the tag policy says so)"),
    AttributeDef(485, 'ciamDataClassification', enum_type(CLASSIFICATIONS), 'meta', True,
                 "How sensitive an environment's data is: public, internal, confidential, restricted"),
    AttributeDef(486, 'ciamTagKey', 'string', 'meta', True,
                 'The key of a tag (a label on Google Cloud) every resource rendered for an environment carries',
                 (("X-PATTERN", r"[A-Za-z][A-Za-z0-9_.:/=+@-]{0,62}"),)),
    AttributeDef(487, 'ciamTagSource', enum_type(TAG_SOURCES), 'meta', True,
                 "Where a tag rule takes its value in each environment: the environment's owner, that owner's cost "
                 "center, the environment's data classification, the environment (cloud/env), its cloud, or the "
                 "rule's own value (literal: ciamTagValue)"),
    AttributeDef(488, 'ciamTagValue', 'string', 'meta', True,
                 "A literal tag rule's value"),
    AttributeDef(489, 'ciamRegionName', 'string', 'meta', True,
                 "A cloud region's name as its provider shows it (Europe (Ireland), West Europe, Belgium)"),
    AttributeDef(490, 'ciamGeography', 'string', 'meta', True,
                 "Where a cloud region is, as its provider places it (a geography, country or continent), when the "
                 "provider says"),
    AttributeDef(491, 'ciamRegionStatus', enum_type(REGION_STATUSES), 'observed', True,
                 "A cloud region as its provider lists it: available, opt-in (open only to accounts that opt in) or "
                 "not-listed (no longer listed; kept so what names it keeps its link)"),
    AttributeDef(492, 'ciamResidencyRef', 'dn', 'intent', True,
                 "The residency an environment's data is held to (a ciamResidency under ou=residencies)"),
    AttributeDef(493, 'ciamAllowedRegion', 'dn', 'intent', False,
                 "A cloud region a residency allows data to be held in (a ciamCloudRegion of the region catalog)"),
    AttributeDef(494, 'ciamFipsEndpoints', 'bool', 'binding', True,
                 "Whether a cloud's clients (renderers' providers, the products' SDKs) use the provider's FIPS 140 "
                 "validated endpoints"),
    AttributeDef(499, 'ciamSecurityKind', enum_type(SECURITY_KINDS), 'binding', True,
                 "What a cloud security service does: threat-detection, vulnerability-scanning, config-recording "
                 "(resources' configuration and its changes) or posture (assessment against compliance frameworks and "
                 "the cloud's own baseline)"),
    AttributeDef(500, 'ciamSecurityCoverage', enum_type(SECURITY_AREAS), 'binding', False,
                 "What a threat-detection or vulnerability-scanning service watches: control-plane, identity, network, "
                 "compute, containers, storage, databases, key-vaults, applications"),
    AttributeDef(501, 'ciamComplianceStandard', 'string', 'binding', False,
                 "A compliance framework a posture service assesses the estate against, by a neutral id the clouds "
                 "share (nist-800-53-r5, nist-800-171-r2, fedramp-high, cmmc-l2, cis: its cloud's CIS benchmark)",
                 (("X-PATTERN", STANDARD_ID),)),
    AttributeDef(502, 'ciamSecurityBaseline', 'string', 'binding', False,
                 "A cloud's own security baseline a posture service assesses, by the name its adapter gives it: "
                 "one cloud's baseline never stands in for another's",
                 (("X-PATTERN", STANDARD_ID),)),
    AttributeDef(503, 'ciamFindingsRole', 'string', 'intent', True,
                 "The role of the binding a security or data discovery service's findings (or recorded "
                 "configuration) go to: an alert "
                 "channel, a log destination, an object store, a stream (a topic); none: they stay in the service"),
    AttributeDef(504, 'ciamQuotaKind', enum_type(QUOTA_KINDS), 'binding', True,
                 "What a quota counts, by a kind every cloud limits: vcpus (the region's standard machines), "
                 "public-ips, networks, load-balancers, database-instances, kubernetes-clusters "
                 "(a provider's own quota: ciamProviderRef)"),
    AttributeDef(505, 'ciamQuotaNeeded', 'int', 'binding', True,
                 "How many of what a quota counts an environment needs (the environments on one account and region "
                 "need their sum)", (("X-MIN", "1"),)),
    AttributeDef(506, 'ciamQuotaDecision', enum_type(QUOTA_DECISIONS), 'intent', True,
                 "The operator's decision on a quota the provider grants less of than needed: request an increase "
                 "(rendered where the cloud takes requests) or deny it (the move stops until the need changes)"),
    AttributeDef(507, 'ciamQuotaRequested', 'int', 'intent', True,
                 "The limit an increase request asks the provider for (when not given, what the environments need)",
                 (("X-MIN", "1"),)),
    AttributeDef(508, 'ciamQuotaValue', 'int', 'observed', True,
                 "The limit a provider grants an account in a region, as fetched", (("X-MIN", "0"),)),
    AttributeDef(509, 'ciamQuotaUsage', 'int', 'observed', True,
                 "How much of a quota the account used when it was fetched, when the provider says",
                 (("X-MIN", "0"),)),
    AttributeDef(510, 'ciamQuotaName', 'string', 'meta', True,
                 "A quota's name as its provider shows it (Running On-Demand Standard instances, "
                 "Total Regional vCPUs)"),
    AttributeDef(511, 'ciamBudgetAmount', 'string', 'binding', True,
                 "How much a budget allows an environment to spend each period, in its currency (1500, 1500.50)",
                 (("X-PATTERN", AMOUNT),)),
    AttributeDef(512, 'ciamCurrency', 'string', 'binding', True,
                 "The currency of a budget's amount (ISO 4217; the billing account's, USD when not given)",
                 (("X-PATTERN", CURRENCY),)),
    AttributeDef(513, 'ciamBudgetPeriod', enum_type(BUDGET_PERIODS), 'binding', True,
                 "The period a budget's amount covers: monthly (when not given), quarterly, annually"),
    AttributeDef(514, 'ciamActualThreshold', 'int', 'binding', False,
                 "A share of a budget (percent) whose actual spending alerts its channel",
                 (("X-MIN", "1"), ("X-MAX", "1000"))),
    AttributeDef(515, 'ciamForecastThreshold', 'int', 'binding', False,
                 "A share of a budget (percent) whose forecast spending alerts its channel",
                 (("X-MIN", "1"), ("X-MAX", "1000"))),
    AttributeDef(516, 'ciamBillingAccountRef', 'string', 'binding', True,
                 "The account a cloud's billing is managed from, where its budgets live: an AWS management (payer) "
                 "or, for GovCloud, the associated standard account; an Azure billing account; a Google Cloud billing "
                 "account"),
    AttributeDef(517, 'ciamReportingObligationRef', 'dn', 'intent', False,
                 "A reporting obligation an environment is held to, or an incident falls under (a "
                 "ciamReportingObligation under ou=reporting-obligations)"),
    AttributeDef(518, 'ciamReportingHours', 'int', 'meta', True,
                 "How many hours from an incident's discovery a reporting obligation gives to report it to its "
                 "authority (DFARS 252.204-7012: 72)", (("X-MIN", "1"),)),
    AttributeDef(519, 'ciamInternalReportingHours', 'int', 'meta', True,
                 "How many hours from discovery the operator's own people have to report an incident to its incident "
                 "response capability (the period NIST SP 800-53 IR-6 leaves the organization to define)",
                 (("X-MIN", "1"),)),
    AttributeDef(520, 'ciamReportingAuthority', 'dn', 'meta', True,
                 "The authority a reporting obligation's reports go to (a party; its ciamContactUrl is where they are "
                 "filed, e.g. https://dibnet.dod.mil)"),
    AttributeDef(521, 'ciamReportingParty', 'dn', 'meta', True,
                 "Who files a reporting obligation's reports (a party: the operator's designated incident reporter)"),
    AttributeDef(522, 'ciamMalwareSubmission', 'url', 'meta', True,
                 "Where a reporting obligation says malicious software found in an incident is submitted (DFARS "
                 "252.204-7012: the DoD Cyber Crime Center, DC3)"),
    AttributeDef(523, 'ciamPreservationDays', 'int', 'meta', True,
                 "How many days after a report a reporting obligation requires images of affected systems and "
                 "monitoring data to be preserved (DFARS 252.204-7012: 90)", (("X-MIN", "1"),)),
    AttributeDef(524, 'ciamReportingCertificateRef', 'dn', 'meta', True,
                 "The certificate a reporting obligation's reports are filed with (a ciamCertificate: its public "
                 "facts only; DFARS 252.204-7012: a DoD-approved medium assurance certificate)"),
    AttributeDef(525, 'ciamContractNumber', 'string', 'meta', False,
                 "A contract that imposes a reporting obligation, by its number"),
    AttributeDef(526, 'ciamPrimeParty', 'dn', 'meta', True,
                 "The prime contractor (or next higher-tier subcontractor) a subcontractor's reporting obligation "
                 "passes the authority's report number to (a party, with its contact)"),
    AttributeDef(527, 'ciamCageCode', 'string', 'meta', True,
                 "A party's Commercial and Government Entity (CAGE) code", (("X-PATTERN", CAGE_CODE),)),
    AttributeDef(528, 'ciamUei', 'string', 'meta', True,
                 "A party's Unique Entity ID (SAM.gov)", (("X-PATTERN", UEI),)),
    AttributeDef(529, 'ciamIncidentRole', 'string', 'intent', True,
                 "The role of the binding a security service's findings at or above its ciamIncidentSeverity also go "
                 "to: the incident process's alert channel, log destination or stream"),
    AttributeDef(530, 'ciamIncidentSeverity', enum_type(SEVERITIES), 'binding', True,
                 "The least severe of a security service's findings that go to the incident process (its "
                 "ciamIncidentRole): low, medium, high (when not given), critical"),
    AttributeDef(531, 'ciamDiscoveredAt', 'time', 'meta', True,
                 "When an incident was discovered: a reporting obligation's clock starts here"),
    AttributeDef(532, 'ciamReportedAt', 'time', 'meta', True,
                 "When an incident's report was submitted to its authority"),
    AttributeDef(533, 'ciamReportRef', 'string', 'meta', True,
                 "The number the authority assigned an incident's report (DIBNet's incident report number)"),
    AttributeDef(534, 'ciamPrimeNotifiedAt', 'time', 'meta', True,
                 "When a subcontractor gave the prime contractor an incident's report number"),
    AttributeDef(535, 'ciamMalwareSubmittedAt', 'time', 'meta', True,
                 "When malicious software found in an incident was submitted where its obligation says"),
    AttributeDef(536, 'ciamMalwareRef', 'string', 'meta', True,
                 "The reference the malware submission was given"),
    AttributeDef(537, 'ciamPreservedUntil', 'time', 'meta', True,
                 "Until when an incident's images and monitoring data are preserved (held)"),
    AttributeDef(538, 'ciamMediaRequest', enum_type(MEDIA_REQUESTS), 'meta', True,
                 "What the authority asked of an incident's preserved media: none (yet), requested, provided, "
                 "declined"),
    AttributeDef(539, 'ciamAffectedEnvironment', 'dn', 'meta', False,
                 "An environment an incident affected (the obligations it is held to apply to the incident)"),
    AttributeDef(540, 'ciamControlRef', 'string', 'meta', False,
                 "A control a POA&M item or exception concerns, as framework:control (nist-800-171-r2:3.13.11, "
                 "nist-800-53-r5:SC-13, cmmc-l2:SC.L2-3.13.11)", (("X-PATTERN", CONTROL_REF),)),
    AttributeDef(541, 'ciamWeakness', 'string', 'meta', True,
                 "What is wrong: the weakness a POA&M item plans to correct"),
    AttributeDef(542, 'ciamDiscoverySource', enum_type(DISCOVERY_SOURCES), 'meta', True,
                 "How a weakness was found: assessment, scan, audit, continuous-monitoring, incident"),
    AttributeDef(543, 'ciamAssessmentRef', 'string', 'meta', True,
                 "The assessment, scan or report a weakness or score comes from (its id or link)"),
    AttributeDef(544, 'ciamScheduledCompletion', 'time', 'meta', True,
                 "When a POA&M item is scheduled to be corrected"),
    AttributeDef(545, 'ciamMilestone', 'string', 'meta', False,
                 "A milestone of a POA&M item: its date and what is done by then (2026-11-30: keys moved to the HSM)"),
    AttributeDef(546, 'ciamPoamStatus', enum_type(POAM_STATUSES), 'meta', True,
                 "Whether a POA&M item is open or closed (corrected and verified)"),
    AttributeDef(547, 'ciamRiskRating', enum_type(RISK_RATINGS), 'meta', True,
                 "How much risk a weakness carries: low, moderate, high"),
    AttributeDef(548, 'ciamVendorDependency', 'bool', 'meta', True,
                 "Whether correcting a weakness waits on a vendor (tracked, not a deviation)"),
    AttributeDef(549, 'ciamFindingRef', 'string', 'meta', False,
                 "A cloud finding or control a POA&M item, exception or suppression concerns, as provider:kind:id (the "
                 "kind and id its adapter defines: aws:securityhub:IAM.6)", (("X-PATTERN", FINDING_REF),)),
    AttributeDef(550, 'ciamEvidenceRef', 'url', 'meta', False,
                 "Where the evidence for a POA&M item, exception or assessment is kept"),
    AttributeDef(551, 'ciamLastReviewedAt', 'time', 'meta', True,
                 "When a POA&M item or exception was last reviewed"),
    AttributeDef(552, 'ciamPointValue', 'int', 'meta', True,
                 "What a POA&M item's requirement is worth in its framework's scoring (CMMC: 1, 3 or 5)",
                 (("X-MIN", "1"), ("X-MAX", "5"))),
    AttributeDef(553, 'ciamExceptionKind', enum_type(EXCEPTION_KINDS), 'meta', True,
                 "What an exception is: risk-adjustment, false-positive, operational-requirement, risk-acceptance, "
                 "compensating-control"),
    AttributeDef(554, 'ciamExceptionStatus', enum_type(EXCEPTION_STATUSES), 'meta', True,
                 "Where an exception stands: requested, approved, rejected, withdrawn"),
    AttributeDef(556, 'ciamCompensatingControl', 'string', 'meta', False,
                 "What meets a control's purpose another way while an exception stands"),
    AttributeDef(557, 'ciamRiskAuthority', 'dn', 'meta', True,
                 "Who may accept the risk an exception carries (a party: the authorizing official, the risk owner)"),
    AttributeDef(558, 'ciamApprovedAt', 'time', 'meta', True,
                 "When an exception was approved"),
    AttributeDef(559, 'ciamExpiresAt', 'time', 'meta', True,
                 "When an exception (or the cloud's suppression carrying it out) ends"),
    AttributeDef(560, 'ciamAcceptsFinding', 'string', 'meta', False,
                 "A planner finding an exception accepts, as its area and a phrase of its text (Budgets: has a "
                 "budget): it is shown as accepted, never hidden; a changed wording makes it count again"),
    AttributeDef(561, 'ciamPoamRef', 'dn', 'meta', True,
                 "The POA&M item an exception belongs to"),
    AttributeDef(562, 'ciamFramework', 'string', 'meta', True,
                 "The framework a compliance assessment is against, by its neutral id (cmmc-l2, nist-800-171-r2)",
                 (("X-PATTERN", STANDARD_ID),)),
    AttributeDef(563, 'ciamAssessmentKind', enum_type(ASSESSMENT_KINDS), 'meta', True,
                 "Who assessed: self, c3pao, dibcac, dod-medium, dod-high"),
    AttributeDef(564, 'ciamAssessmentScore', 'int', 'meta', True,
                 "The score an assessment gave (NIST SP 800-171 DoD methodology: -203 to 110)",
                 (("X-MIN", "-1000"),)),
    AttributeDef(565, 'ciamAssessmentMaxScore', 'int', 'meta', True,
                 "The highest score the assessment's framework gives (110 for NIST SP 800-171 and CMMC Level 2)",
                 (("X-MIN", "1"),)),
    AttributeDef(566, 'ciamAssessedAt', 'time', 'meta', True,
                 "When an assessment was completed (a Conditional status starts its POA&M closeout clock)"),
    AttributeDef(567, 'ciamAssessmentStatus', enum_type(ASSESSMENT_STATUSES), 'meta', True,
                 "The status an assessment gave: conditional (open POA&M items) or final"),
    AttributeDef(568, 'ciamFullScoreBy', 'time', 'meta', True,
                 "When the operator expects to reach the framework's full score (what SPRS asks with the score)"),
    AttributeDef(569, 'ciamExceptionRef', 'dn', 'meta', True,
                 "The exception a cloud's suppression of findings carries out"),
    AttributeDef(570, 'ciamProviderAddOn', 'string', 'intent', False,
                 "A Terraform provider beyond the cloud's own its roots may use, as its adapter names it (an add-on an "
                 "operator allows: Azure's azapi for what azurerm doesn't manage)"),
    AttributeDef(571, 'ciamPackageId', 'string', 'meta', True,
                 "A cloud offering's FedRAMP package id (the Marketplace's: F1603047866)",
                 (("X-PATTERN", r"[A-Za-z0-9][A-Za-z0-9_-]*"),)),
    AttributeDef(572, 'ciamOfferingName', 'string', 'meta', True,
                 "The cloud service offering an authorization covers, as its package names it (AWS GovCloud)"),
    AttributeDef(573, 'ciamProviderName', 'string', 'meta', True,
                 "The cloud service provider, as its package names it"),
    AttributeDef(574, 'ciamDeploymentModel', 'string', 'meta', True,
                 "An offering's deployment model as its package states it (Public Cloud, Government-Only Cloud, ...)"),
    AttributeDef(575, 'ciamAuthorizationLevel', enum_type(LEVELS), 'meta', False,
                 "A level an authorization grants: fedramp-low|moderate|high (Class B, C, D), dod-il2|il4|il5 (a DoD "
                 "provisional authorization)"),
    AttributeDef(576, 'ciamAuthorizationStatus', enum_type(AUTHORIZATION_STATUSES), 'meta', True,
                 "Where an authorization stands: certified (Rev5), validated (20x), equivalent (to FedRAMP Moderate, "
                 "with evidence), in-process, revoked"),
    AttributeDef(577, 'ciamCertificationType', 'string', 'meta', True,
                 "How the offering is certified, as its package says (Rev5, 20x; JAB or agency path)"),
    AttributeDef(578, 'ciamCertifiedAt', 'time', 'meta', True,
                 "When an offering was first certified (authorized)"),
    AttributeDef(579, 'ciamInScopeService', 'string', 'meta', False,
                 "A service inside an authorization's boundary, as the package names it (Amazon Simple Storage Service "
                 "(S3))"),
    AttributeDef(580, 'ciamScopeAsOf', 'time', 'meta', True,
                 "When the in-scope service list an authorization holds was last updated by its provider"),
    AttributeDef(581, 'ciamSourceUrl', 'url', 'meta', True,
                 "Where an imported list was taken from (the provider's published package overview)"),
    AttributeDef(582, 'ciamRetrievedAt', 'time', 'meta', True,
                 "When an imported list was taken from its source"),
    AttributeDef(583, 'ciamCrmRef', 'string', 'meta', True,
                 "The customer responsibility matrix (CIS/CRM workbook) an authorization comes with: its document id "
                 "and version, or where it is kept"),
    AttributeDef(584, 'ciamAuthorizationRef', 'dn', 'intent', True,
                 "The cloud authorization an environment relies on, or a control responsibility belongs to"),
    AttributeDef(585, 'ciamRequiredAuthorization', enum_type(LEVELS), 'intent', False,
                 "A level an environment's cloud authorization must meet (an obligation's requirement: dfars-7012 "
                 "asks for fedramp-moderate; a DoD contract for dod-il4 or dod-il5)"),
    AttributeDef(586, 'ciamRequiresConfiguration', enum_type(CONFIGURATIONS), 'meta', False,
                 "What a customer must configure for its use to be inside an authorization's boundary: "
                 "assured-workload, us-data-location, us-person-support, il5-isolation"),
    AttributeDef(587, 'ciamConfigurationMet', enum_type(CONFIGURATIONS), 'intent', False,
                 "A configuration an environment has in place for its authorization (an Assured Workloads workload, US "
                 "data location, US-person support, IL5 isolation)"),
    AttributeDef(588, 'ciamSspRef', 'string', 'meta', True,
                 "The system security plan a system boundary is documented in: its id and version"),
    AttributeDef(589, 'ciamResponsibility', enum_type(RESPONSIBILITY), 'meta', True,
                 "Who meets a control under an authorization: inherited (the provider), shared, customer"),
    AttributeDef(590, 'ciamCustomerAction', 'string', 'meta', True,
                 "What the customer must do for a control its authorization leaves to it"),
    AttributeDef(591, 'ciamImplementation', 'string', 'meta', True,
                 "How the operator meets a control its authorization leaves to it"),
    AttributeDef(593, 'ciamScansRole', 'string', 'binding', False,
                 "The role of a store a data discovery service examines for sensitive data (an object store, a "
                 "database, a volume)"),
    AttributeDef(594, 'ciamCustomIdentifier', 'string', 'intent', False,
                 "A data type of the organization's own a data discovery service looks for, as `name: regular "
                 "expression` (CUI markings, employee or contract numbers); the clouds' built-in detectors are theirs",
                 (("X-PATTERN", CUSTOM_IDENTIFIER),)),
    AttributeDef(595, 'ciamRescanDays', 'int', 'intent', True,
                 "How often a data discovery service examines its stores again, in days (1 daily, 7 weekly, 30 "
                 "monthly)", (("X-MIN", "1"),)),
    AttributeDef(596, 'ciamResultsRole', 'string', 'intent', True,
                 "The role of the binding a data discovery service keeps its detailed results in (an object store): "
                 "the record of where sensitive data was found"),
)
CLASSES = (
    ClassDef(103, 'ciamCloudAccount', 'top', 'AUXILIARY', (),
             ('ciamAccountRef', 'ciamOrganizationRef', 'ciamBillingAccountRef', 'ciamProviderAddOn'),
             "Added to a cloud: the account its environments run in, the organization above it, the account its "
             "billing is managed from and the Terraform provider add-ons its roots may use"),
    ClassDef(104, 'ciamEnvironmentPlacement', 'top', 'AUXILIARY', (),
             ('ciamResourceGroup', 'ciamDataClassification', 'ciamResidencyRef', 'ciamReportingObligationRef',
              'ciamAuthorizationRef', 'ciamRequiredAuthorization', 'ciamConfigurationMet'),
             "Added to an environment: the resource group its resources go in (where the cloud has them), how "
             "sensitive its data is, the residency and reporting obligations it is held to, the cloud authorization it "
             "relies on (the level it requires, the configurations it has in place)"),
    ClassDef(105, 'ciamChargedParty', 'top', 'AUXILIARY', (), ('ciamCostCenter',),
             "Added to a party: the cost center its spending is charged to"),
    ClassDef(106, 'ciamTagRule', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamTagKey', 'ciamTagSource'), ('ciamTagValue',),
             "One tag of the estate's tag policy (under ou=tag-policy): its key and where its value comes from in "
             "each environment"),
    ClassDef(107, 'ciamRegionCatalog', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamCloudProvider'), (),
             "One provider's regions (under ou=regions, named after the provider): its ciamCloudRegion entries"),
    ClassDef(108, 'ciamCloudRegion', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('ciamRegionName', 'ciamGeography', 'ciamRegionStatus', 'ciamCloudEnvironment'),
             "A region of a provider's catalog, named by the provider's region code (eu-west-1, westeurope, "
             "europe-west1): its name, where it is, its status and partition"),
    ClassDef(109, 'ciamResidency', 'ciamObject', 'STRUCTURAL', ('cn',), ('ciamAllowedRegion',),
             "A residency the estate defines (under ou=residencies): where data held to it may be, as the catalog "
             "regions it allows (any provider's)"),
    ClassDef(110, 'ciamCloudEndpoints', 'top', 'AUXILIARY', (), ('ciamFipsEndpoints',),
             "Added to a cloud: how its clients reach the provider's APIs (FIPS 140 validated endpoints)"),
    ClassDef(112, 'ciamSecurityService', 'ciamBinding', 'STRUCTURAL', ('ciamSecurityKind',),
             ('ciamSecurityCoverage', 'ciamComplianceStandard', 'ciamSecurityBaseline', 'ciamAuditScope',
              'ciamAllRegions', 'ciamFindingsRole', 'ciamIncidentRole', 'ciamIncidentSeverity', 'ciamRetentionDays',
              'ciamProviderRef', 'ciamManagedBy'),
             "A cloud security service an environment runs (threat detection, vulnerability scanning, configuration "
             "recording, posture assessment): what it watches or assesses, one account or the whole organization, "
             "every region or one, where its findings go (and those at or above a severity, to the incident process), "
             "how long it keeps its records (ciamRetentionDays), and who keeps it when the platform team doesn't"),
    ClassDef(113, 'ciamQuotaNeed', 'ciamBinding', 'STRUCTURAL', ('ciamQuotaNeeded',),
             ('ciamQuotaKind', 'ciamProviderRef', 'ciamQuotaDecision', 'ciamQuotaRequested'),
             "What an environment needs of a provider limit: a quota kind (or the provider's own quota, "
             "ciamProviderRef) and how many; and, when the provider grants less, the operator's decision"),
    ClassDef(114, 'ciamBudget', 'ciamBinding', 'STRUCTURAL', ('ciamBudgetAmount',),
             ('ciamCurrency', 'ciamBudgetPeriod', 'ciamActualThreshold', 'ciamForecastThreshold', 'ciamAlertRole',
              'ciamProviderRef', 'ciamManagedBy'),
             "A budget for an environment's spending: its amount per period, the shares of it (spent or forecast) "
             "that alert the channel of its ciamAlertRole, and who keeps it when the platform team doesn't"),
    ClassDef(115, 'ciamQuotaCatalog', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamCloudProvider', 'ciamRegion'),
             ('ciamAccountRef',),
             "The limits a provider grants one account in one region (under ou=quotas), as fetched: its "
             "ciamQuotaLimit entries"),
    ClassDef(116, 'ciamQuotaLimit', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamQuotaValue'),
             ('ciamQuotaName', 'ciamQuotaUsage', 'ciamQuotaKind'),
             "One limit of a quota catalog, named by the provider's quota id: the value granted, its name, the "
             "usage when fetched and the quota kind it answers"),
    ClassDef(117, 'ciamReportingObligation', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamReportingHours'),
             ('ciamInternalReportingHours', 'ciamReportingAuthority', 'ciamReportingParty', 'ciamMalwareSubmission',
              'ciamPreservationDays', 'ciamReportingCertificateRef', 'ciamContractNumber', 'ciamPrimeParty',
              'ciamRunbookRef', 'ciamDocUrl', 'ciamRequiredAuthorization'),
             "An incident reporting obligation the estate is held to (under ou=reporting-obligations, named by the "
             "regime's id: dfars-7012): the hours from discovery to report, to the operator's own incident response "
             "and to the authority; who files and with which certificate; where malware goes; how long evidence is "
             "preserved after a report (and the runbook placing the hold); the contracts imposing it and the prime "
             "contractor a subcontractor reports to"),
    ClassDef(118, 'ciamReportingIdentity', 'top', 'AUXILIARY', (), ('ciamCageCode', 'ciamUei'),
             "Added to a party: what a reporting regime asks to identify it by (CAGE code, Unique Entity ID)"),
    ClassDef(119, 'ciamReportableIncident', 'top', 'AUXILIARY', (),
             ('ciamReportingObligationRef', 'ciamAffectedEnvironment', 'ciamDiscoveredAt', 'ciamReportedAt',
              'ciamReportRef', 'ciamPrimeNotifiedAt', 'ciamMalwareSubmittedAt', 'ciamMalwareRef',
              'ciamPreservedUntil', 'ciamMediaRequest'),
             "Added to an incident: what its reporting needs: the obligations it falls under (its own, else those of "
             "the environments it affected), when it was discovered and reported, the authority's report number, "
             "when the prime was told, malware submitted, until when its media are preserved and what the authority "
             "asked of them"),
    ClassDef(120, 'ciamPoamItem', 'ciamObject', 'STRUCTURAL',
             ('cn', 'ciamWeakness', 'ciamPoamStatus', 'ciamAffectedEnvironment'),
             ('ciamControlRef', 'ciamDiscoverySource', 'ciamAssessmentRef', 'ciamDiscoveredAt',
              'ciamScheduledCompletion', 'ciamMilestone', 'ciamRiskRating', 'ciamVendorDependency', 'ciamInvolved',
              'ciamFindingRef', 'ciamEvidenceRef', 'ciamLastReviewedAt', 'ciamPointValue'),
             "A known weakness the operator plans to correct (under ou=poam): the controls it concerns, how and when "
             "it was found, when and how it will be corrected, its risk, the environments it affects and what it is "
             "worth in its framework's scoring"),
    ClassDef(121, 'ciamRiskException', 'ciamObject', 'STRUCTURAL',
             ('cn', 'ciamExceptionKind', 'ciamExceptionStatus', 'ciamAffectedEnvironment'),
             ('ciamJustification', 'ciamCompensatingControl', 'ciamRiskAuthority', 'ciamApprovedBy', 'ciamApprovedAt',
              'ciamExpiresAt', 'ciamControlRef', 'ciamFindingRef', 'ciamAcceptsFinding', 'ciamPoamRef',
              'ciamEvidenceRef', 'ciamLastReviewedAt'),
             "An approved deviation (under ou=exceptions) for the environments it names, never others: what it is, "
             "why, who may accept the risk and who approved it, until when, and the controls, cloud findings and "
             "planner findings it covers"),
    ClassDef(122, 'ciamComplianceAssessment', 'ciamObject', 'STRUCTURAL',
             ('cn', 'ciamFramework', 'ciamAssessmentKind', 'ciamAssessedAt'),
             ('ciamAssessmentScore', 'ciamAssessmentMaxScore', 'ciamAssessmentStatus', 'ciamAffectedEnvironment',
              'ciamFullScoreBy', 'ciamAssessmentRef', 'ciamEvidenceRef'),
             "A compliance assessment of environments against a framework (under ou=assessments): who assessed, when, "
             "the score and the status it gave"),
    ClassDef(123, 'ciamSuppression', 'ciamBinding', 'STRUCTURAL', (),
             ('ciamFindingRef', 'ciamExceptionRef', 'ciamExpiresAt', 'ciamProviderRef', 'ciamManagedBy'),
             "A cloud's suppression of findings in an environment (archived, muted, exempted), carrying out an "
             "exception: the findings it covers, until when; local to its environment's cloud (a target gets its own "
             "from its own exceptions)"),
    ClassDef(124, 'ciamCloudAuthorization', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamPackageId'),
             ('ciamOfferingName', 'ciamProviderName', 'ciamCloudProvider', 'ciamCloudEnvironment',
              'ciamDeploymentModel', 'ciamAuthorizationLevel', 'ciamAuthorizationStatus', 'ciamCertificationType',
              'ciamCertifiedAt', 'ciamInScopeService', 'ciamScopeAsOf', 'ciamSourceUrl', 'ciamRetrievedAt',
              'ciamCrmRef', 'ciamRequiresConfiguration', 'ciamEvidenceRef', 'ciamDocUrl'),
             "A cloud offering's authorization the estate relies on (under ou=authorizations, named by its package "
             "id): the offering, its levels and status, the services inside its boundary (imported from the "
             "provider's package overview, with where and when), its customer responsibility matrix and what customers "
             "must configure"),
    ClassDef(125, 'ciamSystemBoundary', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('ciamSspRef', 'ciamAffectedEnvironment', 'ciamRiskAuthority', 'ciamDocUrl', 'ciamEvidenceRef'),
             "The operator's own system boundary (under ou=boundaries): the system security plan it is documented in, "
             "the environments inside it and its authorizing official"),
    ClassDef(127, 'ciamDataDiscovery', 'ciamBinding', 'STRUCTURAL', (),
             ('ciamScansRole', 'ciamCustomIdentifier', 'ciamRescanDays', 'ciamFindingsRole', 'ciamResultsRole',
              'ciamProviderRef', 'ciamManagedBy'),
             "A data discovery service an environment runs (Amazon Macie, Defender for Cloud's sensitive data "
             "discovery, Sensitive Data Protection): the stores it examines, the organization's own data types it "
             "looks for, how often, where its findings go and where it keeps its results"),
    ClassDef(126, 'ciamControlResponsibility', 'ciamObject', 'STRUCTURAL',
             ('cn', 'ciamAuthorizationRef', 'ciamControlRef', 'ciamResponsibility'),
             ('ciamCustomerAction', 'ciamImplementation', 'ciamExceptionRef', 'ciamPoamRef', 'ciamEvidenceRef'),
             "Who meets a control under a cloud authorization (under ou=responsibilities, from its customer "
             "responsibility matrix), what the customer must do and how the operator does it (or the exception or "
             "POA&M item covering it)"),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
