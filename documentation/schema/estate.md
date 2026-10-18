# Estate

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 29 object classes · 132 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

Estate domain schema: the cloud accounts the environments run in and how the estate's resources are marked. A cloud (infrastructure's ciamCloud) may name its account (an AWS account, an Azure subscription, a Google Cloud project), the organization above it and the on-prem directory its users come from (the auxiliary class ciamCloudAccount; hybrid.py); an environment its resource group and how sensitive its data is and the residency it is held to (ciamEnvironmentPlacement); a party the cost center its spending is charged to (ciamChargedParty). The tag policy (under ou=tag-policy) says which tags every resource rendered for an environment carries and where each value comes from, so the renderers tag and the importers can say what the cloud has untagged. The region catalog (under ou=regions) holds each provider's regions as the provider lists them, fetched with the provider's own command (an adapter's prerequisite) and managed from then on like any other record; a residency (under ou=residencies) is the estate's own classification of where data may be held, listing the catalog regions it allows, so residency values are the estate's to define yet every environment names one that exists. A cloud may say its clients use FIPS 140 validated endpoints (ciamCloudEndpoints). The cloud security services an environment runs (ciamSecurityService: threat detection, vulnerability scanning, configuration recording, posture assessment) are bindings: what each watches or assesses, where its findings go and how long it keeps its records; so are the data discovery services (ciamDataDiscovery: the stores each examines for sensitive data, the organization's own data types it looks for, how often, where its findings go and where it keeps its results). What an environment needs of a provider limit (ciamQuotaNeed: virtual CPUs, public addresses, networks, ...) is a binding too, with the operator's decision when the provider grants less; the limits themselves are fetched from the provider into the quota catalog (under ou=quotas, one ciamQuotaCatalog per account and region, a ciamQuotaLimit per quota). The compliance frameworks a provider offers are fetched the same way into the framework catalog (under ou=frameworks, one ciamFrameworkCatalog per provider and organization, a ciamProviderFramework per framework, its ciamProviderControl entries when a posture service names it), for the renderers deploying what a posture service assesses. A budget (ciamBudget) caps an environment's spending per period and says at which shares of it, spent or forecast, whom to alert; the account billing is managed from is the cloud's ciamBillingAccountRef. The reporting obligations (under ou=reporting-obligations: a regime's clock from discovery to report, the authority reports go to, who files them, the certificate they are filed with, how long evidence is preserved, the contracts that impose it) are the estate's to define, and an environment names the ones it is held to; a security service says which of its findings (at or above a severity) also go to the incident process; an incident (governance) may carry what its reporting needs (ciamReportable Incident: when it was discovered and reported, the authority's report number, malware submitted, media preserved). The plan of action and milestones (under ou=poam: each known weakness, the controls it concerns, how and when it is fixed), the approved deviations (under ou=exceptions: accepted risks, false positives, operational requirements, each approved by a risk authority until a date, for named environments) and the compliance assessments (under ou=assessments: score, status) are the estate's record of its compliance; a cloud's suppression of findings (ciamSuppression) is a binding of the environment it runs in, named after the exception it carries out.

**Branches:** `ou=assessments,dc=ciam-ops`, `ou=authorizations,dc=ciam-ops`, `ou=boundaries,dc=ciam-ops`, `ou=evidence-queries,dc=ciam-ops`, `ou=exceptions,dc=ciam-ops`, `ou=frameworks,dc=ciam-ops`, `ou=poam,dc=ciam-ops`, `ou=quotas,dc=ciam-ops`, `ou=regions,dc=ciam-ops`, `ou=reporting-obligations,dc=ciam-ops`, `ou=residencies,dc=ciam-ops`, `ou=responsibilities,dc=ciam-ops`, `ou=tag-policy,dc=ciam-ops`

## Object classes

<a id="c-ciambudget"></a>
### ciamBudget

A budget for an environment's spending: its amount per period, the shares of it (spent or forecast) that alert the channel of its ciamAlertRole, and who keeps it when the platform team doesn't

OID `1.3.6.1.4.1.32473.1.2.114` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamBudgetAmount`](#a-ciambudgetamount) | yes | `string` | single | How much a budget allows an environment to spend each period, in its currency (1500, 1500.50) |
| [`ciamCurrency`](#a-ciamcurrency) |  | `string` | single | The currency of a budget's amount (ISO 4217; the billing account's, USD when not given) |
| [`ciamBudgetPeriod`](#a-ciambudgetperiod) |  | `enum` | single | The period a budget's amount covers: monthly (when not given), quarterly, annually |
| [`ciamActualThreshold`](#a-ciamactualthreshold) |  | `int` | multi | A share of a budget (percent) whose actual spending alerts its channel |
| [`ciamForecastThreshold`](#a-ciamforecastthreshold) |  | `int` | multi | A share of a budget (percent) whose forecast spending alerts its channel |
| [`ciamAlertRole`](observability.md#a-ciamalertrole) |  | `string` | single | The binding role of the channel that delivers an alert in each environment (a topic, an action group, a paging service) |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamchargedparty"></a>
### ciamChargedParty

Added to a party: the cost center its spending is charged to

OID `1.3.6.1.4.1.32473.1.2.105` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamCostCenter`](#a-ciamcostcenter) |  | `string` | single | The cost center a party's spending is charged to (resources of environments it owns are tagged with it where the tag policy says so) |

<a id="c-ciamcloudaccount"></a>
### ciamCloudAccount

Added to a cloud: the account its environments run in, the organization above it, where its organization-wide settings are made and who administers its security services, the account its billing is managed from, the Terraform provider add-ons its roots may use and the on-prem directory its users come from (how they sign in, whether passwords are written back)

OID `1.3.6.1.4.1.32473.1.2.103` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamAccountRef`](#a-ciamaccountref) |  | `string` | single | The cloud account a cloud's environments run in: an AWS account ID, an Azure subscription ID, a Google Cloud project ID |
| [`ciamOrganizationRef`](#a-ciamorganizationref) |  | `string` | single | The organization the account belongs to: an AWS organization, an Azure tenant, a Google Cloud organization or folder |
| [`ciamManagementRef`](#a-ciammanagementref) |  | `string` | single | Where a cloud's organization-wide settings are made: an AWS organization's management account ID, an Azure management group ID (a Google Cloud organization's are made on its ciamOrganizationRef) |
| [`ciamSecurityAdminRef`](#a-ciamsecurityadminref) |  | `string` | single | The account that administers a cloud's security services for the whole organization: an AWS delegated administrator account ID (GuardDuty, Inspector, Security Hub, Config) |
| [`ciamBillingAccountRef`](#a-ciambillingaccountref) |  | `string` | single | The account a cloud's billing is managed from, where its budgets live: an AWS management (payer) or, for GovCloud, the associated standard account; an Azure billing account; a Google Cloud billing account |
| [`ciamProviderAddOn`](#a-ciamprovideraddon) |  | `string` | multi | A Terraform provider beyond the cloud's own its roots may use, as its adapter names it (an add-on an operator allows: Azure's azapi for what azurerm doesn't manage) |
| [`ciamOnPremDirectory`](#a-ciamonpremdirectory) |  | `fqdn` | multi | A directory of the organization's own (its domain: corp.example.internal) whose users sign in to the cloud: the cloud's identities are synced from it |
| [`ciamDirectorySync`](#a-ciamdirectorysync) |  | `enum` | multi | How the users of the cloud's on-prem directory sign in to it: password-hash (their password hashes synced), pass-through (checked by an agent on the directory's side), federation (the organization's sign-in service); password-hash may sit beside the others |
| [`ciamPasswordWriteback`](#a-ciampasswordwriteback) |  | `bool` | single | Whether a password changed or reset in the cloud is written back to its on-prem directory |

<a id="c-ciamcloudauthorization"></a>
### ciamCloudAuthorization

A cloud offering's authorization the estate relies on (under ou=authorizations, named by its package id): the offering, its levels and status, the services inside its boundary (imported from the provider's package overview, with where and when), its customer responsibility matrix and what customers must configure

OID `1.3.6.1.4.1.32473.1.2.124` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamPackageId`](#a-ciampackageid) | yes | `string` | single | A cloud offering's FedRAMP package id (the Marketplace's: F1603047866) |
| [`ciamOfferingName`](#a-ciamofferingname) |  | `string` | single | The cloud service offering an authorization covers, as its package names it (AWS GovCloud) |
| [`ciamProviderName`](#a-ciamprovidername) |  | `string` | single | The cloud service provider, as its package names it |
| [`ciamCloudProvider`](infrastructure.md#a-ciamcloudprovider) |  | `vocab` | single | Cloud or hosting provider; the adapters that apply are chosen from it |
| [`ciamCloudEnvironment`](infrastructure.md#a-ciamcloudenvironment) |  | `vocab` | single | Partition of the provider (e.g. commercial vs government cloud) |
| [`ciamDeploymentModel`](#a-ciamdeploymentmodel) |  | `string` | single | An offering's deployment model as its package states it (Public Cloud, Government-Only Cloud, ...) |
| [`ciamAuthorizationLevel`](#a-ciamauthorizationlevel) |  | `enum` | multi | A level an authorization grants: fedramp-low\|moderate\|high (Class B, C, D), dod-il2\|il4\|il5 (a DoD provisional authorization) |
| [`ciamAuthorizationStatus`](#a-ciamauthorizationstatus) |  | `enum` | single | Where an authorization stands: certified (Rev5), validated (20x), equivalent (to FedRAMP Moderate, with evidence), in-process, revoked |
| [`ciamCertificationType`](#a-ciamcertificationtype) |  | `string` | single | How the offering is certified, as its package says (Rev5, 20x; JAB or agency path) |
| [`ciamCertifiedAt`](#a-ciamcertifiedat) |  | `time` | single | When an offering was first certified (authorized) |
| [`ciamInScopeService`](#a-ciaminscopeservice) |  | `string` | multi | A service inside an authorization's boundary, as the package names it (Amazon Simple Storage Service (S3)) |
| [`ciamScopeAsOf`](#a-ciamscopeasof) |  | `time` | single | When the in-scope service list an authorization holds was last updated by its provider |
| [`ciamSourceUrl`](#a-ciamsourceurl) |  | `url` | single | Where an imported list was taken from (the provider's published package overview) |
| [`ciamRetrievedAt`](#a-ciamretrievedat) |  | `time` | single | When an imported list was taken from its source |
| [`ciamCrmRef`](#a-ciamcrmref) |  | `string` | single | The customer responsibility matrix (CIS/CRM workbook) an authorization comes with: its document id and version, or where it is kept |
| [`ciamRequiresConfiguration`](#a-ciamrequiresconfiguration) |  | `enum` | multi | What a customer must configure for its use to be inside an authorization's boundary: assured-workload, us-data-location, us-person-support, il5-isolation |
| [`ciamEvidenceRef`](#a-ciamevidenceref) |  | `url` | multi | Where the evidence for a POA&M item, exception or assessment is kept |
| [`ciamDocUrl`](governance.md#a-ciamdocurl) |  | `url` | single | Document location |

<a id="c-ciamcloudendpoints"></a>
### ciamCloudEndpoints

Added to a cloud: how its clients reach the provider's APIs (FIPS 140 validated endpoints)

OID `1.3.6.1.4.1.32473.1.2.110` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamFipsEndpoints`](#a-ciamfipsendpoints) |  | `bool` | single | Whether a cloud's clients (renderers' providers, the products' SDKs) use the provider's FIPS 140 validated endpoints |

<a id="c-ciamcloudregion"></a>
### ciamCloudRegion

A region of a provider's catalog, named by the provider's region code (eu-west-1, westeurope, europe-west1): its name, where it is, its status and partition

OID `1.3.6.1.4.1.32473.1.2.108` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamRegionName`](#a-ciamregionname) |  | `string` | single | A cloud region's name as its provider shows it (Europe (Ireland), West Europe, Belgium) |
| [`ciamGeography`](#a-ciamgeography) |  | `string` | single | Where a cloud region is, as its provider places it (a geography, country or continent), when the provider says |
| [`ciamRegionStatus`](#a-ciamregionstatus) |  | `enum` | single | A cloud region as its provider lists it: available, opt-in (open only to accounts that opt in) or not-listed (no longer listed; kept so what names it keeps its link) |
| [`ciamCloudEnvironment`](infrastructure.md#a-ciamcloudenvironment) |  | `vocab` | single | Partition of the provider (e.g. commercial vs government cloud) |

<a id="c-ciamcomplianceassessment"></a>
### ciamComplianceAssessment

A compliance assessment of environments against a framework (under ou=assessments): who assessed, when, the score and the status it gave

OID `1.3.6.1.4.1.32473.1.2.122` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamFramework`](#a-ciamframework) | yes | `string` | single | The framework a compliance assessment is against, by its neutral id (cmmc-l2, nist-800-171-r2) |
| [`ciamAssessmentKind`](#a-ciamassessmentkind) | yes | `enum` | single | Who assessed: self, c3pao, dibcac, dod-medium, dod-high |
| [`ciamAssessedAt`](#a-ciamassessedat) | yes | `time` | single | When an assessment was completed (a Conditional status starts its POA&M closeout clock) |
| [`ciamAssessmentScore`](#a-ciamassessmentscore) |  | `int` | single | The score an assessment gave (NIST SP 800-171 DoD methodology: -203 to 110) |
| [`ciamAssessmentMaxScore`](#a-ciamassessmentmaxscore) |  | `int` | single | The highest score the assessment's framework gives (110 for NIST SP 800-171 and CMMC Level 2) |
| [`ciamAssessmentStatus`](#a-ciamassessmentstatus) |  | `enum` | single | The status an assessment gave: conditional (open POA&M items) or final |
| [`ciamAffectedEnvironment`](#a-ciamaffectedenvironment) |  | `dn` | multi | An environment an incident affected (the obligations it is held to apply to the incident) |
| [`ciamFullScoreBy`](#a-ciamfullscoreby) |  | `time` | single | When the operator expects to reach the framework's full score (what SPRS asks with the score) |
| [`ciamAssessmentRef`](#a-ciamassessmentref) |  | `string` | single | The assessment, scan or report a weakness or score comes from (its id or link) |
| [`ciamEvidenceRef`](#a-ciamevidenceref) |  | `url` | multi | Where the evidence for a POA&M item, exception or assessment is kept |

<a id="c-ciamcontrolresponsibility"></a>
### ciamControlResponsibility

Who meets a control under a cloud authorization (under ou=responsibilities, from its customer responsibility matrix), what the customer must do and how the operator does it (or the exception or POA&M item covering it)

OID `1.3.6.1.4.1.32473.1.2.126` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamAuthorizationRef`](#a-ciamauthorizationref) | yes | `dn` | single | The cloud authorization an environment relies on, or a control responsibility belongs to |
| [`ciamControlRef`](#a-ciamcontrolref) | yes | `string` | multi | A control a POA&M item or exception concerns, as framework:control (nist-800-171-r2:3.13.11, nist-800-53-r5:SC-13, cmmc-l2:SC.L2-3.13.11) |
| [`ciamResponsibility`](#a-ciamresponsibility) | yes | `enum` | single | Who meets a control under an authorization: inherited (the provider), shared, customer |
| [`ciamCustomerAction`](#a-ciamcustomeraction) |  | `string` | single | What the customer must do for a control its authorization leaves to it |
| [`ciamImplementation`](#a-ciamimplementation) |  | `string` | single | How the operator meets a control its authorization leaves to it |
| [`ciamExceptionRef`](#a-ciamexceptionref) |  | `dn` | single | The exception a cloud's suppression of findings carries out |
| [`ciamPoamRef`](#a-ciampoamref) |  | `dn` | single | The POA&M item an exception belongs to |
| [`ciamEvidenceRef`](#a-ciamevidenceref) |  | `url` | multi | Where the evidence for a POA&M item, exception or assessment is kept |

<a id="c-ciamdatadiscovery"></a>
### ciamDataDiscovery

A data discovery service an environment runs (Amazon Macie, Defender for Cloud's sensitive data discovery, Sensitive Data Protection): the stores it examines, the organization's own data types it looks for, how often, where its findings go and where it keeps its results

OID `1.3.6.1.4.1.32473.1.2.127` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamScansRole`](#a-ciamscansrole) |  | `string` | multi | The role of a store a data discovery service examines for sensitive data (an object store, a database, a volume) |
| [`ciamCustomIdentifier`](#a-ciamcustomidentifier) |  | `string` | multi | A data type of the organization's own a data discovery service looks for, as `name: regular expression` (CUI markings, employee or contract numbers); the clouds' built-in detectors are theirs |
| [`ciamRescanDays`](#a-ciamrescandays) |  | `int` | single | How often a data discovery service examines its stores again, in days (1 daily, 7 weekly, 30 monthly) |
| [`ciamFindingsRole`](#a-ciamfindingsrole) |  | `string` | single | The role of the binding a security or data discovery service's findings (or recorded configuration) go to: an alert channel, a log destination, an object store, a stream (a topic); none: they stay in the service |
| [`ciamResultsRole`](#a-ciamresultsrole) |  | `string` | single | The role of the binding a data discovery service keeps its detailed results in (an object store): the record of where sensitive data was found |
| [`ciamCatalogRef`](#a-ciamcatalogref) |  | `string` | single | The organization's data catalog account a data discovery service scans through (the provider's id of an account that exists: Microsoft Purview allows one per tenant), which lets its scans recur exactly every ciamRescanDays days |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamenvironmentplacement"></a>
### ciamEnvironmentPlacement

Added to an environment: the resource group its resources go in (where the cloud has them), how sensitive its data is and the regulated data it holds, the residency and reporting obligations it is held to, the cloud authorization it relies on (the level it requires, the configurations it has in place)

OID `1.3.6.1.4.1.32473.1.2.104` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamResourceGroup`](infrastructure.md#a-ciamresourcegroup) |  | `string` | single | Provider resource group or container the resources are placed in |
| [`ciamDataClassification`](#a-ciamdataclassification) |  | `enum` | single | How sensitive an environment's data is: public, internal, confidential, restricted |
| [`ciamResidencyRef`](#a-ciamresidencyref) |  | `dn` | single | The residency an environment's data is held to (a ciamResidency under ou=residencies) |
| [`ciamReportingObligationRef`](#a-ciamreportingobligationref) |  | `dn` | multi | A reporting obligation an environment is held to, or an incident falls under (a ciamReportingObligation under ou=reporting-obligations) |
| [`ciamAuthorizationRef`](#a-ciamauthorizationref) |  | `dn` | single | The cloud authorization an environment relies on, or a control responsibility belongs to |
| [`ciamRequiredAuthorization`](#a-ciamrequiredauthorization) |  | `enum` | multi | A level an environment's cloud authorization must meet (an obligation's requirement: dfars-7012 asks for fedramp-moderate; a DoD contract for dod-il4 or dod-il5) |
| [`ciamConfigurationMet`](#a-ciamconfigurationmet) |  | `enum` | multi | A configuration an environment has in place: for its authorization (an Assured Workloads workload, US data location, US-person support, IL5 isolation), for its threat detection watching identity (the identity and workload risk licenses, the deploying identity's rights to write sign-in policies and export the risk logs), for its data discovery scanning through a data catalog account (the deploying identity's rights in the catalog, the catalog's read access to the databases it scans, its custom scan rule set for the organization's own data types), or for Secrets synced into its clusters (its cloud's CSI provider reading the secret store as each pod's identity, checked there) |
| [`ciamRegulatedData`](#a-ciamregulateddata) |  | `enum` | multi | Regulated data an environment holds (or an obligation brings), by regime: itar, ear (export-controlled technical data), cjis (criminal justice information), hipaa (protected health information), irs-1075 (federal tax information); where it may be held is the cloud's to say |

<a id="c-ciamevidencequery"></a>
### ciamEvidenceQuery

What evidences controls from the record (under ou=evidence-queries): the controls, the report, change history or LDAP search that shows them met, how often its evidence is collected and who keeps it

OID `1.3.6.1.4.1.32473.1.2.143` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamControlRef`](#a-ciamcontrolref) | yes | `string` | multi | A control a POA&M item or exception concerns, as framework:control (nist-800-171-r2:3.13.11, nist-800-53-r5:SC-13, cmmc-l2:SC.L2-3.13.11) |
| [`ciamEvidenceSource`](#a-ciamevidencesource) | yes | `string` | single | What an evidence query runs: a report of the catalogue (`opsdir report` names it: principals, audit-trails, ...), `history` (the record's change history) or `search` (an LDAP search) |
| [`ciamEvidenceDn`](#a-ciamevidencedn) |  | `string` | single | The DN an evidence query runs on: the report's DN argument, the entry whose history it is, or the search's base (none: the whole record) |
| [`ciamEvidenceFilter`](#a-ciamevidencefilter) |  | `string` | single | The LDAP filter of an evidence query's search (RFC 4515) |
| [`ciamEvidenceAttribute`](#a-ciamevidenceattribute) |  | `string` | multi | An attribute an evidence query's search shows (its columns, after the entry's DN) |
| [`ciamEvidenceCadenceDays`](#a-ciamevidencecadencedays) |  | `int` | single | How often an evidence query's evidence must be collected again, in days |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamevidencerun"></a>
### ciamEvidenceRun

A system boundary's last evidence package (cn=evidence under the boundary): when it was taken, its files and their hashes, the queries it ran, where it is kept and the change it was recorded under

OID `1.3.6.1.4.1.32473.1.2.144` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamEvidenceAt`](#a-ciamevidenceat) | yes | `time` | single | When an evidence package was taken (the day the record was evaluated as of) |
| [`ciamEvidenceOutput`](#a-ciamevidenceoutput) | yes | `string` | multi | A file of an evidence package and the SHA-256 of its content, as `<path> <sha256>` |
| [`ciamEvidenceQueryRef`](#a-ciamevidencequeryref) |  | `dn` | multi | An evidence query an evidence package ran |
| [`ciamEvidenceRef`](#a-ciamevidenceref) |  | `url` | multi | Where the evidence for a POA&M item, exception or assessment is kept |

<a id="c-ciamframeworkcatalog"></a>
### ciamFrameworkCatalog

The compliance frameworks a provider offers one organization (under ou=frameworks), as fetched: its ciamProviderFramework entries

OID `1.3.6.1.4.1.32473.1.2.134` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamCloudProvider`](infrastructure.md#a-ciamcloudprovider) | yes | `vocab` | single | Cloud or hosting provider; the adapters that apply are chosen from it |
| [`ciamOrganizationRef`](#a-ciamorganizationref) | yes | `string` | single | The organization the account belongs to: an AWS organization, an Azure tenant, a Google Cloud organization or folder |

<a id="c-ciampoamitem"></a>
### ciamPoamItem

A known weakness the operator plans to correct (under ou=poam): the controls it concerns, how and when it was found, when and how it will be corrected, its risk, the environments it affects and what it is worth in its framework's scoring

OID `1.3.6.1.4.1.32473.1.2.120` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamWeakness`](#a-ciamweakness) | yes | `string` | single | What is wrong: the weakness a POA&M item plans to correct |
| [`ciamPoamStatus`](#a-ciampoamstatus) | yes | `enum` | single | Whether a POA&M item is open or closed (corrected and verified) |
| [`ciamAffectedEnvironment`](#a-ciamaffectedenvironment) | yes | `dn` | multi | An environment an incident affected (the obligations it is held to apply to the incident) |
| [`ciamControlRef`](#a-ciamcontrolref) |  | `string` | multi | A control a POA&M item or exception concerns, as framework:control (nist-800-171-r2:3.13.11, nist-800-53-r5:SC-13, cmmc-l2:SC.L2-3.13.11) |
| [`ciamDiscoverySource`](#a-ciamdiscoverysource) |  | `enum` | single | How a weakness was found: assessment, scan, audit, continuous-monitoring, incident |
| [`ciamAssessmentRef`](#a-ciamassessmentref) |  | `string` | single | The assessment, scan or report a weakness or score comes from (its id or link) |
| [`ciamDiscoveredAt`](#a-ciamdiscoveredat) |  | `time` | single | When an incident was discovered: a reporting obligation's clock starts here |
| [`ciamScheduledCompletion`](#a-ciamscheduledcompletion) |  | `time` | single | When a POA&M item is scheduled to be corrected |
| [`ciamMilestone`](#a-ciammilestone) |  | `string` | multi | A milestone of a POA&M item: its date and what is done by then (2026-11-30: keys moved to the HSM) |
| [`ciamRiskRating`](#a-ciamriskrating) |  | `enum` | single | How much risk a weakness carries: low, moderate, high |
| [`ciamVendorDependency`](#a-ciamvendordependency) |  | `bool` | single | Whether correcting a weakness waits on a vendor (tracked, not a deviation) |
| [`ciamInvolved`](governance.md#a-ciaminvolved) |  | `dn` | multi | Entries involved in the incident |
| [`ciamFindingRef`](#a-ciamfindingref) |  | `string` | multi | A cloud finding or control a POA&M item, exception or suppression concerns, as provider:kind:id (the kind and id its adapter defines: aws:securityhub:IAM.6) |
| [`ciamEvidenceRef`](#a-ciamevidenceref) |  | `url` | multi | Where the evidence for a POA&M item, exception or assessment is kept |
| [`ciamLastReviewedAt`](#a-ciamlastreviewedat) |  | `time` | single | When a POA&M item or exception was last reviewed |
| [`ciamPointValue`](#a-ciampointvalue) |  | `int` | single | What a POA&M item's requirement is worth in its framework's scoring (CMMC: 1, 3 or 5) |

<a id="c-ciamprovidercontrol"></a>
### ciamProviderControl

One control of a provider framework, named by the provider's control id: its full name, revision, how it can be enforced and the parameters it requires (a deployment of the framework lists every one)

OID `1.3.6.1.4.1.32473.1.2.136` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) | yes | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamRevision`](#a-ciamrevision) | yes | `string` | single | The revision of a provider's compliance framework or control, as fetched (a deployment names it) |
| [`ciamEnforcementMode`](#a-ciamenforcementmode) |  | `enum` | multi | How a provider's compliance framework or control can be enforced, as fetched: preventive (blocks a non-compliant change), detective (finds and reports one), audit (gathers evidence) |
| [`ciamControlParameter`](#a-ciamcontrolparameter) |  | `string` | multi | A parameter a provider's control requires, as fetched: name=<its default as JSON>, or the name alone when it has no default |

<a id="c-ciamproviderframework"></a>
### ciamProviderFramework

One framework of a framework catalog, named by the provider's framework id: its full name, revision, name as shown, how it can be enforced and the framework or baseline it answers (by the neutral id a posture service names); its ciamProviderControl entries when a posture service names it

OID `1.3.6.1.4.1.32473.1.2.135` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) | yes | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamRevision`](#a-ciamrevision) | yes | `string` | single | The revision of a provider's compliance framework or control, as fetched (a deployment names it) |
| [`ciamFrameworkName`](#a-ciamframeworkname) |  | `string` | single | A provider compliance framework's name as its provider shows it (NIST SP 800-53 R5) |
| [`ciamEnforcementMode`](#a-ciamenforcementmode) |  | `enum` | multi | How a provider's compliance framework or control can be enforced, as fetched: preventive (blocks a non-compliant change), detective (finds and reports one), audit (gathers evidence) |
| [`ciamComplianceStandard`](#a-ciamcompliancestandard) |  | `string` | multi | A compliance framework a posture service assesses the estate against, by a neutral id the clouds share (nist-800-53-r5, nist-800-171-r2, fedramp-high, cmmc-l2, cis: its cloud's CIS benchmark) |
| [`ciamSecurityBaseline`](#a-ciamsecuritybaseline) |  | `string` | multi | A cloud's own security baseline a posture service assesses, by the name its adapter gives it: one cloud's baseline never stands in for another's |

<a id="c-ciamquotacatalog"></a>
### ciamQuotaCatalog

The limits a provider grants one account in one region (under ou=quotas), as fetched: its ciamQuotaLimit entries

OID `1.3.6.1.4.1.32473.1.2.115` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamCloudProvider`](infrastructure.md#a-ciamcloudprovider) | yes | `vocab` | single | Cloud or hosting provider; the adapters that apply are chosen from it |
| [`ciamRegion`](infrastructure.md#a-ciamregion) | yes | `string` | single | Provider region |
| [`ciamAccountRef`](#a-ciamaccountref) |  | `string` | single | The cloud account a cloud's environments run in: an AWS account ID, an Azure subscription ID, a Google Cloud project ID |

<a id="c-ciamquotalimit"></a>
### ciamQuotaLimit

One limit of a quota catalog, named by the provider's quota id: the value granted, its name, the usage when fetched and the quota kind it answers

OID `1.3.6.1.4.1.32473.1.2.116` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamQuotaValue`](#a-ciamquotavalue) | yes | `int` | single | The limit a provider grants an account in a region, as fetched |
| [`ciamQuotaName`](#a-ciamquotaname) |  | `string` | single | A quota's name as its provider shows it (Running On-Demand Standard instances, Total Regional vCPUs) |
| [`ciamQuotaUsage`](#a-ciamquotausage) |  | `int` | single | How much of a quota the account used when it was fetched, when the provider says |
| [`ciamQuotaKind`](#a-ciamquotakind) |  | `enum` | single | What a quota counts, by a kind every cloud limits: vcpus (the region's standard machines), public-ips, networks, load-balancers, database-instances, kubernetes-clusters (a provider's own quota: ciamProviderRef) |

<a id="c-ciamquotaneed"></a>
### ciamQuotaNeed

What an environment needs of a provider limit: a quota kind (or the provider's own quota, ciamProviderRef) and how many; and, when the provider grants less, the operator's decision

OID `1.3.6.1.4.1.32473.1.2.113` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamQuotaNeeded`](#a-ciamquotaneeded) | yes | `int` | single | How many of what a quota counts an environment needs (the environments on one account and region need their sum) |
| [`ciamQuotaKind`](#a-ciamquotakind) |  | `enum` | single | What a quota counts, by a kind every cloud limits: vcpus (the region's standard machines), public-ips, networks, load-balancers, database-instances, kubernetes-clusters (a provider's own quota: ciamProviderRef) |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamQuotaDecision`](#a-ciamquotadecision) |  | `enum` | single | The operator's decision on a quota the provider grants less of than needed: request an increase (rendered where the cloud takes requests) or deny it (the move stops until the need changes) |
| [`ciamQuotaRequested`](#a-ciamquotarequested) |  | `int` | single | The limit an increase request asks the provider for (when not given, what the environments need) |

<a id="c-ciamregioncatalog"></a>
### ciamRegionCatalog

One provider's regions (under ou=regions, named after the provider): its ciamCloudRegion entries

OID `1.3.6.1.4.1.32473.1.2.107` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamCloudProvider`](infrastructure.md#a-ciamcloudprovider) | yes | `vocab` | single | Cloud or hosting provider; the adapters that apply are chosen from it |

<a id="c-ciamreportableincident"></a>
### ciamReportableIncident

Added to an incident: what its reporting needs: the obligations it falls under (its own, else those of the environments it affected), when it was discovered and reported, the authority's report number, when the prime was told, malware submitted, until when its media are preserved and what the authority asked of them

OID `1.3.6.1.4.1.32473.1.2.119` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamReportingObligationRef`](#a-ciamreportingobligationref) |  | `dn` | multi | A reporting obligation an environment is held to, or an incident falls under (a ciamReportingObligation under ou=reporting-obligations) |
| [`ciamAffectedEnvironment`](#a-ciamaffectedenvironment) |  | `dn` | multi | An environment an incident affected (the obligations it is held to apply to the incident) |
| [`ciamDiscoveredAt`](#a-ciamdiscoveredat) |  | `time` | single | When an incident was discovered: a reporting obligation's clock starts here |
| [`ciamReportedAt`](#a-ciamreportedat) |  | `time` | single | When an incident's report was submitted to its authority |
| [`ciamReportRef`](#a-ciamreportref) |  | `string` | single | The number the authority assigned an incident's report (DIBNet's incident report number) |
| [`ciamPrimeNotifiedAt`](#a-ciamprimenotifiedat) |  | `time` | single | When a subcontractor gave the prime contractor an incident's report number |
| [`ciamMalwareSubmittedAt`](#a-ciammalwaresubmittedat) |  | `time` | single | When malicious software found in an incident was submitted where its obligation says |
| [`ciamMalwareRef`](#a-ciammalwareref) |  | `string` | single | The reference the malware submission was given |
| [`ciamPreservedUntil`](#a-ciampreserveduntil) |  | `time` | single | Until when an incident's images and monitoring data are preserved (held) |
| [`ciamMediaRequest`](#a-ciammediarequest) |  | `enum` | single | What the authority asked of an incident's preserved media: none (yet), requested, provided, declined |

<a id="c-ciamreportingidentity"></a>
### ciamReportingIdentity

Added to a party: what a reporting regime asks to identify it by (CAGE code, Unique Entity ID)

OID `1.3.6.1.4.1.32473.1.2.118` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamCageCode`](#a-ciamcagecode) |  | `string` | single | A party's Commercial and Government Entity (CAGE) code |
| [`ciamUei`](#a-ciamuei) |  | `string` | single | A party's Unique Entity ID (SAM.gov) |

<a id="c-ciamreportingobligation"></a>
### ciamReportingObligation

An incident reporting obligation the estate is held to (under ou=reporting-obligations, named by the regime's id: dfars-7012): the hours from discovery to report, to the operator's own incident response and to the authority; who files and with which certificate; where malware goes; how long evidence is preserved after a report (and the runbook placing the hold); the contracts imposing it and the prime contractor a subcontractor reports to; the authorization level it requires and the regulated data it brings

OID `1.3.6.1.4.1.32473.1.2.117` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamReportingHours`](#a-ciamreportinghours) | yes | `int` | single | How many hours from an incident's discovery a reporting obligation gives to report it to its authority (DFARS 252.204-7012: 72) |
| [`ciamInternalReportingHours`](#a-ciaminternalreportinghours) |  | `int` | single | How many hours from discovery the operator's own people have to report an incident to its incident response capability (the period NIST SP 800-53 IR-6 leaves the organization to define) |
| [`ciamReportingAuthority`](#a-ciamreportingauthority) |  | `dn` | single | The authority a reporting obligation's reports go to (a party; its ciamContactUrl is where they are filed, e.g. https://dibnet.dod.mil) |
| [`ciamReportingParty`](#a-ciamreportingparty) |  | `dn` | single | Who files a reporting obligation's reports (a party: the operator's designated incident reporter) |
| [`ciamMalwareSubmission`](#a-ciammalwaresubmission) |  | `url` | single | Where a reporting obligation says malicious software found in an incident is submitted (DFARS 252.204-7012: the DoD Cyber Crime Center, DC3) |
| [`ciamPreservationDays`](#a-ciampreservationdays) |  | `int` | single | How many days after a report a reporting obligation requires images of affected systems and monitoring data to be preserved (DFARS 252.204-7012: 90) |
| [`ciamReportingCertificateRef`](#a-ciamreportingcertificateref) |  | `dn` | single | The certificate a reporting obligation's reports are filed with (a ciamCertificate: its public facts only; DFARS 252.204-7012: a DoD-approved medium assurance certificate) |
| [`ciamContractNumber`](#a-ciamcontractnumber) |  | `string` | multi | A contract that imposes a reporting obligation, by its number |
| [`ciamPrimeParty`](#a-ciamprimeparty) |  | `dn` | single | The prime contractor (or next higher-tier subcontractor) a subcontractor's reporting obligation passes the authority's report number to (a party, with its contact) |
| [`ciamRunbookRef`](custom.md#a-ciamrunbookref) |  | `dn` | multi | Runbooks about it |
| [`ciamDocUrl`](governance.md#a-ciamdocurl) |  | `url` | single | Document location |
| [`ciamRequiredAuthorization`](#a-ciamrequiredauthorization) |  | `enum` | multi | A level an environment's cloud authorization must meet (an obligation's requirement: dfars-7012 asks for fedramp-moderate; a DoD contract for dod-il4 or dod-il5) |
| [`ciamRegulatedData`](#a-ciamregulateddata) |  | `enum` | multi | Regulated data an environment holds (or an obligation brings), by regime: itar, ear (export-controlled technical data), cjis (criminal justice information), hipaa (protected health information), irs-1075 (federal tax information); where it may be held is the cloud's to say |

<a id="c-ciamresidency"></a>
### ciamResidency

A residency the estate defines (under ou=residencies): where data held to it may be, as the catalog regions it allows (any provider's)

OID `1.3.6.1.4.1.32473.1.2.109` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamAllowedRegion`](#a-ciamallowedregion) |  | `dn` | multi | A cloud region a residency allows data to be held in (a ciamCloudRegion of the region catalog) |

<a id="c-ciamriskexception"></a>
### ciamRiskException

An approved deviation (under ou=exceptions) for the environments it names, never others: what it is, why, who may accept the risk and who approved it, until when, and the controls, cloud findings and planner findings it covers

OID `1.3.6.1.4.1.32473.1.2.121` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamExceptionKind`](#a-ciamexceptionkind) | yes | `enum` | single | What an exception is: risk-adjustment, false-positive, operational-requirement, risk-acceptance, compensating-control |
| [`ciamExceptionStatus`](#a-ciamexceptionstatus) | yes | `enum` | single | Where an exception stands: requested, approved, rejected, withdrawn |
| [`ciamAffectedEnvironment`](#a-ciamaffectedenvironment) | yes | `dn` | multi | An environment an incident affected (the obligations it is held to apply to the incident) |
| [`ciamJustification`](directory.md#a-ciamjustification) |  | `string` | single | Why the access exists |
| [`ciamCompensatingControl`](#a-ciamcompensatingcontrol) |  | `string` | multi | What meets a control's purpose another way while an exception stands |
| [`ciamRiskAuthority`](#a-ciamriskauthority) |  | `dn` | single | Who may accept the risk an exception carries (a party: the authorizing official, the risk owner) |
| [`ciamApprovedBy`](governance.md#a-ciamapprovedby) |  | `string` | single | Approver (CAB) |
| [`ciamApprovedAt`](#a-ciamapprovedat) |  | `time` | single | When an exception was approved |
| [`ciamExpiresAt`](#a-ciamexpiresat) |  | `time` | single | When an exception (or the cloud's suppression carrying it out) ends |
| [`ciamControlRef`](#a-ciamcontrolref) |  | `string` | multi | A control a POA&M item or exception concerns, as framework:control (nist-800-171-r2:3.13.11, nist-800-53-r5:SC-13, cmmc-l2:SC.L2-3.13.11) |
| [`ciamFindingRef`](#a-ciamfindingref) |  | `string` | multi | A cloud finding or control a POA&M item, exception or suppression concerns, as provider:kind:id (the kind and id its adapter defines: aws:securityhub:IAM.6) |
| [`ciamAcceptsFinding`](#a-ciamacceptsfinding) |  | `string` | multi | A planner finding an exception accepts, as its area and a phrase of its text (Budgets: has a budget): it is shown as accepted, never hidden; a changed wording makes it count again |
| [`ciamPoamRef`](#a-ciampoamref) |  | `dn` | single | The POA&M item an exception belongs to |
| [`ciamEvidenceRef`](#a-ciamevidenceref) |  | `url` | multi | Where the evidence for a POA&M item, exception or assessment is kept |
| [`ciamLastReviewedAt`](#a-ciamlastreviewedat) |  | `time` | single | When a POA&M item or exception was last reviewed |

<a id="c-ciamsecurityservice"></a>
### ciamSecurityService

A cloud security service an environment runs (threat detection, vulnerability scanning, configuration recording, posture assessment): what it watches or assesses, one account or the whole organization, every region or one, where its findings go (and those at or above a severity, to the incident process), how long it keeps its records (ciamRetentionDays), and who keeps it when the platform team doesn't

OID `1.3.6.1.4.1.32473.1.2.112` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamSecurityKind`](#a-ciamsecuritykind) | yes | `enum` | single | What a cloud security service does: threat-detection, vulnerability-scanning, config-recording (resources' configuration and its changes) or posture (assessment against compliance frameworks and the cloud's own baseline) |
| [`ciamSecurityCoverage`](#a-ciamsecuritycoverage) |  | `enum` | multi | What a threat-detection or vulnerability-scanning service watches: control-plane, identity, network, compute, containers, storage, databases, key-vaults, applications, on-prem-directory (the organization's own directory its users reach the cloud from) |
| [`ciamComplianceStandard`](#a-ciamcompliancestandard) |  | `string` | multi | A compliance framework a posture service assesses the estate against, by a neutral id the clouds share (nist-800-53-r5, nist-800-171-r2, fedramp-high, cmmc-l2, cis: its cloud's CIS benchmark) |
| [`ciamSecurityBaseline`](#a-ciamsecuritybaseline) |  | `string` | multi | A cloud's own security baseline a posture service assesses, by the name its adapter gives it: one cloud's baseline never stands in for another's |
| [`ciamAuditScope`](observability.md#a-ciamauditscope) |  | `enum` | single | What an audit trail records: one account (an AWS account, an Azure subscription, a Google Cloud project) or every account of the organization |
| [`ciamAllRegions`](observability.md#a-ciamallregions) |  | `bool` | single | Whether an audit trail records activity in every region (and global services), not one region |
| [`ciamFindingsRole`](#a-ciamfindingsrole) |  | `string` | single | The role of the binding a security or data discovery service's findings (or recorded configuration) go to: an alert channel, a log destination, an object store, a stream (a topic); none: they stay in the service |
| [`ciamIncidentRole`](#a-ciamincidentrole) |  | `string` | single | The role of the binding a security service's findings at or above its ciamIncidentSeverity also go to: the incident process's alert channel, log destination or stream |
| [`ciamIncidentSeverity`](#a-ciamincidentseverity) |  | `enum` | single | The least severe of a security service's findings that go to the incident process (its ciamIncidentRole): low, medium, high (when not given), critical |
| [`ciamRetentionDays`](infrastructure.md#a-ciamretentiondays) |  | `int` | single | Retention period in days |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |
| [`ciamRiskPolicy`](#a-ciamriskpolicy) |  | `string` | multi | A risk-based sign-in policy a threat-detection service watching identity enforces: '<sign-in\|user> <low\|medium\|high>+: <mfa\|password-change\|risk-remediation\|block>' (sign-in medium+: mfa; password-change and risk-remediation answer a user's risk only) |
| [`ciamPolicyCovers`](#a-ciampolicycovers) |  | `string` | multi | Whom a security service's risk policies cover: identity bindings' roles (users, groups), or all-users |
| [`ciamPolicyExcludes`](#a-ciampolicyexcludes) |  | `string` | multi | Whom a security service's risk policies leave out: identity bindings' roles (the break-glass accounts, so a policy can never lock everyone out) |
| [`ciamPolicyMode`](#a-ciampolicymode) |  | `enum` | single | Whether a security service's risk policies are enforced or only report what they would do (report-only when not given) |

<a id="c-ciamsuppression"></a>
### ciamSuppression

A cloud's suppression of findings in an environment (archived, muted, exempted), carrying out an exception: the findings it covers, until when; local to its environment's cloud (a target gets its own from its own exceptions)

OID `1.3.6.1.4.1.32473.1.2.123` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamFindingRef`](#a-ciamfindingref) |  | `string` | multi | A cloud finding or control a POA&M item, exception or suppression concerns, as provider:kind:id (the kind and id its adapter defines: aws:securityhub:IAM.6) |
| [`ciamExceptionRef`](#a-ciamexceptionref) |  | `dn` | single | The exception a cloud's suppression of findings carries out |
| [`ciamExpiresAt`](#a-ciamexpiresat) |  | `time` | single | When an exception (or the cloud's suppression carrying it out) ends |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamsystemboundary"></a>
### ciamSystemBoundary

The operator's own system boundary (under ou=boundaries): the system security plan it is documented in, the environments inside it and its authorizing official

OID `1.3.6.1.4.1.32473.1.2.125` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamSspRef`](#a-ciamsspref) |  | `string` | single | The system security plan a system boundary is documented in: its id and version |
| [`ciamAffectedEnvironment`](#a-ciamaffectedenvironment) |  | `dn` | multi | An environment an incident affected (the obligations it is held to apply to the incident) |
| [`ciamRiskAuthority`](#a-ciamriskauthority) |  | `dn` | single | Who may accept the risk an exception carries (a party: the authorizing official, the risk owner) |
| [`ciamDocUrl`](governance.md#a-ciamdocurl) |  | `url` | single | Document location |
| [`ciamEvidenceRef`](#a-ciamevidenceref) |  | `url` | multi | Where the evidence for a POA&M item, exception or assessment is kept |

<a id="c-ciamtagrule"></a>
### ciamTagRule

One tag of the estate's tag policy (under ou=tag-policy): its key and where its value comes from in each environment

OID `1.3.6.1.4.1.32473.1.2.106` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamTagKey`](#a-ciamtagkey) | yes | `string` | single | The key of a tag (a label on Google Cloud) every resource rendered for an environment carries |
| [`ciamTagSource`](#a-ciamtagsource) | yes | `enum` | single | Where a tag rule takes its value in each environment: the environment's owner, that owner's cost center, the environment's data classification, the environment (cloud/env), its cloud, or the rule's own value (literal: ciamTagValue) |
| [`ciamTagValue`](#a-ciamtagvalue) |  | `string` | single | A literal tag rule's value |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamacceptsfinding"></a>`ciamAcceptsFinding` | `1.3.6.1.4.1.32473.1.1.560` | `string` | meta | multi |  | A planner finding an exception accepts, as its area and a phrase of its text (Budgets: has a budget): it is shown as accepted, never hidden; a changed wording makes it count again |
| <a id="a-ciamaccountref"></a>`ciamAccountRef` | `1.3.6.1.4.1.32473.1.1.482` | `string` | binding | single |  | The cloud account a cloud's environments run in: an AWS account ID, an Azure subscription ID, a Google Cloud project ID |
| <a id="a-ciamactualthreshold"></a>`ciamActualThreshold` | `1.3.6.1.4.1.32473.1.1.514` | `int` | binding | multi | X-MIN `1`; X-MAX `1000` | A share of a budget (percent) whose actual spending alerts its channel |
| <a id="a-ciamaffectedenvironment"></a>`ciamAffectedEnvironment` | `1.3.6.1.4.1.32473.1.1.539` | `dn` | meta | multi |  | An environment an incident affected (the obligations it is held to apply to the incident) |
| <a id="a-ciamallowedregion"></a>`ciamAllowedRegion` | `1.3.6.1.4.1.32473.1.1.493` | `dn` | intent | multi |  | A cloud region a residency allows data to be held in (a ciamCloudRegion of the region catalog) |
| <a id="a-ciamapprovedat"></a>`ciamApprovedAt` | `1.3.6.1.4.1.32473.1.1.558` | `time` | meta | single |  | When an exception was approved |
| <a id="a-ciamassessedat"></a>`ciamAssessedAt` | `1.3.6.1.4.1.32473.1.1.566` | `time` | meta | single |  | When an assessment was completed (a Conditional status starts its POA&M closeout clock) |
| <a id="a-ciamassessmentkind"></a>`ciamAssessmentKind` | `1.3.6.1.4.1.32473.1.1.563` | enum: `self`, `c3pao`, `dibcac`, `dod-medium`, `dod-high` | meta | single |  | Who assessed: self, c3pao, dibcac, dod-medium, dod-high |
| <a id="a-ciamassessmentmaxscore"></a>`ciamAssessmentMaxScore` | `1.3.6.1.4.1.32473.1.1.565` | `int` | meta | single | X-MIN `1` | The highest score the assessment's framework gives (110 for NIST SP 800-171 and CMMC Level 2) |
| <a id="a-ciamassessmentref"></a>`ciamAssessmentRef` | `1.3.6.1.4.1.32473.1.1.543` | `string` | meta | single |  | The assessment, scan or report a weakness or score comes from (its id or link) |
| <a id="a-ciamassessmentscore"></a>`ciamAssessmentScore` | `1.3.6.1.4.1.32473.1.1.564` | `int` | meta | single | X-MIN `-1000` | The score an assessment gave (NIST SP 800-171 DoD methodology: -203 to 110) |
| <a id="a-ciamassessmentstatus"></a>`ciamAssessmentStatus` | `1.3.6.1.4.1.32473.1.1.567` | enum: `conditional`, `final` | meta | single |  | The status an assessment gave: conditional (open POA&M items) or final |
| <a id="a-ciamauthorizationlevel"></a>`ciamAuthorizationLevel` | `1.3.6.1.4.1.32473.1.1.575` | enum: `fedramp-low`, `fedramp-moderate`, `fedramp-high`, `dod-il2`, `dod-il4`, `dod-il5` | meta | multi |  | A level an authorization grants: fedramp-low\|moderate\|high (Class B, C, D), dod-il2\|il4\|il5 (a DoD provisional authorization) |
| <a id="a-ciamauthorizationref"></a>`ciamAuthorizationRef` | `1.3.6.1.4.1.32473.1.1.584` | `dn` | intent | single |  | The cloud authorization an environment relies on, or a control responsibility belongs to |
| <a id="a-ciamauthorizationstatus"></a>`ciamAuthorizationStatus` | `1.3.6.1.4.1.32473.1.1.576` | enum: `certified`, `validated`, `equivalent`, `in-process`, `revoked` | meta | single |  | Where an authorization stands: certified (Rev5), validated (20x), equivalent (to FedRAMP Moderate, with evidence), in-process, revoked |
| <a id="a-ciambillingaccountref"></a>`ciamBillingAccountRef` | `1.3.6.1.4.1.32473.1.1.516` | `string` | binding | single |  | The account a cloud's billing is managed from, where its budgets live: an AWS management (payer) or, for GovCloud, the associated standard account; an Azure billing account; a Google Cloud billing account |
| <a id="a-ciambudgetamount"></a>`ciamBudgetAmount` | `1.3.6.1.4.1.32473.1.1.511` | `string` | binding | single | X-PATTERN `[0-9]{1,12}(\.[0-9]{1,2})?` | How much a budget allows an environment to spend each period, in its currency (1500, 1500.50) |
| <a id="a-ciambudgetperiod"></a>`ciamBudgetPeriod` | `1.3.6.1.4.1.32473.1.1.513` | enum: `monthly`, `quarterly`, `annually` | binding | single |  | The period a budget's amount covers: monthly (when not given), quarterly, annually |
| <a id="a-ciamcagecode"></a>`ciamCageCode` | `1.3.6.1.4.1.32473.1.1.527` | `string` | meta | single | X-PATTERN `[A-Z0-9]{5}` | A party's Commercial and Government Entity (CAGE) code |
| <a id="a-ciamcatalogref"></a>`ciamCatalogRef` | `1.3.6.1.4.1.32473.1.1.644` | `string` | binding | single |  | The organization's data catalog account a data discovery service scans through (the provider's id of an account that exists: Microsoft Purview allows one per tenant), which lets its scans recur exactly every ciamRescanDays days |
| <a id="a-ciamcertificationtype"></a>`ciamCertificationType` | `1.3.6.1.4.1.32473.1.1.577` | `string` | meta | single |  | How the offering is certified, as its package says (Rev5, 20x; JAB or agency path) |
| <a id="a-ciamcertifiedat"></a>`ciamCertifiedAt` | `1.3.6.1.4.1.32473.1.1.578` | `time` | meta | single |  | When an offering was first certified (authorized) |
| <a id="a-ciamcompensatingcontrol"></a>`ciamCompensatingControl` | `1.3.6.1.4.1.32473.1.1.556` | `string` | meta | multi |  | What meets a control's purpose another way while an exception stands |
| <a id="a-ciamcompliancestandard"></a>`ciamComplianceStandard` | `1.3.6.1.4.1.32473.1.1.501` | `string` | binding | multi | X-PATTERN `[a-z0-9]+(-[a-z0-9]+)*` | A compliance framework a posture service assesses the estate against, by a neutral id the clouds share (nist-800-53-r5, nist-800-171-r2, fedramp-high, cmmc-l2, cis: its cloud's CIS benchmark) |
| <a id="a-ciamconfigurationmet"></a>`ciamConfigurationMet` | `1.3.6.1.4.1.32473.1.1.587` | enum: `assured-workload`, `us-data-location`, `us-person-support`, `il5-isolation`, `identity-risk-license`, `workload-risk-license`, `risk-policy-permission`, `risk-log-permission`, `catalog-scan-permission`, `catalog-database-access`, `catalog-custom-rules`, `csi-provider-identity` | intent | multi |  | A configuration an environment has in place: for its authorization (an Assured Workloads workload, US data location, US-person support, IL5 isolation), for its threat detection watching identity (the identity and workload risk licenses, the deploying identity's rights to write sign-in policies and export the risk logs), for its data discovery scanning through a data catalog account (the deploying identity's rights in the catalog, the catalog's read access to the databases it scans, its custom scan rule set for the organization's own data types), or for Secrets synced into its clusters (its cloud's CSI provider reading the secret store as each pod's identity, checked there) |
| <a id="a-ciamcontractnumber"></a>`ciamContractNumber` | `1.3.6.1.4.1.32473.1.1.525` | `string` | meta | multi |  | A contract that imposes a reporting obligation, by its number |
| <a id="a-ciamcontrolparameter"></a>`ciamControlParameter` | `1.3.6.1.4.1.32473.1.1.655` | `string` | observed | multi |  | A parameter a provider's control requires, as fetched: name=<its default as JSON>, or the name alone when it has no default |
| <a id="a-ciamcontrolref"></a>`ciamControlRef` | `1.3.6.1.4.1.32473.1.1.540` | `string` | meta | multi | X-PATTERN `[a-z0-9]+(-[a-z0-9]+)*:[A-Za-z0-9][A-Za-z0-9.()-]*` | A control a POA&M item or exception concerns, as framework:control (nist-800-171-r2:3.13.11, nist-800-53-r5:SC-13, cmmc-l2:SC.L2-3.13.11) |
| <a id="a-ciamcostcenter"></a>`ciamCostCenter` | `1.3.6.1.4.1.32473.1.1.484` | `string` | meta | single |  | The cost center a party's spending is charged to (resources of environments it owns are tagged with it where the tag policy says so) |
| <a id="a-ciamcrmref"></a>`ciamCrmRef` | `1.3.6.1.4.1.32473.1.1.583` | `string` | meta | single |  | The customer responsibility matrix (CIS/CRM workbook) an authorization comes with: its document id and version, or where it is kept |
| <a id="a-ciamcurrency"></a>`ciamCurrency` | `1.3.6.1.4.1.32473.1.1.512` | `string` | binding | single | X-PATTERN `[A-Z]{3}` | The currency of a budget's amount (ISO 4217; the billing account's, USD when not given) |
| <a id="a-ciamcustomeraction"></a>`ciamCustomerAction` | `1.3.6.1.4.1.32473.1.1.590` | `string` | meta | single |  | What the customer must do for a control its authorization leaves to it |
| <a id="a-ciamcustomidentifier"></a>`ciamCustomIdentifier` | `1.3.6.1.4.1.32473.1.1.594` | `string` | intent | multi | X-PATTERN `[a-z][a-z0-9-]{0,62}: \S.*` | A data type of the organization's own a data discovery service looks for, as `name: regular expression` (CUI markings, employee or contract numbers); the clouds' built-in detectors are theirs |
| <a id="a-ciamdataclassification"></a>`ciamDataClassification` | `1.3.6.1.4.1.32473.1.1.485` | enum: `public`, `internal`, `confidential`, `restricted` | meta | single |  | How sensitive an environment's data is: public, internal, confidential, restricted |
| <a id="a-ciamdeploymentmodel"></a>`ciamDeploymentModel` | `1.3.6.1.4.1.32473.1.1.574` | `string` | meta | single |  | An offering's deployment model as its package states it (Public Cloud, Government-Only Cloud, ...) |
| <a id="a-ciamdirectorysync"></a>`ciamDirectorySync` | `1.3.6.1.4.1.32473.1.1.642` | enum: `password-hash`, `pass-through`, `federation` | intent | multi |  | How the users of the cloud's on-prem directory sign in to it: password-hash (their password hashes synced), pass-through (checked by an agent on the directory's side), federation (the organization's sign-in service); password-hash may sit beside the others |
| <a id="a-ciamdiscoveredat"></a>`ciamDiscoveredAt` | `1.3.6.1.4.1.32473.1.1.531` | `time` | meta | single |  | When an incident was discovered: a reporting obligation's clock starts here |
| <a id="a-ciamdiscoverysource"></a>`ciamDiscoverySource` | `1.3.6.1.4.1.32473.1.1.542` | enum: `assessment`, `scan`, `audit`, `continuous-monitoring`, `incident` | meta | single |  | How a weakness was found: assessment, scan, audit, continuous-monitoring, incident |
| <a id="a-ciamenforcementmode"></a>`ciamEnforcementMode` | `1.3.6.1.4.1.32473.1.1.654` | enum: `preventive`, `detective`, `audit` | observed | multi |  | How a provider's compliance framework or control can be enforced, as fetched: preventive (blocks a non-compliant change), detective (finds and reports one), audit (gathers evidence) |
| <a id="a-ciamevidenceat"></a>`ciamEvidenceAt` | `1.3.6.1.4.1.32473.1.1.685` | `time` | meta | single |  | When an evidence package was taken (the day the record was evaluated as of) |
| <a id="a-ciamevidenceattribute"></a>`ciamEvidenceAttribute` | `1.3.6.1.4.1.32473.1.1.683` | `string` | meta | multi |  | An attribute an evidence query's search shows (its columns, after the entry's DN) |
| <a id="a-ciamevidencecadencedays"></a>`ciamEvidenceCadenceDays` | `1.3.6.1.4.1.32473.1.1.684` | `int` | meta | single | X-MIN `1` | How often an evidence query's evidence must be collected again, in days |
| <a id="a-ciamevidencedn"></a>`ciamEvidenceDn` | `1.3.6.1.4.1.32473.1.1.681` | `string` | meta | single |  | The DN an evidence query runs on: the report's DN argument, the entry whose history it is, or the search's base (none: the whole record) |
| <a id="a-ciamevidencefilter"></a>`ciamEvidenceFilter` | `1.3.6.1.4.1.32473.1.1.682` | `string` | meta | single |  | The LDAP filter of an evidence query's search (RFC 4515) |
| <a id="a-ciamevidenceoutput"></a>`ciamEvidenceOutput` | `1.3.6.1.4.1.32473.1.1.686` | `string` | meta | multi |  | A file of an evidence package and the SHA-256 of its content, as `<path> <sha256>` |
| <a id="a-ciamevidencequeryref"></a>`ciamEvidenceQueryRef` | `1.3.6.1.4.1.32473.1.1.687` | `dn` | meta | multi |  | An evidence query an evidence package ran |
| <a id="a-ciamevidenceref"></a>`ciamEvidenceRef` | `1.3.6.1.4.1.32473.1.1.550` | `url` | meta | multi |  | Where the evidence for a POA&M item, exception or assessment is kept |
| <a id="a-ciamevidencesource"></a>`ciamEvidenceSource` | `1.3.6.1.4.1.32473.1.1.680` | `string` | meta | single |  | What an evidence query runs: a report of the catalogue (`opsdir report` names it: principals, audit-trails, ...), `history` (the record's change history) or `search` (an LDAP search) |
| <a id="a-ciamexceptionkind"></a>`ciamExceptionKind` | `1.3.6.1.4.1.32473.1.1.553` | enum: `risk-adjustment`, `false-positive`, `operational-requirement`, `risk-acceptance`, `compensating-control` | meta | single |  | What an exception is: risk-adjustment, false-positive, operational-requirement, risk-acceptance, compensating-control |
| <a id="a-ciamexceptionref"></a>`ciamExceptionRef` | `1.3.6.1.4.1.32473.1.1.569` | `dn` | meta | single |  | The exception a cloud's suppression of findings carries out |
| <a id="a-ciamexceptionstatus"></a>`ciamExceptionStatus` | `1.3.6.1.4.1.32473.1.1.554` | enum: `requested`, `approved`, `rejected`, `withdrawn` | meta | single |  | Where an exception stands: requested, approved, rejected, withdrawn |
| <a id="a-ciamexpiresat"></a>`ciamExpiresAt` | `1.3.6.1.4.1.32473.1.1.559` | `time` | meta | single |  | When an exception (or the cloud's suppression carrying it out) ends |
| <a id="a-ciamfindingref"></a>`ciamFindingRef` | `1.3.6.1.4.1.32473.1.1.549` | `string` | meta | multi | X-PATTERN `[a-z0-9-]+:[a-z0-9-]+:.+` | A cloud finding or control a POA&M item, exception or suppression concerns, as provider:kind:id (the kind and id its adapter defines: aws:securityhub:IAM.6) |
| <a id="a-ciamfindingsrole"></a>`ciamFindingsRole` | `1.3.6.1.4.1.32473.1.1.503` | `string` | intent | single |  | The role of the binding a security or data discovery service's findings (or recorded configuration) go to: an alert channel, a log destination, an object store, a stream (a topic); none: they stay in the service |
| <a id="a-ciamfipsendpoints"></a>`ciamFipsEndpoints` | `1.3.6.1.4.1.32473.1.1.494` | `bool` | binding | single |  | Whether a cloud's clients (renderers' providers, the products' SDKs) use the provider's FIPS 140 validated endpoints |
| <a id="a-ciamforecastthreshold"></a>`ciamForecastThreshold` | `1.3.6.1.4.1.32473.1.1.515` | `int` | binding | multi | X-MIN `1`; X-MAX `1000` | A share of a budget (percent) whose forecast spending alerts its channel |
| <a id="a-ciamframework"></a>`ciamFramework` | `1.3.6.1.4.1.32473.1.1.562` | `string` | meta | single | X-PATTERN `[a-z0-9]+(-[a-z0-9]+)*` | The framework a compliance assessment is against, by its neutral id (cmmc-l2, nist-800-171-r2) |
| <a id="a-ciamframeworkname"></a>`ciamFrameworkName` | `1.3.6.1.4.1.32473.1.1.652` | `string` | meta | single |  | A provider compliance framework's name as its provider shows it (NIST SP 800-53 R5) |
| <a id="a-ciamfullscoreby"></a>`ciamFullScoreBy` | `1.3.6.1.4.1.32473.1.1.568` | `time` | meta | single |  | When the operator expects to reach the framework's full score (what SPRS asks with the score) |
| <a id="a-ciamgeography"></a>`ciamGeography` | `1.3.6.1.4.1.32473.1.1.490` | `string` | meta | single |  | Where a cloud region is, as its provider places it (a geography, country or continent), when the provider says |
| <a id="a-ciamimplementation"></a>`ciamImplementation` | `1.3.6.1.4.1.32473.1.1.591` | `string` | meta | single |  | How the operator meets a control its authorization leaves to it |
| <a id="a-ciamincidentrole"></a>`ciamIncidentRole` | `1.3.6.1.4.1.32473.1.1.529` | `string` | intent | single |  | The role of the binding a security service's findings at or above its ciamIncidentSeverity also go to: the incident process's alert channel, log destination or stream |
| <a id="a-ciamincidentseverity"></a>`ciamIncidentSeverity` | `1.3.6.1.4.1.32473.1.1.530` | enum: `low`, `medium`, `high`, `critical` | binding | single |  | The least severe of a security service's findings that go to the incident process (its ciamIncidentRole): low, medium, high (when not given), critical |
| <a id="a-ciaminscopeservice"></a>`ciamInScopeService` | `1.3.6.1.4.1.32473.1.1.579` | `string` | meta | multi |  | A service inside an authorization's boundary, as the package names it (Amazon Simple Storage Service (S3)) |
| <a id="a-ciaminternalreportinghours"></a>`ciamInternalReportingHours` | `1.3.6.1.4.1.32473.1.1.519` | `int` | meta | single | X-MIN `1` | How many hours from discovery the operator's own people have to report an incident to its incident response capability (the period NIST SP 800-53 IR-6 leaves the organization to define) |
| <a id="a-ciamlastreviewedat"></a>`ciamLastReviewedAt` | `1.3.6.1.4.1.32473.1.1.551` | `time` | meta | single |  | When a POA&M item or exception was last reviewed |
| <a id="a-ciammalwareref"></a>`ciamMalwareRef` | `1.3.6.1.4.1.32473.1.1.536` | `string` | meta | single |  | The reference the malware submission was given |
| <a id="a-ciammalwaresubmission"></a>`ciamMalwareSubmission` | `1.3.6.1.4.1.32473.1.1.522` | `url` | meta | single |  | Where a reporting obligation says malicious software found in an incident is submitted (DFARS 252.204-7012: the DoD Cyber Crime Center, DC3) |
| <a id="a-ciammalwaresubmittedat"></a>`ciamMalwareSubmittedAt` | `1.3.6.1.4.1.32473.1.1.535` | `time` | meta | single |  | When malicious software found in an incident was submitted where its obligation says |
| <a id="a-ciammanagementref"></a>`ciamManagementRef` | `1.3.6.1.4.1.32473.1.1.649` | `string` | binding | single |  | Where a cloud's organization-wide settings are made: an AWS organization's management account ID, an Azure management group ID (a Google Cloud organization's are made on its ciamOrganizationRef) |
| <a id="a-ciammediarequest"></a>`ciamMediaRequest` | `1.3.6.1.4.1.32473.1.1.538` | enum: `none`, `requested`, `provided`, `declined` | meta | single |  | What the authority asked of an incident's preserved media: none (yet), requested, provided, declined |
| <a id="a-ciammilestone"></a>`ciamMilestone` | `1.3.6.1.4.1.32473.1.1.545` | `string` | meta | multi |  | A milestone of a POA&M item: its date and what is done by then (2026-11-30: keys moved to the HSM) |
| <a id="a-ciamofferingname"></a>`ciamOfferingName` | `1.3.6.1.4.1.32473.1.1.572` | `string` | meta | single |  | The cloud service offering an authorization covers, as its package names it (AWS GovCloud) |
| <a id="a-ciamonpremdirectory"></a>`ciamOnPremDirectory` | `1.3.6.1.4.1.32473.1.1.641` | `fqdn` | intent | multi |  | A directory of the organization's own (its domain: corp.example.internal) whose users sign in to the cloud: the cloud's identities are synced from it |
| <a id="a-ciamorganizationref"></a>`ciamOrganizationRef` | `1.3.6.1.4.1.32473.1.1.483` | `string` | binding | single |  | The organization the account belongs to: an AWS organization, an Azure tenant, a Google Cloud organization or folder |
| <a id="a-ciampackageid"></a>`ciamPackageId` | `1.3.6.1.4.1.32473.1.1.571` | `string` | meta | single | X-PATTERN `[A-Za-z0-9][A-Za-z0-9_-]*` | A cloud offering's FedRAMP package id (the Marketplace's: F1603047866) |
| <a id="a-ciampasswordwriteback"></a>`ciamPasswordWriteback` | `1.3.6.1.4.1.32473.1.1.643` | `bool` | intent | single |  | Whether a password changed or reset in the cloud is written back to its on-prem directory |
| <a id="a-ciampoamref"></a>`ciamPoamRef` | `1.3.6.1.4.1.32473.1.1.561` | `dn` | meta | single |  | The POA&M item an exception belongs to |
| <a id="a-ciampoamstatus"></a>`ciamPoamStatus` | `1.3.6.1.4.1.32473.1.1.546` | enum: `open`, `closed` | meta | single |  | Whether a POA&M item is open or closed (corrected and verified) |
| <a id="a-ciampointvalue"></a>`ciamPointValue` | `1.3.6.1.4.1.32473.1.1.552` | `int` | meta | single | X-MIN `1`; X-MAX `5` | What a POA&M item's requirement is worth in its framework's scoring (CMMC: 1, 3 or 5) |
| <a id="a-ciampolicycovers"></a>`ciamPolicyCovers` | `1.3.6.1.4.1.32473.1.1.638` | `string` | intent | multi | X-PATTERN `^[A-Za-z0-9][A-Za-z0-9._-]*$` | Whom a security service's risk policies cover: identity bindings' roles (users, groups), or all-users |
| <a id="a-ciampolicyexcludes"></a>`ciamPolicyExcludes` | `1.3.6.1.4.1.32473.1.1.639` | `string` | intent | multi | X-PATTERN `^[A-Za-z0-9][A-Za-z0-9._-]*$` | Whom a security service's risk policies leave out: identity bindings' roles (the break-glass accounts, so a policy can never lock everyone out) |
| <a id="a-ciampolicymode"></a>`ciamPolicyMode` | `1.3.6.1.4.1.32473.1.1.640` | enum: `report-only`, `enforced` | intent | single |  | Whether a security service's risk policies are enforced or only report what they would do (report-only when not given) |
| <a id="a-ciampreservationdays"></a>`ciamPreservationDays` | `1.3.6.1.4.1.32473.1.1.523` | `int` | meta | single | X-MIN `1` | How many days after a report a reporting obligation requires images of affected systems and monitoring data to be preserved (DFARS 252.204-7012: 90) |
| <a id="a-ciampreserveduntil"></a>`ciamPreservedUntil` | `1.3.6.1.4.1.32473.1.1.537` | `time` | meta | single |  | Until when an incident's images and monitoring data are preserved (held) |
| <a id="a-ciamprimenotifiedat"></a>`ciamPrimeNotifiedAt` | `1.3.6.1.4.1.32473.1.1.534` | `time` | meta | single |  | When a subcontractor gave the prime contractor an incident's report number |
| <a id="a-ciamprimeparty"></a>`ciamPrimeParty` | `1.3.6.1.4.1.32473.1.1.526` | `dn` | meta | single |  | The prime contractor (or next higher-tier subcontractor) a subcontractor's reporting obligation passes the authority's report number to (a party, with its contact) |
| <a id="a-ciamprovideraddon"></a>`ciamProviderAddOn` | `1.3.6.1.4.1.32473.1.1.570` | `string` | intent | multi |  | A Terraform provider beyond the cloud's own its roots may use, as its adapter names it (an add-on an operator allows: Azure's azapi for what azurerm doesn't manage) |
| <a id="a-ciamprovidername"></a>`ciamProviderName` | `1.3.6.1.4.1.32473.1.1.573` | `string` | meta | single |  | The cloud service provider, as its package names it |
| <a id="a-ciamquotadecision"></a>`ciamQuotaDecision` | `1.3.6.1.4.1.32473.1.1.506` | enum: `request`, `deny` | intent | single |  | The operator's decision on a quota the provider grants less of than needed: request an increase (rendered where the cloud takes requests) or deny it (the move stops until the need changes) |
| <a id="a-ciamquotakind"></a>`ciamQuotaKind` | `1.3.6.1.4.1.32473.1.1.504` | enum: `vcpus`, `public-ips`, `networks`, `load-balancers`, `database-instances`, `kubernetes-clusters` | binding | single |  | What a quota counts, by a kind every cloud limits: vcpus (the region's standard machines), public-ips, networks, load-balancers, database-instances, kubernetes-clusters (a provider's own quota: ciamProviderRef) |
| <a id="a-ciamquotaname"></a>`ciamQuotaName` | `1.3.6.1.4.1.32473.1.1.510` | `string` | meta | single |  | A quota's name as its provider shows it (Running On-Demand Standard instances, Total Regional vCPUs) |
| <a id="a-ciamquotaneeded"></a>`ciamQuotaNeeded` | `1.3.6.1.4.1.32473.1.1.505` | `int` | binding | single | X-MIN `1` | How many of what a quota counts an environment needs (the environments on one account and region need their sum) |
| <a id="a-ciamquotarequested"></a>`ciamQuotaRequested` | `1.3.6.1.4.1.32473.1.1.507` | `int` | intent | single | X-MIN `1` | The limit an increase request asks the provider for (when not given, what the environments need) |
| <a id="a-ciamquotausage"></a>`ciamQuotaUsage` | `1.3.6.1.4.1.32473.1.1.509` | `int` | observed | single | X-MIN `0` | How much of a quota the account used when it was fetched, when the provider says |
| <a id="a-ciamquotavalue"></a>`ciamQuotaValue` | `1.3.6.1.4.1.32473.1.1.508` | `int` | observed | single | X-MIN `0` | The limit a provider grants an account in a region, as fetched |
| <a id="a-ciamregionname"></a>`ciamRegionName` | `1.3.6.1.4.1.32473.1.1.489` | `string` | meta | single |  | A cloud region's name as its provider shows it (Europe (Ireland), West Europe, Belgium) |
| <a id="a-ciamregionstatus"></a>`ciamRegionStatus` | `1.3.6.1.4.1.32473.1.1.491` | enum: `available`, `opt-in`, `not-listed` | observed | single |  | A cloud region as its provider lists it: available, opt-in (open only to accounts that opt in) or not-listed (no longer listed; kept so what names it keeps its link) |
| <a id="a-ciamregulateddata"></a>`ciamRegulatedData` | `1.3.6.1.4.1.32473.1.1.656` | enum: `itar`, `ear`, `cjis`, `hipaa`, `irs-1075` | intent | multi |  | Regulated data an environment holds (or an obligation brings), by regime: itar, ear (export-controlled technical data), cjis (criminal justice information), hipaa (protected health information), irs-1075 (federal tax information); where it may be held is the cloud's to say |
| <a id="a-ciamreportedat"></a>`ciamReportedAt` | `1.3.6.1.4.1.32473.1.1.532` | `time` | meta | single |  | When an incident's report was submitted to its authority |
| <a id="a-ciamreportingauthority"></a>`ciamReportingAuthority` | `1.3.6.1.4.1.32473.1.1.520` | `dn` | meta | single |  | The authority a reporting obligation's reports go to (a party; its ciamContactUrl is where they are filed, e.g. https://dibnet.dod.mil) |
| <a id="a-ciamreportingcertificateref"></a>`ciamReportingCertificateRef` | `1.3.6.1.4.1.32473.1.1.524` | `dn` | meta | single |  | The certificate a reporting obligation's reports are filed with (a ciamCertificate: its public facts only; DFARS 252.204-7012: a DoD-approved medium assurance certificate) |
| <a id="a-ciamreportinghours"></a>`ciamReportingHours` | `1.3.6.1.4.1.32473.1.1.518` | `int` | meta | single | X-MIN `1` | How many hours from an incident's discovery a reporting obligation gives to report it to its authority (DFARS 252.204-7012: 72) |
| <a id="a-ciamreportingobligationref"></a>`ciamReportingObligationRef` | `1.3.6.1.4.1.32473.1.1.517` | `dn` | intent | multi |  | A reporting obligation an environment is held to, or an incident falls under (a ciamReportingObligation under ou=reporting-obligations) |
| <a id="a-ciamreportingparty"></a>`ciamReportingParty` | `1.3.6.1.4.1.32473.1.1.521` | `dn` | meta | single |  | Who files a reporting obligation's reports (a party: the operator's designated incident reporter) |
| <a id="a-ciamreportref"></a>`ciamReportRef` | `1.3.6.1.4.1.32473.1.1.533` | `string` | meta | single |  | The number the authority assigned an incident's report (DIBNet's incident report number) |
| <a id="a-ciamrequiredauthorization"></a>`ciamRequiredAuthorization` | `1.3.6.1.4.1.32473.1.1.585` | enum: `fedramp-low`, `fedramp-moderate`, `fedramp-high`, `dod-il2`, `dod-il4`, `dod-il5` | intent | multi |  | A level an environment's cloud authorization must meet (an obligation's requirement: dfars-7012 asks for fedramp-moderate; a DoD contract for dod-il4 or dod-il5) |
| <a id="a-ciamrequiresconfiguration"></a>`ciamRequiresConfiguration` | `1.3.6.1.4.1.32473.1.1.586` | enum: `assured-workload`, `us-data-location`, `us-person-support`, `il5-isolation` | meta | multi |  | What a customer must configure for its use to be inside an authorization's boundary: assured-workload, us-data-location, us-person-support, il5-isolation |
| <a id="a-ciamrescandays"></a>`ciamRescanDays` | `1.3.6.1.4.1.32473.1.1.595` | `int` | intent | single | X-MIN `1` | How often a data discovery service examines its stores again, in days (1 daily, 7 weekly, 30 monthly) |
| <a id="a-ciamresidencyref"></a>`ciamResidencyRef` | `1.3.6.1.4.1.32473.1.1.492` | `dn` | intent | single |  | The residency an environment's data is held to (a ciamResidency under ou=residencies) |
| <a id="a-ciamresponsibility"></a>`ciamResponsibility` | `1.3.6.1.4.1.32473.1.1.589` | enum: `inherited`, `shared`, `customer` | meta | single |  | Who meets a control under an authorization: inherited (the provider), shared, customer |
| <a id="a-ciamresultsrole"></a>`ciamResultsRole` | `1.3.6.1.4.1.32473.1.1.596` | `string` | intent | single |  | The role of the binding a data discovery service keeps its detailed results in (an object store): the record of where sensitive data was found |
| <a id="a-ciamretrievedat"></a>`ciamRetrievedAt` | `1.3.6.1.4.1.32473.1.1.582` | `time` | meta | single |  | When an imported list was taken from its source |
| <a id="a-ciamrevision"></a>`ciamRevision` | `1.3.6.1.4.1.32473.1.1.653` | `string` | observed | single |  | The revision of a provider's compliance framework or control, as fetched (a deployment names it) |
| <a id="a-ciamriskauthority"></a>`ciamRiskAuthority` | `1.3.6.1.4.1.32473.1.1.557` | `dn` | meta | single |  | Who may accept the risk an exception carries (a party: the authorizing official, the risk owner) |
| <a id="a-ciamriskpolicy"></a>`ciamRiskPolicy` | `1.3.6.1.4.1.32473.1.1.637` | `string` | intent | multi | X-PATTERN `^(sign-in\|user) (low\|medium\|high)\+: (mfa\|password-change\|risk-remediation\|block)$` | A risk-based sign-in policy a threat-detection service watching identity enforces: '<sign-in\|user> <low\|medium\|high>+: <mfa\|password-change\|risk-remediation\|block>' (sign-in medium+: mfa; password-change and risk-remediation answer a user's risk only) |
| <a id="a-ciamriskrating"></a>`ciamRiskRating` | `1.3.6.1.4.1.32473.1.1.547` | enum: `low`, `moderate`, `high` | meta | single |  | How much risk a weakness carries: low, moderate, high |
| <a id="a-ciamscansrole"></a>`ciamScansRole` | `1.3.6.1.4.1.32473.1.1.593` | `string` | binding | multi |  | The role of a store a data discovery service examines for sensitive data (an object store, a database, a volume) |
| <a id="a-ciamscheduledcompletion"></a>`ciamScheduledCompletion` | `1.3.6.1.4.1.32473.1.1.544` | `time` | meta | single |  | When a POA&M item is scheduled to be corrected |
| <a id="a-ciamscopeasof"></a>`ciamScopeAsOf` | `1.3.6.1.4.1.32473.1.1.580` | `time` | meta | single |  | When the in-scope service list an authorization holds was last updated by its provider |
| <a id="a-ciamsecurityadminref"></a>`ciamSecurityAdminRef` | `1.3.6.1.4.1.32473.1.1.650` | `string` | binding | single |  | The account that administers a cloud's security services for the whole organization: an AWS delegated administrator account ID (GuardDuty, Inspector, Security Hub, Config) |
| <a id="a-ciamsecuritybaseline"></a>`ciamSecurityBaseline` | `1.3.6.1.4.1.32473.1.1.502` | `string` | binding | multi | X-PATTERN `[a-z0-9]+(-[a-z0-9]+)*` | A cloud's own security baseline a posture service assesses, by the name its adapter gives it: one cloud's baseline never stands in for another's |
| <a id="a-ciamsecuritycoverage"></a>`ciamSecurityCoverage` | `1.3.6.1.4.1.32473.1.1.500` | enum: `control-plane`, `identity`, `network`, `compute`, `containers`, `storage`, `databases`, `key-vaults`, `applications`, `on-prem-directory` | binding | multi |  | What a threat-detection or vulnerability-scanning service watches: control-plane, identity, network, compute, containers, storage, databases, key-vaults, applications, on-prem-directory (the organization's own directory its users reach the cloud from) |
| <a id="a-ciamsecuritykind"></a>`ciamSecurityKind` | `1.3.6.1.4.1.32473.1.1.499` | enum: `threat-detection`, `vulnerability-scanning`, `config-recording`, `posture` | binding | single |  | What a cloud security service does: threat-detection, vulnerability-scanning, config-recording (resources' configuration and its changes) or posture (assessment against compliance frameworks and the cloud's own baseline) |
| <a id="a-ciamsourceurl"></a>`ciamSourceUrl` | `1.3.6.1.4.1.32473.1.1.581` | `url` | meta | single |  | Where an imported list was taken from (the provider's published package overview) |
| <a id="a-ciamsspref"></a>`ciamSspRef` | `1.3.6.1.4.1.32473.1.1.588` | `string` | meta | single |  | The system security plan a system boundary is documented in: its id and version |
| <a id="a-ciamtagkey"></a>`ciamTagKey` | `1.3.6.1.4.1.32473.1.1.486` | `string` | meta | single | X-PATTERN `[A-Za-z][A-Za-z0-9_.:/=+@-]{0,62}` | The key of a tag (a label on Google Cloud) every resource rendered for an environment carries |
| <a id="a-ciamtagsource"></a>`ciamTagSource` | `1.3.6.1.4.1.32473.1.1.487` | enum: `owner`, `cost-center`, `classification`, `environment`, `cloud`, `literal` | meta | single |  | Where a tag rule takes its value in each environment: the environment's owner, that owner's cost center, the environment's data classification, the environment (cloud/env), its cloud, or the rule's own value (literal: ciamTagValue) |
| <a id="a-ciamtagvalue"></a>`ciamTagValue` | `1.3.6.1.4.1.32473.1.1.488` | `string` | meta | single |  | A literal tag rule's value |
| <a id="a-ciamuei"></a>`ciamUei` | `1.3.6.1.4.1.32473.1.1.528` | `string` | meta | single | X-PATTERN `[A-Z0-9]{12}` | A party's Unique Entity ID (SAM.gov) |
| <a id="a-ciamvendordependency"></a>`ciamVendorDependency` | `1.3.6.1.4.1.32473.1.1.548` | `bool` | meta | single |  | Whether correcting a weakness waits on a vendor (tracked, not a deviation) |
| <a id="a-ciamweakness"></a>`ciamWeakness` | `1.3.6.1.4.1.32473.1.1.541` | `string` | meta | single |  | What is wrong: the weakness a POA&M item plans to correct |
