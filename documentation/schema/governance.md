# Governance

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 14 object classes · 69 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

**Branches:** `ou=applications,dc=ciam-ops`, `ou=changes,dc=ciam-ops`, `ou=grants,dc=ciam-ops`, `ou=imports,dc=ciam-ops`, `ou=incidents,dc=ciam-ops`, `ou=owners,dc=ciam-ops`, `ou=people,dc=ciam-ops`, `ou=runbooks,dc=ciam-ops`, `ou=source-objects,dc=ciam-ops`, `ou=tickets,dc=ciam-ops`, `ou=unknowns,dc=ciam-ops`

## Object classes

<a id="c-ciamapplication"></a>
### ciamApplication

An application as the business knows it, grouping the entries it is made of (ciamApplicationPart) and the binding roles it uses in each environment (ciamUsesRole): what an application view and its dependency graph show together; nothing is grouped unless recorded here

OID `1.3.6.1.4.1.32473.1.2.140` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamApplicationPart`](#a-ciamapplicationpart) |  | `dn` | multi | An entry that is part of the application (an integration, a directory consumer, an external service, a canary, a job): the views and dependency graph of the application start from its parts |
| [`ciamUsesRole`](automation.md#a-ciamusesrole) |  | `string` | multi | A binding role the job uses (a secret, a service name, a storage location): each environment binds it |
| [`ciamCriticality`](core.md#a-ciamcriticality) |  | `enum` | single | Business criticality |

<a id="c-ciamchange"></a>
### ciamChange

Change record (mirrored from ITSM; a proposed one may carry the records it applies, and names the ticket it is tracked by)

OID `1.3.6.1.4.1.32473.1.2.30` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamTitle`](#a-ciamtitle) | yes | `string` | single | Title |
| [`ciamChangeStatus`](#a-ciamchangestatus) | yes | `enum` | single | Change record status |
| [`ciamApprovedBy`](#a-ciamapprovedby) |  | `string` | single | Approver (CAB) |
| [`ciamPlannedAt`](#a-ciamplannedat) |  | `time` | single | Planned implementation time |
| [`ciamChangeRecords`](#a-ciamchangerecords) |  | `string` | single | The LDIF change records a proposed change applies once approved (an assisted fix, from an operator or an AI): what the approver reviews and what is applied, unchanged |
| [`ciamTicketRef`](#a-ciamticketref) |  | `string` | multi | An ITSM ticket a change record is tracked by, as <adapter>:<number> (servicenow:CHG0030101): the operator's link (its change ticket, and the work ticket a team was handed its findings by); what the ticket says is read into its own entry under ou=tickets, never here |
| [`ciamAuthor`](#a-ciamauthor) |  | `string` | single | Who wrote a change record: the database login that created it, set by the store (never by the writer) and kept; the approver is someone else unless approval-separation is off |

<a id="c-ciamcollectionattempt"></a>
### ciamCollectionAttempt

The last attempt by `opsdir collect` to collect one importer's export of one environment (or estate-wide), recorded under the change it ran with (ciamChangeRef) whatever the outcome: complete, or incomplete or skipped with its problems and the calls it made, so a failed collection stays visible after the run

OID `1.3.6.1.4.1.32473.1.2.129` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamImporter`](#a-ciamimporter) | yes | `string` | single | The importer an import run used (or a collection source feeds), as adapter/importer |
| [`ciamCollectionOutcome`](#a-ciamcollectionoutcome) | yes | `enum` | single | How a collection attempt ended: complete (its export read in full), incomplete (a call failed or was refused: nothing imported) or skipped (nothing collected: the identity check failed or the collector could not start) |
| [`ciamCollectedAt`](#a-ciamcollectedat) | yes | `time` | single | When a collection attempt read the live system |
| [`ciamCollectedEnvironment`](#a-ciamcollectedenvironment) |  | `extdn` | single | The environment a collection attempt read (absent: estate-wide, provider data such as regions and quotas); a DN, not a reference, like an import run's scopes |
| [`ciamCollectionProblem`](#a-ciamcollectionproblem) |  | `string` | multi | Why a collection attempt was incomplete or skipped: a failing call and its error output, a refused call, a bound reached, a failed identity check (credentials masked) |
| [`ciamCollectionIdentity`](#a-ciamcollectionidentity) |  | `string` | single | Who the provider said the collector was when an import run's export was collected, or a collection was attempted (its identity check: account, subscription, project) |
| [`ciamCollectedCall`](#a-ciamcollectedcall) |  | `string` | multi | A call that collected part of an import run's export, or that a collection attempt made: the SHA-256 of what it returned (absent: nothing there; failed: the call failed), the file it became and the command or URL (never a credential) |
| [`ciamCollectionCredential`](#a-ciamcollectioncredential) |  | `string` | multi | A credential reference an import run's collection, or a collection attempt, resolved (the reference, never the value) |

<a id="c-ciamcollectionsource"></a>
### ciamCollectionSource

Where `opsdir collect` reads an environment for an importer that needs more than the operator's own cloud login: a Terraform state object, or a product's admin endpoint (a URL, or the servers of a role on a port) with the credential and trust anchor it is read with: the operator's opt-in

OID `1.3.6.1.4.1.32473.1.2.128` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamImporter`](#a-ciamimporter) | yes | `string` | single | The importer an import run used (or a collection source feeds), as adapter/importer |
| [`ciamSourceRef`](#a-ciamsourceref) |  | `string` | single | Where a collection source is read: an endpoint URL (https://host:port) or a stored object (s3://bucket/key, azblob://account/container/blob, gs://bucket/object: a Terraform state, its workspace prefix included) |
| [`ciamTargetRole`](infrastructure.md#a-ciamtargetrole) |  | `vocab` | single | Server role a service or rule targets |
| [`ciamPort`](infrastructure.md#a-ciamport) |  | `port` | multi | TCP/UDP port |
| [`ciamCredentialRole`](#a-ciamcredentialrole) |  | `string` | single | The role of the binding holding the reference to the credential a collection source is read with (resolved when collecting, held in memory for the call, never stored) |
| [`ciamCaRole`](#a-ciamcarole) |  | `string` | single | The role of the certificate binding a collection source's TLS endpoint is trusted by |
| [`ciamLoginName`](#a-ciamloginname) |  | `string` | single | The account a collection source's credential signs in as (a read-only service account) |
| [`ciamCredentialScheme`](#a-ciamcredentialscheme) |  | `enum` | single | How a collection source's credential is sent: basic (a password, with ciamLoginName; the default), bearer (an access token or signed JWT minted outside opsdir, sent as Authorization: Bearer), token (a session token obtained outside opsdir, sent as the Authorization header's whole value), api-key (an API key, sent alone in the header the product names) or client-certificate (a PEM holding a client certificate, its chain and private key, presented in the TLS handshake: mutual TLS, no Authorization header); the importer's collector says which it accepts |

<a id="c-ciamgrant"></a>
### ciamGrant

A permission (under ou=grants): the actions it gives, to which people or teams, limited to which environments and to what which teams own or keep; once any grant is recorded, every action but reading and administration needs one

OID `1.3.6.1.4.1.32473.1.2.208` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamGrantAction`](#a-ciamgrantaction) | yes | `enum` | multi | An action a grant gives (the permission catalog: read, render, plan, migrate, propose, approve, apply, settings, workspace, admin) |
| [`ciamGrantee`](#a-ciamgrantee) | yes | `dn` | multi | Who a grant is for: a person (ciamPerson) or a team (ciamParty), every member of which holds it |
| [`ciamGrantEnvironment`](#a-ciamgrantenvironment) |  | `string` | multi | An environment (cloud/env) a grant is limited to; none: every environment |
| [`ciamGrantOwner`](#a-ciamgrantowner) |  | `dn` | multi | A team (ciamParty) whose areas a grant is limited to: what it owns or keeps; none: every area |
| [`description`](../SCHEMA.md#standard-description) |  | `string` |  | Free text |

<a id="c-ciamimportrun"></a>
### ciamImportRun

The last import by one importer of one scope set (ciamImportScope) in one environment (or of what environments share), named by the set: when the live system was read back, what it read and under which change (ciamChangeRef), and when opsdir collected the export itself, how (the identity the provider saw, each call and the hash of what it returned, the credential references used), otherwise each file it was read from and its hash (ciamImportedFile); what a fix that needs a fresh read checks

OID `1.3.6.1.4.1.32473.1.2.91` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamImporter`](#a-ciamimporter) | yes | `string` | single | The importer an import run used (or a collection source feeds), as adapter/importer |
| [`ciamImportScope`](#a-ciamimportscope) | yes | `extdn` | multi | The parts of the record an import run read back (bindings of an environment, a product's objects): what it made match the live system (DNs, not references: a run never holds what it read in place) |
| [`ciamImportedAt`](#a-ciamimportedat) | yes | `time` | single | When the export an import run read was taken (the live system as of then) |
| [`ciamCollectionIdentity`](#a-ciamcollectionidentity) |  | `string` | single | Who the provider said the collector was when an import run's export was collected, or a collection was attempted (its identity check: account, subscription, project) |
| [`ciamCollectedCall`](#a-ciamcollectedcall) |  | `string` | multi | A call that collected part of an import run's export, or that a collection attempt made: the SHA-256 of what it returned (absent: nothing there; failed: the call failed), the file it became and the command or URL (never a credential) |
| [`ciamCollectionCredential`](#a-ciamcollectioncredential) |  | `string` | multi | A credential reference an import run's collection, or a collection attempt, resolved (the reference, never the value) |
| [`ciamImportedFile`](#a-ciamimportedfile) |  | `string` | multi | A file an import run's export was read from when opsdir didn't collect it (an export read off disk, or provider commands' output): the SHA-256 of its text and its path in the export, never its content; what `opsdir onboard verify` checks the originals it is given against |

<a id="c-ciamincident"></a>
### ciamIncident

Incident / postmortem

OID `1.3.6.1.4.1.32473.1.2.31` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamTitle`](#a-ciamtitle) | yes | `string` | single | Title |
| [`ciamOpenedAt`](#a-ciamopenedat) | yes | `time` | single | Incident opened |
| [`ciamSeverity`](#a-ciamseverity) |  | `enum` | single | Incident severity |
| [`ciamInvolved`](#a-ciaminvolved) |  | `dn` | multi | Entries involved in the incident |
| [`ciamRootCause`](#a-ciamrootcause) |  | `string` | single | Root cause |

<a id="c-ciamparty"></a>
### ciamParty

Team, partner, vendor, or the operator of the platform (how to reach it: mail, telephone, contact link)

OID `1.3.6.1.4.1.32473.1.2.32` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamOwnerKind`](#a-ciamownerkind) | yes | `enum` | single | Kind of party |
| [`mail`](../SCHEMA.md#standard-mail) |  | `string` |  | Contact email |
| [`telephoneNumber`](../SCHEMA.md#standard-telephonenumber) |  | `string` |  | Contact telephone number |
| [`ciamContactUrl`](#a-ciamcontacturl) |  | `url` | single | Contact / escalation link |
| [`ciamDisplayName`](#a-ciamdisplayname) |  | `string` | single | Name used in correspondence (the organization operating the platform, a team) |
| [`ciamTakesGeneratedInfra`](#a-ciamtakesgeneratedinfra) |  | `bool` | single | Whether the party takes the infrastructure opsdir generates for what it keeps (ciamManagedBy, the landing zone it owns): TRUE, the default render gives it its own complete root to apply; absent or FALSE, what it keeps is named in the render and asked of it in a request, and its root is rendered only on a keeper-scoped request |

<a id="c-ciamperson"></a>
### ciamPerson

A person who works on the record (under ou=people), named by their own database login (cn), and the teams they belong to; once people are recorded, only a recorded person approves a change

OID `1.3.6.1.4.1.32473.1.2.207` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamDisplayName`](#a-ciamdisplayname) |  | `string` | single | Name used in correspondence (the organization operating the platform, a team) |
| [`mail`](../SCHEMA.md#standard-mail) |  | `string` |  | Contact email |
| [`ciamMemberOf`](#a-ciammemberof) |  | `dn` | multi | The teams (ciamParty) a person belongs to |
| [`ciamIdpSubject`](#a-ciamidpsubject) |  | `string` | multi | How the company's identity provider names the person: '<issuer> <subject>', the token's iss and sub claims; how the HTTP API finds who signed in |
| [`description`](../SCHEMA.md#standard-description) |  | `string` |  | Free text |

<a id="c-ciamrecordidentity"></a>
### ciamRecordIdentity

The record's own identity (cn=record, below the root): the organization or company it belongs to, its identifier and its group; carried in exports and evidence so two companies' records can be combined after a merger

OID `1.3.6.1.4.1.32473.1.2.206` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamOrgCode`](#a-ciamorgcode) | yes | `string` | single | The code of the organization or company a record belongs to (lowercase letters, digits, single hyphens): fixed once set, and the prefix of its change records' names |
| [`ciamRecordId`](#a-ciamrecordid) | yes | `string` | single | A record's own identifier (a UUID made when its identity is first set): fixed once set, so the record is told apart from any other, even one using the same org code |
| [`ciamParentOrgCode`](#a-ciamparentorgcode) |  | `string` | single | The org code of the group a company's record belongs to (a subsidiary's parent); may change, as when a company leaves its group |
| [`description`](../SCHEMA.md#standard-description) |  | `string` |  | Free text |

<a id="c-ciamrunbook"></a>
### ciamRunbook

Work instruction

OID `1.3.6.1.4.1.32473.1.2.29` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamTitle`](#a-ciamtitle) | yes | `string` | single | Title |
| [`ciamLastValidated`](#a-ciamlastvalidated) | yes | `time` | single | When the work instruction was last validated against config |
| [`ciamVersion`](#a-ciamversion) |  | `string` | single | Document version |
| [`ciamAppliesTo`](#a-ciamappliesto) |  | `dn` | multi | Entries this work instruction depends on |
| [`ciamDocUrl`](#a-ciamdocurl) |  | `url` | single | Document location |

<a id="c-ciamsourceobject"></a>
### ciamSourceObject

What a product a migration retires holds that the standard model has no equivalent for (under ou=source-objects, below a branch per importer): its own type and facts, the server role that holds it (ciamTargetRole), how it is handled and whether a move waits for that (ciamBlocking), the entries it concerns; the planner makes each an action, or a blocker, for a target that doesn't run the role

OID `1.3.6.1.4.1.32473.1.2.163` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamSourceClass`](#a-ciamsourceclass) | yes | `string` | single | The product's own type of a source object, as the product names it |
| [`ciamTargetRole`](infrastructure.md#a-ciamtargetrole) | yes | `vocab` | single | Server role a service or rule targets |
| [`ciamHandling`](#a-ciamhandling) | yes | `enum` | single | What a source object needs when its product is retired: rebuilt in the target's products, its secrets re-provisioned, its hosts re-registered, replaced by what the target already does, retired (nothing in the target needs it) or reviewed (what it does isn't known yet) |
| [`ciamSourceFact`](#a-ciamsourcefact) |  | `string` | multi | What a source object holds, as "<setting> <value>" (never a secret: sensitive settings are named by the importer as withheld, not kept) |
| [`ciamHow`](#a-ciamhow) |  | `string` | single | How a source object is handled, in words: what the target needs instead and where |
| [`ciamBlocking`](#a-ciamblocking) |  | `bool` | single | Whether a move may not proceed without the answer: TRUE, the planner blocks while it is open; absent or FALSE, an open question is an action |
| [`ciamConcerns`](#a-ciamconcerns) |  | `dn` | multi | The environments (or entries inside them) a question concerns; none: the whole estate. A DN, not a reference |
| [`ciamImportedAt`](#a-ciamimportedat) |  | `time` | single | When the export an import run read was taken (the live system as of then) |

<a id="c-ciamticket"></a>
### ciamTicket

An ITSM ticket a change record names (ciamTicketRef), as its add-on's importer last read it (under cn=<number>,ou=<adapter>,ou=tickets; ciamImportedAt: when the export was taken): its state, overall approval, planned and actual windows, approval records and other fields, with the system's own identifier (ciamProviderRef) and address (ciamDocUrl). Evidence compared with the record, never an approval opsdir acts on

OID `1.3.6.1.4.1.32473.1.2.156` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamImportedAt`](#a-ciamimportedat) | yes | `time` | single | When the export an import run read was taken (the live system as of then) |
| [`ciamTitle`](#a-ciamtitle) |  | `string` | single | Title |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamDocUrl`](#a-ciamdocurl) |  | `url` | single | Document location |
| [`ciamTicketState`](#a-ciamticketstate) |  | `enum` | single | A ticket's lifecycle state in neutral terms, as its add-on maps the system's own (absent: the mapping doesn't know the ticket's state model; ciamTicketNativeState holds what the system said) |
| [`ciamTicketApproval`](#a-ciamticketapproval) |  | `enum` | single | The ticket's overall approval as its system reports it: evidence, never an approval of the record's change |
| [`ciamTicketNativeState`](#a-ciamticketnativestate) |  | `string` | single | The ticket's state as its system gives it (its raw code, then its label when the export has one) |
| [`ciamTicketPlannedStart`](#a-ciamticketplannedstart) |  | `time` | single | When the ticket plans the work to start |
| [`ciamTicketPlannedEnd`](#a-ciamticketplannedend) |  | `time` | single | When the ticket plans the work to end |
| [`ciamTicketWorkStart`](#a-ciamticketworkstart) |  | `time` | single | When the ticket says the work actually started |
| [`ciamTicketWorkEnd`](#a-ciamticketworkend) |  | `time` | single | When the ticket says the work actually ended |
| [`ciamTicketApprover`](#a-ciamticketapprover) |  | `string` | multi | One approval record of the ticket, as detail only: "<state> <approver id> updated <time>" (the system's identifiers, never names; the update time is not when it was approved) |
| [`ciamTicketFact`](#a-ciamticketfact) |  | `string` | multi | Another field of the ticket as its system gave it: "<field> <raw value>" (type, model, close code, assignment group, configuration item, requester, correlation, last update) |
| [`ciamTicketApprovalStep`](#a-ciamticketapprovalstep) |  | `string` | multi | One approval step of the ticket as its system decided it, where approval goes by steps (a workflow's approval statuses): "<approved\|declined\|pending> <step id> created <time>[ completed <time>]"; the overall approval its add-on derives from them is ciamTicketApproval, the people asked are ciamTicketApprover |
| [`ciamTicketChangeType`](#a-ciamticketchangetype) |  | `enum` | single | The kind of change the ticket is, in neutral terms: standard (pre-approved), normal or emergency, as its system classes it |
| [`ciamTicketKind`](#a-ciamticketkind) |  | `enum` | single | What the ticket is: a change ticket (change management approves it; absent means change) or a work ticket handing work to a team (a ServiceNow task, a Jira issue, a work order), which has no approval to compare |
| [`ciamTicketDue`](#a-ciamticketdue) |  | `time` | single | When a work ticket wants the work done (its due date or scheduled end) |

<a id="c-ciamunknown"></a>
### ciamUnknown

A question the record can't answer yet (under ou=unknowns): what isn't known, the party who must answer it (ciamOwner), whether a move waits for it, what it concerns, when it was raised and is needed, and its answer once given; the planner counts the open ones

OID `1.3.6.1.4.1.32473.1.2.137` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamQuestion`](#a-ciamquestion) | yes | `string` | single | What isn't known: the question someone must answer |
| [`ciamOwner`](core.md#a-ciamowner) | yes | `dn` | multi | Owning party (team, partner, vendor) |
| [`ciamBlocking`](#a-ciamblocking) |  | `bool` | single | Whether a move may not proceed without the answer: TRUE, the planner blocks while it is open; absent or FALSE, an open question is an action |
| [`ciamConcerns`](#a-ciamconcerns) |  | `dn` | multi | The environments (or entries inside them) a question concerns; none: the whole estate. A DN, not a reference |
| [`ciamRaisedAt`](#a-ciamraisedat) |  | `time` | single | When the question was asked |
| [`ciamNeededBy`](#a-ciamneededby) |  | `time` | single | When the answer is needed: the planner dates the open question by it (else the planned cutover) |
| [`ciamAnswer`](#a-ciamanswer) |  | `string` | single | The answer: a question that has one is answered |
| [`ciamAnsweredAt`](#a-ciamansweredat) |  | `time` | single | When the question was answered |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamanswer"></a>`ciamAnswer` | `1.3.6.1.4.1.32473.1.1.666` | `string` | meta | single |  | The answer: a question that has one is answered |
| <a id="a-ciamansweredat"></a>`ciamAnsweredAt` | `1.3.6.1.4.1.32473.1.1.667` | `time` | meta | single |  | When the question was answered |
| <a id="a-ciamapplicationpart"></a>`ciamApplicationPart` | `1.3.6.1.4.1.32473.1.1.670` | `dn` | meta | multi |  | An entry that is part of the application (an integration, a directory consumer, an external service, a canary, a job): the views and dependency graph of the application start from its parts |
| <a id="a-ciamappliesto"></a>`ciamAppliesTo` | `1.3.6.1.4.1.32473.1.1.112` | `dn` | meta | multi |  | Entries this work instruction depends on |
| <a id="a-ciamapprovedby"></a>`ciamApprovedBy` | `1.3.6.1.4.1.32473.1.1.116` | `string` | meta | single |  | Approver (CAB) |
| <a id="a-ciamauthor"></a>`ciamAuthor` | `1.3.6.1.4.1.32473.1.1.978` | `string` | meta | single |  | Who wrote a change record: the database login that created it, set by the store (never by the writer) and kept; the approver is someone else unless approval-separation is off |
| <a id="a-ciamblocking"></a>`ciamBlocking` | `1.3.6.1.4.1.32473.1.1.662` | `bool` | meta | single |  | Whether a move may not proceed without the answer: TRUE, the planner blocks while it is open; absent or FALSE, an open question is an action |
| <a id="a-ciamcarole"></a>`ciamCaRole` | `1.3.6.1.4.1.32473.1.1.599` | `string` | intent | single |  | The role of the certificate binding a collection source's TLS endpoint is trusted by |
| <a id="a-ciamchangerecords"></a>`ciamChangeRecords` | `1.3.6.1.4.1.32473.1.1.421` | `string` | meta | single |  | The LDIF change records a proposed change applies once approved (an assisted fix, from an operator or an AI): what the approver reviews and what is applied, unchanged |
| <a id="a-ciamchangestatus"></a>`ciamChangeStatus` | `1.3.6.1.4.1.32473.1.1.115` | enum: `proposed`, `approved`, `applied`, `rejected` | meta | single |  | Change record status |
| <a id="a-ciamcollectedat"></a>`ciamCollectedAt` | `1.3.6.1.4.1.32473.1.1.605` | `time` | meta | single |  | When a collection attempt read the live system |
| <a id="a-ciamcollectedcall"></a>`ciamCollectedCall` | `1.3.6.1.4.1.32473.1.1.602` | `string` | meta | multi |  | A call that collected part of an import run's export, or that a collection attempt made: the SHA-256 of what it returned (absent: nothing there; failed: the call failed), the file it became and the command or URL (never a credential) |
| <a id="a-ciamcollectedenvironment"></a>`ciamCollectedEnvironment` | `1.3.6.1.4.1.32473.1.1.607` | `extdn` | meta | single |  | The environment a collection attempt read (absent: estate-wide, provider data such as regions and quotas); a DN, not a reference, like an import run's scopes |
| <a id="a-ciamcollectioncredential"></a>`ciamCollectionCredential` | `1.3.6.1.4.1.32473.1.1.603` | `string` | meta | multi |  | A credential reference an import run's collection, or a collection attempt, resolved (the reference, never the value) |
| <a id="a-ciamcollectionidentity"></a>`ciamCollectionIdentity` | `1.3.6.1.4.1.32473.1.1.601` | `string` | meta | single |  | Who the provider said the collector was when an import run's export was collected, or a collection was attempted (its identity check: account, subscription, project) |
| <a id="a-ciamcollectionoutcome"></a>`ciamCollectionOutcome` | `1.3.6.1.4.1.32473.1.1.604` | enum: `complete`, `incomplete`, `skipped` | meta | single |  | How a collection attempt ended: complete (its export read in full), incomplete (a call failed or was refused: nothing imported) or skipped (nothing collected: the identity check failed or the collector could not start) |
| <a id="a-ciamcollectionproblem"></a>`ciamCollectionProblem` | `1.3.6.1.4.1.32473.1.1.606` | `string` | meta | multi |  | Why a collection attempt was incomplete or skipped: a failing call and its error output, a refused call, a bound reached, a failed identity check (credentials masked) |
| <a id="a-ciamconcerns"></a>`ciamConcerns` | `1.3.6.1.4.1.32473.1.1.663` | `dn` | meta | multi |  | The environments (or entries inside them) a question concerns; none: the whole estate. A DN, not a reference |
| <a id="a-ciamcontacturl"></a>`ciamContactUrl` | `1.3.6.1.4.1.32473.1.1.123` | `url` | meta | single |  | Contact / escalation link |
| <a id="a-ciamcredentialrole"></a>`ciamCredentialRole` | `1.3.6.1.4.1.32473.1.1.598` | `string` | intent | single |  | The role of the binding holding the reference to the credential a collection source is read with (resolved when collecting, held in memory for the call, never stored) |
| <a id="a-ciamcredentialscheme"></a>`ciamCredentialScheme` | `1.3.6.1.4.1.32473.1.1.633` | enum: `basic`, `bearer`, `token`, `api-key`, `client-certificate` | intent | single |  | How a collection source's credential is sent: basic (a password, with ciamLoginName; the default), bearer (an access token or signed JWT minted outside opsdir, sent as Authorization: Bearer), token (a session token obtained outside opsdir, sent as the Authorization header's whole value), api-key (an API key, sent alone in the header the product names) or client-certificate (a PEM holding a client certificate, its chain and private key, presented in the TLS handshake: mutual TLS, no Authorization header); the importer's collector says which it accepts |
| <a id="a-ciamdisplayname"></a>`ciamDisplayName` | `1.3.6.1.4.1.32473.1.1.124` | `string` | meta | single |  | Name used in correspondence (the organization operating the platform, a team) |
| <a id="a-ciamdocurl"></a>`ciamDocUrl` | `1.3.6.1.4.1.32473.1.1.114` | `url` | meta | single |  | Document location |
| <a id="a-ciamgrantaction"></a>`ciamGrantAction` | `1.3.6.1.4.1.32473.1.1.980` | enum: `read`, `render`, `plan`, `migrate`, `propose`, `approve`, `apply`, `settings`, `workspace`, `admin` | meta | multi |  | An action a grant gives (the permission catalog: read, render, plan, migrate, propose, approve, apply, settings, workspace, admin) |
| <a id="a-ciamgrantee"></a>`ciamGrantee` | `1.3.6.1.4.1.32473.1.1.981` | `dn` | meta | multi |  | Who a grant is for: a person (ciamPerson) or a team (ciamParty), every member of which holds it |
| <a id="a-ciamgrantenvironment"></a>`ciamGrantEnvironment` | `1.3.6.1.4.1.32473.1.1.982` | `string` | meta | multi | X-PATTERN `^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$` | An environment (cloud/env) a grant is limited to; none: every environment |
| <a id="a-ciamgrantowner"></a>`ciamGrantOwner` | `1.3.6.1.4.1.32473.1.1.983` | `dn` | meta | multi |  | A team (ciamParty) whose areas a grant is limited to: what it owns or keeps; none: every area |
| <a id="a-ciamhandling"></a>`ciamHandling` | `1.3.6.1.4.1.32473.1.1.762` | enum: `rebuild`, `re-provision`, `re-register`, `replace`, `retire`, `review` | meta | single |  | What a source object needs when its product is retired: rebuilt in the target's products, its secrets re-provisioned, its hosts re-registered, replaced by what the target already does, retired (nothing in the target needs it) or reviewed (what it does isn't known yet) |
| <a id="a-ciamhow"></a>`ciamHow` | `1.3.6.1.4.1.32473.1.1.763` | `string` | meta | single |  | How a source object is handled, in words: what the target needs instead and where |
| <a id="a-ciamidpsubject"></a>`ciamIdpSubject` | `1.3.6.1.4.1.32473.1.1.987` | `string` | meta | multi | X-PATTERN `^https://[^ ]+ [^ ]+$` | How the company's identity provider names the person: '<issuer> <subject>', the token's iss and sub claims; how the HTTP API finds who signed in |
| <a id="a-ciamimportedat"></a>`ciamImportedAt` | `1.3.6.1.4.1.32473.1.1.424` | `time` | meta | single |  | When the export an import run read was taken (the live system as of then) |
| <a id="a-ciamimportedfile"></a>`ciamImportedFile` | `1.3.6.1.4.1.32473.1.1.986` | `string` | meta | multi |  | A file an import run's export was read from when opsdir didn't collect it (an export read off disk, or provider commands' output): the SHA-256 of its text and its path in the export, never its content; what `opsdir onboard verify` checks the originals it is given against |
| <a id="a-ciamimporter"></a>`ciamImporter` | `1.3.6.1.4.1.32473.1.1.422` | `string` | meta | single |  | The importer an import run used (or a collection source feeds), as adapter/importer |
| <a id="a-ciamimportscope"></a>`ciamImportScope` | `1.3.6.1.4.1.32473.1.1.423` | `extdn` | meta | multi |  | The parts of the record an import run read back (bindings of an environment, a product's objects): what it made match the live system (DNs, not references: a run never holds what it read in place) |
| <a id="a-ciaminvolved"></a>`ciamInvolved` | `1.3.6.1.4.1.32473.1.1.120` | `dn` | meta | multi |  | Entries involved in the incident |
| <a id="a-ciamlastvalidated"></a>`ciamLastValidated` | `1.3.6.1.4.1.32473.1.1.113` | `time` | meta | single |  | When the work instruction was last validated against config |
| <a id="a-ciamloginname"></a>`ciamLoginName` | `1.3.6.1.4.1.32473.1.1.600` | `string` | intent | single |  | The account a collection source's credential signs in as (a read-only service account) |
| <a id="a-ciammemberof"></a>`ciamMemberOf` | `1.3.6.1.4.1.32473.1.1.979` | `dn` | meta | multi |  | The teams (ciamParty) a person belongs to |
| <a id="a-ciamneededby"></a>`ciamNeededBy` | `1.3.6.1.4.1.32473.1.1.665` | `time` | meta | single |  | When the answer is needed: the planner dates the open question by it (else the planned cutover) |
| <a id="a-ciamopenedat"></a>`ciamOpenedAt` | `1.3.6.1.4.1.32473.1.1.118` | `time` | meta | single |  | Incident opened |
| <a id="a-ciamorgcode"></a>`ciamOrgCode` | `1.3.6.1.4.1.32473.1.1.975` | `string` | meta | single | X-PATTERN `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`; X-MAX-LENGTH `32` | The code of the organization or company a record belongs to (lowercase letters, digits, single hyphens): fixed once set, and the prefix of its change records' names |
| <a id="a-ciamownerkind"></a>`ciamOwnerKind` | `1.3.6.1.4.1.32473.1.1.122` | enum: `team`, `partner`, `vendor`, `operator` | meta | single |  | Kind of party |
| <a id="a-ciamparentorgcode"></a>`ciamParentOrgCode` | `1.3.6.1.4.1.32473.1.1.977` | `string` | meta | single | X-PATTERN `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`; X-MAX-LENGTH `32` | The org code of the group a company's record belongs to (a subsidiary's parent); may change, as when a company leaves its group |
| <a id="a-ciamplannedat"></a>`ciamPlannedAt` | `1.3.6.1.4.1.32473.1.1.117` | `time` | meta | single |  | Planned implementation time |
| <a id="a-ciamquestion"></a>`ciamQuestion` | `1.3.6.1.4.1.32473.1.1.661` | `string` | meta | single |  | What isn't known: the question someone must answer |
| <a id="a-ciamraisedat"></a>`ciamRaisedAt` | `1.3.6.1.4.1.32473.1.1.664` | `time` | meta | single |  | When the question was asked |
| <a id="a-ciamrecordid"></a>`ciamRecordId` | `1.3.6.1.4.1.32473.1.1.976` | `string` | meta | single | X-PATTERN `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$` | A record's own identifier (a UUID made when its identity is first set): fixed once set, so the record is told apart from any other, even one using the same org code |
| <a id="a-ciamrootcause"></a>`ciamRootCause` | `1.3.6.1.4.1.32473.1.1.121` | `string` | meta | single |  | Root cause |
| <a id="a-ciamseverity"></a>`ciamSeverity` | `1.3.6.1.4.1.32473.1.1.119` | enum: `sev1`, `sev2`, `sev3`, `sev4` | meta | single |  | Incident severity |
| <a id="a-ciamsourceclass"></a>`ciamSourceClass` | `1.3.6.1.4.1.32473.1.1.760` | `string` | observed | single |  | The product's own type of a source object, as the product names it |
| <a id="a-ciamsourcefact"></a>`ciamSourceFact` | `1.3.6.1.4.1.32473.1.1.761` | `string` | observed | multi |  | What a source object holds, as "<setting> <value>" (never a secret: sensitive settings are named by the importer as withheld, not kept) |
| <a id="a-ciamsourceref"></a>`ciamSourceRef` | `1.3.6.1.4.1.32473.1.1.597` | `string` | binding | single |  | Where a collection source is read: an endpoint URL (https://host:port) or a stored object (s3://bucket/key, azblob://account/container/blob, gs://bucket/object: a Terraform state, its workspace prefix included) |
| <a id="a-ciamtakesgeneratedinfra"></a>`ciamTakesGeneratedInfra` | `1.3.6.1.4.1.32473.1.1.646` | `bool` | meta | single |  | Whether the party takes the infrastructure opsdir generates for what it keeps (ciamManagedBy, the landing zone it owns): TRUE, the default render gives it its own complete root to apply; absent or FALSE, what it keeps is named in the render and asked of it in a request, and its root is rendered only on a keeper-scoped request |
| <a id="a-ciamticketapproval"></a>`ciamTicketApproval` | `1.3.6.1.4.1.32473.1.1.742` | enum: `not-requested`, `requested`, `approved`, `rejected` | meta | single |  | The ticket's overall approval as its system reports it: evidence, never an approval of the record's change |
| <a id="a-ciamticketapprovalstep"></a>`ciamTicketApprovalStep` | `1.3.6.1.4.1.32473.1.1.834` | `string` | meta | multi |  | One approval step of the ticket as its system decided it, where approval goes by steps (a workflow's approval statuses): "<approved\|declined\|pending> <step id> created <time>[ completed <time>]"; the overall approval its add-on derives from them is ciamTicketApproval, the people asked are ciamTicketApprover |
| <a id="a-ciamticketapprover"></a>`ciamTicketApprover` | `1.3.6.1.4.1.32473.1.1.748` | `string` | meta | multi |  | One approval record of the ticket, as detail only: "<state> <approver id> updated <time>" (the system's identifiers, never names; the update time is not when it was approved) |
| <a id="a-ciamticketchangetype"></a>`ciamTicketChangeType` | `1.3.6.1.4.1.32473.1.1.835` | enum: `standard`, `normal`, `emergency` | meta | single |  | The kind of change the ticket is, in neutral terms: standard (pre-approved), normal or emergency, as its system classes it |
| <a id="a-ciamticketdue"></a>`ciamTicketDue` | `1.3.6.1.4.1.32473.1.1.985` | `time` | meta | single |  | When a work ticket wants the work done (its due date or scheduled end) |
| <a id="a-ciamticketfact"></a>`ciamTicketFact` | `1.3.6.1.4.1.32473.1.1.749` | `string` | meta | multi |  | Another field of the ticket as its system gave it: "<field> <raw value>" (type, model, close code, assignment group, configuration item, requester, correlation, last update) |
| <a id="a-ciamticketkind"></a>`ciamTicketKind` | `1.3.6.1.4.1.32473.1.1.984` | enum: `change`, `work` | meta | single |  | What the ticket is: a change ticket (change management approves it; absent means change) or a work ticket handing work to a team (a ServiceNow task, a Jira issue, a work order), which has no approval to compare |
| <a id="a-ciamticketnativestate"></a>`ciamTicketNativeState` | `1.3.6.1.4.1.32473.1.1.743` | `string` | meta | single |  | The ticket's state as its system gives it (its raw code, then its label when the export has one) |
| <a id="a-ciamticketplannedend"></a>`ciamTicketPlannedEnd` | `1.3.6.1.4.1.32473.1.1.745` | `time` | meta | single |  | When the ticket plans the work to end |
| <a id="a-ciamticketplannedstart"></a>`ciamTicketPlannedStart` | `1.3.6.1.4.1.32473.1.1.744` | `time` | meta | single |  | When the ticket plans the work to start |
| <a id="a-ciamticketref"></a>`ciamTicketRef` | `1.3.6.1.4.1.32473.1.1.740` | `string` | meta | multi |  | An ITSM ticket a change record is tracked by, as <adapter>:<number> (servicenow:CHG0030101): the operator's link (its change ticket, and the work ticket a team was handed its findings by); what the ticket says is read into its own entry under ou=tickets, never here |
| <a id="a-ciamticketstate"></a>`ciamTicketState` | `1.3.6.1.4.1.32473.1.1.741` | enum: `new`, `assess`, `authorize`, `scheduled`, `implement`, `review`, `closed`, `cancelled` | meta | single |  | A ticket's lifecycle state in neutral terms, as its add-on maps the system's own (absent: the mapping doesn't know the ticket's state model; ciamTicketNativeState holds what the system said) |
| <a id="a-ciamticketworkend"></a>`ciamTicketWorkEnd` | `1.3.6.1.4.1.32473.1.1.747` | `time` | meta | single |  | When the ticket says the work actually ended |
| <a id="a-ciamticketworkstart"></a>`ciamTicketWorkStart` | `1.3.6.1.4.1.32473.1.1.746` | `time` | meta | single |  | When the ticket says the work actually started |
| <a id="a-ciamtitle"></a>`ciamTitle` | `1.3.6.1.4.1.32473.1.1.110` | `string` | meta | single |  | Title |
| <a id="a-ciamversion"></a>`ciamVersion` | `1.3.6.1.4.1.32473.1.1.111` | `string` | meta | single |  | Document version |
