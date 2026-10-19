"""governance domain schema fragment: its attribute types and object classes (OIDs pinned by number)."""
from ...core.standard import AttributeDef, ClassDef, enum_type, fragment

# How a source object is handled when its product is retired (governance.source_objects)
HANDLINGS = ("rebuild", "re-provision", "re-register", "replace", "retire", "review")
# An ITSM ticket's lifecycle state and overall approval in neutral terms (governance.tickets): what each ITSM add-on
# maps its system's own states and approvals to (an operator's mapping is checked against these)
TICKET_STATES = ("new", "assess", "authorize", "scheduled", "implement", "review", "closed", "cancelled")
TICKET_APPROVALS = ("not-requested", "requested", "approved", "rejected")
TICKET_CHANGE_TYPES = ("standard", "normal", "emergency")
# What a ticket is (ciamTicketKind): a change ticket change management approves, or a work ticket handing work to a
# team (a draft opsdir wrote for a team's findings, filed by the team: decision 3409)
TICKET_KINDS = ("change", "work")
# The permission catalog (governance.grants): every action an operation is one of
ACTIONS = ("read", "render", "plan", "migrate", "propose", "approve", "apply", "settings", "workspace", "admin")
# A record identity's org codes (governance.identity) and record ID
ORG_CODE = "^[a-z][a-z0-9]*(-[a-z0-9]+)*$"
UUID = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

ATTRIBUTES = (
    AttributeDef(110, 'ciamTitle', 'string', 'meta', True,
                 'Title'),
    AttributeDef(111, 'ciamVersion', 'string', 'meta', True,
                 'Document version'),
    AttributeDef(112, 'ciamAppliesTo', 'dn', 'meta', False,
                 'Entries this work instruction depends on'),
    AttributeDef(113, 'ciamLastValidated', 'time', 'meta', True,
                 'When the work instruction was last validated against config'),
    AttributeDef(114, 'ciamDocUrl', 'url', 'meta', True,
                 'Document location'),
    AttributeDef(115, 'ciamChangeStatus', 'enum:proposed|approved|applied|rejected', 'meta', True,
                 'Change record status'),
    AttributeDef(116, 'ciamApprovedBy', 'string', 'meta', True,
                 'Approver (CAB)'),
    AttributeDef(117, 'ciamPlannedAt', 'time', 'meta', True,
                 'Planned implementation time'),
    AttributeDef(118, 'ciamOpenedAt', 'time', 'meta', True,
                 'Incident opened'),
    AttributeDef(119, 'ciamSeverity', 'enum:sev1|sev2|sev3|sev4', 'meta', True,
                 'Incident severity'),
    AttributeDef(120, 'ciamInvolved', 'dn', 'meta', False,
                 'Entries involved in the incident'),
    AttributeDef(121, 'ciamRootCause', 'string', 'meta', True,
                 'Root cause'),
    AttributeDef(122, 'ciamOwnerKind', 'enum:team|partner|vendor|operator', 'meta', True,
                 'Kind of party'),
    AttributeDef(123, 'ciamContactUrl', 'url', 'meta', True,
                 'Contact / escalation link'),
    AttributeDef(124, 'ciamDisplayName', 'string', 'meta', True,
                 'Name used in correspondence (the organization operating the platform, a team)'),
    AttributeDef(646, 'ciamTakesGeneratedInfra', 'bool', 'meta', True,
                 'Whether the party takes the infrastructure opsdir generates for what it keeps (ciamManagedBy, the '
                 'landing zone it owns): TRUE, the default render gives it its own complete root to apply; absent or '
                 'FALSE, what it keeps is named in the render and asked of it in a request, and its root is rendered '
                 'only on a keeper-scoped request'),
    AttributeDef(421, 'ciamChangeRecords', 'string', 'meta', True,
                 'The LDIF change records a proposed change applies once approved (an assisted fix, from an '
                 'operator or an AI): what the approver reviews and what is applied, unchanged'),
    AttributeDef(422, 'ciamImporter', 'string', 'meta', True,
                 'The importer an import run used (or a collection source feeds), as adapter/importer'),
    AttributeDef(423, 'ciamImportScope', 'extdn', 'meta', False,
                 'The parts of the record an import run read back (bindings of an environment, a product\'s '
                 'objects): what it made match the live system (DNs, not references: a run never holds what it read '
                 'in place)'),
    AttributeDef(424, 'ciamImportedAt', 'time', 'meta', True,
                 'When the export an import run read was taken (the live system as of then)'),
    AttributeDef(597, 'ciamSourceRef', 'string', 'binding', True,
                 'Where a collection source is read: an endpoint URL (https://host:port) or a stored object '
                 '(s3://bucket/key, azblob://account/container/blob, gs://bucket/object: a Terraform state, its '
                 'workspace prefix included)'),
    AttributeDef(598, 'ciamCredentialRole', 'string', 'intent', True,
                 'The role of the binding holding the reference to the credential a collection source is read with '
                 '(resolved when collecting, held in memory for the call, never stored)'),
    AttributeDef(599, 'ciamCaRole', 'string', 'intent', True,
                 'The role of the certificate binding a collection source\'s TLS endpoint is trusted by'),
    AttributeDef(600, 'ciamLoginName', 'string', 'intent', True,
                 'The account a collection source\'s credential signs in as (a read-only service account)'),
    AttributeDef(633, 'ciamCredentialScheme', 'enum:basic|bearer|token|api-key|client-certificate', 'intent', True,
                 'How a collection source\'s credential is sent: basic (a password, with ciamLoginName; the default), '
                 'bearer (an access token or signed JWT minted outside opsdir, sent as Authorization: Bearer), '
                 'token (a session token obtained outside opsdir, sent as the Authorization header\'s whole value), '
                 'api-key (an API key, sent alone in the header the product names) or client-certificate (a PEM '
                 'holding a client certificate, its chain and private key, presented in the TLS handshake: mutual '
                 'TLS, no Authorization header); the importer\'s collector says which it accepts'),
    AttributeDef(601, 'ciamCollectionIdentity', 'string', 'meta', True,
                 'Who the provider said the collector was when an import run\'s export was collected, or a collection '
                 'was attempted (its identity check: account, subscription, project)'),
    AttributeDef(602, 'ciamCollectedCall', 'string', 'meta', False,
                 'A call that collected part of an import run\'s export, or that a collection attempt made: '
                 'the SHA-256 of what it returned (absent: nothing there; failed: the call failed), the file it '
                 'became and the command or URL (never a credential)'),
    AttributeDef(603, 'ciamCollectionCredential', 'string', 'meta', False,
                 'A credential reference an import run\'s collection, or a collection attempt, resolved (the '
                 'reference, never the value)'),
    AttributeDef(986, 'ciamImportedFile', 'string', 'meta', False,
                 'A file an import run\'s export was read from when opsdir didn\'t collect it (an export read off '
                 'disk, or provider commands\' output): the SHA-256 of its text and its path in the export, never '
                 'its content; what `opsdir onboard verify` checks the originals it is given against'),
    AttributeDef(604, 'ciamCollectionOutcome', 'enum:complete|incomplete|skipped', 'meta', True,
                 'How a collection attempt ended: complete (its export read in full), incomplete (a call failed or '
                 'was refused: nothing imported) or skipped (nothing collected: the identity check failed or the '
                 'collector could not start)'),
    AttributeDef(605, 'ciamCollectedAt', 'time', 'meta', True,
                 'When a collection attempt read the live system'),
    AttributeDef(606, 'ciamCollectionProblem', 'string', 'meta', False,
                 'Why a collection attempt was incomplete or skipped: a failing call and its error output, a refused '
                 'call, a bound reached, a failed identity check (credentials masked)'),
    AttributeDef(607, 'ciamCollectedEnvironment', 'extdn', 'meta', True,
                 'The environment a collection attempt read (absent: estate-wide, provider data such as regions and '
                 'quotas); a DN, not a reference, like an import run\'s scopes'),
    # the unknowns register (milestone 6.3): questions nobody can answer from the record yet, with an owner
    AttributeDef(661, 'ciamQuestion', 'string', 'meta', True,
                 'What isn\'t known: the question someone must answer'),
    AttributeDef(662, 'ciamBlocking', 'bool', 'meta', True,
                 'Whether a move may not proceed without the answer: TRUE, the planner blocks while it is open; '
                 'absent or FALSE, an open question is an action'),
    AttributeDef(663, 'ciamConcerns', 'dn', 'meta', False,
                 'The environments (or entries inside them) a question concerns; none: the whole estate. A DN, not '
                 'a reference'),
    AttributeDef(664, 'ciamRaisedAt', 'time', 'meta', True,
                 'When the question was asked'),
    AttributeDef(665, 'ciamNeededBy', 'time', 'meta', True,
                 'When the answer is needed: the planner dates the open question by it (else the planned cutover)'),
    AttributeDef(666, 'ciamAnswer', 'string', 'meta', True,
                 'The answer: a question that has one is answered'),
    AttributeDef(667, 'ciamAnsweredAt', 'time', 'meta', True,
                 'When the question was answered'),
    AttributeDef(670, 'ciamApplicationPart', 'dn', 'meta', False,
                 'An entry that is part of the application (an integration, a directory consumer, an external '
                 'service, a canary, a job): the views and dependency graph of the application start from its parts'),
    # ITSM ticket evidence (milestone 6.2f): the operator's link from a change to its ticket, and what an ITSM add-on's
    # importer read of the ticket (ciamTicket under ou=tickets), evidence only: never an approval opsdir acts on
    AttributeDef(740, 'ciamTicketRef', 'string', 'meta', False,
                 'An ITSM ticket a change record is tracked by, as <adapter>:<number> (servicenow:CHG0030101): the '
                 'operator\'s link (its change ticket, and the work ticket a team was handed its findings by); what '
                 'the ticket says is read into its own entry under ou=tickets, never here'),
    AttributeDef(741, 'ciamTicketState', enum_type(TICKET_STATES), 'meta', True,
                 'A ticket\'s lifecycle state in neutral terms, as its add-on maps the system\'s own (absent: the '
                 'mapping doesn\'t know the ticket\'s state model; ciamTicketNativeState holds what the system said)'),
    AttributeDef(742, 'ciamTicketApproval', enum_type(TICKET_APPROVALS), 'meta', True,
                 'The ticket\'s overall approval as its system reports it: evidence, never an approval of the '
                 'record\'s change'),
    AttributeDef(743, 'ciamTicketNativeState', 'string', 'meta', True,
                 'The ticket\'s state as its system gives it (its raw code, then its label when the export has one)'),
    AttributeDef(744, 'ciamTicketPlannedStart', 'time', 'meta', True,
                 'When the ticket plans the work to start'),
    AttributeDef(745, 'ciamTicketPlannedEnd', 'time', 'meta', True,
                 'When the ticket plans the work to end'),
    AttributeDef(746, 'ciamTicketWorkStart', 'time', 'meta', True,
                 'When the ticket says the work actually started'),
    AttributeDef(747, 'ciamTicketWorkEnd', 'time', 'meta', True,
                 'When the ticket says the work actually ended'),
    AttributeDef(748, 'ciamTicketApprover', 'string', 'meta', False,
                 'One approval record of the ticket, as detail only: "<state> <approver id> updated <time>" (the '
                 'system\'s identifiers, never names; the update time is not when it was approved)'),
    AttributeDef(749, 'ciamTicketFact', 'string', 'meta', False,
                 'Another field of the ticket as its system gave it: "<field> <raw value>" (type, model, close code, '
                 'assignment group, configuration item, requester, correlation, last update)'),
    AttributeDef(834, 'ciamTicketApprovalStep', 'string', 'meta', False,
                 'One approval step of the ticket as its system decided it, where approval goes by steps (a '
                 'workflow\'s approval statuses): "<approved|declined|pending> <step id> created <time>[ completed '
                 '<time>]"; the overall approval its add-on derives from them is ciamTicketApproval, the people '
                 'asked are ciamTicketApprover'),
    AttributeDef(835, 'ciamTicketChangeType', enum_type(TICKET_CHANGE_TYPES), 'meta', True,
                 'The kind of change the ticket is, in neutral terms: standard (pre-approved), normal or emergency, '
                 'as its system classes it'),
    AttributeDef(984, 'ciamTicketKind', enum_type(TICKET_KINDS), 'meta', True,
                 'What the ticket is: a change ticket (change management approves it; absent means change) or a work '
                 'ticket handing work to a team (a ServiceNow task, a Jira issue, a work order), which has no '
                 'approval to compare'),
    AttributeDef(985, 'ciamTicketDue', 'time', 'meta', True,
                 'When a work ticket wants the work done (its due date or scheduled end)'),
    # source objects (milestone 6.1): what a product a migration retires holds that the standard model has no
    # equivalent for, carried as data so the plan says what each needs (ciamSourceObject under ou=source-objects)
    AttributeDef(760, 'ciamSourceClass', 'string', 'observed', True,
                 'The product\'s own type of a source object, as the product names it'),
    AttributeDef(761, 'ciamSourceFact', 'string', 'observed', False,
                 'What a source object holds, as "<setting> <value>" (never a secret: sensitive settings are named '
                 'by the importer as withheld, not kept)'),
    AttributeDef(762, 'ciamHandling', enum_type(HANDLINGS), 'meta', True,
                 'What a source object needs when its product is retired: rebuilt in the target\'s products, its '
                 'secrets re-provisioned, its hosts re-registered, replaced by what the target already does, retired '
                 '(nothing in the target needs it) or reviewed (what it does isn\'t known yet)'),
    AttributeDef(763, 'ciamHow', 'string', 'meta', True,
                 'How a source object is handled, in words: what the target needs instead and where'),
    AttributeDef(975, 'ciamOrgCode', 'string', 'meta', True,
                 'The code of the organization or company a record belongs to (lowercase letters, digits, single '
                 'hyphens): fixed once set, and the prefix of its change records\' names',
                 (("X-PATTERN", ORG_CODE), ("X-MAX-LENGTH", "32"))),
    AttributeDef(976, 'ciamRecordId', 'string', 'meta', True,
                 'A record\'s own identifier (a UUID made when its identity is first set): fixed once set, so the '
                 'record is told apart from any other, even one using the same org code',
                 (("X-PATTERN", UUID),)),
    AttributeDef(977, 'ciamParentOrgCode', 'string', 'meta', True,
                 'The org code of the group a company\'s record belongs to (a subsidiary\'s parent); may change, '
                 'as when a company leaves its group',
                 (("X-PATTERN", ORG_CODE), ("X-MAX-LENGTH", "32"))),
    AttributeDef(978, 'ciamAuthor', 'string', 'meta', True,
                 'Who wrote a change record: the database login that created it, set by the store (never by the '
                 'writer) and kept; the approver is someone else unless approval-separation is off'),
    AttributeDef(979, 'ciamMemberOf', 'dn', 'meta', False,
                 'The teams (ciamParty) a person belongs to'),
    AttributeDef(980, 'ciamGrantAction', enum_type(ACTIONS), 'meta', False,
                 'An action a grant gives (the permission catalog: read, render, plan, migrate, propose, approve, '
                 'apply, settings, workspace, admin)'),
    AttributeDef(981, 'ciamGrantee', 'dn', 'meta', False,
                 'Who a grant is for: a person (ciamPerson) or a team (ciamParty), every member of which holds it'),
    AttributeDef(982, 'ciamGrantEnvironment', 'string', 'meta', False,
                 'An environment (cloud/env) a grant is limited to; none: every environment',
                 (("X-PATTERN", "^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$"),)),
    AttributeDef(983, 'ciamGrantOwner', 'dn', 'meta', False,
                 'A team (ciamParty) whose areas a grant is limited to: what it owns or keeps; none: every area'),
    AttributeDef(987, 'ciamIdpSubject', 'string', 'meta', False,
                 'How the company\'s identity provider names the person: \'<issuer> <subject>\', the token\'s iss and '
                 'sub claims; how the HTTP API finds who signed in',
                 (("X-PATTERN", "^https://[^ ]+ [^ ]+$"),)),
    AttributeDef(988, 'ciamIdpGroup', 'string', 'meta', False,
                 'An identity provider group a team stands for: \'<issuer> <group id>\', the token\'s iss and a value '
                 'of its groups claim (the group\'s immutable ID, never its display name). Whoever the provider puts '
                 'in the group is a member of the team for the HTTP API, request by request; recorded memberships of '
                 'the team are then ignored',
                 (("X-PATTERN", "^https://[^ ]+ [^ ]+$"),)),
    AttributeDef(989, 'ciamApprovedAs', 'string', 'meta', False,
                 'The teams mapped to identity provider groups (ciamIdpGroup) each approver belonged to when approving '
                 'a change, as \'<login> <team>\': set by the store with ciamApprovals (never by the writer), and what '
                 'the approvers\' grants are checked with when the change is applied'),
    AttributeDef(1010, 'ciamApprovals', 'string', 'meta', False,
                 'The people who approved a change, each once and never its author while approval-separation is on: '
                 'set by the store (never by the writer). The approvals-required setting says how many a change '
                 'needs for its environments; it stays proposed until it has them'),
    AttributeDef(1011, 'ciamChangeBase', 'string', 'meta', False,
                 'What a proposed change was proposed against: for each entry its records touch, \'<normalized DN> '
                 '<last history id>\' (0: the entry didn\'t exist yet), set by the store whenever the proposed '
                 'records are written or change (never by the writer). Applying the records is refused for an entry '
                 'another change wrote since: they are proposed again'),
)
CLASSES = (
    ClassDef(29, 'ciamRunbook', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamTitle', 'ciamLastValidated'),
             ('ciamVersion', 'ciamAppliesTo', 'ciamDocUrl'),
             'Work instruction'),
    ClassDef(30, 'ciamChange', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamTitle', 'ciamChangeStatus'),
             ('ciamApprovedBy', 'ciamPlannedAt', 'ciamChangeRecords', 'ciamTicketRef', 'ciamAuthor',
              'ciamApprovedAs', 'ciamApprovals', 'ciamChangeBase'),
             'Change record (mirrored from ITSM; a proposed one may carry the records it applies, and names the '
             'ticket it is tracked by)'),
    ClassDef(31, 'ciamIncident', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamTitle', 'ciamOpenedAt'),
             ('ciamSeverity', 'ciamInvolved', 'ciamRootCause'),
             'Incident / postmortem'),
    ClassDef(32, 'ciamParty', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamOwnerKind'),
             ('mail', 'telephoneNumber', 'ciamContactUrl', 'ciamDisplayName', 'ciamTakesGeneratedInfra',
              'ciamIdpGroup'),
             'Team, partner, vendor, or the operator of the platform (how to reach it: mail, telephone, contact '
             'link)'),
    ClassDef(91, 'ciamImportRun', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamImporter', 'ciamImportScope',
                                                               'ciamImportedAt'),
             ('ciamCollectionIdentity', 'ciamCollectedCall', 'ciamCollectionCredential', 'ciamImportedFile'),
             'The last import by one importer of one scope set (ciamImportScope) in one environment (or of what '
             'environments share), named by the set: when the live system was read back, what it read and under '
             'which change (ciamChangeRef), and when opsdir collected the export itself, how (the identity the '
             'provider saw, each call and the hash of what it returned, the credential references used), otherwise '
             'each file it was read from and its hash (ciamImportedFile); what a fix that needs a fresh read checks'),
    ClassDef(128, 'ciamCollectionSource', 'ciamBinding', 'STRUCTURAL', ('ciamImporter',),
             ('ciamSourceRef', 'ciamTargetRole', 'ciamPort', 'ciamCredentialRole', 'ciamCaRole', 'ciamLoginName',
              'ciamCredentialScheme'),
             'Where `opsdir collect` reads an environment for an importer that needs more than the operator\'s own '
             'cloud login: a Terraform state object, or a product\'s admin endpoint (a URL, or the servers of a role '
             'on a port) with the credential and trust anchor it is read with: the operator\'s opt-in'),
    ClassDef(129, 'ciamCollectionAttempt', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamImporter', 'ciamCollectionOutcome',
                                                                        'ciamCollectedAt'),
             ('ciamCollectedEnvironment', 'ciamCollectionProblem', 'ciamCollectionIdentity', 'ciamCollectedCall',
              'ciamCollectionCredential'),
             'The last attempt by `opsdir collect` to collect one importer\'s export of one environment '
             '(or estate-wide), recorded under the change it ran with (ciamChangeRef) whatever the outcome: '
             'complete, or incomplete or skipped with its problems and the calls it made, so a failed collection '
             'stays visible after the run'),
    ClassDef(137, 'ciamUnknown', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamQuestion', 'ciamOwner'),
             ('ciamBlocking', 'ciamConcerns', 'ciamRaisedAt', 'ciamNeededBy', 'ciamAnswer', 'ciamAnsweredAt'),
             'A question the record can\'t answer yet (under ou=unknowns): what isn\'t known, the party who must '
             'answer it (ciamOwner), whether a move waits for it, what it concerns, when it was raised and is '
             'needed, and its answer once given; the planner counts the open ones'),
    ClassDef(140, 'ciamApplication', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('ciamApplicationPart', 'ciamUsesRole', 'ciamCriticality'),
             'An application as the business knows it, grouping the entries it is made of (ciamApplicationPart) and '
             'the binding roles it uses in each environment (ciamUsesRole): what an application view and its '
             'dependency graph show together; nothing is grouped unless recorded here'),
    ClassDef(156, 'ciamTicket', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamImportedAt'),
             ('ciamTitle', 'ciamProviderRef', 'ciamDocUrl', 'ciamTicketState', 'ciamTicketApproval',
              'ciamTicketNativeState', 'ciamTicketPlannedStart', 'ciamTicketPlannedEnd', 'ciamTicketWorkStart',
              'ciamTicketWorkEnd', 'ciamTicketApprover', 'ciamTicketFact', 'ciamTicketApprovalStep',
              'ciamTicketChangeType', 'ciamTicketKind', 'ciamTicketDue'),
             'An ITSM ticket a change record names (ciamTicketRef), as its add-on\'s importer last read it (under '
             'cn=<number>,ou=<adapter>,ou=tickets; ciamImportedAt: when the export was taken): its state, overall '
             'approval, planned and actual windows, approval records and other fields, with the system\'s own '
             'identifier (ciamProviderRef) and address (ciamDocUrl). Evidence compared with the record, never an '
             'approval opsdir acts on'),
    ClassDef(163, 'ciamSourceObject', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamSourceClass', 'ciamTargetRole',
                                                                   'ciamHandling'),
             ('ciamSourceFact', 'ciamHow', 'ciamBlocking', 'ciamConcerns', 'ciamImportedAt'),
             'What a product a migration retires holds that the standard model has no equivalent for (under '
             'ou=source-objects, below a branch per importer): its own type and facts, the server role that holds it '
             '(ciamTargetRole), how it is handled and whether a move waits for that (ciamBlocking), the entries it '
             'concerns; the planner makes each an action, or a blocker, for a target that doesn\'t run the role'),
    ClassDef(206, 'ciamRecordIdentity', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamOrgCode', 'ciamRecordId'),
             ('ciamParentOrgCode', 'description'),
             'The record\'s own identity (cn=record, below the root): the organization or company it belongs to, '
             'its identifier and its group; carried in exports and evidence so two companies\' records can be '
             'combined after a merger'),
    ClassDef(207, 'ciamPerson', 'ciamObject', 'STRUCTURAL', ('cn',), ('ciamDisplayName', 'mail', 'ciamMemberOf',
                                                                     'ciamIdpSubject', 'description'),
             'A person who works on the record (under ou=people), named by their own database login (cn), and the '
             'teams they belong to; once people are recorded, only a recorded person approves a change'),
    ClassDef(208, 'ciamGrant', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamGrantAction', 'ciamGrantee'),
             ('ciamGrantEnvironment', 'ciamGrantOwner', 'description'),
             'A permission (under ou=grants): the actions it gives, to which people or teams, limited to which '
             'environments and to what which teams own or keep; once any grant is recorded, every action but '
             'reading and administration needs one'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
