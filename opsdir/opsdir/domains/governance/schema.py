"""governance domain schema fragment: its attribute types and object classes (OIDs pinned by number)."""
from ...core.standard import AttributeDef, ClassDef, fragment

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
    AttributeDef(601, 'ciamCollectionIdentity', 'string', 'meta', True,
                 'Who the provider said the collector was when an import run\'s export was collected, or a collection '
                 'was attempted (its identity check: account, subscription, project)'),
    AttributeDef(602, 'ciamCollectedCall', 'string', 'meta', False,
                 'A call that collected part of an import run\'s export, or that a collection attempt made: the SHA-256 '
                 'of what it returned (absent: nothing there; failed: the call failed), the file it became and the '
                 'command or URL (never a credential)'),
    AttributeDef(603, 'ciamCollectionCredential', 'string', 'meta', False,
                 'A credential reference an import run\'s collection, or a collection attempt, resolved (the '
                 'reference, never the value)'),
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
)
CLASSES = (
    ClassDef(29, 'ciamRunbook', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamTitle', 'ciamLastValidated'),
             ('ciamVersion', 'ciamAppliesTo', 'ciamDocUrl'),
             'Work instruction'),
    ClassDef(30, 'ciamChange', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamTitle', 'ciamChangeStatus'),
             ('ciamApprovedBy', 'ciamPlannedAt', 'ciamChangeRecords'),
             'Change record (mirrored from ITSM; a proposed one may carry the records it applies)'),
    ClassDef(31, 'ciamIncident', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamTitle', 'ciamOpenedAt'),
             ('ciamSeverity', 'ciamInvolved', 'ciamRootCause'),
             'Incident / postmortem'),
    ClassDef(32, 'ciamParty', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamOwnerKind'),
             ('mail', 'telephoneNumber', 'ciamContactUrl', 'ciamDisplayName'),
             'Team, partner, vendor, or the operator of the platform (how to reach it: mail, telephone, contact '
             'link)'),
    ClassDef(91, 'ciamImportRun', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamImporter', 'ciamImportScope',
                                                               'ciamImportedAt'),
             ('ciamCollectionIdentity', 'ciamCollectedCall', 'ciamCollectionCredential'),
             'The last import by one importer of one environment (or of what environments share): when the live '
             'system was read back, what it read and under which change (ciamChangeRef), and when opsdir collected '
             'the export itself, how (the identity the provider saw, each call and the hash of what it returned, '
             'the credential references used); what a fix that needs a fresh read checks'),
    ClassDef(128, 'ciamCollectionSource', 'ciamBinding', 'STRUCTURAL', ('ciamImporter',),
             ('ciamSourceRef', 'ciamTargetRole', 'ciamPort', 'ciamCredentialRole', 'ciamCaRole', 'ciamLoginName'),
             'Where `opsdir collect` reads an environment for an importer that needs more than the operator\'s own '
             'cloud login: a Terraform state object, or a product\'s admin endpoint (a URL, or the servers of a role '
             'on a port) with the credential and trust anchor it is read with: the operator\'s opt-in'),
    ClassDef(129, 'ciamCollectionAttempt', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamImporter', 'ciamCollectionOutcome',
                                                                        'ciamCollectedAt'),
             ('ciamCollectedEnvironment', 'ciamCollectionProblem', 'ciamCollectionIdentity', 'ciamCollectedCall',
              'ciamCollectionCredential'),
             'The last attempt by `opsdir collect` to collect one importer\'s export of one environment (or estate-wide), '
             'recorded under the change it ran with (ciamChangeRef) whatever the outcome: complete, or incomplete or '
             'skipped with its problems and the calls it made, so a failed collection stays visible after the run'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
