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
                 'The importer an import run used, as adapter/importer'),
    AttributeDef(423, 'ciamImportScope', 'extdn', 'meta', False,
                 'The parts of the record an import run read back (bindings of an environment, a product\'s '
                 'objects): what it made match the live system (DNs, not references: a run never holds what it read '
                 'in place)'),
    AttributeDef(424, 'ciamImportedAt', 'time', 'meta', True,
                 'When the export an import run read was taken (the live system as of then)'),
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
                                                               'ciamImportedAt'), (),
             'The last import by one importer of one environment (or of what environments share): when the live '
             'system was read back, what it read and under which change (ciamChangeRef); what a fix that needs a '
             'fresh read checks'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
