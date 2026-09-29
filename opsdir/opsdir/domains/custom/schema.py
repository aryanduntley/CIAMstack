"""custom domain schema fragment: how operators define fields and record types of their own (OIDs pinned by number).

The definitions are entries (governed, historied, exported like everything else); the metadata says what a field is,
what values it takes, which records carry it, where its value lives (settings of captured config files, or other
systems), and how it behaves in a migration.
"""
from ...core.standard import AttributeDef, ClassDef, fragment

ATTRIBUTES = (
    AttributeDef(150, 'ciamDefinitionNumber', 'int', 'meta', True,
                 'Pinned OID number of a custom definition (under the custom arc)'),
    AttributeDef(151, 'ciamValueType', 'string', 'meta', True,
                 'Value type of a custom field: string, int, bool, time, dn, extdn, cidr, ip, fqdn, url, port, '
                 'ref-uri, json or enum:a|b|c'),
    AttributeDef(152, 'ciamPortability', 'enum:intent|contract|binding|secret-ref|observed|meta', 'meta', True,
                 'What happens to the value in a migration (SPEC 3.1)'),
    AttributeDef(153, 'ciamMultiValued', 'bool', 'meta', True,
                 'The field may hold several values (default: one)'),
    AttributeDef(154, 'ciamCarriedBy', 'string', 'meta', False,
                 'Record types (object classes) that may carry the field'),
    AttributeDef(155, 'ciamUnit', 'string', 'meta', True,
                 'Unit of the value (days, seconds, MB, ...)'),
    AttributeDef(156, 'ciamExample', 'string', 'meta', False,
                 'Example value'),
    AttributeDef(157, 'ciamDefaultValue', 'string', 'meta', True,
                 'Value assumed when a record does not carry the field'),
    AttributeDef(158, 'ciamMinValue', 'int', 'meta', True,
                 'Smallest allowed value (int and port fields)'),
    AttributeDef(159, 'ciamMaxValue', 'int', 'meta', True,
                 'Largest allowed value (int and port fields)'),
    AttributeDef(160, 'ciamPattern', 'string', 'meta', True,
                 'Regular expression every value must match'),
    AttributeDef(161, 'ciamMaxLength', 'int', 'meta', True,
                 'Longest allowed value, in characters'),
    AttributeDef(162, 'ciamOverridable', 'bool', 'meta', True,
                 'An environment may override the value (environment overlays)'),
    AttributeDef(163, 'ciamValueSource', 'string', 'meta', False,
                 'Where the value lives in a system the record does not hold, as "system: locator" (a console, a '
                 'register, an API path); for a config file held in the record use ciamSettingRef'),
    AttributeDef(164, 'ciamUsedBy', 'string', 'meta', False,
                 'Adapters, parsers or renderers that read or write it'),
    AttributeDef(165, 'ciamDefinitionStatus', 'enum:proposed|active|deprecated', 'meta', True,
                 'Lifecycle of a custom definition'),
    AttributeDef(166, 'ciamDocumentation', 'url', 'meta', False,
                 'Documentation about it'),
    AttributeDef(167, 'ciamRunbookRef', 'dn', 'meta', False,
                 'Runbooks about it'),
    AttributeDef(168, 'ciamRecordKind', 'enum:structural|auxiliary', 'meta', True,
                 'Structural (a kind of record) or auxiliary (a set of fields any record may add)'),
    AttributeDef(169, 'ciamParentType', 'string', 'meta', True,
                 'Record type a custom record type extends (default: ciamObject; auxiliary: top)'),
    AttributeDef(170, 'ciamRequiredField', 'string', 'meta', False,
                 'Fields a record of this type must carry (besides cn)'),
    AttributeDef(171, 'ciamOptionalField', 'string', 'meta', False,
                 'Fields a record of this type may carry'),
    AttributeDef(186, 'ciamSettingRef', 'dn', 'meta', False,
                 'Settings of captured config files (ou=config-files) where the value lives'),
)
CLASSES = (
    ClassDef(36, 'ciamCustomDefinition', 'ciamObject', 'ABSTRACT', ('cn', 'ciamDefinitionNumber'),
             ('ciamPurpose', 'ciamPiiClass', 'ciamDefinitionStatus', 'ciamDocumentation', 'ciamRunbookRef',
              'ciamValueSource', 'ciamSettingRef', 'ciamUsedBy'),
             'A field or record type an operator defines'),
    ClassDef(37, 'ciamFieldDefinition', 'ciamCustomDefinition', 'STRUCTURAL', ('ciamValueType', 'ciamPortability'),
             ('ciamMultiValued', 'ciamCarriedBy', 'ciamUnit', 'ciamExample', 'ciamDefaultValue', 'ciamMinValue',
              'ciamMaxValue', 'ciamPattern', 'ciamMaxLength', 'ciamOverridable'),
             'Definition of a custom field'),
    ClassDef(38, 'ciamRecordTypeDefinition', 'ciamCustomDefinition', 'STRUCTURAL', (),
             ('ciamRecordKind', 'ciamParentType', 'ciamRequiredField', 'ciamOptionalField'),
             'Definition of a custom record type'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
