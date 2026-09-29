"""PingIDM schema fragment, under this package's own OID arc: an IDM deployment's managed objects, connectors, sync
mappings and schedules. Settings are kept as IDM writes them (JSON), with values that may be secret withheld; what
differs per environment is not in them: a connector names the binding role of the system it connects to and the
secret role of its credentials, and each environment renders its own host and secret reference."""
from opsdir.core.standard import AttributeDef, ClassDef, fragment

ARC = "1.3.6.1.4.1.32473.3.2"      # packages in this repository: .3.<n> of the documentation PEN (SPEC 2.1)
ORIGIN = "pingidm"

ATTRIBUTES = (
    AttributeDef(1, 'pingidmPosition', 'int', 'intent', True,
                 'Its place in the file IDM keeps it in (managed.json objects, sync.json mappings)', (("X-MIN", "0"),)),
    AttributeDef(2, 'pingidmSchema', 'json', 'intent', True,
                 "A managed object's schema, as IDM writes it"),
    AttributeDef(3, 'pingidmConfig', 'json', 'intent', True,
                 'The other settings, as IDM writes them (values that may be secret withheld)'),
    AttributeDef(4, 'pingidmConnectorName', 'string', 'intent', True,
                 "The connector's implementation (connectorRef.connectorName)"),
    AttributeDef(5, 'pingidmBundle', 'string', 'intent', True,
                 'The connector bundle (connectorRef.bundleName)'),
    AttributeDef(6, 'pingidmBundleVersion', 'string', 'intent', True,
                 'The bundle versions the connector accepts (connectorRef.bundleVersion)'),
    AttributeDef(7, 'pingidmTargetRole', 'string', 'intent', True,
                 'The binding role of the system the connector reaches: each environment renders its host from it'),
    AttributeDef(8, 'pingidmCredentialRole', 'string', 'intent', True,
                 'The secret role holding the connector credentials: each environment renders its reference'),
    AttributeDef(9, 'pingidmConsumer', 'dn', 'meta', True,
                 'The directory consumer record of the account the connector binds as'),
    AttributeDef(10, 'pingidmWithheld', 'string', 'meta', False,
                 'Settings withheld at import because they may be secret (JSON Pointer)'),
    AttributeDef(11, 'pingidmSource', 'string', 'intent', True,
                 "A mapping's source (system/<connector>/<type>, managed/<object>)"),
    AttributeDef(12, 'pingidmTarget', 'string', 'intent', True,
                 "A mapping's target"),
    AttributeDef(13, 'pingidmEnabled', 'bool', 'intent', True,
                 'Whether the schedule runs'),
)
CLASSES = (
    ClassDef(1, 'pingidmManagedObject', 'ciamObject', 'STRUCTURAL', ('cn', 'pingidmPosition'),
             ('pingidmSchema', 'pingidmConfig', 'pingidmWithheld'),
             'A managed object type (user, role, ...)'),
    ClassDef(2, 'pingidmConnector', 'ciamObject', 'STRUCTURAL', ('cn', 'pingidmConnectorName'),
             ('pingidmBundle', 'pingidmBundleVersion', 'pingidmTargetRole', 'pingidmCredentialRole', 'pingidmConsumer',
              'pingidmConfig', 'pingidmWithheld'),
             'A connector (provisioner) to a system IDM reads or writes'),
    ClassDef(3, 'pingidmMapping', 'ciamObject', 'STRUCTURAL', ('cn', 'pingidmPosition', 'pingidmSource', 'pingidmTarget'),
             ('pingidmConfig', 'pingidmWithheld'),
             'A sync mapping: properties, situations and policies from a source to a target'),
    ClassDef(4, 'pingidmSchedule', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('pingidmEnabled', 'pingidmConfig', 'pingidmWithheld'),
             'A schedule (reconciliation, a script, ...)'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES, ARC, ORIGIN)
