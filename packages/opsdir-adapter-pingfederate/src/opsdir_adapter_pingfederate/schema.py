"""PingFederate schema fragment, under this package's own OID arc: PingFederate's own configuration objects, beyond
what the standard bases describe (integrations, certificates and identity services are the federation and PKI
domains'). Each object keeps its settings as the Admin API writes them (JSON), with values that may be secret
withheld; what differs per environment is not in them: an object names the binding role of the system it reaches and
the secret role of its credentials, and each environment renders its own hosts and secret references."""
from opsdir.core.standard import AttributeDef, ClassDef, fragment

ARC = "1.3.6.1.4.1.32473.3.4"      # packages in this repository: .3.<n> of the documentation PEN (SPEC 2.1)
ORIGIN = "pingfederate"

ATTRIBUTES = (
    AttributeDef(1, 'pingfedStoreType', 'string', 'intent', True,
                 "The data store's type, as PingFederate names it (LDAP, JDBC, CUSTOM)"),
    AttributeDef(2, 'pingfedTargetRole', 'string', 'intent', True,
                 'The binding role of the service the object reaches: each environment renders its host from it'),
    AttributeDef(3, 'pingfedPort', 'int', 'intent', True,
                 'The port the object reaches its target role on', (("X-MIN", "1"), ("X-MAX", "65535"))),
    AttributeDef(4, 'pingfedCredentialRole', 'string', 'intent', True,
                 'The secret role holding the credentials: each environment renders its reference'),
    AttributeDef(5, 'pingfedConsumer', 'dn', 'meta', True,
                 'The directory consumer record of the account the object binds to the directory as'),
    AttributeDef(6, 'pingfedConfig', 'json', 'intent', True,
                 'The other settings, as the Admin API writes them (values that may be secret withheld)'),
    AttributeDef(7, 'pingfedWithheld', 'string', 'meta', False,
                 'Settings withheld at import because they may be secret (JSON Pointer)'),
)
CLASSES = (
    ClassDef(1, 'pingfedDataStore', 'ciamObject', 'STRUCTURAL', ('cn', 'pingfedStoreType'),
             ('pingfedTargetRole', 'pingfedPort', 'pingfedCredentialRole', 'pingfedConsumer', 'pingfedConfig',
              'pingfedWithheld'),
             'A data store PingFederate reads users or keeps state in (cn: its id): a directory, a database, a '
             'custom store'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES, ARC, ORIGIN)
