"""PingFederate schema fragment, under this package's own OID arc: PingFederate's own configuration objects, beyond
what the standard bases describe (integrations, certificates and identity services are the federation and PKI
domains'): data stores, plugin instances (validators, adapters, selectors), authentication policy contracts, policies
and fragments. Each object keeps its settings as the Admin API writes them (JSON), with values that may be secret
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
    AttributeDef(8, 'pingfedPluginKind', 'enum:validator|idp-adapter|selector', 'intent', True,
                 'What a plugin instance is: a password credential validator, an IdP adapter, an authentication '
                 'selector'),
    AttributeDef(9, 'pingfedPluginType', 'string', 'intent', True,
                 "The plugin an instance is (pluginDescriptorRef: its implementation's class name)"),
    AttributeDef(10, 'pingfedParent', 'dn', 'intent', True,
                 'The instance a plugin instance inherits its settings from (parentRef)'),
    AttributeDef(11, 'pingfedUses', 'dn', 'intent', False,
                 "PingFederate objects the settings name: a validator's data store, an adapter's validators, the "
                 "adapters, selectors, contracts and fragments a policy runs"),
    AttributeDef(12, 'pingfedPosition', 'int', 'intent', True,
                 'Its place in the list PingFederate keeps it in (authentication policy trees)', (("X-MIN", "0"),)),
    AttributeDef(13, 'pingfedEnabled', 'bool', 'intent', True,
                 'Whether the authentication policy tree is used'),
    AttributeDef(14, 'pingfedPolicyTree', 'json', 'intent', True,
                 "The policy's tree as PingFederate writes it (rootNode: each node's action and its children, by the "
                 "result that leads to them)"),
    AttributeDef(15, 'pingfedConnectionId', 'string', 'intent', True,
                 "The id PingFederate knows a partner connection by: what its authentication policies name"),
)
CLASSES = (
    ClassDef(1, 'pingfedDataStore', 'ciamObject', 'STRUCTURAL', ('cn', 'pingfedStoreType'),
             ('pingfedTargetRole', 'pingfedPort', 'pingfedCredentialRole', 'pingfedConsumer', 'pingfedConfig',
              'pingfedWithheld'),
             'A data store PingFederate reads users or keeps state in (cn: its id): a directory, a database, a '
             'custom store'),
    ClassDef(2, 'pingfedPlugin', 'ciamObject', 'STRUCTURAL', ('cn', 'pingfedPluginKind', 'pingfedPluginType'),
             ('pingfedParent', 'pingfedUses', 'pingfedCredentialRole', 'pingfedConfig', 'pingfedWithheld'),
             'A plugin instance (cn: its id): a password credential validator, an IdP adapter, an authentication '
             'selector'),
    ClassDef(3, 'pingfedPolicyContract', 'ciamObject', 'STRUCTURAL', ('cn',), ('pingfedConfig',),
             'An authentication policy contract (cn: its id): the attributes an authentication policy hands on'),
    ClassDef(4, 'pingfedAuthPolicySet', 'ciamObject', 'STRUCTURAL', ('cn',), ('pingfedConfig',),
             "The authentication policies' own settings (cn: default): its trees are its children"),
    ClassDef(5, 'pingfedAuthPolicy', 'ciamObject', 'STRUCTURAL', ('cn', 'pingfedPolicyTree'),
             ('pingfedPosition', 'pingfedEnabled', 'pingfedUses', 'pingfedConfig'),
             'An authentication policy tree (cn: its name), or a policy fragment (cn: its id)'),
    ClassDef(6, 'pingfedConnection', 'top', 'AUXILIARY', ('pingfedConnectionId',), (),
             'An integration that is a PingFederate partner connection (an IdP connection): the id policies name it by'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES, ARC, ORIGIN)
