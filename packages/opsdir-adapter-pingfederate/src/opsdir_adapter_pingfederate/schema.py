"""PingFederate schema fragment, under this package's own OID arc: PingFederate's own configuration objects, beyond
what the standard bases describe (integrations, certificates and identity services are the federation and PKI
domains'): data stores, plugin instances (validators, adapters, selectors, access token managers), authentication
policy contracts, policies and fragments, OIDC policies, settings resources (the authorization server's). Each object
keeps its settings as the Admin API writes them (JSON), with values that may be secret withheld; what differs per
environment is not in them: an object names the binding role of the system it reaches and the secret role of its
credentials, and each environment renders its own hosts and secret references."""
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
    AttributeDef(8, 'pingfedPluginKind',
                 'enum:validator|idp-adapter|selector|access-token-manager|notification-publisher|captcha-provider',
                 'intent', True,
                 'What a plugin instance is: a password credential validator, an IdP adapter, an authentication '
                 'selector, an access token manager, a notification publisher, a CAPTCHA provider'),
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
    AttributeDef(16, 'pingfedKeyPairId', 'string', 'intent', True,
                 "The id PingFederate knows one of its key pairs by: what its token managers sign with"),
    AttributeDef(17, 'pingfedScope', 'string', 'intent', False,
                 'A scope the authorization server defines (common and exclusive scopes)'),
    AttributeDef(18, 'pingfedOperationalMode', 'enum:CLUSTERED_CONSOLE|CLUSTERED_ENGINE|STANDALONE', 'intent', True,
                 "What a PingFederate node is in its cluster (run.properties pf.operational.mode)"),
    AttributeDef(19, 'pingfedNodeTags', 'string', 'intent', False,
                 "A PingFederate node's tags (run.properties node.tags: what adaptive clustering groups it by)"),
    AttributeDef(20, 'pingfedListener', 'string', 'intent', False,
                 'A port a PingFederate node listens on, by what for: runtime=9031, admin=9999, cluster=7600',
                 (("X-PATTERN", "^[a-z][a-z0-9-]*=[0-9]+$"),)),
    AttributeDef(21, 'pingfedDiscovery', 'string', 'meta', True,
                 "The JGroups discovery protocol a node uses, as found on the node (bin/jgroups.properties, or "
                 "an upgraded install's tcp.xml): TCPPING, NATIVE_S3_PING, DNS_PING, ..."),
    AttributeDef(22, 'pingfedResourceType', 'string', 'intent', True,
                 "The Admin API resource a held-as-is item comes from (/serverSettings, "
                 "/oauth/accessTokenMappings, ...)"),
    AttributeDef(23, 'pingfedDiscoveryProtocol', 'vocab', 'binding', True,
                 "The JGroups discovery protocol an environment's PingFederate nodes find each other with, chosen per "
                 "environment from the protocols the adapter renders (TCPPING, NATIVE_S3_PING, DNS_PING)"),
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
             'An integration that is a PingFederate partner connection (an IdP connection): '
             'the id policies name it by'),
    ClassDef(7, 'pingfedKeyPair', 'top', 'AUXILIARY', ('pingfedKeyPairId',), (),
             "A certificate of one of PingFederate's own key pairs: the id its token managers name it by"),
    ClassDef(8, 'pingfedOidcPolicy', 'ciamObject', 'STRUCTURAL', ('cn',), ('pingfedUses', 'pingfedConfig'),
             'An OpenID Connect policy (cn: its id): the ID token it issues, from the token manager it names'),
    ClassDef(9, 'pingfedSettings', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('pingfedScope', 'pingfedUses', 'pingfedCredentialRole', 'pingfedConfig', 'pingfedWithheld'),
             "One of PingFederate's settings resources (cn: which: oauth-auth-server, ...), "
             "as the Admin API writes it"),
    ClassDef(10, 'pingfedClient', 'top', 'AUXILIARY', (), ('pingfedUses',),
             'An OAuth client of PingFederate: the token manager and OIDC policy it is issued tokens by'),
    ClassDef(11, 'pingfedNode', 'top', 'AUXILIARY', (),
             ('pingfedOperationalMode', 'pingfedNodeTags', 'pingfedListener', 'pingfedDiscovery',
              'pingfedCredentialRole', 'pingfedConfig', 'pingfedWithheld'),
             "A server that is a PingFederate node: its run.properties (mode, tags, listeners, other settings) and the "
             "cluster discovery protocol it uses"),
    ClassDef(12, 'pingfedResource', 'ciamObject', 'STRUCTURAL', ('cn', 'pingfedResourceType'),
             ('pingfedCredentialRole', 'pingfedConfig', 'pingfedWithheld'),
             'An item of an Admin API resource the adapter does not model, held as the Admin API writes it '
             '(cn: its id; settings for a resource that is one object)'),
    ClassDef(13, 'pingfedClusterDiscovery', 'ciamBinding', 'STRUCTURAL', ('pingfedDiscoveryProtocol',),
             ('ciamStorageRef', 'ciamFqdn'),
             "Where an environment's PingFederate nodes find each other (role pf-cluster-discovery): the protocol "
             "chosen, and the bucket (NATIVE_S3_PING) or DNS name (DNS_PING) it needs; TCPPING needs neither"),
    ClassDef(14, 'pingfedHeldSettings', 'top', 'AUXILIARY', (),
             ('pingfedConfig', 'pingfedWithheld', 'pingfedCredentialRole'),
             "An integration (SP connection, IdP connection, OAuth client) with PingFederate's own settings held as "
             "the Admin API writes them (secrets withheld): rendered back with the record's standard facts in place"),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES, ARC, ORIGIN)
