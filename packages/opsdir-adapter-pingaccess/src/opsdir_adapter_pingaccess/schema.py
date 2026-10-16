"""PingAccess schema fragment, under this package's own OID arc: what PingAccess protects and how. Each object keeps its
settings as the Admin API writes them (JSON, secrets withheld, the objects it names by name instead of PingAccess's
ids); what differs per environment is not in them: a virtual host names the service name role it answers as, a site
the role of the application behind it, a web session the integration it signs users in as, and each environment
renders its own hosts, client id and secret references. Keys, trust, listeners, cluster nodes and agents are held as
environment-bound objects, never rendered."""
from opsdir.core.standard import AttributeDef, ClassDef, fragment

ARC = "1.3.6.1.4.1.32473.3.5"      # packages in this repository: .3.<n> of the documentation PEN (SPEC 2.1)
ORIGIN = "pingaccess"

ATTRIBUTES = (
    AttributeDef(1, 'paConfig', 'json', 'intent', True,
                 "The object's settings as the Admin API writes them: secrets withheld, the objects it names as "
                 "${pingaccess-id:<collection>/<name>}"),
    AttributeDef(2, 'paWithheld', 'string', 'meta', False,
                 'Settings withheld at import because they are or may be secret (JSON Pointer): their presence only'),
    AttributeDef(3, 'paCredentialRole', 'string', 'intent', True,
                 "The secret role whose binding references the object's withheld values in each environment"),
    AttributeDef(4, 'paSourceVersion', 'string', 'meta', True,
                 'The PingAccess version the settings were read from'),
    AttributeDef(5, 'paObjectType', 'string', 'intent', True,
                 "An object held as is: its Admin API collection (keyPairs, availabilityProfiles, ...)"),
    AttributeDef(6, 'paUses', 'dn', 'intent', False,
                 "The PingAccess objects the object's settings name (what PingAccess refuses it without)"),
    AttributeDef(7, 'paContextRoot', 'string', 'contract', True,
                 "The path an application is reached at on its virtual hosts"),
    AttributeDef(8, 'paServiceRole', 'string', 'intent', True,
                 'The service name role a virtual host answers as: each environment renders its host name'),
    AttributeDef(9, 'paPort', 'port', 'intent', True,
                 "The port the application behind a site listens on"),
    AttributeDef(10, 'paBackendRole', 'string', 'intent', True,
                 'The binding role of the application a site sends requests to: each environment renders its hosts'),
    AttributeDef(11, 'paIntegration', 'dn', 'intent', True,
                 'The OpenID Connect client integration a web session signs users in as'),
    AttributeDef(12, 'paIssuer', 'url', 'contract', True,
                 'The OpenID provider a web session signs users in with (its issuer)'),
    AttributeDef(13, 'paHeaderContract', 'dn', 'intent', False,
                 'The header contracts of the headers an identity mapping sets'),
    AttributeDef(14, 'paEnvironmentBound', 'bool', 'intent', True,
                 'Whether an object held as is differs per environment (keys, trust, listeners, nodes, agents): '
                 'created in each environment, never rendered'),
    AttributeDef(15, 'paRuleKind', 'enum:rule|rule-set', 'intent', True,
                 'A rule, or a rule set of rules or rule sets'),
)
COMMON = ('paConfig', 'paWithheld', 'paCredentialRole', 'paSourceVersion', 'paUses')
CLASSES = (
    ClassDef(1, 'paApplication', 'ciamObject', 'STRUCTURAL', ('cn',), (*COMMON, 'paContextRoot'),
             'An application PingAccess protects: where it is reached, the site behind it, its web session, '
             'identity mappings and policy'),
    ClassDef(2, 'paResource', 'ciamObject', 'STRUCTURAL', ('cn',), COMMON,
             "A resource of an application: its paths and methods, how they are authenticated, their policy"),
    ClassDef(3, 'paSite', 'ciamObject', 'STRUCTURAL', ('cn',), (*COMMON, 'paBackendRole', 'paPort'),
             'Where PingAccess sends an application\'s requests'),
    ClassDef(4, 'paVirtualHost', 'ciamObject', 'STRUCTURAL', ('cn',), (*COMMON, 'paServiceRole'),
             'A host name and port PingAccess answers on'),
    ClassDef(5, 'paWebSession', 'ciamObject', 'STRUCTURAL', ('cn',), (*COMMON, 'paIntegration', 'paIssuer'),
             'How PingAccess signs users in, as an OpenID Connect relying party, and keeps their session'),
    ClassDef(6, 'paIdentityMapping', 'ciamObject', 'STRUCTURAL', ('cn',), (*COMMON, 'paHeaderContract'),
             'What PingAccess tells an application about the user: headers or a signed JWT'),
    ClassDef(7, 'paRule', 'ciamObject', 'STRUCTURAL', ('cn', 'paRuleKind'), COMMON,
             'An access control or processing rule, or a rule set'),
    ClassDef(8, 'paHeld', 'ciamObject', 'STRUCTURAL', ('cn', 'paObjectType'), (*COMMON, 'paEnvironmentBound'),
             'A PingAccess object held as is (not modeled): token provider, validators, keys, trust, listeners'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES, ARC, ORIGIN)
