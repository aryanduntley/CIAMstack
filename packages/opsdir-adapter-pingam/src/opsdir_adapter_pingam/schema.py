"""PingAM schema fragment, under this package's own OID arc: what the standard layers don't describe. A realm is one
of the platform's identity services (auxiliary class pingamRealm: its realm path); authentication journeys (trees of
nodes) and policy sets (of policies) are AM's own, held under ou=pingam. Node, tree and policy settings are kept as
AM writes them (JSON), with values that may be secret withheld."""
from opsdir.core.standard import AttributeDef, ClassDef, fragment

ARC = "1.3.6.1.4.1.32473.3.1"      # packages in this repository: .3.<n> of the documentation PEN (SPEC 2.1)
ORIGIN = "pingam"

ATTRIBUTES = (
    AttributeDef(1, 'pingamRealmPath', 'string', 'contract', True,
                 "The AM realm an identity service is ('/', '/customers'): part of its endpoint URLs",
                 (("X-PATTERN", "^/([A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*)?$"),)),
    AttributeDef(2, 'pingamRealm', 'dn', 'intent', True,
                 'The realm (identity service) a journey or policy set belongs to'),
    AttributeDef(3, 'pingamEntryNode', 'string', 'intent', True,
                 'The node a journey starts at'),
    AttributeDef(4, 'pingamEnabled', 'bool', 'intent', True,
                 'Whether the journey can be used'),
    AttributeDef(5, 'pingamTreeConfig', 'json', 'intent', True,
                 "The journey's other settings, as AM writes them"),
    AttributeDef(6, 'pingamNodeType', 'string', 'intent', True,
                 'The AM node type (UsernameCollectorNode, DataStoreDecisionNode, PageNode, ...)'),
    AttributeDef(7, 'pingamDisplayName', 'string', 'intent', True,
                 "The node's name in the journey"),
    AttributeDef(8, 'pingamNodeConfig', 'json', 'intent', True,
                 "The node's settings, as AM writes them (values that may be secret withheld)"),
    AttributeDef(9, 'pingamOutcome', 'string', 'intent', False,
                 'Where an outcome of the node leads: outcome=node id (the success and failure nodes end the journey)',
                 (("X-PATTERN", "^[^=]+=.+$"),)),
    AttributeDef(10, 'pingamWithheld', 'string', 'meta', False,
                 'Settings withheld at import because they may be secret (JSON Pointer): '
                 'the environment supplies them'),
    AttributeDef(11, 'pingamApplicationType', 'string', 'intent', True,
                 "A policy set's application type"),
    AttributeDef(12, 'pingamSetConfig', 'json', 'intent', True,
                 "The policy set's other settings, as AM writes them"),
    AttributeDef(13, 'pingamPolicyConfig', 'json', 'intent', True,
                 "The policy: resources, actions, subject and conditions, as AM writes them"),
)
CLASSES = (
    ClassDef(1, 'pingamRealm', 'top', 'AUXILIARY', ('pingamRealmPath',), (),
             'An identity service that is an AM realm'),
    ClassDef(2, 'pingamJourney', 'ciamObject', 'STRUCTURAL', ('cn', 'pingamRealm', 'pingamEntryNode'),
             ('pingamEnabled', 'pingamTreeConfig'),
             'An authentication journey (tree): its nodes are its children'),
    ClassDef(3, 'pingamNode', 'ciamObject', 'STRUCTURAL', ('cn', 'pingamNodeType'),
             ('pingamDisplayName', 'pingamNodeConfig', 'pingamOutcome', 'pingamWithheld'),
             'One node of a journey (cn: its node id)'),
    ClassDef(4, 'pingamPolicySet', 'ciamObject', 'STRUCTURAL', ('cn', 'pingamRealm'),
             ('pingamApplicationType', 'pingamSetConfig'),
             'A policy set (AM application): its policies are its children'),
    ClassDef(5, 'pingamPolicy', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('pingamPolicyConfig', 'pingamWithheld'),
             'One authorization policy of a policy set'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES, ARC, ORIGIN)
