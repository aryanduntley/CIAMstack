"""PingGateway schema fragment, under this package's own OID arc: the gateway's routes. A route keeps its settings
as the gateway writes them (JSON, secrets withheld); what differs per environment is not in them: the route names the
binding role of the application it protects, and each environment renders its own backend address."""
from opsdir.core.standard import AttributeDef, ClassDef, fragment

ARC = "1.3.6.1.4.1.32473.3.3"      # packages in this repository: .3.<n> of the documentation PEN (SPEC 2.1)
ORIGIN = "pinggateway"

ATTRIBUTES = (
    AttributeDef(1, 'pinggwCondition', 'string', 'intent', True,
                 'When the route handles a request (the gateway expression)'),
    AttributeDef(2, 'pinggwBackendRole', 'string', 'intent', True,
                 'The binding role of the application the route protects: each environment renders its address'),
    AttributeDef(3, 'pinggwBackendScheme', 'enum:http|https', 'intent', True,
                 'How the gateway reaches the application'),
    AttributeDef(4, 'pinggwIntegration', 'dn', 'intent', True,
                 'The integration whose client the route signs users in as (its OAuth 2.0 client filter)'),
    AttributeDef(5, 'pinggwIssuer', 'url', 'contract', True,
                 'The OpenID provider the route trusts (issuer or well-known URL)'),
    AttributeDef(6, 'pinggwConfig', 'json', 'intent', True,
                 "The route's other settings, as the gateway writes them (values that may be secret withheld)"),
    AttributeDef(7, 'pinggwWithheld', 'string', 'meta', False,
                 'Settings withheld at import because they may be secret (JSON Pointer)'),
)
CLASSES = (
    ClassDef(1, 'pinggwRoute', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('pinggwCondition', 'pinggwBackendRole', 'pinggwBackendScheme', 'pinggwIntegration', 'pinggwIssuer',
              'pinggwConfig', 'pinggwWithheld'),
             'A gateway route: which requests it handles, how it protects them, where it sends them'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES, ARC, ORIGIN)
