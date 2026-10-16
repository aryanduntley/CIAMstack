"""webaccess domain schema fragment: its attribute types and object classes (OIDs pinned by number).

A protected web application is held in neutral terms, whatever product enforces it: where it is reached (base path,
the service names it is published as), what enforces it (a server role, overridable per environment to move it to
another product), what sits behind it, how users sign in and how long their sessions last, the headers it is told who
the user is with, its path resources and the access rules they apply. A product's importer projects its own objects
onto it (ciamProjectedFrom names the product entry); operators may record one with no product yet."""
from ...core.standard import OVERRIDABLE, AttributeDef, ClassDef, enum_type, fragment
from .naming import ACCESS_MODES, EFFECTS, HTTP_METHODS, MATCH_KINDS, RULE_MATCHES, SIGN_ONS, WHO

ATTRIBUTES = (
    AttributeDef(776, 'ciamBasePath', 'string', 'contract', True,
                 'The path a protected application is reached at on its hosts (its resources\' patterns are '
                 'relative to it)', (("X-PATTERN", "^/[^ ]*$"),)),
    AttributeDef(777, 'ciamPublishedAs', 'string', 'intent', False,
                 'A service name role clients reach a protected application at: each environment renders its host'),
    AttributeDef(778, 'ciamEnforcedByRole', 'string', 'intent', True,
                 'The server role that enforces a protected application (a gateway, or an agent in the application\'s '
                 'own web server): an environment overrides it to have another product protect the application',
                 OVERRIDABLE),
    AttributeDef(779, 'ciamBackendRole', 'string', 'intent', True,
                 'The binding role of the application a gateway sends requests to (none: the enforcement point runs '
                 'inside the application\'s own web server)'),
    AttributeDef(780, 'ciamBackendPort', 'port', 'intent', True,
                 'The port the application behind a gateway listens on (none: its binding\'s)'),
    AttributeDef(781, 'ciamBackendTls', 'bool', 'intent', True,
                 'Whether a gateway reaches the application behind it over TLS'),
    AttributeDef(782, 'ciamSignOn', enum_type(SIGN_ONS), 'intent', True,
                 'How users sign in: through an identity service (oidc), with a bearer token (token), with credentials '
                 'the enforcement point collects (form, basic, certificate), a federation journey of its own, the '
                 'operator\'s own code (custom), or not at all'),
    AttributeDef(783, 'ciamSignInAs', 'dn', 'intent', True,
                 'The integration (an OpenID Connect client) the enforcement point signs users in as'),
    AttributeDef(784, 'ciamIdleTimeout', 'int', 'intent', True,
                 'How long a session may be idle, in seconds', (("X-MIN", "0"),)),
    AttributeDef(785, 'ciamMaxSessionTime', 'int', 'intent', True,
                 'How long a session may last, in seconds', (("X-MIN", "0"),)),
    AttributeDef(786, 'ciamSetsHeader', 'dn', 'intent', False,
                 'A header contract the enforcement point sets for the application (who the user is)'),
    AttributeDef(787, 'ciamRuleRef', 'dn', 'intent', False,
                 'An access rule applying: on an application, to every resource; on a resource, its own, after the '
                 'application\'s'),
    AttributeDef(788, 'ciamProjectedFrom', 'dn', 'meta', True,
                 'The product entry an importer projected this entry from (its importer keeps it in step); none: '
                 'recorded by an operator'),
    AttributeDef(789, 'ciamPathPattern', 'string', 'contract', False,
                 'A path a resource matches, relative to its application\'s base path'),
    AttributeDef(790, 'ciamMatchKind', enum_type(MATCH_KINDS), 'intent', True,
                 'How a resource\'s patterns match: prefix, wildcard (* is any run of characters, / included) or '
                 'regex'),
    AttributeDef(791, 'ciamHttpMethod', enum_type(HTTP_METHODS), 'intent', False,
                 'An HTTP method a resource matches (none: every method)'),
    AttributeDef(792, 'ciamAccessMode', enum_type(ACCESS_MODES), 'intent', True,
                 'standard: users sign in and the rules apply; anonymous: no sign-in, the rules still apply; '
                 'unprotected: passed through'),
    AttributeDef(793, 'ciamOrder', 'int', 'intent', True,
                 'A resource\'s place among its application\'s (lowest first; none: the most specific first)',
                 (("X-MIN", "0"),)),
    AttributeDef(794, 'ciamEffect', enum_type(EFFECTS), 'intent', True,
                 'What an access rule does when it matches: allow, deny (a denial beats an allowance), or custom (a '
                 'product rule the neutral terms can\'t express: rebuilt by hand in another product)'),
    AttributeDef(795, 'ciamWho', 'string', 'intent', False,
                 'Who an access rule is about: "authenticated", or "<user|group|filter|attribute|scope|network> '
                 '<value>"', (("X-PATTERN", WHO),)),
    AttributeDef(796, 'ciamRuleMatch', enum_type(RULE_MATCHES), 'intent', True,
                 'Whether any or all of a rule\'s subjects and included rules must match (none: any)'),
    AttributeDef(797, 'ciamIncludesRule', 'dn', 'intent', False,
                 'An access rule a rule set combines'),
    AttributeDef(798, 'ciamCaseSensitive', 'bool', 'intent', True,
                 'Whether an application\'s paths match case-sensitively'),
)
CLASSES = (
    ClassDef(169, 'ciamProtectedApp', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamBasePath', 'ciamEnforcedByRole'),
             ('ciamPublishedAs', 'ciamBackendRole', 'ciamBackendPort', 'ciamBackendTls', 'ciamSignOn',
              'ciamSignInAs', 'ciamServedBy', 'ciamCredentialRole', 'ciamIdleTimeout', 'ciamMaxSessionTime',
              'ciamSetsHeader', 'ciamRuleRef', 'ciamProjectedFrom', 'ciamCaseSensitive'),
             'A web application an access gateway or agent protects, in neutral terms (under '
             'ou=protected-applications): where it is reached, the server role enforcing it (overridable per '
             'environment), what is behind it, how users sign in (the integration, the identity service, the secret '
             'role of its client) and how long sessions last, the headers it trusts, the rules every resource '
             'applies; its path resources below it'),
    ClassDef(170, 'ciamPathResource', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamPathPattern', 'ciamMatchKind'),
             ('ciamHttpMethod', 'ciamAccessMode', 'ciamOrder', 'ciamRuleRef', 'ciamProjectedFrom'),
             'Paths of a protected application (below it): the patterns and methods they match, whether users sign '
             'in, their order and the access rules they apply'),
    ClassDef(171, 'ciamAccessRule', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamEffect'),
             ('ciamWho', 'ciamRuleMatch', 'ciamIncludesRule', 'ciamProjectedFrom'),
             'An access rule (under ou=access-rules,ou=protected-applications): allow or deny whom, any or all of '
             'its subjects and included rules; custom when a product\'s rule has no neutral form'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
