"""SiteMinder schema fragment, under this package's own OID arc: its policy store's objects as SiteMinder holds them,
read from an XPSExport for a migration away from it. Policy domains hold realms (a resource filter an agent protects,
its sign-on scheme and session limits; rules below them) and policies (rules granted to user selections, with
responses); authentication schemes, user directories and agents beside them. Auxiliary class smObject carries the
SiteMinder identity of every entry the import makes, its own and the standard ones (integrations, header contracts,
source objects): its XID, its XPS class, its other settings (JSON) and the sensitive settings withheld.

These map one to one onto the planned neutral protected-web-application layer (realm: an application's path and
sign-on; rule: a path rule; policy: who it admits).

An agent's own files (importer agent-files) add each server's Web Agent instances (smWebAgent under ou=web-agents: the
agent identities it acts as, its configuration objects, its trusted host, its policy servers, a gateway virtual host's
names) and an Access Gateway's proxy rules as ordered routes (smRoute under ou=routes), each naming its server
(smServer): in SiteMinder's own branch, so no other importer's scope reaches them."""
from opsdir.core.standard import AttributeDef, ClassDef, enum_type, fragment

ARC = "1.3.6.1.4.1.32473.3.6"      # packages in this repository: .3.<n> of the documentation PEN (SPEC 2.1)
ORIGIN = "siteminder"

ATTRIBUTES = (
    AttributeDef(1, 'smXid', 'string', 'observed', True,
                 'The object\'s XID in the policy store (CA.SM::Realm@...): where it is in the export'),
    AttributeDef(2, 'smClass', 'string', 'observed', True,
                 'The object\'s XPS class (CA.SM::Realm, CA.FED::SPPartnership, ...)'),
    AttributeDef(3, 'smConfig', 'json', 'intent', True,
                 'The object\'s other settings, as the export writes them (property name -> values; sensitive '
                 'settings withheld)'),
    AttributeDef(4, 'smWithheld', 'string', 'meta', False,
                 'A sensitive setting the import withheld: "<property>: <what it is>; re-provision in the target" '
                 '(the value, clear or encrypted, is never kept)'),
    AttributeDef(5, 'smResourceFilter', 'string', 'intent', True,
                 'The resources a realm protects (its filter, under the agent\'s host) or a rule matches (under its '
                 'realm\'s)'),
    AttributeDef(6, 'smRegex', 'bool', 'intent', True,
                 'Whether a rule\'s resource is a regular expression (else a prefix with * wildcards)'),
    AttributeDef(7, 'smAction', 'string', 'intent', False,
                 'An action a rule matches (an HTTP method, or an authentication or authorization event)'),
    AttributeDef(8, 'smAllow', 'bool', 'intent', True,
                 'Whether a rule allows access (else it denies)'),
    AttributeDef(9, 'smEnabled', 'bool', 'intent', True,
                 'Whether the rule or policy is enabled'),
    AttributeDef(10, 'smAgent', 'dn', 'intent', True,
                 'The agent (enforcement point) protecting a realm'),
    AttributeDef(11, 'smAuthScheme', 'dn', 'intent', True,
                 'The authentication scheme a realm signs users in with'),
    AttributeDef(12, 'smIdleTimeout', 'int', 'intent', True,
                 'A realm\'s session idle timeout, in seconds'),
    AttributeDef(13, 'smMaxTimeout', 'int', 'intent', True,
                 'A realm\'s session maximum lifetime, in seconds'),
    AttributeDef(14, 'smRule', 'dn', 'intent', False,
                 'A rule a policy grants'),
    AttributeDef(15, 'smResponse', 'dn', 'intent', False,
                 'What a policy returns when it grants: a header contract, or the source object of a response with '
                 'no standard equivalent'),
    AttributeDef(16, 'smSubject', 'string', 'intent', False,
                 'A user selection of a policy: "<user directory> <kind> <value>" (kind user, group, filter, '
                 'role, all, as the export names it)'),
    AttributeDef(17, 'smAgentType', 'string', 'intent', True,
                 'An agent\'s type, as SiteMinder names it (Web Agent, SPS, ...)'),
    AttributeDef(18, 'smNamespace', 'string', 'intent', True,
                 'A user directory\'s kind: LDAP:, AD:, ODBC:, ...'),
    AttributeDef(19, 'smServiceRole', 'string', 'intent', True,
                 'The role a user directory\'s servers are in the record (a service name or an external host): '
                 'each environment\'s own hosts'),
    AttributeDef(20, 'smPort', 'int', 'intent', True,
                 'The port a user directory\'s servers share'),
    AttributeDef(21, 'smConsumer', 'dn', 'intent', True,
                 'The directory consumer a user directory binds as'),
    AttributeDef(22, 'smSchemeType', 'string', 'intent', True,
                 'An authentication scheme\'s type (HTML Form, Basic, X.509, Custom, ...)'),
    AttributeDef(23, 'smProtectionLevel', 'int', 'intent', True,
                 'An authentication scheme\'s protection level (1-1000)'),
    AttributeDef(24, 'smLibrary', 'string', 'intent', True,
                 'The library an authentication scheme runs (a custom one is rebuilt in the target)'),
    AttributeDef(25, 'smActsAs', 'dn', 'intent', False,
                 'An agent identity (smAgent) a Web Agent instance acts as (its DefaultAgentName, its AgentName '
                 'mappings): the realms naming that agent are what it protects'),
    AttributeDef(26, 'smAgentConfig', 'dn', 'intent', True,
                 'The agent configuration object a Web Agent instance reads its settings from (its source object)'),
    AttributeDef(27, 'smHostConfig', 'dn', 'intent', True,
                 'The host configuration object a Web Agent instance\'s SmHost.conf names (its source object)'),
    AttributeDef(28, 'smTrustedHost', 'dn', 'intent', True,
                 'The trusted host a Web Agent instance registered as (its source object; SmHost.conf hostname)'),
    AttributeDef(29, 'smPolicyServer', 'dn', 'intent', False,
                 'A policy server (a server of its environment) a Web Agent instance asks'),
    AttributeDef(30, 'smVirtualHost', 'string', 'intent', False,
                 'A host name an Access Gateway virtual host answers to (its agent instance\'s)'),
    AttributeDef(31, 'smCondition', 'string', 'intent', False,
                 'A condition of an Access Gateway route, all of which must hold: "<type> <criteria> <value>" (type '
                 'host, uri, query, header:<name>, cookie; criteria equals, beginswith, endswith, contains, exists, '
                 'regex)'),
    AttributeDef(32, 'smRouteAction', enum_type(("forward", "redirect")), 'intent', True,
                 'What an Access Gateway route does: forward the request to its target, or redirect the client'),
    AttributeDef(33, 'smRouteTarget', 'string', 'intent', True,
                 'Where an Access Gateway route sends the request, as its proxy rules write it ($0 the request URI, $1 '
                 'what follows the matched prefix or the first regex group)'),
    AttributeDef(34, 'smServer', 'dn', 'intent', True,
                 'The server (ciamServer) a Web Agent instance runs on, or whose Access Gateway a route is'),
)
CLASSES = (
    ClassDef(1, 'smObject', 'top', 'AUXILIARY', ('smXid', 'smClass'), ('smConfig', 'smWithheld'),
             'An entry read from a SiteMinder policy store: its XID, XPS class, other settings and what was withheld'),
    ClassDef(2, 'smPolicyDomain', 'ciamObject', 'STRUCTURAL', ('cn',), (),
             'A policy domain: its realms (ou=realms) and policies (ou=policies) are below it'),
    ClassDef(3, 'smRealm', 'ciamObject', 'STRUCTURAL', ('cn', 'smResourceFilter'),
             ('smAgent', 'smAuthScheme', 'smIdleTimeout', 'smMaxTimeout'),
             'A realm: the resources an agent protects, how users sign in and their session limits; its rules are '
             'its children'),
    ClassDef(4, 'smRule', 'ciamObject', 'STRUCTURAL', ('cn', 'smResourceFilter'),
             ('smRegex', 'smAction', 'smAllow', 'smEnabled'),
             'A rule of a realm: the resources and actions it matches, allowed or denied'),
    ClassDef(5, 'smPolicy', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('smRule', 'smResponse', 'smSubject', 'smEnabled'),
             'A policy of a domain: the rules it grants to its user selections, and the responses it returns'),
    ClassDef(6, 'smAuthScheme', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('smSchemeType', 'smProtectionLevel', 'smLibrary'),
             'An authentication scheme'),
    ClassDef(7, 'smUserDirectory', 'ciamObject', 'STRUCTURAL', ('cn', 'smNamespace'),
             ('smServiceRole', 'smPort', 'smConsumer'),
             'A user directory connection: where SiteMinder finds users, the role of its servers, the consumer it '
             'binds as (credentials withheld)'),
    ClassDef(8, 'smAgent', 'ciamObject', 'STRUCTURAL', ('cn',), ('smAgentType', 'ciamTargetRole'),
             'An agent: the enforcement point realms name, and the server role it runs on (ciamTargetRole)'),
    ClassDef(9, 'smWebAgent', 'ciamObject', 'STRUCTURAL', ('cn', 'smServer'),
             ('smEnabled', 'smActsAs', 'smAgentConfig', 'smHostConfig', 'smTrustedHost', 'smPolicyServer',
              'smVirtualHost', 'smConfig', 'smWithheld'),
             'A Web Agent instance on a server (smServer: a web server\'s, or an Access Gateway virtual host\'s), as '
             'its WebAgent.conf, SmHost.conf and LocalConfig.conf say: the agent identities it acts as, its '
             'configuration objects, its trusted host and policy servers, its other settings (secrets withheld)'),
    ClassDef(10, 'smRoute', 'ciamObject', 'STRUCTURAL', ('cn', 'smServer', 'smRouteAction', 'smRouteTarget'),
             ('smCondition', 'ciamOrder', 'smConfig'),
             'A route of an Access Gateway (smServer; its proxy rules): the conditions a request meets, its place '
             'among the routes (the first that matches is taken) and where it sends the request'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES, ARC, ORIGIN)
