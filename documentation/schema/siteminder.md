# SiteMinder (opsdir-adapter-siteminder)

*Package · OID arc `1.3.6.1.4.1.32473.3.6` · 10 object classes · 34 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

SiteMinder schema fragment, under this package's own OID arc: its policy store's objects as SiteMinder holds them, read from an XPSExport for a migration away from it. Policy domains hold realms (a resource filter an agent protects, its sign-on scheme and session limits; rules below them) and policies (rules granted to user selections, with responses); authentication schemes, user directories and agents beside them. Auxiliary class smObject carries the SiteMinder identity of every entry the import makes, its own and the standard ones (integrations, header contracts, source objects): its XID, its XPS class, its other settings (JSON) and the sensitive settings withheld. These map one to one onto the planned neutral protected-web-application layer (realm: an application's path and sign-on; rule: a path rule; policy: who it admits). An agent's own files (importer agent-files) add each server's Web Agent instances (smWebAgent under ou=web-agents: the agent identities it acts as, its configuration objects, its trusted host, its policy servers, a gateway virtual host's names) and an Access Gateway's proxy rules as ordered routes (smRoute under ou=routes), each naming its server (smServer): in SiteMinder's own branch, so no other importer's scope reaches them.

## Object classes

<a id="c-smagent"></a>
### smAgent

An agent: the enforcement point realms name, and the server role it runs on (ciamTargetRole)

OID `1.3.6.1.4.1.32473.3.6.2.8` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`smAgentType`](#a-smagenttype) |  | `string` | single | An agent's type, as SiteMinder names it (Web Agent, SPS, ...) |
| [`ciamTargetRole`](infrastructure.md#a-ciamtargetrole) |  | `vocab` | single | Server role a service or rule targets |

<a id="c-smauthscheme"></a>
### smAuthScheme

An authentication scheme

OID `1.3.6.1.4.1.32473.3.6.2.6` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`smSchemeType`](#a-smschemetype) |  | `string` | single | An authentication scheme's type (HTML Form, Basic, X.509, Custom, ...) |
| [`smProtectionLevel`](#a-smprotectionlevel) |  | `int` | single | An authentication scheme's protection level (1-1000) |
| [`smLibrary`](#a-smlibrary) |  | `string` | single | The library an authentication scheme runs (a custom one is rebuilt in the target) |

<a id="c-smobject"></a>
### smObject

An entry read from a SiteMinder policy store: its XID, XPS class, other settings and what was withheld

OID `1.3.6.1.4.1.32473.3.6.2.1` · auxiliary

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`smXid`](#a-smxid) | yes | `string` | single | The object's XID in the policy store (CA.SM::Realm@...): where it is in the export |
| [`smClass`](#a-smclass) | yes | `string` | single | The object's XPS class (CA.SM::Realm, CA.FED::SPPartnership, ...) |
| [`smConfig`](#a-smconfig) |  | `json` | single | The object's other settings, as the export writes them (property name -> values; sensitive settings withheld) |
| [`smWithheld`](#a-smwithheld) |  | `string` | multi | A sensitive setting the import withheld: "<property>: <what it is>; re-provision in the target" (the value, clear or encrypted, is never kept) |

<a id="c-smpolicy"></a>
### smPolicy

A policy of a domain: the rules it grants to its user selections, and the responses it returns

OID `1.3.6.1.4.1.32473.3.6.2.5` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`smRule`](#c-smrule) |  | `dn` | multi | A rule a policy grants |
| [`smResponse`](#a-smresponse) |  | `dn` | multi | What a policy returns when it grants: a header contract, or the source object of a response with no standard equivalent |
| [`smSubject`](#a-smsubject) |  | `string` | multi | A user selection of a policy: "<user directory> <kind> <value>" (kind user, group, filter, role, all, as the export names it) |
| [`smEnabled`](#a-smenabled) |  | `bool` | single | Whether the rule or policy is enabled |

<a id="c-smpolicydomain"></a>
### smPolicyDomain

A policy domain: its realms (ou=realms) and policies (ou=policies) are below it

OID `1.3.6.1.4.1.32473.3.6.2.2` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |

<a id="c-smrealm"></a>
### smRealm

A realm: the resources an agent protects, how users sign in and their session limits; its rules are its children

OID `1.3.6.1.4.1.32473.3.6.2.3` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`smResourceFilter`](#a-smresourcefilter) | yes | `string` | single | The resources a realm protects (its filter, under the agent's host) or a rule matches (under its realm's) |
| [`smAgent`](#c-smagent) |  | `dn` | single | The agent (enforcement point) protecting a realm |
| [`smAuthScheme`](#c-smauthscheme) |  | `dn` | single | The authentication scheme a realm signs users in with |
| [`smIdleTimeout`](#a-smidletimeout) |  | `int` | single | A realm's session idle timeout, in seconds |
| [`smMaxTimeout`](#a-smmaxtimeout) |  | `int` | single | A realm's session maximum lifetime, in seconds |

<a id="c-smroute"></a>
### smRoute

A route of an Access Gateway (smServer; its proxy rules): the conditions a request meets, its place among the routes (the first that matches is taken) and where it sends the request

OID `1.3.6.1.4.1.32473.3.6.2.10` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`smServer`](#a-smserver) | yes | `dn` | single | The server (ciamServer) a Web Agent instance runs on, or whose Access Gateway a route is |
| [`smRouteAction`](#a-smrouteaction) | yes | `enum` | single | What an Access Gateway route does: forward the request to its target, or redirect the client |
| [`smRouteTarget`](#a-smroutetarget) | yes | `string` | single | Where an Access Gateway route sends the request, as its proxy rules write it ($0 the request URI, $1 what follows the matched prefix or the first regex group) |
| [`smCondition`](#a-smcondition) |  | `string` | multi | A condition of an Access Gateway route, all of which must hold: "<type> <criteria> <value>" (type host, uri, query, header:<name>, cookie; criteria equals, beginswith, endswith, contains, exists, regex) |
| [`ciamOrder`](webaccess.md#a-ciamorder) |  | `int` | single | A resource's place among its application's (lowest first; none: the most specific first) |
| [`smConfig`](#a-smconfig) |  | `json` | single | The object's other settings, as the export writes them (property name -> values; sensitive settings withheld) |

<a id="c-smrule"></a>
### smRule

A rule of a realm: the resources and actions it matches, allowed or denied

OID `1.3.6.1.4.1.32473.3.6.2.4` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`smResourceFilter`](#a-smresourcefilter) | yes | `string` | single | The resources a realm protects (its filter, under the agent's host) or a rule matches (under its realm's) |
| [`smRegex`](#a-smregex) |  | `bool` | single | Whether a rule's resource is a regular expression (else a prefix with * wildcards) |
| [`smAction`](#a-smaction) |  | `string` | multi | An action a rule matches (an HTTP method, or an authentication or authorization event) |
| [`smAllow`](#a-smallow) |  | `bool` | single | Whether a rule allows access (else it denies) |
| [`smEnabled`](#a-smenabled) |  | `bool` | single | Whether the rule or policy is enabled |

<a id="c-smuserdirectory"></a>
### smUserDirectory

A user directory connection: where SiteMinder finds users, the role of its servers, the consumer it binds as (credentials withheld)

OID `1.3.6.1.4.1.32473.3.6.2.7` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`smNamespace`](#a-smnamespace) | yes | `string` | single | A user directory's kind: LDAP:, AD:, ODBC:, ... |
| [`smServiceRole`](#a-smservicerole) |  | `string` | single | The role a user directory's servers are in the record (a service name or an external host): each environment's own hosts |
| [`smPort`](#a-smport) |  | `int` | single | The port a user directory's servers share |
| [`smConsumer`](#a-smconsumer) |  | `dn` | single | The directory consumer a user directory binds as |

<a id="c-smwebagent"></a>
### smWebAgent

A Web Agent instance on a server (smServer: a web server's, or an Access Gateway virtual host's), as its WebAgent.conf, SmHost.conf and LocalConfig.conf say: the agent identities it acts as, its configuration objects, its trusted host and policy servers, its other settings (secrets withheld)

OID `1.3.6.1.4.1.32473.3.6.2.9` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`smServer`](#a-smserver) | yes | `dn` | single | The server (ciamServer) a Web Agent instance runs on, or whose Access Gateway a route is |
| [`smEnabled`](#a-smenabled) |  | `bool` | single | Whether the rule or policy is enabled |
| [`smActsAs`](#a-smactsas) |  | `dn` | multi | An agent identity (smAgent) a Web Agent instance acts as (its DefaultAgentName, its AgentName mappings): the realms naming that agent are what it protects |
| [`smAgentConfig`](#a-smagentconfig) |  | `dn` | single | The agent configuration object a Web Agent instance reads its settings from (its source object) |
| [`smHostConfig`](#a-smhostconfig) |  | `dn` | single | The host configuration object a Web Agent instance's SmHost.conf names (its source object) |
| [`smTrustedHost`](#a-smtrustedhost) |  | `dn` | single | The trusted host a Web Agent instance registered as (its source object; SmHost.conf hostname) |
| [`smPolicyServer`](#a-smpolicyserver) |  | `dn` | multi | A policy server (a server of its environment) a Web Agent instance asks |
| [`smVirtualHost`](#a-smvirtualhost) |  | `string` | multi | A host name an Access Gateway virtual host answers to (its agent instance's) |
| [`smConfig`](#a-smconfig) |  | `json` | single | The object's other settings, as the export writes them (property name -> values; sensitive settings withheld) |
| [`smWithheld`](#a-smwithheld) |  | `string` | multi | A sensitive setting the import withheld: "<property>: <what it is>; re-provision in the target" (the value, clear or encrypted, is never kept) |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-smaction"></a>`smAction` | `1.3.6.1.4.1.32473.3.6.1.7` | `string` | intent | multi |  | An action a rule matches (an HTTP method, or an authentication or authorization event) |
| <a id="a-smactsas"></a>`smActsAs` | `1.3.6.1.4.1.32473.3.6.1.25` | `dn` | intent | multi |  | An agent identity (smAgent) a Web Agent instance acts as (its DefaultAgentName, its AgentName mappings): the realms naming that agent are what it protects |
| <a id="a-smagent"></a>`smAgent` | `1.3.6.1.4.1.32473.3.6.1.10` | `dn` | intent | single |  | The agent (enforcement point) protecting a realm |
| <a id="a-smagentconfig"></a>`smAgentConfig` | `1.3.6.1.4.1.32473.3.6.1.26` | `dn` | intent | single |  | The agent configuration object a Web Agent instance reads its settings from (its source object) |
| <a id="a-smagenttype"></a>`smAgentType` | `1.3.6.1.4.1.32473.3.6.1.17` | `string` | intent | single |  | An agent's type, as SiteMinder names it (Web Agent, SPS, ...) |
| <a id="a-smallow"></a>`smAllow` | `1.3.6.1.4.1.32473.3.6.1.8` | `bool` | intent | single |  | Whether a rule allows access (else it denies) |
| <a id="a-smauthscheme"></a>`smAuthScheme` | `1.3.6.1.4.1.32473.3.6.1.11` | `dn` | intent | single |  | The authentication scheme a realm signs users in with |
| <a id="a-smclass"></a>`smClass` | `1.3.6.1.4.1.32473.3.6.1.2` | `string` | observed | single |  | The object's XPS class (CA.SM::Realm, CA.FED::SPPartnership, ...) |
| <a id="a-smcondition"></a>`smCondition` | `1.3.6.1.4.1.32473.3.6.1.31` | `string` | intent | multi |  | A condition of an Access Gateway route, all of which must hold: "<type> <criteria> <value>" (type host, uri, query, header:<name>, cookie; criteria equals, beginswith, endswith, contains, exists, regex) |
| <a id="a-smconfig"></a>`smConfig` | `1.3.6.1.4.1.32473.3.6.1.3` | `json` | intent | single |  | The object's other settings, as the export writes them (property name -> values; sensitive settings withheld) |
| <a id="a-smconsumer"></a>`smConsumer` | `1.3.6.1.4.1.32473.3.6.1.21` | `dn` | intent | single |  | The directory consumer a user directory binds as |
| <a id="a-smenabled"></a>`smEnabled` | `1.3.6.1.4.1.32473.3.6.1.9` | `bool` | intent | single |  | Whether the rule or policy is enabled |
| <a id="a-smhostconfig"></a>`smHostConfig` | `1.3.6.1.4.1.32473.3.6.1.27` | `dn` | intent | single |  | The host configuration object a Web Agent instance's SmHost.conf names (its source object) |
| <a id="a-smidletimeout"></a>`smIdleTimeout` | `1.3.6.1.4.1.32473.3.6.1.12` | `int` | intent | single |  | A realm's session idle timeout, in seconds |
| <a id="a-smlibrary"></a>`smLibrary` | `1.3.6.1.4.1.32473.3.6.1.24` | `string` | intent | single |  | The library an authentication scheme runs (a custom one is rebuilt in the target) |
| <a id="a-smmaxtimeout"></a>`smMaxTimeout` | `1.3.6.1.4.1.32473.3.6.1.13` | `int` | intent | single |  | A realm's session maximum lifetime, in seconds |
| <a id="a-smnamespace"></a>`smNamespace` | `1.3.6.1.4.1.32473.3.6.1.18` | `string` | intent | single |  | A user directory's kind: LDAP:, AD:, ODBC:, ... |
| <a id="a-smpolicyserver"></a>`smPolicyServer` | `1.3.6.1.4.1.32473.3.6.1.29` | `dn` | intent | multi |  | A policy server (a server of its environment) a Web Agent instance asks |
| <a id="a-smport"></a>`smPort` | `1.3.6.1.4.1.32473.3.6.1.20` | `int` | intent | single |  | The port a user directory's servers share |
| <a id="a-smprotectionlevel"></a>`smProtectionLevel` | `1.3.6.1.4.1.32473.3.6.1.23` | `int` | intent | single |  | An authentication scheme's protection level (1-1000) |
| <a id="a-smregex"></a>`smRegex` | `1.3.6.1.4.1.32473.3.6.1.6` | `bool` | intent | single |  | Whether a rule's resource is a regular expression (else a prefix with * wildcards) |
| <a id="a-smresourcefilter"></a>`smResourceFilter` | `1.3.6.1.4.1.32473.3.6.1.5` | `string` | intent | single |  | The resources a realm protects (its filter, under the agent's host) or a rule matches (under its realm's) |
| <a id="a-smresponse"></a>`smResponse` | `1.3.6.1.4.1.32473.3.6.1.15` | `dn` | intent | multi |  | What a policy returns when it grants: a header contract, or the source object of a response with no standard equivalent |
| <a id="a-smrouteaction"></a>`smRouteAction` | `1.3.6.1.4.1.32473.3.6.1.32` | enum: `forward`, `redirect` | intent | single |  | What an Access Gateway route does: forward the request to its target, or redirect the client |
| <a id="a-smroutetarget"></a>`smRouteTarget` | `1.3.6.1.4.1.32473.3.6.1.33` | `string` | intent | single |  | Where an Access Gateway route sends the request, as its proxy rules write it ($0 the request URI, $1 what follows the matched prefix or the first regex group) |
| <a id="a-smrule"></a>`smRule` | `1.3.6.1.4.1.32473.3.6.1.14` | `dn` | intent | multi |  | A rule a policy grants |
| <a id="a-smschemetype"></a>`smSchemeType` | `1.3.6.1.4.1.32473.3.6.1.22` | `string` | intent | single |  | An authentication scheme's type (HTML Form, Basic, X.509, Custom, ...) |
| <a id="a-smserver"></a>`smServer` | `1.3.6.1.4.1.32473.3.6.1.34` | `dn` | intent | single |  | The server (ciamServer) a Web Agent instance runs on, or whose Access Gateway a route is |
| <a id="a-smservicerole"></a>`smServiceRole` | `1.3.6.1.4.1.32473.3.6.1.19` | `string` | intent | single |  | The role a user directory's servers are in the record (a service name or an external host): each environment's own hosts |
| <a id="a-smsubject"></a>`smSubject` | `1.3.6.1.4.1.32473.3.6.1.16` | `string` | intent | multi |  | A user selection of a policy: "<user directory> <kind> <value>" (kind user, group, filter, role, all, as the export names it) |
| <a id="a-smtrustedhost"></a>`smTrustedHost` | `1.3.6.1.4.1.32473.3.6.1.28` | `dn` | intent | single |  | The trusted host a Web Agent instance registered as (its source object; SmHost.conf hostname) |
| <a id="a-smvirtualhost"></a>`smVirtualHost` | `1.3.6.1.4.1.32473.3.6.1.30` | `string` | intent | multi |  | A host name an Access Gateway virtual host answers to (its agent instance's) |
| <a id="a-smwithheld"></a>`smWithheld` | `1.3.6.1.4.1.32473.3.6.1.4` | `string` | meta | multi |  | A sensitive setting the import withheld: "<property>: <what it is>; re-provision in the target" (the value, clear or encrypted, is never kept) |
| <a id="a-smxid"></a>`smXid` | `1.3.6.1.4.1.32473.3.6.1.1` | `string` | observed | single |  | The object's XID in the policy store (CA.SM::Realm@...): where it is in the export |
