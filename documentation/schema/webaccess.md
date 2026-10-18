# Web access

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 3 object classes · 23 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

A protected web application is held in neutral terms, whatever product enforces it: where it is reached (base path, the service names it is published as), what enforces it (a server role, overridable per environment to move it to another product), what sits behind it, how users sign in and how long their sessions last, the headers it is told who the user is with, its path resources and the access rules they apply. A product's importer projects its own objects onto it (ciamProjectedFrom names the product entry); operators may record one with no product yet.

**Branches:** `ou=protected-applications,dc=ciam-ops`, `ou=access-rules,ou=protected-applications,dc=ciam-ops`

## Object classes

<a id="c-ciamaccessrule"></a>
### ciamAccessRule

An access rule (under ou=access-rules,ou=protected-applications): allow or deny whom, any or all of its subjects and included rules; custom when a product's rule has no neutral form

OID `1.3.6.1.4.1.32473.1.2.171` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamEffect`](#a-ciameffect) | yes | `enum` | single | What an access rule does when it matches: allow, deny (a denial beats an allowance), or custom (a product rule the neutral terms can't express: rebuilt by hand in another product) |
| [`ciamWho`](#a-ciamwho) |  | `string` | multi | Who an access rule is about: "authenticated", or "<user\|group\|filter\|attribute\|scope\|network> <value>" |
| [`ciamRuleMatch`](#a-ciamrulematch) |  | `enum` | single | Whether any or all of a rule's subjects and included rules must match (none: any) |
| [`ciamIncludesRule`](#a-ciamincludesrule) |  | `dn` | multi | An access rule a rule set combines |
| [`ciamProjectedFrom`](#a-ciamprojectedfrom) |  | `dn` | single | The product entry an importer projected this entry from (its importer keeps it in step); none: recorded by an operator |

<a id="c-ciampathresource"></a>
### ciamPathResource

Paths of a protected application (below it): the patterns and methods they match, whether users sign in, their order and the access rules they apply

OID `1.3.6.1.4.1.32473.1.2.170` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamPathPattern`](#a-ciampathpattern) | yes | `string` | multi | A path a resource matches, relative to its application's base path |
| [`ciamMatchKind`](#a-ciammatchkind) | yes | `enum` | single | How a resource's patterns match: prefix, wildcard (* is any run of characters, / included) or regex |
| [`ciamHttpMethod`](#a-ciamhttpmethod) |  | `enum` | multi | An HTTP method a resource matches (none: every method) |
| [`ciamAccessMode`](#a-ciamaccessmode) |  | `enum` | single | standard: users sign in and the rules apply; anonymous: no sign-in, the rules still apply; unprotected: passed through |
| [`ciamOrder`](#a-ciamorder) |  | `int` | single | A resource's place among its application's (lowest first; none: the most specific first) |
| [`ciamRuleRef`](#a-ciamruleref) |  | `dn` | multi | An access rule applying: on an application, to every resource; on a resource, its own, after the application's |
| [`ciamProjectedFrom`](#a-ciamprojectedfrom) |  | `dn` | single | The product entry an importer projected this entry from (its importer keeps it in step); none: recorded by an operator |

<a id="c-ciamprotectedapp"></a>
### ciamProtectedApp

A web application an access gateway or agent protects, in neutral terms (under ou=protected-applications): where it is reached, the server role enforcing it (overridable per environment), what is behind it, how users sign in (the integration, the identity service, the secret role of its client) and how long sessions last, the headers it trusts, the rules every resource applies; its path resources below it

OID `1.3.6.1.4.1.32473.1.2.169` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamBasePath`](#a-ciambasepath) | yes | `string` | single | The path a protected application is reached at on its hosts (its resources' patterns are relative to it) |
| [`ciamEnforcedByRole`](#a-ciamenforcedbyrole) | yes | `string` | single | The server role that enforces a protected application (a gateway, or an agent in the application's own web server): an environment overrides it to have another product protect the application |
| [`ciamPublishedAs`](#a-ciampublishedas) |  | `string` | multi | A service name role clients reach a protected application at: each environment renders its host |
| [`ciamBackendRole`](#a-ciambackendrole) |  | `string` | single | The binding role of the application a gateway sends requests to (none: the enforcement point runs inside the application's own web server) |
| [`ciamBackendPort`](#a-ciambackendport) |  | `port` | single | The port the application behind a gateway listens on (none: its binding's) |
| [`ciamBackendTls`](#a-ciambackendtls) |  | `bool` | single | Whether a gateway reaches the application behind it over TLS |
| [`ciamSignOn`](#a-ciamsignon) |  | `enum` | single | How users sign in: through an identity service (oidc), with a bearer token (token), with credentials the enforcement point collects (form, basic, certificate), a federation journey of its own, the operator's own code (custom), or not at all |
| [`ciamSignInAs`](#a-ciamsigninas) |  | `dn` | single | The integration (an OpenID Connect client) the enforcement point signs users in as |
| [`ciamServedBy`](federation.md#a-ciamservedby) |  | `dn` | single | The identity service the integration is registered with (none: every identity service serves it) |
| [`ciamCredentialRole`](governance.md#a-ciamcredentialrole) |  | `string` | single | The role of the binding holding the reference to the credential a collection source is read with (resolved when collecting, held in memory for the call, never stored) |
| [`ciamIdleTimeout`](#a-ciamidletimeout) |  | `int` | single | How long a session may be idle, in seconds |
| [`ciamMaxSessionTime`](#a-ciammaxsessiontime) |  | `int` | single | How long a session may last, in seconds |
| [`ciamSetsHeader`](#a-ciamsetsheader) |  | `dn` | multi | A header contract the enforcement point sets for the application (who the user is) |
| [`ciamRuleRef`](#a-ciamruleref) |  | `dn` | multi | An access rule applying: on an application, to every resource; on a resource, its own, after the application's |
| [`ciamProjectedFrom`](#a-ciamprojectedfrom) |  | `dn` | single | The product entry an importer projected this entry from (its importer keeps it in step); none: recorded by an operator |
| [`ciamCaseSensitive`](#a-ciamcasesensitive) |  | `bool` | single | Whether an application's paths match case-sensitively |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamaccessmode"></a>`ciamAccessMode` | `1.3.6.1.4.1.32473.1.1.792` | enum: `standard`, `anonymous`, `unprotected` | intent | single |  | standard: users sign in and the rules apply; anonymous: no sign-in, the rules still apply; unprotected: passed through |
| <a id="a-ciambackendport"></a>`ciamBackendPort` | `1.3.6.1.4.1.32473.1.1.780` | `port` | intent | single |  | The port the application behind a gateway listens on (none: its binding's) |
| <a id="a-ciambackendrole"></a>`ciamBackendRole` | `1.3.6.1.4.1.32473.1.1.779` | `string` | intent | single |  | The binding role of the application a gateway sends requests to (none: the enforcement point runs inside the application's own web server) |
| <a id="a-ciambackendtls"></a>`ciamBackendTls` | `1.3.6.1.4.1.32473.1.1.781` | `bool` | intent | single |  | Whether a gateway reaches the application behind it over TLS |
| <a id="a-ciambasepath"></a>`ciamBasePath` | `1.3.6.1.4.1.32473.1.1.776` | `string` | contract | single | X-PATTERN `^/[^ ]*$` | The path a protected application is reached at on its hosts (its resources' patterns are relative to it) |
| <a id="a-ciamcasesensitive"></a>`ciamCaseSensitive` | `1.3.6.1.4.1.32473.1.1.798` | `bool` | intent | single |  | Whether an application's paths match case-sensitively |
| <a id="a-ciameffect"></a>`ciamEffect` | `1.3.6.1.4.1.32473.1.1.794` | enum: `allow`, `deny`, `custom` | intent | single |  | What an access rule does when it matches: allow, deny (a denial beats an allowance), or custom (a product rule the neutral terms can't express: rebuilt by hand in another product) |
| <a id="a-ciamenforcedbyrole"></a>`ciamEnforcedByRole` | `1.3.6.1.4.1.32473.1.1.778` | `string` | intent | single | X-OVERRIDABLE `TRUE` | The server role that enforces a protected application (a gateway, or an agent in the application's own web server): an environment overrides it to have another product protect the application |
| <a id="a-ciamhttpmethod"></a>`ciamHttpMethod` | `1.3.6.1.4.1.32473.1.1.791` | enum: `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `TRACE` | intent | multi |  | An HTTP method a resource matches (none: every method) |
| <a id="a-ciamidletimeout"></a>`ciamIdleTimeout` | `1.3.6.1.4.1.32473.1.1.784` | `int` | intent | single | X-MIN `0` | How long a session may be idle, in seconds |
| <a id="a-ciamincludesrule"></a>`ciamIncludesRule` | `1.3.6.1.4.1.32473.1.1.797` | `dn` | intent | multi |  | An access rule a rule set combines |
| <a id="a-ciammatchkind"></a>`ciamMatchKind` | `1.3.6.1.4.1.32473.1.1.790` | enum: `prefix`, `wildcard`, `regex` | intent | single |  | How a resource's patterns match: prefix, wildcard (* is any run of characters, / included) or regex |
| <a id="a-ciammaxsessiontime"></a>`ciamMaxSessionTime` | `1.3.6.1.4.1.32473.1.1.785` | `int` | intent | single | X-MIN `0` | How long a session may last, in seconds |
| <a id="a-ciamorder"></a>`ciamOrder` | `1.3.6.1.4.1.32473.1.1.793` | `int` | intent | single | X-MIN `0` | A resource's place among its application's (lowest first; none: the most specific first) |
| <a id="a-ciampathpattern"></a>`ciamPathPattern` | `1.3.6.1.4.1.32473.1.1.789` | `string` | contract | multi |  | A path a resource matches, relative to its application's base path |
| <a id="a-ciamprojectedfrom"></a>`ciamProjectedFrom` | `1.3.6.1.4.1.32473.1.1.788` | `dn` | meta | single |  | The product entry an importer projected this entry from (its importer keeps it in step); none: recorded by an operator |
| <a id="a-ciampublishedas"></a>`ciamPublishedAs` | `1.3.6.1.4.1.32473.1.1.777` | `string` | intent | multi |  | A service name role clients reach a protected application at: each environment renders its host |
| <a id="a-ciamrulematch"></a>`ciamRuleMatch` | `1.3.6.1.4.1.32473.1.1.796` | enum: `any`, `all` | intent | single |  | Whether any or all of a rule's subjects and included rules must match (none: any) |
| <a id="a-ciamruleref"></a>`ciamRuleRef` | `1.3.6.1.4.1.32473.1.1.787` | `dn` | intent | multi |  | An access rule applying: on an application, to every resource; on a resource, its own, after the application's |
| <a id="a-ciamsetsheader"></a>`ciamSetsHeader` | `1.3.6.1.4.1.32473.1.1.786` | `dn` | intent | multi |  | A header contract the enforcement point sets for the application (who the user is) |
| <a id="a-ciamsigninas"></a>`ciamSignInAs` | `1.3.6.1.4.1.32473.1.1.783` | `dn` | intent | single |  | The integration (an OpenID Connect client) the enforcement point signs users in as |
| <a id="a-ciamsignon"></a>`ciamSignOn` | `1.3.6.1.4.1.32473.1.1.782` | enum: `oidc`, `token`, `form`, `basic`, `certificate`, `federated`, `custom`, `none` | intent | single |  | How users sign in: through an identity service (oidc), with a bearer token (token), with credentials the enforcement point collects (form, basic, certificate), a federation journey of its own, the operator's own code (custom), or not at all |
| <a id="a-ciamwho"></a>`ciamWho` | `1.3.6.1.4.1.32473.1.1.795` | `string` | intent | multi | X-PATTERN `^(authenticated\|(user\|group\|filter\|attribute\|scope\|network) [^ ].*)$` | Who an access rule is about: "authenticated", or "<user\|group\|filter\|attribute\|scope\|network> <value>" |
