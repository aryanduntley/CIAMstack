# Messaging

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 5 object classes · 26 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

Messaging domain schema: the services outside the platform it depends on (SMTP relays and email APIs, SMS and voice providers, MFA vendors, CAPTCHA), the addresses it sends mail from, and the event streams it publishes identity events to. A service, a sender and a stream are intent, the same in every environment; where an environment sends a domain's mail from (a cloud sending identity) and the queue or bus that carries a stream are bindings.

**Branches:** `ou=event-streams,dc=ciam-ops`, `ou=external-services,dc=ciam-ops`, `ou=mail-senders,dc=ciam-ops`

## Object classes

<a id="c-ciameventstream"></a>
### ciamEventStream

Identity events the platform publishes: what carries them, which events, who publishes and reads them

OID `1.3.6.1.4.1.32473.1.2.57` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamStreamKind`](#a-ciamstreamkind) | yes | `enum` | single | What carries an event stream: a queue, a topic, an event bus, an event hub, a webhook, a log stream |
| [`ciamEventType`](#a-ciameventtype) |  | `string` | multi | A kind of identity event a stream carries (sign-in, registration, password-change, ...) |
| [`ciamPublishedBy`](#a-ciampublishedby) |  | `string` | multi | A server role that publishes to a stream |
| [`ciamStreamRole`](#a-ciamstreamrole) |  | `string` | single | The binding role of the queue, topic or bus that carries a stream in each environment |
| [`ciamConsumedBy`](#a-ciamconsumedby) |  | `string` | multi | Who reads a stream (a SIEM, a CRM, a team) |
| [`ciamCriticality`](core.md#a-ciamcriticality) |  | `enum` | single | Business criticality |

<a id="c-ciamexternalservice"></a>
### ciamExternalService

A service outside the platform it depends on: a mail relay or API, an SMS or voice provider, an MFA vendor, CAPTCHA

OID `1.3.6.1.4.1.32473.1.2.54` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamServiceKind`](#a-ciamservicekind) | yes | `enum` | single | What an external service is: an SMTP relay, an email or SMS API, an MFA vendor, CAPTCHA, ... |
| [`ciamVendor`](#a-ciamvendor) |  | `string` | single | Who provides an external service |
| [`ciamEndpointHost`](#a-ciamendpointhost) |  | `fqdn` | single | The host the platform reaches an external service at (an SMTP relay, an API); an environment overrides it where it differs |
| [`ciamPort`](infrastructure.md#a-ciamport) |  | `port` | multi | TCP/UDP port |
| [`ciamAllowedDomain`](#a-ciamalloweddomain) |  | `fqdn` | multi | A domain an external service accepts the platform's requests from or for (CAPTCHA allowed domains, a vendor's redirect allowlist): the public names of the roles that use it must be among them, or the service stops working when they change |
| [`ciamReachedFrom`](#a-ciamreachedfrom) |  | `string` | multi | A server role whose servers use an external service (its egress, its public names) |
| [`ciamUsesRole`](automation.md#a-ciamusesrole) |  | `string` | multi | A binding role the job uses (a secret, a service name, a storage location): each environment binds it |
| [`ciamSmtpAuth`](#a-ciamsmtpauth) |  | `enum` | single | How the platform signs in to an SMTP relay: none, basic (a password), or an OAuth 2.0 bearer token from the client credentials grant, with a client secret (oauth-client-credentials) or a private-key JWT (oauth-private-key-jwt); its OAuth client is ciamClientId (with ciamScope), its secret the binding of ciamUsesRole |
| [`ciamTokenEndpoint`](#a-ciamtokenendpoint) |  | `url` | single | The OAuth 2.0 token endpoint the platform obtains an external service's access tokens from |
| [`ciamClientId`](federation.md#a-ciamclientid) |  | `string` | single | OIDC client id |
| [`ciamScope`](federation.md#a-ciamscope) |  | `string` | multi | OAuth 2.0 scopes (a client may request / a service supports) |
| [`ciamSenderId`](#a-ciamsenderid) |  | `string` | multi | An SMS sender ID (alphanumeric or short code) a provider sends with |
| [`ciamOriginatingNumber`](#a-ciamoriginatingnumber) |  | `string` | multi | A number messages and calls come from: users and carriers know it |
| [`ciamRegisteredCountry`](#a-ciamregisteredcountry) |  | `string` | multi | A country where sending is registered with carriers or regulators, and how (US: 10DLC brand) |
| [`ciamSpendLimit`](#a-ciamspendlimit) |  | `string` | single | An external service's spend limit |
| [`ciamPartnerContact`](pki.md#a-ciampartnercontact) |  | `dn` | single | Partner to coordinate rotation with |
| [`ciamCriticality`](core.md#a-ciamcriticality) |  | `enum` | single | Business criticality |

<a id="c-ciammailsender"></a>
### ciamMailSender

An address the platform sends mail from, what it sends and how

OID `1.3.6.1.4.1.32473.1.2.55` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamSenderAddress`](#a-ciamsenderaddress) | yes | `string` | single | The address mail is sent from: users see it, filters and allowlists hold it |
| [`ciamSenderDomain`](#a-ciamsenderdomain) |  | `fqdn` | single | The domain a sender sends as (and a sending identity is verified for) |
| [`ciamSentBy`](#a-ciamsentby) |  | `dn` | single | The external service that sends a sender's mail |
| [`ciamSendingRole`](#a-ciamsendingrole) |  | `string` | single | The binding role of a sender's sending identity in each environment |
| [`ciamBounceHandling`](#a-ciambouncehandling) |  | `string` | single | What happens to bounces and complaints (a mailbox, a queue, a suppression list) |
| [`ciamMessagePurpose`](#a-ciammessagepurpose) |  | `string` | multi | What a sender sends: password-reset, registration, mfa, notification, ... |

<a id="c-ciamsendingidentity"></a>
### ciamSendingIdentity

Where an environment sends a domain's mail from (a cloud email service's identity for the domain): its DKIM, SPF and DMARC facts

OID `1.3.6.1.4.1.32473.1.2.56` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamSenderDomain`](#a-ciamsenderdomain) | yes | `fqdn` | single | The domain a sender sends as (and a sending identity is verified for) |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamDkimVerified`](#a-ciamdkimverified) |  | `bool` | single | Whether a sending identity's domain signs with DKIM keys the domain's DNS publishes |
| [`ciamSpfAuthorized`](#a-ciamspfauthorized) |  | `bool` | single | Whether the domain's SPF record authorizes a sending identity's service |
| [`ciamDmarcPolicy`](#a-ciamdmarcpolicy) |  | `enum` | single | The policy the domain's DMARC record asks receivers to apply |

<a id="c-ciamstreambinding"></a>
### ciamStreamBinding

The queue, topic or bus that carries a stream in an environment

OID `1.3.6.1.4.1.32473.1.2.58` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) | yes | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamStreamKind`](#a-ciamstreamkind) |  | `enum` | single | What carries an event stream: a queue, a topic, an event bus, an event hub, a webhook, a log stream |
| [`ciamSendSecretRole`](#a-ciamsendsecretrole) |  | `string` | single | Binding role of the secret holding what a producer sends to a stream with (an Event Hub's connection string), read when applied: a reference, never the value |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamalloweddomain"></a>`ciamAllowedDomain` | `1.3.6.1.4.1.32473.1.1.269` | `fqdn` | contract | multi |  | A domain an external service accepts the platform's requests from or for (CAPTCHA allowed domains, a vendor's redirect allowlist): the public names of the roles that use it must be among them, or the service stops working when they change |
| <a id="a-ciambouncehandling"></a>`ciamBounceHandling` | `1.3.6.1.4.1.32473.1.1.279` | `string` | intent | single |  | What happens to bounces and complaints (a mailbox, a queue, a suppression list) |
| <a id="a-ciamconsumedby"></a>`ciamConsumedBy` | `1.3.6.1.4.1.32473.1.1.288` | `string` | intent | multi |  | Who reads a stream (a SIEM, a CRM, a team) |
| <a id="a-ciamdkimverified"></a>`ciamDkimVerified` | `1.3.6.1.4.1.32473.1.1.281` | `bool` | binding | single |  | Whether a sending identity's domain signs with DKIM keys the domain's DNS publishes |
| <a id="a-ciamdmarcpolicy"></a>`ciamDmarcPolicy` | `1.3.6.1.4.1.32473.1.1.283` | enum: `none`, `quarantine`, `reject` | binding | single |  | The policy the domain's DMARC record asks receivers to apply |
| <a id="a-ciamendpointhost"></a>`ciamEndpointHost` | `1.3.6.1.4.1.32473.1.1.268` | `fqdn` | binding | single |  | The host the platform reaches an external service at (an SMTP relay, an API); an environment overrides it where it differs |
| <a id="a-ciameventtype"></a>`ciamEventType` | `1.3.6.1.4.1.32473.1.1.285` | `string` | intent | multi |  | A kind of identity event a stream carries (sign-in, registration, password-change, ...) |
| <a id="a-ciammessagepurpose"></a>`ciamMessagePurpose` | `1.3.6.1.4.1.32473.1.1.280` | `string` | intent | multi |  | What a sender sends: password-reset, registration, mfa, notification, ... |
| <a id="a-ciamoriginatingnumber"></a>`ciamOriginatingNumber` | `1.3.6.1.4.1.32473.1.1.272` | `string` | contract | multi |  | A number messages and calls come from: users and carriers know it |
| <a id="a-ciampublishedby"></a>`ciamPublishedBy` | `1.3.6.1.4.1.32473.1.1.286` | `string` | intent | multi |  | A server role that publishes to a stream |
| <a id="a-ciamreachedfrom"></a>`ciamReachedFrom` | `1.3.6.1.4.1.32473.1.1.270` | `string` | intent | multi |  | A server role whose servers use an external service (its egress, its public names) |
| <a id="a-ciamregisteredcountry"></a>`ciamRegisteredCountry` | `1.3.6.1.4.1.32473.1.1.273` | `string` | intent | multi |  | A country where sending is registered with carriers or regulators, and how (US: 10DLC brand) |
| <a id="a-ciamsenderaddress"></a>`ciamSenderAddress` | `1.3.6.1.4.1.32473.1.1.275` | `string` | contract | single |  | The address mail is sent from: users see it, filters and allowlists hold it |
| <a id="a-ciamsenderdomain"></a>`ciamSenderDomain` | `1.3.6.1.4.1.32473.1.1.276` | `fqdn` | contract | single |  | The domain a sender sends as (and a sending identity is verified for) |
| <a id="a-ciamsenderid"></a>`ciamSenderId` | `1.3.6.1.4.1.32473.1.1.271` | `string` | intent | multi |  | An SMS sender ID (alphanumeric or short code) a provider sends with |
| <a id="a-ciamsendingrole"></a>`ciamSendingRole` | `1.3.6.1.4.1.32473.1.1.278` | `string` | intent | single |  | The binding role of a sender's sending identity in each environment |
| <a id="a-ciamsendsecretrole"></a>`ciamSendSecretRole` | `1.3.6.1.4.1.32473.1.1.651` | `string` | binding | single |  | Binding role of the secret holding what a producer sends to a stream with (an Event Hub's connection string), read when applied: a reference, never the value |
| <a id="a-ciamsentby"></a>`ciamSentBy` | `1.3.6.1.4.1.32473.1.1.277` | `dn` | intent | single |  | The external service that sends a sender's mail |
| <a id="a-ciamservicekind"></a>`ciamServiceKind` | `1.3.6.1.4.1.32473.1.1.266` | enum: `smtp-relay`, `email-api`, `sms`, `voice`, `mfa`, `captcha`, `push`, `other` | intent | single |  | What an external service is: an SMTP relay, an email or SMS API, an MFA vendor, CAPTCHA, ... |
| <a id="a-ciamsmtpauth"></a>`ciamSmtpAuth` | `1.3.6.1.4.1.32473.1.1.635` | enum: `none`, `basic`, `oauth-client-credentials`, `oauth-private-key-jwt` | intent | single |  | How the platform signs in to an SMTP relay: none, basic (a password), or an OAuth 2.0 bearer token from the client credentials grant, with a client secret (oauth-client-credentials) or a private-key JWT (oauth-private-key-jwt); its OAuth client is ciamClientId (with ciamScope), its secret the binding of ciamUsesRole |
| <a id="a-ciamspendlimit"></a>`ciamSpendLimit` | `1.3.6.1.4.1.32473.1.1.274` | `string` | meta | single |  | An external service's spend limit |
| <a id="a-ciamspfauthorized"></a>`ciamSpfAuthorized` | `1.3.6.1.4.1.32473.1.1.282` | `bool` | binding | single |  | Whether the domain's SPF record authorizes a sending identity's service |
| <a id="a-ciamstreamkind"></a>`ciamStreamKind` | `1.3.6.1.4.1.32473.1.1.284` | enum: `queue`, `topic`, `bus`, `event-hub`, `webhook`, `log-stream`, `other` | intent | single |  | What carries an event stream: a queue, a topic, an event bus, an event hub, a webhook, a log stream |
| <a id="a-ciamstreamrole"></a>`ciamStreamRole` | `1.3.6.1.4.1.32473.1.1.287` | `string` | intent | single |  | The binding role of the queue, topic or bus that carries a stream in each environment |
| <a id="a-ciamtokenendpoint"></a>`ciamTokenEndpoint` | `1.3.6.1.4.1.32473.1.1.636` | `url` | contract | single |  | The OAuth 2.0 token endpoint the platform obtains an external service's access tokens from |
| <a id="a-ciamvendor"></a>`ciamVendor` | `1.3.6.1.4.1.32473.1.1.267` | `string` | intent | single |  | Who provides an external service |
