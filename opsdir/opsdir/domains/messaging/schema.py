"""Messaging domain schema: the services outside the platform it depends on (SMTP relays and email APIs, SMS and voice
providers, MFA vendors, CAPTCHA), the addresses it sends mail from, and the event streams it publishes identity events
to. A service, a sender and a stream are intent, the same in every environment; where an environment sends a
domain's mail from (a cloud sending identity) and the queue or bus that carries a stream are bindings."""
from ...core.standard import AttributeDef, ClassDef, enum_type, fragment
from .naming import DMARC_STRENGTH, SERVICE_KINDS, STREAM_KINDS

ATTRIBUTES = (
    # ------------------------------------------------------------------ external services
    AttributeDef(266, 'ciamServiceKind', enum_type(SERVICE_KINDS), 'intent', True,
                 'What an external service is: an SMTP relay, an email or SMS API, an MFA vendor, CAPTCHA, ...'),
    AttributeDef(267, 'ciamVendor', 'string', 'intent', True, 'Who provides an external service'),
    AttributeDef(268, 'ciamEndpointHost', 'fqdn', 'binding', True,
                 'The host the platform reaches an external service at (an SMTP relay, an API); an environment '
                 'overrides it where it differs'),
    AttributeDef(269, 'ciamAllowedDomain', 'fqdn', 'contract', False,
                 "A domain an external service accepts the platform's requests from or for (CAPTCHA allowed "
                 "domains, a vendor's redirect allowlist): the public names of the roles that use it must be among "
                 "them, or the service stops working when they change"),
    AttributeDef(270, 'ciamReachedFrom', 'string', 'intent', False,
                 'A server role whose servers use an external service (its egress, its public names)'),
    AttributeDef(271, 'ciamSenderId', 'string', 'intent', False,
                 'An SMS sender ID (alphanumeric or short code) a provider sends with'),
    AttributeDef(272, 'ciamOriginatingNumber', 'string', 'contract', False,
                 'A number messages and calls come from: users and carriers know it'),
    AttributeDef(273, 'ciamRegisteredCountry', 'string', 'intent', False,
                 'A country where sending is registered with carriers or regulators, and how (US: 10DLC brand)'),
    AttributeDef(274, 'ciamSpendLimit', 'string', 'meta', True, "An external service's spend limit"),
    # ------------------------------------------------------------------ mail senders
    AttributeDef(275, 'ciamSenderAddress', 'string', 'contract', True,
                 'The address mail is sent from: users see it, filters and allowlists hold it'),
    AttributeDef(276, 'ciamSenderDomain', 'fqdn', 'contract', True,
                 'The domain a sender sends as (and a sending identity is verified for)'),
    AttributeDef(277, 'ciamSentBy', 'dn', 'intent', True, 'The external service that sends a sender\'s mail'),
    AttributeDef(278, 'ciamSendingRole', 'string', 'intent', True,
                 "The binding role of a sender's sending identity in each environment"),
    AttributeDef(279, 'ciamBounceHandling', 'string', 'intent', True,
                 'What happens to bounces and complaints (a mailbox, a queue, a suppression list)'),
    AttributeDef(280, 'ciamMessagePurpose', 'string', 'intent', False,
                 'What a sender sends: password-reset, registration, mfa, notification, ...'),
    AttributeDef(281, 'ciamDkimVerified', 'bool', 'binding', True,
                 "Whether a sending identity's domain signs with DKIM keys the domain's DNS publishes"),
    AttributeDef(282, 'ciamSpfAuthorized', 'bool', 'binding', True,
                 "Whether the domain's SPF record authorizes a sending identity's service"),
    AttributeDef(283, 'ciamDmarcPolicy', enum_type(DMARC_STRENGTH), 'binding', True,
                 "The policy the domain's DMARC record asks receivers to apply"),
    # ------------------------------------------------------------------ event streams
    AttributeDef(284, 'ciamStreamKind', enum_type(STREAM_KINDS), 'intent', True,
                 'What carries an event stream: a queue, a topic, an event bus, an event hub, a webhook, a log '
                 'stream'),
    AttributeDef(285, 'ciamEventType', 'string', 'intent', False,
                 'A kind of identity event a stream carries (sign-in, registration, password-change, ...)'),
    AttributeDef(286, 'ciamPublishedBy', 'string', 'intent', False, 'A server role that publishes to a stream'),
    AttributeDef(287, 'ciamStreamRole', 'string', 'intent', True,
                 'The binding role of the queue, topic or bus that carries a stream in each environment'),
    AttributeDef(288, 'ciamConsumedBy', 'string', 'intent', False, 'Who reads a stream (a SIEM, a CRM, a team)'),
)
CLASSES = (
    ClassDef(54, 'ciamExternalService', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamServiceKind'),
             ('ciamVendor', 'ciamEndpointHost', 'ciamPort', 'ciamAllowedDomain', 'ciamReachedFrom', 'ciamUsesRole',
              'ciamSenderId', 'ciamOriginatingNumber', 'ciamRegisteredCountry', 'ciamSpendLimit',
              'ciamPartnerContact', 'ciamCriticality'),
             'A service outside the platform it depends on: a mail relay or API, an SMS or voice provider, an MFA '
             'vendor, CAPTCHA'),
    ClassDef(55, 'ciamMailSender', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamSenderAddress'),
             ('ciamSenderDomain', 'ciamSentBy', 'ciamSendingRole', 'ciamBounceHandling', 'ciamMessagePurpose'),
             'An address the platform sends mail from, what it sends and how'),
    ClassDef(56, 'ciamSendingIdentity', 'ciamBinding', 'STRUCTURAL', ('ciamSenderDomain',),
             ('ciamProviderRef', 'ciamDkimVerified', 'ciamSpfAuthorized', 'ciamDmarcPolicy'),
             "Where an environment sends a domain's mail from (a cloud email service's identity for the domain): "
             "its DKIM, SPF and DMARC facts"),
    ClassDef(57, 'ciamEventStream', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamStreamKind'),
             ('ciamEventType', 'ciamPublishedBy', 'ciamStreamRole', 'ciamConsumedBy', 'ciamCriticality'),
             'Identity events the platform publishes: what carries them, which events, who publishes and reads them'),
    ClassDef(58, 'ciamStreamBinding', 'ciamBinding', 'STRUCTURAL', ('ciamProviderRef',), ('ciamStreamKind',),
             'The queue, topic or bus that carries a stream in an environment'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
