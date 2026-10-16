"""federation domain schema fragment: its attribute types and object classes (OIDs pinned by number)."""
from ...core.standard import OVERRIDABLE, AttributeDef, ClassDef, enum_type, fragment

# Standard values (the protocols' own names), so every product adapter maps from one vocabulary.
GRANT_TYPES = ("authorization_code", "client_credentials", "refresh_token",
               "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:jwt-bearer",
               "urn:ietf:params:oauth:grant-type:saml2-bearer", "urn:ietf:params:oauth:grant-type:token-exchange")
TOKEN_AUTH_METHODS = ("none", "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt",
                      "tls_client_auth", "self_signed_tls_client_auth")      # RFC 7591, OIDC Core 9, RFC 8705
SAML_BINDINGS = ("HTTP-POST", "HTTP-Redirect", "HTTP-Artifact", "SOAP")     # urn:oasis:names:tc:SAML:2.0:bindings:*
NAMEID_FORMATS = ("unspecified", "emailAddress", "persistent", "transient")  # SAML 2.0 core 8.3
# How a managed identity service's sign-in flow signs users in (sign-up: accounts are created in it), and the events a
# custom authentication extension answers (a token being issued, attributes being collected at sign-up, a one-time
# passcode being sent, a password being submitted: just-in-time migration)
SIGN_IN_METHODS = ("email-password", "email-otp", "sign-up", "federated")
EXTENSION_EVENTS = ("token-issuance-start", "attribute-collection-start", "attribute-collection-submit", "otp-send",
                    "password-submit")
SIGNING_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")   # RFC 7518

ATTRIBUTES = (
    AttributeDef(86, 'ciamProtocolType', 'enum:saml2-sp|oidc-client|saml2-idp|ldap', 'intent', True,
                 'Integration type'),
    AttributeDef(87, 'ciamEntityId', 'url', 'contract', True,
                 'SAML entity ID', OVERRIDABLE),
    AttributeDef(88, 'ciamAcsUrl', 'url', 'contract', True,
                 'SAML assertion consumer service URL'),
    AttributeDef(89, 'ciamRedirectUri', 'url', 'contract', False,
                 'OIDC redirect URI'),
    AttributeDef(90, 'ciamClientId', 'string', 'contract', True,
                 'OIDC client id'),
    AttributeDef(91, 'ciamGrantType', 'enum:' + '|'.join(GRANT_TYPES), 'intent', False,
                 'OAuth 2.0 grant types (RFC 6749 and extension grants by URN)'),
    AttributeDef(92, 'ciamPkceRequired', 'bool', 'intent', True,
                 'PKCE required'),
    AttributeDef(94, 'ciamMfaRequired', 'bool', 'intent', True,
                 'MFA required'),
    AttributeDef(95, 'ciamUsesCertificate', 'dn', 'intent', False,
                 'Certificates this integration depends on'),
    AttributeDef(96, 'ciamJitBaseDn', 'extdn', 'intent', True,
                 'Where just-in-time provisioned partner users are created'),
    AttributeDef(97, 'ciamClaimName', 'string', 'contract', True,
                 'Claim / SAML attribute name the application receives'),
    AttributeDef(98, 'ciamSourceAttribute', 'dn', 'intent', True,
                 'User-directory attribute record the claim comes from'),
    AttributeDef(99, 'ciamTransform', 'string', 'intent', True,
                 'Transformation applied to the value'),
    AttributeDef(140, 'ciamTokenAuthMethod', 'enum:' + '|'.join(TOKEN_AUTH_METHODS), 'intent', False,
                 'Token endpoint client authentication methods (a product taking one per client renders the first)'),
    AttributeDef(634, 'ciamDpopBound', 'bool', 'intent', True,
                 'Whether the client\'s access tokens are DPoP-bound: it must present DPoP proofs (RFC 9449 '
                 'dpop_bound_access_tokens)'),
    AttributeDef(141, 'ciamScope', 'string', 'contract', False,
                 'OAuth 2.0 scopes (a client may request / a service supports)'),
    AttributeDef(142, 'ciamPostLogoutRedirectUri', 'url', 'contract', False,
                 'OIDC post-logout redirect URI'),
    AttributeDef(143, 'ciamSamlBinding', 'enum:' + '|'.join(SAML_BINDINGS), 'contract', True,
                 'SAML binding of the assertion consumer service (or single sign-on service)'),
    AttributeDef(144, 'ciamNameIdFormat', 'enum:' + '|'.join(NAMEID_FORMATS), 'contract', False,
                 'SAML NameID formats (a partner expects / a service supports)'),
    AttributeDef(145, 'ciamSsoUrl', 'url', 'contract', True,
                 'Single sign-on service URL of a partner identity provider'),
    AttributeDef(146, 'ciamOidcIssuer', 'url', 'contract', True,
                 'OIDC issuer identifier', OVERRIDABLE),
    AttributeDef(147, 'ciamBaseUrl', 'url', 'contract', True,
                 'Public base URL of an identity service (its endpoints are paths under it)', OVERRIDABLE),
    AttributeDef(148, 'ciamSigningAlg', 'enum:' + '|'.join(SIGNING_ALGS), 'intent', False,
                 'Token signing algorithms (JWS)'),
    AttributeDef(213, 'ciamServedBy', 'dn', 'intent', True,
                 'The identity service the integration is registered with (none: every identity service serves it)'),
    AttributeDef(770, 'ciamManagedService', 'vocab', 'binding', True,
                 'The cloud-managed identity service a binding is, as the adapter declaring it names it (a user pool '
                 'service, an external tenant)'),
    AttributeDef(771, 'ciamPartnerOf', 'dn', 'intent', False,
                 'The integrations a managed identity service is the partner side of (a neighbour the platform '
                 'federates with): whether it is their relying party or their issuer follows from their protocol type'),
    AttributeDef(808, 'ciamFlowApplications', 'dn', 'intent', False,
                 'The integrations a sign-in flow signs users in to'),
    AttributeDef(809, 'ciamSignInMethod', enum_type(SIGN_IN_METHODS), 'intent', False,
                 'How a sign-in flow signs users in (sign-up: it also creates their accounts; federated: through an '
                 'upstream identity provider)'),
    AttributeDef(810, 'ciamUpstreamProvider', 'string', 'intent', False,
                 'An upstream identity provider a sign-in flow offers, as the managed service names it'),
    AttributeDef(811, 'ciamCollectedAttribute', 'string', 'intent', False,
                 'A user attribute a sign-in flow collects at sign-up, as the managed service names it'),
    AttributeDef(812, 'ciamFlowExtension', 'dn', 'intent', False,
                 'The custom authentication extensions a sign-in flow calls'),
    AttributeDef(813, 'ciamExtensionEvent', enum_type(EXTENSION_EVENTS), 'intent', True,
                 'The sign-in event a custom authentication extension answers'),
    AttributeDef(814, 'ciamExtensionResource', 'string', 'binding', True,
                 'The application a custom authentication extension authenticates to its API as (its app ID URI or '
                 'ID); where the API runs is not recorded'),
    AttributeDef(815, 'ciamExtensionClaim', 'string', 'contract', False,
                 'A claim a custom authentication extension returns for tokens'),
    AttributeDef(816, 'ciamDataGeography', 'vocab', 'binding', True,
                 'Where a managed identity service keeps its users\' data, as the adapter declaring it names the '
                 'geography (a tenant\'s data residency)'),
)
CLASSES = (
    ClassDef(26, 'ciamIntegration', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamProtocolType'),
             ('ciamEntityId', 'ciamAcsUrl', 'ciamRedirectUri', 'ciamClientId', 'ciamGrantType', 'ciamPkceRequired',
              'ciamDpopBound',
              'ciamPopulation', 'ciamMfaRequired', 'ciamUsesCertificate', 'ciamJitBaseDn', 'ciamCriticality',
              'ciamTokenAuthMethod', 'ciamScope', 'ciamPostLogoutRedirectUri', 'ciamSamlBinding', 'ciamNameIdFormat',
              'ciamSsoUrl', 'ciamServedBy'),
             'Application or partner integration'),
    ClassDef(27, 'ciamClaimMap', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamClaimName', 'ciamSourceAttribute'),
             ('ciamTransform',),
             'One claim / SAML attribute mapping'),
    ClassDef(35, 'ciamIdentityService', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamBaseUrl'),
             ('ciamEntityId', 'ciamOidcIssuer', 'ciamScope', 'ciamSigningAlg', 'ciamNameIdFormat',
              'ciamUsesCertificate', 'ciamTargetRole', 'ciamCriticality'),
             'The platform\'s own identity provider / OpenID provider, as partners and applications know it'),
    ClassDef(167, 'ciamManagedIdentity', 'ciamBinding', 'STRUCTURAL', ('ciamManagedService',),
             ('ciamRealizes', 'ciamPartnerOf', 'ciamProviderRef', 'ciamFqdn', 'ciamTlsCertificate', 'ciamManagedBy',
              'ciamDataGeography'),
             "A cloud-managed identity service an environment uses: the platform's own identity service run on it "
             "there (ciamRealizes: the identity service's name; a target), or a neighbour the platform federates "
             "with (ciamPartnerOf: the integrations it is the partner side of); its resource (ciamProviderRef), the "
             "sign-in host it serves at (ciamFqdn, a custom domain presenting ciamTlsCertificate), where it keeps its "
             "users' data (ciamDataGeography) and who keeps it when it isn't the platform team (ciamManagedBy); a "
             "target's sign-in flows and custom authentication extensions are entries beneath it"),
    ClassDef(178, 'ciamSignInFlow', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('ciamFlowApplications', 'ciamSignInMethod', 'ciamUpstreamProvider', 'ciamCollectedAttribute',
              'ciamFlowExtension'),
             "A sign-in flow of a managed identity service (beneath its binding): the integrations it signs users in "
             "to, how (its methods, its upstream identity providers), what it collects at sign-up and the custom "
             "authentication extensions it calls"),
    ClassDef(179, 'ciamAuthExtension', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamExtensionEvent'),
             ('ciamExtensionResource', 'ciamExtensionClaim'),
             "A custom authentication extension of a managed identity service (beneath its binding): the event it "
             "answers, the application it authenticates as and the claims it returns; its endpoint and the code "
             "behind it aren't recorded"),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
