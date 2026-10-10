"""federation domain schema fragment: its attribute types and object classes (OIDs pinned by number)."""
from ...core.standard import OVERRIDABLE, AttributeDef, ClassDef, fragment

# Standard values (the protocols' own names), so every product adapter maps from one vocabulary.
GRANT_TYPES = ("authorization_code", "client_credentials", "refresh_token",
               "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:jwt-bearer",
               "urn:ietf:params:oauth:grant-type:saml2-bearer", "urn:ietf:params:oauth:grant-type:token-exchange")
TOKEN_AUTH_METHODS = ("none", "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt",
                      "tls_client_auth", "self_signed_tls_client_auth")      # RFC 7591, OIDC Core 9, RFC 8705
SAML_BINDINGS = ("HTTP-POST", "HTTP-Redirect", "HTTP-Artifact", "SOAP")     # urn:oasis:names:tc:SAML:2.0:bindings:*
NAMEID_FORMATS = ("unspecified", "emailAddress", "persistent", "transient")  # SAML 2.0 core 8.3
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
                 'Token endpoint client authentication methods'),
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
)
CLASSES = (
    ClassDef(26, 'ciamIntegration', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamProtocolType'),
             ('ciamEntityId', 'ciamAcsUrl', 'ciamRedirectUri', 'ciamClientId', 'ciamGrantType', 'ciamPkceRequired',
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
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
