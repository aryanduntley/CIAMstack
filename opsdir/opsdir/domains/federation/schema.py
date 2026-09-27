"""federation domain schema fragment: its attribute types and object classes (OIDs pinned by number)."""
from ...core.standard import AttributeDef, ClassDef, SchemaFragment

ATTRIBUTES = (
    AttributeDef(86, 'ciamProtocolType', 'enum:saml2-sp|oidc-client|saml2-idp|ldap', 'intent', True,
                 'Integration type'),
    AttributeDef(87, 'ciamEntityId', 'url', 'contract', True,
                 'SAML entity ID'),
    AttributeDef(88, 'ciamAcsUrl', 'url', 'contract', True,
                 'SAML assertion consumer service URL'),
    AttributeDef(89, 'ciamRedirectUri', 'url', 'contract', False,
                 'OIDC redirect URI'),
    AttributeDef(90, 'ciamClientId', 'string', 'contract', True,
                 'OIDC client id'),
    AttributeDef(91, 'ciamGrantType', 'enum:authorization_code|client_credentials|refresh_token', 'intent', False,
                 'OIDC grant types'),
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
)
CLASSES = (
    ClassDef(26, 'ciamIntegration', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamProtocolType'),
             ('ciamEntityId', 'ciamAcsUrl', 'ciamRedirectUri', 'ciamClientId', 'ciamGrantType', 'ciamPkceRequired', 'ciamPopulation', 'ciamMfaRequired', 'ciamUsesCertificate', 'ciamJitBaseDn', 'ciamCriticality'),
             'Application or partner integration'),
    ClassDef(27, 'ciamClaimMap', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamClaimName', 'ciamSourceAttribute'),
             ('ciamTransform',),
             'One claim / SAML attribute mapping'),
)

FRAGMENT = SchemaFragment(ATTRIBUTES, CLASSES)
