"""Federation fixture data: the platform's identity service (74-identity-services), SAML/OIDC integrations and their
claim maps (75-integrations)."""
from .common import IDS, INTS, PEOPLE, cert, ou, owner, spec, ua
from .custom import TOKEN_LIFETIMES

INTEGRATIONS = (
    ("customer-portal", "saml2-sp", dict(
        ciamEntityId="https://portal.example-aero.test/saml/sp", ciamAcsUrl="https://portal.example-aero.test/saml/acs",
        ciamSamlBinding="HTTP-POST", ciamNameIdFormat="persistent", ciamPopulation="customers", ciamMfaRequired="TRUE", ciamCriticality="critical",
        ciamUsesCertificate=cert("pf-signing-2025", "customer-portal-sp-signing", "sso-tls-2026"),
        ciamOwner=owner("customer-portal-team")),
     [("email", "mail", None), ("given_name", "givenName", None), ("family_name", "sn", None),
      ("company", "companyId", None), ("roles", "appEntitlement", "keep values with prefix 'customer-portal:', strip prefix")]),
    ("supplier-portal", "saml2-sp", dict(
        ciamEntityId="https://suppliers.example-aero.test/saml/sp", ciamAcsUrl="https://suppliers.example-aero.test/saml/acs",
        ciamSamlBinding="HTTP-POST", ciamNameIdFormat="emailAddress", ciamPopulation="suppliers", ciamMfaRequired="TRUE", ciamCriticality="high",
        ciamUsesCertificate=cert("pf-signing-2025", "supplier-portal-sp-signing", "sso-tls-2026"),
        ciamOwner=owner("supplier-portal-team")),
     [("email", "mail", None), ("company", "companyId", None), ("sold_to", "soldToAccount", None),
      ("roles", "appEntitlement", "keep values with prefix 'supplier-portal:', strip prefix")]),
    ("tech-pubs", "oidc-client", dict(
        ciamClientId="tech-pubs-web", ciamRedirectUri="https://techpubs.example-aero.test/oidc/callback",
        ciamPostLogoutRedirectUri="https://techpubs.example-aero.test/signed-out",
        ciamGrantType=["authorization_code", "refresh_token"], ciamPkceRequired="TRUE", ciamTokenAuthMethod="none",
        ciamScope=["openid", "profile", "email"],
        ciamPopulation=["customers", "suppliers"], ciamMfaRequired="FALSE", ciamCriticality="high",
        ciamUsesCertificate=cert("pf-signing-2025", "sso-tls-2026"), ciamOwner=owner("tech-pubs-team")),
     [("email", "mail", None), ("org", "companyId", None), ("entitlements", "appEntitlement", None),
      ("export_status", "exportScreeningStatus", None)]),
    ("mobile-ops", "oidc-client", dict(
        ciamClientId="mobile-ops", ciamRedirectUri="https://mobile.example-aero.test/oauth2/callback",
        ciamGrantType=["authorization_code", "refresh_token"], ciamPkceRequired="TRUE", ciamTokenAuthMethod="none",
        ciamScope=["openid", "email", "offline_access"],
        ciamPopulation="customers", ciamMfaRequired="TRUE", ciamCriticality="medium",
        ciamUsesCertificate=cert("pf-signing-2025", "sso-tls-2026"), ciamOwner=owner("mobile-team")),
     [("sub", "uid", None), ("email", "mail", None), ("org", "companyId", None)]),
    ("skyline-air-federation", "saml2-idp", dict(
        ciamEntityId="https://idp.skyline-air.example/saml", ciamSsoUrl="https://idp.skyline-air.example/saml/sso",
        ciamNameIdFormat="persistent", ciamPopulation="partners", ciamCriticality="high",
        ciamJitBaseDn=f"ou=partners,{PEOPLE}", ciamUsesCertificate=cert("skyline-air-idp-signing", "sso-tls-2026"),
        ciamOwner=owner("ciam-platform", "skyline-air")), []),
    ("harbor-mro-federation", "saml2-idp", dict(
        ciamEntityId="https://sso.harbor-mro.example/idp", ciamSsoUrl="https://sso.harbor-mro.example/idp/SSO.saml2",
        ciamPopulation="partners", ciamCriticality="medium",
        ciamJitBaseDn=f"ou=partners,{PEOPLE}", ciamUsesCertificate=cert("harbor-mro-idp-signing", "sso-tls-2026"),
        ciamOwner=owner("ciam-platform", "harbor-mro")), []),
)


# The platform's own identity provider / OpenID provider, as partners and applications know it (all contracts but
# the algorithms): served by the pf-engine servers behind the pf-sso-service name.
IDENTITY_SERVICE = dict(
    ciamBaseUrl="https://sso.example-aero.test", ciamEntityId="https://sso.example-aero.test/idp",
    ciamOidcIssuer="https://sso.example-aero.test", ciamScope=["openid", "profile", "email", "offline_access"],
    ciamSigningAlg=["RS256", "PS256"], ciamNameIdFormat=["persistent", "emailAddress", "transient"],
    ciamUsesCertificate=cert("pf-signing-2025"), ciamTargetRole="pf-engine", ciamCriticality="critical",
    ciamOwner=owner("ciam-platform"), description="Single sign-on for customers, suppliers and partners")


def identity_services():
    return (spec("74-identity-services", f"cn=sso,{IDS}", ["top", "ciamIdentityService"], cn="sso", **IDENTITY_SERVICE),)


def _integration(cn, ptype, kw, claims):
    idn = f"cn={cn},{INTS}"
    return (spec("75-integrations", idn, ["top", "ciamIntegration"], cn=cn, ciamProtocolType=ptype,
                 xTokenLifetimeMinutes=TOKEN_LIFETIMES.get(cn), **kw),
            *((ou("75-integrations", "claims", idn),) if claims else ()),
            *(spec("75-integrations", f"cn={claim},ou=claims,{idn}", ["top", "ciamClaimMap"], cn=claim,
                   ciamClaimName=claim, ciamSourceAttribute=ua(src)[0], ciamTransform=transform)
              for claim, src, transform in claims))


def integrations():
    return tuple(s for cn, ptype, kw, claims in INTEGRATIONS for s in _integration(cn, ptype, kw, claims))
