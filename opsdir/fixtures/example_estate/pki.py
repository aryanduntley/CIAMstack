"""PKI fixture data: certificates as public facts (70-certificates), some expiring before the planned cutover."""
from .common import CERTS, RB, fp, owner, spec, t

CERTIFICATES = (
    ("ds-ldaps-2026", "tls-server", "CN=ldap.id.example-aero.test", "CN=Example Aero Issuing CA 2",
     "2025-12-20", "2026-12-20", ["ldap.id.example-aero.test"], "ds-tls-keystore", "ciam-platform", None, "WI-CIAM-002", None),
    ("sso-tls-2026", "tls-server", "CN=sso.example-aero.test", "CN=Public CA R11",
     "2026-02-10", "2027-02-10", ["sso.example-aero.test"], "sso-tls-keystore", "ciam-platform", None, None, None),
    ("pf-signing-2025", "saml-signing", "CN=Example Aero SSO Signing 2025", "self-signed",
     "2025-07-01", "2027-06-30", None, "pf-signing-key", "ciam-platform", None, "WI-CIAM-010", "2025-07-01"),
    ("customer-portal-sp-signing", "saml-signing", "CN=portal.example-aero.test SP", "self-signed",
     "2024-03-01", "2027-03-01", None, None, "customer-portal-team", None, None, None),
    ("supplier-portal-sp-signing", "saml-signing", "CN=suppliers.example-aero.test SP", "self-signed",
     "2023-11-30", "2026-11-30", None, None, "supplier-portal-team", None, None, None),
    ("skyline-air-idp-signing", "partner-signing", "CN=Skyline Air IdP Signing", "self-signed",
     "2024-11-02", "2026-11-02", None, None, "ciam-platform", "skyline-air", "WI-CIAM-001", None),
    ("harbor-mro-idp-signing", "partner-signing", "CN=Harbor MRO SSO", "self-signed",
     "2025-01-15", "2028-01-15", None, None, "ciam-platform", "harbor-mro", "WI-CIAM-001", None),
)


def certificates():
    return tuple(spec("70-certificates", f"cn={cn},{CERTS}", ["top", "ciamCertificate"], cn=cn, ciamFingerprint=fp(cn),
                      ciamCertPurpose=purpose, ciamSubject=subject, ciamIssuer=issuer, ciamNotBefore=t(nb),
                      ciamNotAfter=t(na), ciamSubjectAltName=sans, ciamKeyRole=keyrole, ciamOwner=owner(own),
                      ciamPartnerContact=owner(partner)[0] if partner else None,
                      ciamRotationRunbook=f"cn={rb},{RB}" if rb else None, ciamLastChanged=t(changed) if changed else None)
                 for cn, purpose, subject, issuer, nb, na, sans, keyrole, own, partner, rb, changed in CERTIFICATES)
