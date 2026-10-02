"""PKI fixture data: certificates as public facts (70-certificates), some expiring before the planned cutover, and
the platform's keys and secrets as credentials (72-credentials): what each is, how it rotates, whether the same
material must reach the target environment, and where it is used. Each environment binds them by role (40/45)."""
from .common import CERTS, CREDS, RB, fp, owner, spec, t

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


# (role, type, algorithm, size, usage, format, HSM required, exportable, rotation days, continuity, why, used in, runbook)
CREDENTIALS = (
    ("ds-deployment-id", "deployment-id", None, None, ["replication", "encryption"], "text", None, "TRUE", None,
     "carry-over", "DS replicas join a replication deployment only with its deployment id, which also protects the "
     "keys that encrypt backups", None, None),
    ("ds-deployment-password", "password", None, None, ["replication", "encryption"], "text", None, "TRUE", None,
     "carry-over", "it unlocks the deployment's shared master key", None, None),
    ("ds-root-password", "password", None, None, ["administration"], "text", None, "TRUE", 90,
     "per-environment", None, None, None),
    ("ds-tls-keystore", "keystore", "RSA", 2048, ["tls"], "pkcs12", None, "TRUE", 365, "per-environment", None, None,
     "WI-CIAM-002"),
    ("sso-tls-keystore", "keystore", "RSA", 2048, ["tls"], "pkcs12", None, "TRUE", 365, "per-environment", None, None,
     None),
    ("pf-signing-key", "private-key", "RSA", 2048, ["signing"], "pkcs12", None, "TRUE", 730, "carry-over",
     "partners and applications trust its certificate; a new key means new metadata for every one of them", None,
     None),
    ("pf-admin-password", "password", None, None, ["administration"], "text", None, "TRUE", 30, "per-environment",
     None, "cn=run.properties,ou=config-files,dc=ciam-ops", None),
    ("disk-encryption", "symmetric-key", "AES-256", 256, ["encryption", "key-wrapping"], "raw", "TRUE", "FALSE", 365,
     "per-environment", None, None, None),
    ("am-admin-password", "password", None, None, ["administration"], "text", None, "TRUE", 90, "per-environment",
     None, None, None),
    ("am-keystore", "keystore", "RSA", 2048, ["signing", "encryption"], "jceks", None, "TRUE", 730, "carry-over",
     "tokens and assertions signed before cutover must still verify, and partners cache the realm's signing keys",
     None, None),
    ("am-ds-bind-password", "password", None, None, ["authentication"], "text", None, "TRUE", 90, "per-environment",
     None, None, None),
    ("idm-admin-password", "password", None, None, ["administration"], "text", None, "TRUE", 90, "per-environment",
     None, None, None),
    ("idm-keystore", "keystore", "AES", 256, ["encryption"], "jceks", None, "TRUE", None, "carry-over",
     "IDM encrypts managed object properties and its settings with it; a new key can't read what the old one wrote",
     None, None),
    ("idm-ds-bind-password", "password", None, None, ["authentication"], "text", None, "TRUE", 90, "per-environment",
     None, "cn=idm-sync,ou=consumers,dc=ciam-ops", None),
    ("idm-hrdb-password", "password", None, None, ["authentication"], "text", None, "TRUE", 180, "per-environment",
     None, None, None),
    ("pf-ds-bind-password", "password", None, None, ["authentication"], "text", None, "TRUE", 90, "per-environment",
     None, "cn=pf-ds-svc,ou=consumers,dc=ciam-ops", None),
    ("pf-grants-db-password", "password", None, None, ["authentication"], "text", None, "TRUE", 180, "per-environment",
     None, None, None),
    ("pf-smtp-password", "password", None, None, ["authentication"], "text", None, "TRUE", 90, "per-environment",
     None, None, None),
    ("pf-captcha-secret", "api-token", None, None, ["authentication"], "text", None, "TRUE", 365, "carry-over",
     "reCAPTCHA's secret key belongs to the site key the vendor issued; a new environment keeps the same pair", None,
     None),
    ("ig-keystore", "keystore", "RSA", 2048, ["tls"], "pkcs12", None, "TRUE", 365, "per-environment", None, None,
     None),
)


def credentials():
    return tuple(spec("72-credentials", f"cn={role},{CREDS}", ["top", "ciamCredential"], cn=role,
                      ciamBindingRole=role, ciamCredentialType=kind, ciamKeyAlgorithm=alg, ciamKeySize=size,
                      ciamKeyUsage=usage, ciamMaterialFormat=fmt, ciamHsmRequired=hsm, ciamExportable=export,
                      ciamRotationDays=days, ciamContinuity=continuity, ciamContinuityReason=why, ciamUsedIn=used,
                      ciamRotationRunbook=f"cn={rb},{RB}" if rb else None, ciamOwner=owner("ciam-platform"))
                 for role, kind, alg, size, usage, fmt, hsm, export, days, continuity, why, used, rb in CREDENTIALS)
