"""pki domain schema fragment: its attribute types and object classes (OIDs pinned by number)."""
from ...core.standard import AttributeDef, ClassDef, SchemaFragment

ATTRIBUTES = (
    AttributeDef(100, 'ciamFingerprint', 'string', 'meta', True,
                 'SHA-256 fingerprint'),
    AttributeDef(101, 'ciamSubject', 'string', 'meta', True,
                 'Certificate subject'),
    AttributeDef(102, 'ciamIssuer', 'string', 'meta', True,
                 'Certificate issuer'),
    AttributeDef(103, 'ciamNotBefore', 'time', 'meta', True,
                 'Valid from'),
    AttributeDef(104, 'ciamNotAfter', 'time', 'meta', True,
                 'Expires'),
    AttributeDef(105, 'ciamCertPurpose', 'enum:tls-server|saml-signing|saml-encryption|jwt-signing|partner-signing', 'intent', True,
                 'What the certificate is for'),
    AttributeDef(106, 'ciamSubjectAltName', 'fqdn', 'contract', False,
                 'DNS names the certificate is valid for'),
    AttributeDef(107, 'ciamKeyRole', 'string', 'meta', True,
                 'Binding role of the secret holding the private key (per environment)'),
    AttributeDef(108, 'ciamPartnerContact', 'dn', 'meta', True,
                 'Partner to coordinate rotation with'),
    AttributeDef(109, 'ciamRotationRunbook', 'dn', 'meta', True,
                 'Work instruction for rotation'),
)
CLASSES = (
    ClassDef(28, 'ciamCertificate', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamFingerprint', 'ciamNotAfter', 'ciamCertPurpose'),
             ('ciamSubject', 'ciamIssuer', 'ciamNotBefore', 'ciamSubjectAltName', 'ciamKeyRole', 'ciamPartnerContact', 'ciamRotationRunbook'),
             'Certificate (public facts only)'),
)

FRAGMENT = SchemaFragment(ATTRIBUTES, CLASSES)
