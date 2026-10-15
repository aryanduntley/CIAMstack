"""pki domain schema fragment: its attribute types and object classes (OIDs pinned by number).

Keys, secrets and certificates are described in two layers joined by binding role. A credential (ou=credentials) is
what a key or secret is, the same in every environment: its type, algorithm, what it is for, whether it must stay in
an HSM or may be exported, how often it rotates, whether the same material must reach every environment that takes
over from this one, and everywhere it is used. Each environment binds the role to where it keeps the material: a
secret or key reference (and, for a certificate held in a cloud certificate store, a certificate reference), with
what the store does for it (protection level, automatic rotation, replicas, who may use it). The material itself is
never in the record (SPEC R4): only references to it.

A secret store's inventory (ou=secret-inventory) is what the store said it holds, metadata only, as its importers read
it: per container (a PAM safe, a key/value mount) when it was listed and whether completely, and each object found with
its state and what the store says of its rotation. The record's references are reconciled with it (inventory.py);
nothing an inventory observes is written onto the bindings themselves.

Certification authorities (ou=certificate-authorities) are the CAs the estate's certificates come from, as their
importers read them, with what the operator adds: the CA's own certificates in the record (the hierarchy runs
certificate by certificate: ciamIssuedBy), the templates it issues from and the revocation endpoints it puts in
the certificates it issues (CRL distribution points, delta CRLs, OCSP, CA issuers), its children. Certificate templates
(ou=certificate-templates) are what a CA may issue, with who renews what they issue. A CA's issued-certificate
inventory (ou=issued-certificates) is what its database said it issued, metadata only, never a key: the record's
certificates are reconciled with it (issued.py), and nothing it observes is written onto them.
"""
from ...core.standard import AttributeDef, ClassDef, fragment

ATTRIBUTES = (
    AttributeDef(35, 'ciamRefUri', 'ref-uri', 'secret-ref', True,
                 "Reference to a secret or key in the environment's store. Never the value"),
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
    AttributeDef(105, 'ciamCertPurpose',
                 'enum:tls-server|saml-signing|saml-encryption|jwt-signing|partner-signing|client-auth|ca', 'intent',
                 True, 'What the certificate is for (client-auth: one the operator presents to authenticate, e.g. to '
                       'a reporting portal; ca: a certification authority a truststore adds)'),
    AttributeDef(106, 'ciamSubjectAltName', 'fqdn', 'contract', False,
                 'DNS names the certificate is valid for'),
    AttributeDef(107, 'ciamKeyRole', 'string', 'meta', True,
                 'Binding role of the secret holding the private key (per environment)'),
    AttributeDef(108, 'ciamPartnerContact', 'dn', 'meta', True,
                 'Partner to coordinate rotation with'),
    AttributeDef(109, 'ciamRotationRunbook', 'dn', 'meta', True,
                 'Work instruction for rotation'),
    AttributeDef(624, 'ciamCertificatePem', 'string', 'meta', True,
                 'The certificate itself as PEM: public material only, never a key; recorded for a CA something '
                 'must be given to trust (a gateway checking its backends)'),
    AttributeDef(187, 'ciamCredentialType',
                 'enum:private-key|symmetric-key|keystore|password|api-token|client-secret|shared-secret|'
                 'deployment-id|ssh-key|other', 'intent', True,
                 'What kind of key or secret the credential is'),
    AttributeDef(188, 'ciamKeyAlgorithm', 'string', 'intent', True,
                 'Key algorithm (e.g. RSA, EC P-256, AES-256, HMAC-SHA256)'),
    AttributeDef(189, 'ciamKeySize', 'int', 'intent', True,
                 'Key size in bits', (("X-MIN", "1"),)),
    AttributeDef(190, 'ciamKeyUsage',
                 'enum:signing|encryption|key-wrapping|tls|authentication|replication|administration|other',
                 'intent', False,
                 'What the credential is used for'),
    AttributeDef(191, 'ciamMaterialFormat', 'enum:pem|der|pkcs12|jks|jceks|jwk|raw|text|other', 'intent', True,
                 'The form the material takes where it is used'),
    AttributeDef(608, 'ciamPasswordRole', 'string', 'meta', True,
                 'Binding role of the secret holding the password that protects the material where it is kept (a '
                 'PKCS#12 file\'s), per environment like the material\'s own role'),
    AttributeDef(192, 'ciamHsmRequired', 'bool', 'intent', True,
                 'The material must be generated and kept in a hardware security module'),
    AttributeDef(193, 'ciamExportable', 'bool', 'intent', True,
                 'The material may leave the store that holds it (be copied to another store or environment)'),
    AttributeDef(194, 'ciamRotationDays', 'int', 'intent', True,
                 'Rotation policy: the longest the same material may stay in use, in days', (("X-MIN", "1"),)),
    AttributeDef(195, 'ciamContinuity', 'enum:carry-over|per-environment', 'intent', True,
                 'carry-over: the same material must reach every environment that takes over from or joins this one '
                 '(replication deployment keys, signing keys partners trust, session encryption keys); '
                 'per-environment: each environment may hold its own'),
    AttributeDef(196, 'ciamContinuityReason', 'string', 'meta', True,
                 'What breaks if the material is not carried over'),
    AttributeDef(197, 'ciamUsedIn', 'dn', 'meta', False,
                 'Where the credential is configured or used (config files, consumers, integrations, bundles)'),
    AttributeDef(198, 'ciamProtectionLevel', 'enum:software|hsm|managed-hsm|external', 'binding', True,
                 'How the store protects the material: in software, in an HSM, a managed HSM, or an external key '
                 'store'),
    AttributeDef(199, 'ciamAutoRotate', 'bool', 'binding', True,
                 'The store rotates (or renews) the material automatically'),
    AttributeDef(200, 'ciamRotationFunction', 'string', 'binding', True,
                 'Provider id of the function or job that rotates the material'),
    AttributeDef(201, 'ciamReplicaRegion', 'string', 'binding', False,
                 'Regions the key or secret is replicated to (multi-region keys, replicated secrets)'),
    AttributeDef(202, 'ciamKeyUser', 'string', 'binding', False,
                 'Principal the store lets use the material (provider id of a role, identity or service account)'),
    AttributeDef(203, 'ciamKeyAdmin', 'string', 'binding', False,
                 'Principal the store lets manage the key or secret (provider id)'),
    AttributeDef(204, 'ciamLastRotated', 'time', 'observed', True,
                 'When the material in this environment was last rotated'),
    AttributeDef(205, 'ciamCopyRef', 'ref-uri', 'secret-ref', False,
                 'Another place this environment holds the same material (a PAM safe, a second store): rotating it '
                 'must update these too'),
    AttributeDef(206, 'ciamMaterialFrom', 'dn', 'binding', True,
                 'The binding in another environment whose material this one holds (carried over, not regenerated)'),
    AttributeDef(207, 'ciamHoldsCertificate', 'dn', 'binding', True,
                 'The certificate a certificate store entry holds'),
    AttributeDef(341, 'ciamEncryptedByRole', 'string', 'binding', True,
                 "The binding role of the key that encrypts a secret in its store (a customer managed key): who reads "
                 "or writes the secret may also need to use that key"),
    # ------------------------------------------------------------------ secret stores (per environment)
    AttributeDef(616, 'ciamRefScheme', 'string', 'binding', True,
                 'The ref-uri scheme whose references a secret store holds (vault, aws-sm, azkv, gcp-sm, ...)'),
    AttributeDef(617, 'ciamStoreEndpoint', 'url', 'binding', True,
                 "The address workloads reach a secret store at when the reference doesn't say (a Vault server)"),
    AttributeDef(618, 'ciamStoreAuthRole', 'string', 'binding', True,
                 "The role a Kubernetes workload logs in to a secret store as (a Vault Kubernetes auth role)"),
    AttributeDef(619, 'ciamStoreAuthMount', 'string', 'binding', True,
                 'The secret store auth method mount Kubernetes workloads log in through (a Vault auth mount path)'),
    AttributeDef(620, 'ciamStoreKvVersion', 'enum:1|2', 'binding', True,
                 "The version of a key/value secret store's engine (Vault KV 1 or 2); 2 when not recorded"),
    # ------------------------------------------------------------------ secret-store inventories (observed, metadata)
    AttributeDef(690, 'ciamInventoryAt', 'time', 'observed', True,
                 "When a secret store container's inventory was taken"),
    AttributeDef(691, 'ciamInventoryState', 'enum:complete|incomplete|denied', 'observed', True,
                 'complete: every object in the container (or under its listed prefixes) was listed; incomplete: '
                 'the listing may have missed some (truncated, unread pages); denied: the store refused to list it'),
    AttributeDef(692, 'ciamInventoryProblem', 'string', 'observed', False,
                 'Why an inventory is incomplete or denied, in words'),
    AttributeDef(693, 'ciamInventoryPrefix', 'string', 'observed', False,
                 'The path prefixes an inventory listed in its container; none: the whole container'),
    AttributeDef(694, 'ciamObjectState', 'enum:active|deleted|disabled', 'observed', True,
                 "A secret store object's state: deleted (its current version deleted or destroyed, or scheduled "
                 "for deletion) and disabled objects can't be read by what references them"),
    AttributeDef(695, 'ciamRotationManaged', 'bool', 'observed', True,
                 "The store manages the object's rotation itself (a PAM vault's automatic management)"),
    AttributeDef(696, 'ciamRotationStatus', 'enum:success|failure|in-progress', 'observed', True,
                 "How the store's last management (rotation) of the object went"),
    AttributeDef(697, 'ciamStoreModified', 'time', 'observed', True,
                 'When the store last changed the object (any write): never evidence of rotation'),
    AttributeDef(698, 'ciamLastVerified', 'time', 'observed', True,
                 'When the store last verified that the object still works where it is used'),
    AttributeDef(699, 'ciamManualReason', 'string', 'observed', True,
                 "Why the store doesn't manage the object's rotation, as the store records it"),
    # ------------------------------------------------------------------ certification authorities and templates
    AttributeDef(720, 'ciamCaCertificate', 'dn', 'meta', False,
                 "A certification authority's own certificates in the record (ou=certificates): the one it signs "
                 "with, and those it renewed"),
    AttributeDef(721, 'ciamIssuedBy', 'dn', 'meta', True,
                 'The certificate of the CA that issued this one (ou=certificates): the CA hierarchy, link by link'),
    AttributeDef(722, 'ciamTemplateName', 'string', 'observed', False,
                 'The certificate templates a CA issues from; on an issued certificate, the one it was issued from '
                 '(its name when the template is known, else the value the CA recorded)'),
    AttributeDef(723, 'ciamTemplateOid', 'string', 'observed', True,
                 "A certificate template's own OID (not its extended key usages)"),
    AttributeDef(724, 'ciamMaxValidityDays', 'int', 'observed', True,
                 'The longest validity a certificate template issues, in days', (("X-MIN", "1"),)),
    AttributeDef(725, 'ciamExtendedKeyUsage', 'string', 'observed', False,
                 'The extended key usages a certificate template issues, as OIDs'),
    AttributeDef(726, 'ciamRenewalOwner', 'dn', 'meta', True,
                 "Who renews the certificates a template issues that the record holds no certificate for (a party "
                 "under ou=owners); a recorded certificate's own owner renews it"),
    AttributeDef(727, 'ciamRevocationKind', 'enum:crl|delta-crl|ocsp|ca-issuers', 'observed', True,
                 'What a revocation endpoint serves: a CRL distribution point, a delta CRL (freshest CRL), an OCSP '
                 "responder, or the CA's own certificate (authority information access, CA issuers)"),
    AttributeDef(728, 'ciamEndpointUrl', 'string', 'observed', True,
                 'Where a revocation endpoint is reached, as its CA writes it into the certificates it issues (a '
                 "URL; the CA's template when its variables couldn't all be filled)"),
    # ------------------------------------------------------------------ issued-certificate inventories (observed)
    AttributeDef(729, 'ciamSerialNumber', 'string', 'meta', True,
                 "A certificate's serial number, as hex"),
    AttributeDef(730, 'ciamRequester', 'string', 'observed', True,
                 'Who requested an issued certificate, as its CA records it (an account name)'),
    AttributeDef(731, 'ciamRevokedAt', 'time', 'observed', True,
                 'When an issued certificate\'s revocation takes effect (it may be back- or future-dated)'),
    AttributeDef(732, 'ciamRevocationReason', 'string', 'observed', True,
                 'Why an issued certificate was revoked: the RFC 5280 reason (keyCompromise, superseded, ...), or the '
                 "CA's value as it is when it is no RFC 5280 reason; present on every revoked certificate"),
)
KEY_SERVICE = ('ciamProtectionLevel', 'ciamAutoRotate', 'ciamRotationFunction', 'ciamReplicaRegion', 'ciamKeyUser',
               'ciamKeyAdmin', 'ciamLastRotated', 'ciamCopyRef', 'ciamMaterialFrom')
CLASSES = (
    ClassDef(10, 'ciamSecretRef', 'ciamBinding', 'STRUCTURAL', ('ciamRefUri',),
             (*KEY_SERVICE, 'ciamEncryptedByRole'),
             'Reference to a secret'),
    ClassDef(131, 'ciamSecretStore', 'ciamBinding', 'STRUCTURAL', ('ciamRefScheme',),
             ('ciamStoreEndpoint', 'ciamStoreAuthRole', 'ciamStoreAuthMount', 'ciamStoreKvVersion', 'ciamProviderRef'),
             "Where an environment's references of one scheme are read from, beyond what each reference says: the "
             "store's address and how Kubernetes workloads log in to it"),
    ClassDef(11, 'ciamKeyRef', 'ciamBinding', 'STRUCTURAL', ('ciamRefUri',),
             KEY_SERVICE,
             'Reference to an encryption key'),
    ClassDef(28, 'ciamCertificate', 'ciamObject', 'STRUCTURAL',
             ('cn', 'ciamFingerprint', 'ciamNotAfter', 'ciamCertPurpose'),
             ('ciamSubject', 'ciamIssuer', 'ciamNotBefore', 'ciamSubjectAltName', 'ciamKeyRole', 'ciamPartnerContact',
              'ciamRotationRunbook', 'ciamCertificatePem', 'ciamIssuedBy', 'ciamSerialNumber'),
             'Certificate (public facts only)'),
    ClassDef(42, 'ciamCredential', 'ciamObject', 'STRUCTURAL',
             ('cn', 'ciamBindingRole', 'ciamCredentialType', 'ciamContinuity'),
             ('ciamKeyAlgorithm', 'ciamKeySize', 'ciamKeyUsage', 'ciamMaterialFormat', 'ciamPasswordRole',
              'ciamHsmRequired', 'ciamExportable', 'ciamRotationDays', 'ciamContinuityReason', 'ciamUsedIn',
              'ciamRotationRunbook'),
             'A key or secret as metadata, the same in every environment: each environment binds its role to where '
             'the material is kept'),
    ClassDef(43, 'ciamCertificateRef', 'ciamBinding', 'STRUCTURAL', ('ciamRefUri', 'ciamHoldsCertificate'),
             ('ciamAutoRotate', 'ciamLastRotated', 'ciamReplicaRegion', 'ciamKeyUser', 'ciamMaterialFrom'),
             'A certificate held in a cloud certificate store'),
    ClassDef(145, 'ciamSecretInventory', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamInventoryAt', 'ciamInventoryState'),
             ('ciamInventoryProblem', 'ciamInventoryPrefix', 'ciamStoreEndpoint'),
             "The last inventory of one secret store container (a PAM safe, a key/value mount; under "
             "ou=<scheme>,ou=secret-inventory), metadata only: when it was taken, whether it is complete, and the "
             "objects found as its children; what the record's references are reconciled with"),
    ClassDef(146, 'ciamSecretObject', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('ciamObjectState', 'ciamRotationManaged', 'ciamRotationStatus', 'ciamLastRotated', 'ciamStoreModified',
              'ciamLastVerified', 'ciamManualReason'),
             "An object a secret store inventory found in its container (cn: its name or path), metadata only, "
             "never its value: its state and what the store says of its rotation (ciamLastRotated only from a "
             "timestamp that means rotation)"),
    ClassDef(151, 'ciamCertAuthority', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('ciamProviderRef', 'ciamCaCertificate', 'ciamTemplateName'),
             "A certification authority (cn: its name; ciamProviderRef: how its product names it, an AD CS CA's "
             "HOST\\CA): its own certificates in the record, the templates it issues from, and its revocation "
             "endpoints as children"),
    ClassDef(152, 'ciamCertTemplate', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('ciamTemplateOid', 'ciamMaxValidityDays', 'ciamExtendedKeyUsage', 'ciamCertPurpose', 'ciamRenewalOwner'),
             'A certificate template CAs issue from (cn: its name; description: its display name): what it issues, '
             'and who renews what it issues that the record holds no certificate for'),
    ClassDef(153, 'ciamRevocationEndpoint', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamRevocationKind', 'ciamEndpointUrl'),
             (),
             'Where the certificates a CA issues say to check their revocation or find their issuer (a child of the '
             'ciamCertAuthority; cn: <kind>-<n>)'),
    ClassDef(154, 'ciamCertInventory', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamInventoryAt', 'ciamInventoryState'),
             ('ciamInventoryProblem', 'ciamProviderRef'),
             "The last inventory of one CA's issued certificates (cn: the CA's name; under ou=issued-certificates), "
             "metadata only: when it was taken, whether it is complete, and the certificates found as its children"),
    ClassDef(155, 'ciamIssuedCertificate', 'ciamObject', 'STRUCTURAL', ('cn',),
             ('ciamSerialNumber', 'ciamFingerprint', 'ciamSubject', 'ciamNotBefore', 'ciamNotAfter', 'ciamTemplateName',
              'ciamRequester', 'ciamRevokedAt', 'ciamRevocationReason'),
             "A certificate a CA's inventory says it issued (cn: its request id), metadata only, never a key: serial, "
             "SHA-256 fingerprint, subject, validity, template, requester and, once revoked, when and why"),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
