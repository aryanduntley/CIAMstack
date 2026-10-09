"""pki domain schema fragment: its attribute types and object classes (OIDs pinned by number).

Keys, secrets and certificates are described in two layers joined by binding role. A credential (ou=credentials) is
what a key or secret is, the same in every environment: its type, algorithm, what it is for, whether it must stay in
an HSM or may be exported, how often it rotates, whether the same material must reach every environment that takes
over from this one, and everywhere it is used. Each environment binds the role to where it keeps the material: a
secret or key reference (and, for a certificate held in a cloud certificate store, a certificate reference), with
what the store does for it (protection level, automatic rotation, replicas, who may use it). The material itself is
never in the record (SPEC R4): only references to it.
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
    ClassDef(28, 'ciamCertificate', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamFingerprint', 'ciamNotAfter', 'ciamCertPurpose'),
             ('ciamSubject', 'ciamIssuer', 'ciamNotBefore', 'ciamSubjectAltName', 'ciamKeyRole', 'ciamPartnerContact', 'ciamRotationRunbook'),
             'Certificate (public facts only)'),
    ClassDef(42, 'ciamCredential', 'ciamObject', 'STRUCTURAL',
             ('cn', 'ciamBindingRole', 'ciamCredentialType', 'ciamContinuity'),
             ('ciamKeyAlgorithm', 'ciamKeySize', 'ciamKeyUsage', 'ciamMaterialFormat', 'ciamPasswordRole',
              'ciamHsmRequired', 'ciamExportable', 'ciamRotationDays', 'ciamContinuityReason', 'ciamUsedIn', 'ciamRotationRunbook'),
             'A key or secret as metadata, the same in every environment: each environment binds its role to where '
             'the material is kept'),
    ClassDef(43, 'ciamCertificateRef', 'ciamBinding', 'STRUCTURAL', ('ciamRefUri', 'ciamHoldsCertificate'),
             ('ciamAutoRotate', 'ciamLastRotated', 'ciamReplicaRegion', 'ciamKeyUser', 'ciamMaterialFrom'),
             'A certificate held in a cloud certificate store'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
