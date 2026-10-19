# PKI

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 21 object classes · 128 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

Keys, secrets and certificates are described in two layers joined by binding role. A credential (ou=credentials) is what a key or secret is, the same in every environment: its type, algorithm, what it is for, whether it must stay in an HSM or may be exported, how often it rotates, whether the same material must reach every environment that takes over from this one, and everywhere it is used. Each environment binds the role to where it keeps the material: a secret or key reference (and, for a certificate held in a cloud certificate store, a certificate reference), with what the store does for it (protection level, automatic rotation, replicas, who may use it). The material itself is never in the record (SPEC R4): only references to it. A secret store's inventory (ou=secret-inventory) is what the store said it holds, metadata only, as its importers read it: per container (a PAM safe, a key/value mount) when it was listed and whether completely, and each object found with its state and what the store says of its rotation. The record's references are reconciled with it (inventory.py); nothing an inventory observes is written onto the bindings themselves. Certification authorities (ou=certificate-authorities) are the CAs the estate's certificates come from, as their importers read them, with what the operator adds: the CA's own certificates in the record (the hierarchy runs certificate by certificate: ciamIssuedBy), the templates it issues from and the revocation endpoints it puts in the certificates it issues (CRL distribution points, delta CRLs, OCSP, CA issuers), its children. Certificate templates (ou=certificate-templates) are what a CA may issue, with who renews what they issue, what they let a requester do (name the subject, skip approval) and who may request from them (templates.py judges the risk). A CA's issued-certificate inventory (ou=issued-certificates) is what its database said it issued, metadata only, never a key: the record's certificates are reconciled with it (issued.py), and nothing it observes is written onto them. What each CA's revocation endpoints answered when last observed (ou=revocation-observations, per CA and endpoint) is kept apart from the endpoints themselves: whether they answered, how current what they served was, and whether the CA the record holds signed it (revocation.py judges it). A certificate manager's inventory (ou=managed-certificates, per collection source) is what a manager said it holds: the certificates it discovered on the network, was given, or enrolls and renews itself, metadata only, with how it manages each, who it notifies, where it says each is installed and what it reports wrong. It is never a CA's issuance record: a certificate it doesn't hold isn't missing anywhere (managed.py reconciles the record's certificates with it). Trust bundles (ou=trust-bundles) are outside PKIs' published sets of CA certificates (DISA's DoD and ECA bundles) as last imported, with how their integrity was established; trust policies (ou=trust-policies) are what the platform accepts certificates under: anchors a person approved (record CA certificates, never a bundle's members by being there), the bundles they follow, restrictions, identity mapping and revocation, and who accepts them: server roles and, by name, the identity services signing certificates in (trust.py). Cross-certificates (ou=cross-certificates) are one CA certifying another PKI's CA, recorded as facts of the graph (what each joins, its policy mappings, its validity), never as trust: what they make reachable from the approved anchors is reported and watched (cross.py). A certificate's own facts (its typed alternative names, key identifiers, basic constraints, policies and key usages) are what it says of itself, read from it where its PEM is known.

**Branches:** `ou=certificate-authorities,dc=ciam-ops`, `ou=certificate-templates,dc=ciam-ops`, `ou=certificates,dc=ciam-ops`, `ou=credentials,dc=ciam-ops`, `ou=cross-certificates,dc=ciam-ops`, `ou=issued-certificates,dc=ciam-ops`, `ou=managed-certificates,dc=ciam-ops`, `ou=revocation-observations,dc=ciam-ops`, `ou=secret-inventory,dc=ciam-ops`, `ou=trust-bundles,dc=ciam-ops`, `ou=trust-policies,dc=ciam-ops`

## Object classes

<a id="c-ciambundlecertificate"></a>
### ciamBundleCertificate

A CA certificate a trust bundle holds (cn: its subject's common name), public facts only: never trusted by being here; a trust policy's anchors are record certificates a person approved

OID `1.3.6.1.4.1.32473.1.2.202` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamFingerprint`](#a-ciamfingerprint) | yes | `string` | single | SHA-256 fingerprint |
| [`ciamNotAfter`](#a-ciamnotafter) | yes | `time` | single | Expires |
| [`ciamSubject`](#a-ciamsubject) |  | `string` | single | Certificate subject |
| [`ciamIssuer`](#a-ciamissuer) |  | `string` | single | Certificate issuer |
| [`ciamNotBefore`](#a-ciamnotbefore) |  | `time` | single | Valid from |
| [`ciamSerialNumber`](#a-ciamserialnumber) |  | `string` | single | A certificate's serial number, as hex |
| [`ciamCaType`](#a-ciamcatype) |  | `enum` | single | Whether a certification authority is a root (its own certificate self-signed) or subordinate to another CA, as its product says |
| [`ciamCertificatePem`](#a-ciamcertificatepem) |  | `string` | single | The certificate itself as PEM: public material only, never a key; recorded for a CA something must be given to trust (a gateway checking its backends) |
| [`ciamCertPolicyOid`](#a-ciamcertpolicyoid) |  | `string` | multi | A certificate policy OID the certificate asserts (its certificatePolicies extension; anyPolicy is 2.5.29.32.0) |
| [`ciamBundleGroup`](#a-ciambundlegroup) |  | `string` | single | The part of a trust bundle a member certificate came in, as the publisher groups them (the root CA it sits under: DoD Root CA 6) |

<a id="c-ciamcertauthority"></a>
### ciamCertAuthority

A certification authority (cn: its name; ciamProviderRef: how its product names it, an AD CS CA's HOST\CA): its own certificates in the record, the templates it issues from, and its revocation endpoints as children; what its product says of it (root or subordinate, state, signing key, the CA above it) when the product tells

OID `1.3.6.1.4.1.32473.1.2.151` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamCaCertificate`](#a-ciamcacertificate) |  | `dn` | multi | A certification authority's own certificates in the record (ou=certificates): the one it signs with, and those it renewed |
| [`ciamTemplateName`](#a-ciamtemplatename) |  | `string` | multi | The certificate templates a CA issues from; on an issued certificate, the one it was issued from (its name when the template is known, else the value the CA recorded) |
| [`ciamCaType`](#a-ciamcatype) |  | `enum` | single | Whether a certification authority is a root (its own certificate self-signed) or subordinate to another CA, as its product says |
| [`ciamCaState`](#a-ciamcastate) |  | `enum` | single | A certification authority's state in its product: active (issuing), disabled, pending (not yet activated: awaiting its certificate or its activation), expired, deleted (still restorable) or failed (its creation failed) |
| [`ciamCaKeyAlgorithm`](#a-ciamcakeyalgorithm) |  | `string` | single | The algorithm of the key a certification authority signs with, as its product names it (RSA_4096, EC_P384_SHA384) |
| [`ciamCaKeyStorage`](#a-ciamcakeystorage) |  | `string` | single | Where a certification authority's signing key is kept, as its product says (an HSM standard such as FIPS 140-2 Level 3, a provider-managed HSM, a customer-managed key) |
| [`ciamCaKeyRef`](#a-ciamcakeyref) |  | `string` | single | The customer-managed key a certification authority signs with (its key service's name for it): a reference, never key material |
| [`ciamParentAuthority`](#a-ciamparentauthority) |  | `dn` | single | The certification authority (ou=certificate-authorities) that issued a subordinate CA's certificate, as the CA's product says |
| [`ciamCaRestorableUntil`](#a-ciamcarestorableuntil) |  | `time` | single | Until when a deleted certification authority can still be restored in its product (AWS Private CA's RestorableUntil; Google CAS's purge time): after it, the CA and what it would renew are gone |

<a id="c-ciamcertificate"></a>
### ciamCertificate

Certificate (public facts only): what it is for, and what it says of itself (names, policies, key usages, key identifiers, basic constraints) as read from it

OID `1.3.6.1.4.1.32473.1.2.28` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamFingerprint`](#a-ciamfingerprint) | yes | `string` | single | SHA-256 fingerprint |
| [`ciamNotAfter`](#a-ciamnotafter) | yes | `time` | single | Expires |
| [`ciamCertPurpose`](#a-ciamcertpurpose) | yes | `enum` | single | What the certificate is for (client-auth: one the operator presents to authenticate, e.g. to a reporting portal; ca: a certification authority a truststore adds) |
| [`ciamSubject`](#a-ciamsubject) |  | `string` | single | Certificate subject |
| [`ciamIssuer`](#a-ciamissuer) |  | `string` | single | Certificate issuer |
| [`ciamNotBefore`](#a-ciamnotbefore) |  | `time` | single | Valid from |
| [`ciamSubjectAltName`](#a-ciamsubjectaltname) |  | `fqdn` | multi | DNS names the certificate is valid for |
| [`ciamKeyRole`](#a-ciamkeyrole) |  | `string` | single | Binding role of the secret holding the private key (per environment) |
| [`ciamPartnerContact`](#a-ciampartnercontact) |  | `dn` | single | Partner to coordinate rotation with |
| [`ciamRotationRunbook`](#a-ciamrotationrunbook) |  | `dn` | single | Work instruction for rotation |
| [`ciamCertificatePem`](#a-ciamcertificatepem) |  | `string` | single | The certificate itself as PEM: public material only, never a key; recorded for a CA something must be given to trust (a gateway checking its backends) |
| [`ciamIssuedBy`](#a-ciamissuedby) |  | `dn` | single | The certificate of the CA that issued this one (ou=certificates): the CA hierarchy, link by link |
| [`ciamSerialNumber`](#a-ciamserialnumber) |  | `string` | single | A certificate's serial number, as hex |
| [`ciamCertPolicyOid`](#a-ciamcertpolicyoid) |  | `string` | multi | A certificate policy OID the certificate asserts (its certificatePolicies extension; anyPolicy is 2.5.29.32.0) |
| [`ciamExtendedKeyUsage`](#a-ciamextendedkeyusage) |  | `string` | multi | The extended key usages a certificate template issues, as OIDs |
| [`ciamSanUpn`](#a-ciamsanupn) |  | `string` | multi | A user principal name the certificate's subject alternative name carries (the UPN otherName, 1.3.6.1.4.1.311.20.2.3), exactly as written: what a relying party mapping certificates by UPN (ciamIdentityMapping san-upn) finds the account by |
| [`ciamSanEmail`](#a-ciamsanemail) |  | `string` | multi | An email address the certificate's subject alternative name carries (rfc822Name), as written |
| [`ciamSanUri`](#a-ciamsanuri) |  | `string` | multi | A URI the certificate's subject alternative name carries (uniformResourceIdentifier), as written |
| [`ciamSubjectIdentifier`](#a-ciamsubjectidentifier) |  | `string` | multi | An identifier the certificate's names carry by a recognised convention, as <form>:<value> (edipi: the 10-digit DoD EDIPI a CAC's UPN of digits at mil begins with); derived from the names recorded (ciamSanUpn), never assumed: a certificate whose names follow no known convention (an ECA subscriber's) has none |
| [`ciamSubjectKeyId`](#a-ciamsubjectkeyid) |  | `string` | single | The certificate's subject key identifier (RFC 5280 4.2.1.2), as lowercase hex |
| [`ciamAuthorityKeyId`](#a-ciamauthoritykeyid) |  | `string` | single | The key identifier of the CA key that signed the certificate (its authority key identifier, RFC 5280 4.2.1.1), as lowercase hex: the issuer certificate's ciamSubjectKeyId |
| [`ciamIsCa`](#a-ciamisca) |  | `bool` | single | Whether the certificate's basic constraints make it a CA certificate (cA); absent when it has no basic constraints extension |
| [`ciamPathLength`](#a-ciampathlength) |  | `int` | single | The most CA certificates that may follow a CA certificate in a path (its basic constraints' pathLenConstraint); absent: no limit |

<a id="c-ciamcertificateref"></a>
### ciamCertificateRef

A certificate held in a cloud certificate store

OID `1.3.6.1.4.1.32473.1.2.43` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamRefUri`](#a-ciamrefuri) | yes | `ref-uri` | single | Reference to a secret or key in the environment's store. Never the value |
| [`ciamHoldsCertificate`](#a-ciamholdscertificate) | yes | `dn` | single | The certificate a certificate store entry holds |
| [`ciamAutoRotate`](#a-ciamautorotate) |  | `bool` | single | The store rotates (or renews) the material automatically |
| [`ciamLastRotated`](#a-ciamlastrotated) |  | `time` | single | When the material in this environment was last rotated |
| [`ciamReplicaRegion`](#a-ciamreplicaregion) |  | `string` | multi | Regions the key, secret or managed directory is replicated to (multi-region keys, replicated secrets, a managed directory's further regions) |
| [`ciamKeyUser`](#a-ciamkeyuser) |  | `string` | multi | Principal the store lets use the material (provider id of a role, identity or service account) |
| [`ciamMaterialFrom`](#a-ciammaterialfrom) |  | `dn` | single | The binding in another environment whose material this one holds (carried over, not regenerated) |

<a id="c-ciamcertinventory"></a>
### ciamCertInventory

The last inventory of one CA's issued certificates (cn: the CA's name; under ou=issued-certificates), metadata only: when it was taken, whether it is complete, and the certificates found as its children

OID `1.3.6.1.4.1.32473.1.2.154` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamInventoryAt`](#a-ciaminventoryat) | yes | `time` | single | When a secret store container's inventory was taken |
| [`ciamInventoryState`](#a-ciaminventorystate) | yes | `enum` | single | complete: every object in the container (or under its listed prefixes) was listed; incomplete: the listing may have missed some (truncated, unread pages); denied: the store refused to list it |
| [`ciamInventoryProblem`](#a-ciaminventoryproblem) |  | `string` | multi | Why an inventory is incomplete or denied, in words |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |

<a id="c-ciamcerttemplate"></a>
### ciamCertTemplate

A certificate template CAs issue from (cn: its name; description: its display name): what it issues, who renews what it issues that the record holds no certificate for, what it lets requesters do (name the subject, skip approval) and who may request from it, and the CA it belongs to when it is that CA's own

OID `1.3.6.1.4.1.32473.1.2.152` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamTemplateOid`](#a-ciamtemplateoid) |  | `string` | single | A certificate template's own OID (not its extended key usages) |
| [`ciamMaxValidityDays`](#a-ciammaxvaliditydays) |  | `int` | single | The longest validity a certificate template issues, in days |
| [`ciamExtendedKeyUsage`](#a-ciamextendedkeyusage) |  | `string` | multi | The extended key usages a certificate template issues, as OIDs |
| [`ciamCertPurpose`](#a-ciamcertpurpose) |  | `enum` | single | What the certificate is for (client-auth: one the operator presents to authenticate, e.g. to a reporting portal; ca: a certification authority a truststore adds) |
| [`ciamRenewalOwner`](#a-ciamrenewalowner) |  | `dn` | single | Who renews the certificates a template issues that the record holds no certificate for (a party under ou=owners); a recorded certificate's own owner renews it |
| [`ciamSubjectFromRequest`](#a-ciamsubjectfromrequest) |  | `bool` | single | Whether a certificate template takes the subject and alternative names from the request (the requester names them) instead of building them from the directory |
| [`ciamApprovalRequired`](#a-ciamapprovalrequired) |  | `bool` | single | Whether a certificate template's requests wait for a CA manager's approval before they are issued |
| [`ciamRequiredSignatures`](#a-ciamrequiredsignatures) |  | `int` | single | How many authorized signatures (an enrollment agent's) a certificate template's requests need |
| [`ciamTemplateVersion`](#a-ciamtemplateversion) |  | `int` | single | A certificate template's schema version, as its directory records it |
| [`ciamEnrollee`](#a-ciamenrollee) |  | `string` | multi | Who a certificate template's access rights let request certificates from it, as its directory names them (an identifier, with its well-known name when it has one); metadata only |
| [`ciamEnrollmentScope`](#a-ciamenrollmentscope) |  | `enum` | single | Whether a certificate template lets a broad group request certificates (anyone, every authenticated account, all of a domain's users or computers), or only named principals; unknown when its access rights weren't read or hold entries that can't be judged |
| [`ciamTemplateAuthority`](#a-ciamtemplateauthority) |  | `dn` | single | The certification authority (ou=certificate-authorities) a CA-scoped certificate template is its own (a Vault PKI role): only that CA issues from it and only its importer replaces it; absent on templates a directory shares with every CA (AD CS's forest templates) |

<a id="c-ciamcredential"></a>
### ciamCredential

A key or secret as metadata, the same in every environment: each environment binds its role to where the material is kept

OID `1.3.6.1.4.1.32473.1.2.42` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamBindingRole`](infrastructure.md#a-ciambindingrole) | yes | `string` | single | Abstract role a binding fulfils (for a credential, the role of the bindings that hold it); migrations match roles across environments |
| [`ciamCredentialType`](#a-ciamcredentialtype) | yes | `enum` | single | What kind of key or secret the credential is |
| [`ciamContinuity`](#a-ciamcontinuity) | yes | `enum` | single | carry-over: the same material must reach every environment that takes over from or joins this one (replication deployment keys, signing keys partners trust, session encryption keys); per-environment: each environment may hold its own |
| [`ciamKeyAlgorithm`](#a-ciamkeyalgorithm) |  | `string` | single | Key algorithm (e.g. RSA, EC P-256, AES-256, HMAC-SHA256) |
| [`ciamKeySize`](#a-ciamkeysize) |  | `int` | single | Key size in bits |
| [`ciamKeyUsage`](#a-ciamkeyusage) |  | `enum` | multi | What the credential is used for |
| [`ciamMaterialFormat`](#a-ciammaterialformat) |  | `enum` | single | The form the material takes where it is used |
| [`ciamPasswordRole`](#a-ciampasswordrole) |  | `string` | single | Binding role of the secret holding the password that protects the material where it is kept (a PKCS#12 file's), per environment like the material's own role |
| [`ciamHsmRequired`](#a-ciamhsmrequired) |  | `bool` | single | The material must be generated and kept in a hardware security module |
| [`ciamExportable`](#a-ciamexportable) |  | `bool` | single | The material may leave the store that holds it (be copied to another store or environment) |
| [`ciamRotationDays`](#a-ciamrotationdays) |  | `int` | single | Rotation policy: the longest the same material may stay in use, in days |
| [`ciamContinuityReason`](#a-ciamcontinuityreason) |  | `string` | single | What breaks if the material is not carried over |
| [`ciamUsedIn`](#a-ciamusedin) |  | `dn` | multi | Where the credential is configured or used (config files, consumers, integrations, bundles) |
| [`ciamRotationRunbook`](#a-ciamrotationrunbook) |  | `dn` | single | Work instruction for rotation |

<a id="c-ciamcrosscertificate"></a>
### ciamCrossCertificate

A cross-certificate (under ou=cross-certificates): one CA (ciamIssuer) certifying another PKI's CA (ciamSubject), what it joins, the policy mappings it carries, its validity and, when observed, its fingerprint, serial and PEM. Recorded as a fact of the graph, never trusted by being here: a trust policy accepts its approved anchors only (cross.py reports what the cross-certificates make reachable)

OID `1.3.6.1.4.1.32473.1.2.209` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamIssuer`](#a-ciamissuer) | yes | `string` | single | Certificate issuer |
| [`ciamSubject`](#a-ciamsubject) | yes | `string` | single | Certificate subject |
| [`ciamNotAfter`](#a-ciamnotafter) | yes | `time` | single | Expires |
| [`ciamCrossRole`](#a-ciamcrossrole) |  | `enum` | single | What a cross-certificate joins: two PKIs certifying each other directly (peer), a bridge CA certifying a member PKI's CA (bridge-to-member), or a member PKI's CA certifying the bridge (member-to-bridge) |
| [`ciamPolicyMapping`](#a-ciampolicymapping) |  | `string` | multi | A policy mapping a cross-certificate carries (RFC 5280 4.2.1.5), as <issuerDomainPolicy>=<subjectDomainPolicy>: the issuer's policy OID a relying party under the issuer reads the subject's policy OID as |
| [`ciamFingerprint`](#a-ciamfingerprint) |  | `string` | single | SHA-256 fingerprint |
| [`ciamSerialNumber`](#a-ciamserialnumber) |  | `string` | single | A certificate's serial number, as hex |
| [`ciamNotBefore`](#a-ciamnotbefore) |  | `time` | single | Valid from |
| [`ciamCertificatePem`](#a-ciamcertificatepem) |  | `string` | single | The certificate itself as PEM: public material only, never a key; recorded for a CA something must be given to trust (a gateway checking its backends) |
| [`ciamCertPolicyOid`](#a-ciamcertpolicyoid) |  | `string` | multi | A certificate policy OID the certificate asserts (its certificatePolicies extension; anyPolicy is 2.5.29.32.0) |
| [`ciamSubjectKeyId`](#a-ciamsubjectkeyid) |  | `string` | single | The certificate's subject key identifier (RFC 5280 4.2.1.2), as lowercase hex |
| [`ciamAuthorityKeyId`](#a-ciamauthoritykeyid) |  | `string` | single | The key identifier of the CA key that signed the certificate (its authority key identifier, RFC 5280 4.2.1.1), as lowercase hex: the issuer certificate's ciamSubjectKeyId |
| [`ciamPathLength`](#a-ciampathlength) |  | `int` | single | The most CA certificates that may follow a CA certificate in a path (its basic constraints' pathLenConstraint); absent: no limit |

<a id="c-ciamendpointobservation"></a>
### ciamEndpointObservation

What one of a CA's revocation endpoints answered when observed (cn: the endpoint's, crl-1; the URL observed): whether it answered, how current what it served was, whether the CA signed it, and for an OCSP responder what it said of the certificate it was asked about (ciamSerialNumber)

OID `1.3.6.1.4.1.32473.1.2.181` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamRevocationKind`](#a-ciamrevocationkind) | yes | `enum` | single | What a revocation endpoint serves: a CRL distribution point, a delta CRL (freshest CRL), an OCSP responder, or the CA's own certificate (authority information access, CA issuers) |
| [`ciamEndpointUrl`](#a-ciamendpointurl) | yes | `string` | single | Where a revocation endpoint is reached, as its CA writes it into the certificates it issues (a URL; the CA's template when its variables couldn't all be filled) |
| [`ciamInventoryAt`](#a-ciaminventoryat) | yes | `time` | single | When a secret store container's inventory was taken |
| [`ciamEndpointAnswer`](#a-ciamendpointanswer) |  | `enum` | single | What a revocation endpoint answered when observed: answered (a CRL or OCSP response read), http-error (an error status), unreachable (no answer), unreadable (an answer that isn't a CRL or a successful OCSP response), or not-observed (nothing to fetch: not an http(s) URL, unfilled variables, nothing to ask an OCSP responder about) |
| [`ciamThisUpdate`](#a-ciamthisupdate) |  | `time` | single | When the CRL or OCSP response an endpoint served was issued (its thisUpdate) |
| [`ciamNextUpdate`](#a-ciamnextupdate) |  | `time` | single | When the CRL or OCSP response an endpoint served says newer information will be available by (its nextUpdate); absent when it gave none |
| [`ciamCrlNumber`](#a-ciamcrlnumber) |  | `string` | single | The CRL number (RFC 5280 5.2.3) of the CRL an endpoint served, as decimal |
| [`ciamBaseCrlNumber`](#a-ciambasecrlnumber) |  | `string` | single | The delta CRL indicator of a delta CRL an endpoint served (RFC 5280 5.2.4): the number of the oldest complete CRL it can be combined with, as decimal |
| [`ciamSignatureCheck`](#a-ciamsignaturecheck) |  | `enum` | single | Whether what an endpoint served was signed by the CA the record holds: valid; invalid (its signature doesn't verify with the CA's key); other-issuer (another issuer's); unauthorized-responder (an OCSP response signed by a certificate the CA didn't authorize); no-ca-certificate (the record holds none of the CA's certificates to check it with); unsupported (a signature algorithm the check doesn't verify) |
| [`ciamSignedBy`](#a-ciamsignedby) |  | `dn` | single | The CA certificate in the record (ou=certificates) whose key verified what an endpoint served, directly or through the OCSP responder certificate it issued |
| [`ciamOcspStatus`](#a-ciamocspstatus) |  | `enum` | single | What an OCSP responder said of the certificate it was asked about (ciamSerialNumber): good, revoked or unknown, or the status of a response that wasn't successful (RFC 6960 4.2.1) |
| [`ciamSerialNumber`](#a-ciamserialnumber) |  | `string` | single | A certificate's serial number, as hex |
| [`ciamInventoryProblem`](#a-ciaminventoryproblem) |  | `string` | multi | Why an inventory is incomplete or denied, in words |

<a id="c-ciamissuedcertificate"></a>
### ciamIssuedCertificate

A certificate a CA's inventory says it issued (cn: its request id), metadata only, never a key: serial, SHA-256 fingerprint, subject, validity, template, requester and, once revoked, when and why

OID `1.3.6.1.4.1.32473.1.2.155` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamSerialNumber`](#a-ciamserialnumber) |  | `string` | single | A certificate's serial number, as hex |
| [`ciamFingerprint`](#a-ciamfingerprint) |  | `string` | single | SHA-256 fingerprint |
| [`ciamSubject`](#a-ciamsubject) |  | `string` | single | Certificate subject |
| [`ciamNotBefore`](#a-ciamnotbefore) |  | `time` | single | Valid from |
| [`ciamNotAfter`](#a-ciamnotafter) |  | `time` | single | Expires |
| [`ciamTemplateName`](#a-ciamtemplatename) |  | `string` | multi | The certificate templates a CA issues from; on an issued certificate, the one it was issued from (its name when the template is known, else the value the CA recorded) |
| [`ciamRequester`](#a-ciamrequester) |  | `string` | single | Who requested an issued certificate, as its CA records it (an account name) |
| [`ciamRevokedAt`](#a-ciamrevokedat) |  | `time` | single | When an issued certificate's revocation takes effect (it may be back- or future-dated) |
| [`ciamRevocationReason`](#a-ciamrevocationreason) |  | `string` | single | Why an issued certificate was revoked: the RFC 5280 reason (keyCompromise, superseded, ...), or the CA's value as it is when it is no RFC 5280 reason; present on every revoked certificate |

<a id="c-ciamkeyref"></a>
### ciamKeyRef

Reference to an encryption key

OID `1.3.6.1.4.1.32473.1.2.11` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamRefUri`](#a-ciamrefuri) | yes | `ref-uri` | single | Reference to a secret or key in the environment's store. Never the value |
| [`ciamProtectionLevel`](#a-ciamprotectionlevel) |  | `enum` | single | How the store protects the material: in software, in an HSM, a managed HSM, or an external key store |
| [`ciamAutoRotate`](#a-ciamautorotate) |  | `bool` | single | The store rotates (or renews) the material automatically |
| [`ciamRotationFunction`](#a-ciamrotationfunction) |  | `string` | single | Provider id of the function or job that rotates the material |
| [`ciamReplicaRegion`](#a-ciamreplicaregion) |  | `string` | multi | Regions the key, secret or managed directory is replicated to (multi-region keys, replicated secrets, a managed directory's further regions) |
| [`ciamKeyUser`](#a-ciamkeyuser) |  | `string` | multi | Principal the store lets use the material (provider id of a role, identity or service account) |
| [`ciamKeyAdmin`](#a-ciamkeyadmin) |  | `string` | multi | Principal the store lets manage the key or secret (provider id) |
| [`ciamLastRotated`](#a-ciamlastrotated) |  | `time` | single | When the material in this environment was last rotated |
| [`ciamCopyRef`](#a-ciamcopyref) |  | `ref-uri` | multi | Another place this environment holds the same material (a PAM safe, a second store): rotating it must update these too |
| [`ciamMaterialFrom`](#a-ciammaterialfrom) |  | `dn` | single | The binding in another environment whose material this one holds (carried over, not regenerated) |

<a id="c-ciammanagedcertificate"></a>
### ciamManagedCertificate

A certificate a certificate manager's inventory holds (cn: the manager's id for it), metadata only, never a key: serial, fingerprint or thumbprint, subject, issuer, validity and names; how the manager manages it and what it is set to do, who it notifies, where it says it is installed, what it reports wrong, once revoked (as the manager says) when and why, and for an earlier version what replaced it

OID `1.3.6.1.4.1.32473.1.2.200` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamSerialNumber`](#a-ciamserialnumber) |  | `string` | single | A certificate's serial number, as hex |
| [`ciamFingerprint`](#a-ciamfingerprint) |  | `string` | single | SHA-256 fingerprint |
| [`ciamThumbprint`](#a-ciamthumbprint) |  | `string` | single | A certificate's SHA-1 thumbprint, as colon-separated hex: what a certificate manager gives when it gives no SHA-256 fingerprint |
| [`ciamSubject`](#a-ciamsubject) |  | `string` | single | Certificate subject |
| [`ciamIssuer`](#a-ciamissuer) |  | `string` | single | Certificate issuer |
| [`ciamNotBefore`](#a-ciamnotbefore) |  | `time` | single | Valid from |
| [`ciamNotAfter`](#a-ciamnotafter) |  | `time` | single | Expires |
| [`ciamCertificateName`](#a-ciamcertificatename) |  | `string` | multi | The DNS names and IP addresses a certificate names (its subject common name and alternative names), as its manager reports them, wildcards kept |
| [`ciamManagerPath`](#a-ciammanagerpath) |  | `string` | single | Where a certificate manager files a certificate (a policy folder's object, a vault's certificate name) |
| [`ciamManagement`](#a-ciammanagement) |  | `enum` | single | What a certificate manager does for a certificate: unassigned (nothing), monitored (watches its expiry; someone else renews it), enrolled (requests and renews it; someone installs it) or provisioned (renews it and installs it where it is used) |
| [`ciamManagedOrigin`](#a-ciammanagedorigin) |  | `enum` | single | How a certificate came to its manager: discovered (found by a network or agent scan) or added (enrolled through it, imported, or created by someone) |
| [`ciamManagerContact`](#a-ciammanagercontact) |  | `string` | multi | Who a certificate manager notifies about a certificate, as the manager names them (its own identities); metadata only |
| [`ciamInstalledAt`](#a-ciaminstalledat) |  | `string` | multi | Where a certificate manager says a certificate is installed or was found (an application, a device, host:port), as the manager names it |
| [`ciamManagerProblem`](#a-ciammanagerproblem) |  | `string` | multi | What a certificate manager reports wrong with a certificate now (a failed renewal or installation, a revocation requested or failed), in its words |
| [`ciamManagedAuthority`](#a-ciammanagedauthority) |  | `string` | single | The certification authority (or its template) a certificate manager renews a certificate through, as the manager names it |
| [`ciamRevokedAt`](#a-ciamrevokedat) |  | `time` | single | When an issued certificate's revocation takes effect (it may be back- or future-dated) |
| [`ciamRevocationReason`](#a-ciamrevocationreason) |  | `string` | single | Why an issued certificate was revoked: the RFC 5280 reason (keyCompromise, superseded, ...), or the CA's value as it is when it is no RFC 5280 reason; present on every revoked certificate |
| [`ciamObjectState`](#a-ciamobjectstate) |  | `enum` | single | A secret store object's state: deleted (its current version deleted or destroyed, or scheduled for deletion) and disabled objects can't be read by what references them |
| [`ciamManagerAction`](#a-ciammanageraction) |  | `string` | multi | What a certificate manager is set to do for a certificate on its own, as the manager says it (a renewal or notification trigger: AutoRenew at 80% of lifetime, EmailContacts 30 days before expiry) |
| [`ciamRenewedAs`](#a-ciamrenewedas) |  | `string` | single | An earlier version of a certificate a certificate manager holds: the manager's id (cn) of the certificate that replaced it in the same inventory, as the manager links its versions |

<a id="c-ciammanagedinventory"></a>
### ciamManagedInventory

The last inventory of one certificate manager's source (cn: the collection source's name; under ou=managed-certificates), metadata only: when it was taken, whether the folders it lists (ciamInventoryPrefix) were listed completely, the manager's address (ciamProviderRef), and the certificates found as its children. Never a CA's issuance record: what it doesn't hold isn't missing

OID `1.3.6.1.4.1.32473.1.2.199` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamInventoryAt`](#a-ciaminventoryat) | yes | `time` | single | When a secret store container's inventory was taken |
| [`ciamInventoryState`](#a-ciaminventorystate) | yes | `enum` | single | complete: every object in the container (or under its listed prefixes) was listed; incomplete: the listing may have missed some (truncated, unread pages); denied: the store refused to list it |
| [`ciamInventoryProblem`](#a-ciaminventoryproblem) |  | `string` | multi | Why an inventory is incomplete or denied, in words |
| [`ciamInventoryPrefix`](#a-ciaminventoryprefix) |  | `string` | multi | The path prefixes an inventory listed in its container; none: the whole container |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |

<a id="c-ciamrevocationendpoint"></a>
### ciamRevocationEndpoint

Where the certificates a CA issues say to check their revocation or find their issuer (a child of the ciamCertAuthority; cn: <kind>-<n>)

OID `1.3.6.1.4.1.32473.1.2.153` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamRevocationKind`](#a-ciamrevocationkind) | yes | `enum` | single | What a revocation endpoint serves: a CRL distribution point, a delta CRL (freshest CRL), an OCSP responder, or the CA's own certificate (authority information access, CA issuers) |
| [`ciamEndpointUrl`](#a-ciamendpointurl) | yes | `string` | single | Where a revocation endpoint is reached, as its CA writes it into the certificates it issues (a URL; the CA's template when its variables couldn't all be filled) |

<a id="c-ciamrevocationobservation"></a>
### ciamRevocationObservation

The last observation of one CA's revocation endpoints (cn: the CA's name; under ou=revocation-observations): when it was made, whether every endpoint was observed, and each endpoint's answer as its children

OID `1.3.6.1.4.1.32473.1.2.180` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamInventoryAt`](#a-ciaminventoryat) | yes | `time` | single | When a secret store container's inventory was taken |
| [`ciamInventoryState`](#a-ciaminventorystate) |  | `enum` | single | complete: every object in the container (or under its listed prefixes) was listed; incomplete: the listing may have missed some (truncated, unread pages); denied: the store refused to list it |
| [`ciamInventoryProblem`](#a-ciaminventoryproblem) |  | `string` | multi | Why an inventory is incomplete or denied, in words |

<a id="c-ciamsecretinventory"></a>
### ciamSecretInventory

The last inventory of one secret store container (a PAM safe, a key/value mount; under ou=<scheme>,ou=secret-inventory), metadata only: when it was taken, whether it is complete, and the objects found as its children; what the record's references are reconciled with

OID `1.3.6.1.4.1.32473.1.2.145` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamInventoryAt`](#a-ciaminventoryat) | yes | `time` | single | When a secret store container's inventory was taken |
| [`ciamInventoryState`](#a-ciaminventorystate) | yes | `enum` | single | complete: every object in the container (or under its listed prefixes) was listed; incomplete: the listing may have missed some (truncated, unread pages); denied: the store refused to list it |
| [`ciamInventoryProblem`](#a-ciaminventoryproblem) |  | `string` | multi | Why an inventory is incomplete or denied, in words |
| [`ciamInventoryPrefix`](#a-ciaminventoryprefix) |  | `string` | multi | The path prefixes an inventory listed in its container; none: the whole container |
| [`ciamStoreEndpoint`](#a-ciamstoreendpoint) |  | `url` | single | The address workloads reach a secret store at when the reference doesn't say (a Vault server) |

<a id="c-ciamsecretobject"></a>
### ciamSecretObject

An object a secret store inventory found in its container (cn: its name or path), metadata only, never its value: its state and what the store says of its rotation (ciamLastRotated only from a timestamp that means rotation)

OID `1.3.6.1.4.1.32473.1.2.146` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamObjectState`](#a-ciamobjectstate) |  | `enum` | single | A secret store object's state: deleted (its current version deleted or destroyed, or scheduled for deletion) and disabled objects can't be read by what references them |
| [`ciamRotationManaged`](#a-ciamrotationmanaged) |  | `bool` | single | The store manages the object's rotation itself (a PAM vault's automatic management) |
| [`ciamRotationStatus`](#a-ciamrotationstatus) |  | `enum` | single | How the store's last management (rotation) of the object went |
| [`ciamLastRotated`](#a-ciamlastrotated) |  | `time` | single | When the material in this environment was last rotated |
| [`ciamStoreModified`](#a-ciamstoremodified) |  | `time` | single | When the store last changed the object (any write): never evidence of rotation |
| [`ciamLastVerified`](#a-ciamlastverified) |  | `time` | single | When the store last verified that the object still works where it is used |
| [`ciamManualReason`](#a-ciammanualreason) |  | `string` | single | Why the store doesn't manage the object's rotation, as the store records it |

<a id="c-ciamsecretref"></a>
### ciamSecretRef

Reference to a secret

OID `1.3.6.1.4.1.32473.1.2.10` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamRefUri`](#a-ciamrefuri) | yes | `ref-uri` | single | Reference to a secret or key in the environment's store. Never the value |
| [`ciamProtectionLevel`](#a-ciamprotectionlevel) |  | `enum` | single | How the store protects the material: in software, in an HSM, a managed HSM, or an external key store |
| [`ciamAutoRotate`](#a-ciamautorotate) |  | `bool` | single | The store rotates (or renews) the material automatically |
| [`ciamRotationFunction`](#a-ciamrotationfunction) |  | `string` | single | Provider id of the function or job that rotates the material |
| [`ciamReplicaRegion`](#a-ciamreplicaregion) |  | `string` | multi | Regions the key, secret or managed directory is replicated to (multi-region keys, replicated secrets, a managed directory's further regions) |
| [`ciamKeyUser`](#a-ciamkeyuser) |  | `string` | multi | Principal the store lets use the material (provider id of a role, identity or service account) |
| [`ciamKeyAdmin`](#a-ciamkeyadmin) |  | `string` | multi | Principal the store lets manage the key or secret (provider id) |
| [`ciamLastRotated`](#a-ciamlastrotated) |  | `time` | single | When the material in this environment was last rotated |
| [`ciamCopyRef`](#a-ciamcopyref) |  | `ref-uri` | multi | Another place this environment holds the same material (a PAM safe, a second store): rotating it must update these too |
| [`ciamMaterialFrom`](#a-ciammaterialfrom) |  | `dn` | single | The binding in another environment whose material this one holds (carried over, not regenerated) |
| [`ciamEncryptedByRole`](#a-ciamencryptedbyrole) |  | `string` | single | The binding role of the key that encrypts a secret in its store (a customer managed key): who reads or writes the secret may also need to use that key |

<a id="c-ciamsecretstore"></a>
### ciamSecretStore

Where an environment's references of one scheme are read from, beyond what each reference says: the store's address and how Kubernetes workloads log in to it

OID `1.3.6.1.4.1.32473.1.2.131` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamRefScheme`](#a-ciamrefscheme) | yes | `string` | single | The ref-uri scheme whose references a secret store holds (vault, aws-sm, azkv, gcp-sm, ...) |
| [`ciamStoreEndpoint`](#a-ciamstoreendpoint) |  | `url` | single | The address workloads reach a secret store at when the reference doesn't say (a Vault server) |
| [`ciamStoreAuthRole`](#a-ciamstoreauthrole) |  | `string` | single | The role a Kubernetes workload logs in to a secret store as (a Vault Kubernetes auth role) |
| [`ciamStoreAuthMount`](#a-ciamstoreauthmount) |  | `string` | single | The secret store auth method mount Kubernetes workloads log in through (a Vault auth mount path) |
| [`ciamStoreKvVersion`](#a-ciamstorekvversion) |  | `enum` | single | The version of a key/value secret store's engine (Vault KV 1 or 2); 2 when not recorded |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |

<a id="c-ciamtrustbundle"></a>
### ciamTrustBundle

A published trust bundle as last imported (cn: its name, the publisher's group: dod, eca; under ou=trust-bundles), observed: its release, where it came from, how its integrity was established (signer, the root the signer chains to, what failed) and its CA certificates as children

OID `1.3.6.1.4.1.32473.1.2.201` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamInventoryAt`](#a-ciaminventoryat) | yes | `time` | single | When a secret store container's inventory was taken |
| [`ciamBundleVerification`](#a-ciambundleverification) | yes | `enum` | single | How a trust bundle's integrity was established when imported: verified (its signed manifest's signature checks, its signer chains to a CA certificate the record holds, every file matches its digest); signed-unanchored (as verified, but the signer's root isn't in the record yet: compare its fingerprint with the publisher's); digests-only (files match a manifest whose signature wasn't checked); failed (a bad signature, a digest mismatch or a listed file missing) |
| [`ciamTrustBundleRelease`](#a-ciamtrustbundlerelease) |  | `string` | single | A trust bundle's release as its publisher labels it (DISA's 5.14) |
| [`ciamBundleSource`](#a-ciambundlesource) |  | `string` | single | Where a trust bundle was taken from: the archive or URL the publisher distributes it as |
| [`ciamBundleDigest`](#a-ciambundledigest) |  | `string` | single | SHA-256 of the archive a trust bundle was imported from (hex) |
| [`ciamBundleSigner`](#a-ciambundlesigner) |  | `string` | single | SHA-256 fingerprint of the certificate that signed a trust bundle's manifest |
| [`ciamSignerAnchor`](#a-ciamsigneranchor) |  | `string` | single | SHA-256 fingerprint of the root CA certificate a trust bundle's signer chains to |
| [`ciamInventoryProblem`](#a-ciaminventoryproblem) |  | `string` | multi | Why an inventory is incomplete or denied, in words |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |

<a id="c-ciamtrustpolicy"></a>
### ciamTrustPolicy

Which certificates the platform accepts for one purpose (under ou=trust-policies): the approved anchors, the bundles it follows, the certificate policies and key usages it requires, how an accepted certificate maps to an account, how revocation is checked and what happens when it can't be, and the server roles and identity services that accept them

OID `1.3.6.1.4.1.32473.1.2.203` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamTrustPurpose`](#a-ciamtrustpurpose) | yes | `enum` | single | What a trust policy accepts certificates for: authenticating users or partners (CAC/PIV, ECA), verifying partners' signatures, or trusting the servers the platform calls |
| [`ciamTrustAnchor`](#a-ciamtrustanchor) |  | `dn` | multi | A CA certificate (purpose ca, under ou=certificates) a trust policy accepts certificates under: an approved anchor; with its public PEM, what the policy's consumers are given to trust |
| [`ciamTrustBundleRef`](#a-ciamtrustbundleref) |  | `dn` | multi | A trust bundle (under ou=trust-bundles) a trust policy follows: its new roots are proposed as anchors for review and anchors it drops are flagged; its subordinate CAs complete the anchors' chains |
| [`ciamAllowedPolicyOid`](#a-ciamallowedpolicyoid) |  | `string` | multi | A certificate policy OID a trust policy accepts (one is enough); none recorded: any policy the anchors' CAs issue under |
| [`ciamRequiredEku`](#a-ciamrequiredeku) |  | `string` | multi | An extended key usage OID a certificate must carry to be accepted under a trust policy (TLS client authentication is 1.3.6.1.5.5.7.3.2) |
| [`ciamIdentityMapping`](#a-ciamidentitymapping) |  | `enum` | single | How a trust policy's consumers map an accepted certificate to an account: the subject alternative name's UPN (a DoD CAC's EDIPI@mil) or email, the subject DN or common name, or none (the certificate authenticates a partner, not a user) |
| [`ciamRevocationMode`](#a-ciamrevocationmode) |  | `enum` | single | How a trust policy's consumers check an accepted certificate's revocation: OCSP, CRLs, one then the other when the first gives no answer, or none |
| [`ciamRevocationFailure`](#a-ciamrevocationfailure) |  | `enum` | single | What a trust policy's consumers do when revocation can't be checked: reject the certificate, accept on a cached answer no older than ciamRevocationCacheHours, or allow it (fail open) |
| [`ciamRevocationCacheHours`](#a-ciamrevocationcachehours) |  | `int` | single | How old a cached revocation answer a trust policy's consumers may rely on when checking fails, in hours |
| [`ciamAcceptedByRole`](#a-ciamacceptedbyrole) |  | `string` | multi | A server role that accepts certificates under a trust policy (its gateway, load balancer or identity provider checks them) |
| [`ciamDeclinedAnchor`](#a-ciamdeclinedanchor) |  | `string` | multi | SHA-256 fingerprint of a root in a bundle a trust policy follows that a person decided the policy doesn't accept (a decommissioned root, a test hierarchy): no longer proposed as an anchor |
| [`ciamTrustEnforcedAt`](#a-ciamtrustenforcedat) |  | `enum` | single | Where a trust policy's certificates are checked: edge (the load balancer in front of its accepting roles validates the client certificate and passes it on in a header only it may set) or product (TLS reaches the product, which validates; the default) |
| [`ciamTrustStoreRole`](#a-ciamtruststorerole) |  | `string` | single | The binding role of the object store a consumer reads a trust policy's bundle from where it takes it from storage (an AWS load balancer's trust store reads it from S3) |
| [`ciamAcceptedByService`](#a-ciamacceptedbyservice) |  | `dn` | multi | An identity service (under ou=identity-services) that accepts certificates under a trust policy: where its product signs them in (a realm's certificate journey); its server role (ciamTargetRole) is one of the policy's ciamAcceptedByRole |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamacceptedbyrole"></a>`ciamAcceptedByRole` | `1.3.6.1.4.1.32473.1.1.945` | `string` | intent | multi |  | A server role that accepts certificates under a trust policy (its gateway, load balancer or identity provider checks them) |
| <a id="a-ciamacceptedbyservice"></a>`ciamAcceptedByService` | `1.3.6.1.4.1.32473.1.1.966` | `dn` | intent | multi |  | An identity service (under ou=identity-services) that accepts certificates under a trust policy: where its product signs them in (a realm's certificate journey); its server role (ciamTargetRole) is one of the policy's ciamAcceptedByRole |
| <a id="a-ciamallowedpolicyoid"></a>`ciamAllowedPolicyOid` | `1.3.6.1.4.1.32473.1.1.939` | `string` | intent | multi |  | A certificate policy OID a trust policy accepts (one is enough); none recorded: any policy the anchors' CAs issue under |
| <a id="a-ciamapprovalrequired"></a>`ciamApprovalRequired` | `1.3.6.1.4.1.32473.1.1.801` | `bool` | observed | single |  | Whether a certificate template's requests wait for a CA manager's approval before they are issued |
| <a id="a-ciamauthoritykeyid"></a>`ciamAuthorityKeyId` | `1.3.6.1.4.1.32473.1.1.995` | `string` | observed | single |  | The key identifier of the CA key that signed the certificate (its authority key identifier, RFC 5280 4.2.1.1), as lowercase hex: the issuer certificate's ciamSubjectKeyId |
| <a id="a-ciamautorotate"></a>`ciamAutoRotate` | `1.3.6.1.4.1.32473.1.1.199` | `bool` | binding | single |  | The store rotates (or renews) the material automatically |
| <a id="a-ciambasecrlnumber"></a>`ciamBaseCrlNumber` | `1.3.6.1.4.1.32473.1.1.822` | `string` | observed | single |  | The delta CRL indicator of a delta CRL an endpoint served (RFC 5280 5.2.4): the number of the oldest complete CRL it can be combined with, as decimal |
| <a id="a-ciambundledigest"></a>`ciamBundleDigest` | `1.3.6.1.4.1.32473.1.1.931` | `string` | observed | single |  | SHA-256 of the archive a trust bundle was imported from (hex) |
| <a id="a-ciambundlegroup"></a>`ciamBundleGroup` | `1.3.6.1.4.1.32473.1.1.935` | `string` | observed | single |  | The part of a trust bundle a member certificate came in, as the publisher groups them (the root CA it sits under: DoD Root CA 6) |
| <a id="a-ciambundlesigner"></a>`ciamBundleSigner` | `1.3.6.1.4.1.32473.1.1.933` | `string` | observed | single |  | SHA-256 fingerprint of the certificate that signed a trust bundle's manifest |
| <a id="a-ciambundlesource"></a>`ciamBundleSource` | `1.3.6.1.4.1.32473.1.1.930` | `string` | observed | single |  | Where a trust bundle was taken from: the archive or URL the publisher distributes it as |
| <a id="a-ciambundleverification"></a>`ciamBundleVerification` | `1.3.6.1.4.1.32473.1.1.932` | enum: `verified`, `signed-unanchored`, `digests-only`, `failed` | observed | single |  | How a trust bundle's integrity was established when imported: verified (its signed manifest's signature checks, its signer chains to a CA certificate the record holds, every file matches its digest); signed-unanchored (as verified, but the signer's root isn't in the record yet: compare its fingerprint with the publisher's); digests-only (files match a manifest whose signature wasn't checked); failed (a bad signature, a digest mismatch or a listed file missing) |
| <a id="a-ciamcacertificate"></a>`ciamCaCertificate` | `1.3.6.1.4.1.32473.1.1.720` | `dn` | meta | multi |  | A certification authority's own certificates in the record (ou=certificates): the one it signs with, and those it renewed |
| <a id="a-ciamcakeyalgorithm"></a>`ciamCaKeyAlgorithm` | `1.3.6.1.4.1.32473.1.1.912` | `string` | observed | single |  | The algorithm of the key a certification authority signs with, as its product names it (RSA_4096, EC_P384_SHA384) |
| <a id="a-ciamcakeyref"></a>`ciamCaKeyRef` | `1.3.6.1.4.1.32473.1.1.914` | `string` | observed | single |  | The customer-managed key a certification authority signs with (its key service's name for it): a reference, never key material |
| <a id="a-ciamcakeystorage"></a>`ciamCaKeyStorage` | `1.3.6.1.4.1.32473.1.1.913` | `string` | observed | single |  | Where a certification authority's signing key is kept, as its product says (an HSM standard such as FIPS 140-2 Level 3, a provider-managed HSM, a customer-managed key) |
| <a id="a-ciamcarestorableuntil"></a>`ciamCaRestorableUntil` | `1.3.6.1.4.1.32473.1.1.916` | `time` | observed | single |  | Until when a deleted certification authority can still be restored in its product (AWS Private CA's RestorableUntil; Google CAS's purge time): after it, the CA and what it would renew are gone |
| <a id="a-ciamcastate"></a>`ciamCaState` | `1.3.6.1.4.1.32473.1.1.911` | enum: `active`, `disabled`, `pending`, `expired`, `deleted`, `failed` | observed | single |  | A certification authority's state in its product: active (issuing), disabled, pending (not yet activated: awaiting its certificate or its activation), expired, deleted (still restorable) or failed (its creation failed) |
| <a id="a-ciamcatype"></a>`ciamCaType` | `1.3.6.1.4.1.32473.1.1.910` | enum: `root`, `subordinate` | observed | single |  | Whether a certification authority is a root (its own certificate self-signed) or subordinate to another CA, as its product says |
| <a id="a-ciamcertificatename"></a>`ciamCertificateName` | `1.3.6.1.4.1.32473.1.1.921` | `string` | observed | multi |  | The DNS names and IP addresses a certificate names (its subject common name and alternative names), as its manager reports them, wildcards kept |
| <a id="a-ciamcertificatepem"></a>`ciamCertificatePem` | `1.3.6.1.4.1.32473.1.1.624` | `string` | meta | single |  | The certificate itself as PEM: public material only, never a key; recorded for a CA something must be given to trust (a gateway checking its backends) |
| <a id="a-ciamcertpolicyoid"></a>`ciamCertPolicyOid` | `1.3.6.1.4.1.32473.1.1.936` | `string` | observed | multi |  | A certificate policy OID the certificate asserts (its certificatePolicies extension; anyPolicy is 2.5.29.32.0) |
| <a id="a-ciamcertpurpose"></a>`ciamCertPurpose` | `1.3.6.1.4.1.32473.1.1.105` | enum: `tls-server`, `saml-signing`, `saml-encryption`, `jwt-signing`, `partner-signing`, `client-auth`, `ca` | intent | single |  | What the certificate is for (client-auth: one the operator presents to authenticate, e.g. to a reporting portal; ca: a certification authority a truststore adds) |
| <a id="a-ciamcontinuity"></a>`ciamContinuity` | `1.3.6.1.4.1.32473.1.1.195` | enum: `carry-over`, `per-environment` | intent | single |  | carry-over: the same material must reach every environment that takes over from or joins this one (replication deployment keys, signing keys partners trust, session encryption keys); per-environment: each environment may hold its own |
| <a id="a-ciamcontinuityreason"></a>`ciamContinuityReason` | `1.3.6.1.4.1.32473.1.1.196` | `string` | meta | single |  | What breaks if the material is not carried over |
| <a id="a-ciamcopyref"></a>`ciamCopyRef` | `1.3.6.1.4.1.32473.1.1.205` | `ref-uri` | secret-ref | multi |  | Another place this environment holds the same material (a PAM safe, a second store): rotating it must update these too |
| <a id="a-ciamcredentialtype"></a>`ciamCredentialType` | `1.3.6.1.4.1.32473.1.1.187` | enum: `private-key`, `symmetric-key`, `keystore`, `password`, `api-token`, `client-secret`, `shared-secret`, `deployment-id`, `ssh-key`, `other` | intent | single |  | What kind of key or secret the credential is |
| <a id="a-ciamcrlnumber"></a>`ciamCrlNumber` | `1.3.6.1.4.1.32473.1.1.821` | `string` | observed | single |  | The CRL number (RFC 5280 5.2.3) of the CRL an endpoint served, as decimal |
| <a id="a-ciamcrossrole"></a>`ciamCrossRole` | `1.3.6.1.4.1.32473.1.1.998` | enum: `peer`, `bridge-to-member`, `member-to-bridge` | meta | single |  | What a cross-certificate joins: two PKIs certifying each other directly (peer), a bridge CA certifying a member PKI's CA (bridge-to-member), or a member PKI's CA certifying the bridge (member-to-bridge) |
| <a id="a-ciamdeclinedanchor"></a>`ciamDeclinedAnchor` | `1.3.6.1.4.1.32473.1.1.947` | `string` | intent | multi |  | SHA-256 fingerprint of a root in a bundle a trust policy follows that a person decided the policy doesn't accept (a decommissioned root, a test hierarchy): no longer proposed as an anchor |
| <a id="a-ciamencryptedbyrole"></a>`ciamEncryptedByRole` | `1.3.6.1.4.1.32473.1.1.341` | `string` | binding | single |  | The binding role of the key that encrypts a secret in its store (a customer managed key): who reads or writes the secret may also need to use that key |
| <a id="a-ciamendpointanswer"></a>`ciamEndpointAnswer` | `1.3.6.1.4.1.32473.1.1.818` | enum: `answered`, `http-error`, `unreachable`, `unreadable`, `not-observed` | observed | single |  | What a revocation endpoint answered when observed: answered (a CRL or OCSP response read), http-error (an error status), unreachable (no answer), unreadable (an answer that isn't a CRL or a successful OCSP response), or not-observed (nothing to fetch: not an http(s) URL, unfilled variables, nothing to ask an OCSP responder about) |
| <a id="a-ciamendpointurl"></a>`ciamEndpointUrl` | `1.3.6.1.4.1.32473.1.1.728` | `string` | observed | single |  | Where a revocation endpoint is reached, as its CA writes it into the certificates it issues (a URL; the CA's template when its variables couldn't all be filled) |
| <a id="a-ciamenrollee"></a>`ciamEnrollee` | `1.3.6.1.4.1.32473.1.1.804` | `string` | observed | multi |  | Who a certificate template's access rights let request certificates from it, as its directory names them (an identifier, with its well-known name when it has one); metadata only |
| <a id="a-ciamenrollmentscope"></a>`ciamEnrollmentScope` | `1.3.6.1.4.1.32473.1.1.805` | enum: `broad`, `restricted`, `unknown` | observed | single |  | Whether a certificate template lets a broad group request certificates (anyone, every authenticated account, all of a domain's users or computers), or only named principals; unknown when its access rights weren't read or hold entries that can't be judged |
| <a id="a-ciamexportable"></a>`ciamExportable` | `1.3.6.1.4.1.32473.1.1.193` | `bool` | intent | single |  | The material may leave the store that holds it (be copied to another store or environment) |
| <a id="a-ciamextendedkeyusage"></a>`ciamExtendedKeyUsage` | `1.3.6.1.4.1.32473.1.1.725` | `string` | observed | multi |  | The extended key usages a certificate template issues, as OIDs |
| <a id="a-ciamfingerprint"></a>`ciamFingerprint` | `1.3.6.1.4.1.32473.1.1.100` | `string` | meta | single |  | SHA-256 fingerprint |
| <a id="a-ciamholdscertificate"></a>`ciamHoldsCertificate` | `1.3.6.1.4.1.32473.1.1.207` | `dn` | binding | single |  | The certificate a certificate store entry holds |
| <a id="a-ciamhsmrequired"></a>`ciamHsmRequired` | `1.3.6.1.4.1.32473.1.1.192` | `bool` | intent | single |  | The material must be generated and kept in a hardware security module |
| <a id="a-ciamidentitymapping"></a>`ciamIdentityMapping` | `1.3.6.1.4.1.32473.1.1.941` | enum: `san-upn`, `san-email`, `subject-dn`, `subject-cn`, `none` | intent | single |  | How a trust policy's consumers map an accepted certificate to an account: the subject alternative name's UPN (a DoD CAC's EDIPI@mil) or email, the subject DN or common name, or none (the certificate authenticates a partner, not a user) |
| <a id="a-ciaminstalledat"></a>`ciamInstalledAt` | `1.3.6.1.4.1.32473.1.1.926` | `string` | observed | multi |  | Where a certificate manager says a certificate is installed or was found (an application, a device, host:port), as the manager names it |
| <a id="a-ciaminventoryat"></a>`ciamInventoryAt` | `1.3.6.1.4.1.32473.1.1.690` | `time` | observed | single |  | When a secret store container's inventory was taken |
| <a id="a-ciaminventoryprefix"></a>`ciamInventoryPrefix` | `1.3.6.1.4.1.32473.1.1.693` | `string` | observed | multi |  | The path prefixes an inventory listed in its container; none: the whole container |
| <a id="a-ciaminventoryproblem"></a>`ciamInventoryProblem` | `1.3.6.1.4.1.32473.1.1.692` | `string` | observed | multi |  | Why an inventory is incomplete or denied, in words |
| <a id="a-ciaminventorystate"></a>`ciamInventoryState` | `1.3.6.1.4.1.32473.1.1.691` | enum: `complete`, `incomplete`, `denied` | observed | single |  | complete: every object in the container (or under its listed prefixes) was listed; incomplete: the listing may have missed some (truncated, unread pages); denied: the store refused to list it |
| <a id="a-ciamisca"></a>`ciamIsCa` | `1.3.6.1.4.1.32473.1.1.996` | `bool` | observed | single |  | Whether the certificate's basic constraints make it a CA certificate (cA); absent when it has no basic constraints extension |
| <a id="a-ciamissuedby"></a>`ciamIssuedBy` | `1.3.6.1.4.1.32473.1.1.721` | `dn` | meta | single |  | The certificate of the CA that issued this one (ou=certificates): the CA hierarchy, link by link |
| <a id="a-ciamissuer"></a>`ciamIssuer` | `1.3.6.1.4.1.32473.1.1.102` | `string` | meta | single |  | Certificate issuer |
| <a id="a-ciamkeyadmin"></a>`ciamKeyAdmin` | `1.3.6.1.4.1.32473.1.1.203` | `string` | binding | multi |  | Principal the store lets manage the key or secret (provider id) |
| <a id="a-ciamkeyalgorithm"></a>`ciamKeyAlgorithm` | `1.3.6.1.4.1.32473.1.1.188` | `string` | intent | single |  | Key algorithm (e.g. RSA, EC P-256, AES-256, HMAC-SHA256) |
| <a id="a-ciamkeyrole"></a>`ciamKeyRole` | `1.3.6.1.4.1.32473.1.1.107` | `string` | meta | single |  | Binding role of the secret holding the private key (per environment) |
| <a id="a-ciamkeysize"></a>`ciamKeySize` | `1.3.6.1.4.1.32473.1.1.189` | `int` | intent | single | X-MIN `1` | Key size in bits |
| <a id="a-ciamkeyusage"></a>`ciamKeyUsage` | `1.3.6.1.4.1.32473.1.1.190` | enum: `signing`, `encryption`, `key-wrapping`, `tls`, `authentication`, `replication`, `administration`, `other` | intent | multi |  | What the credential is used for |
| <a id="a-ciamkeyuser"></a>`ciamKeyUser` | `1.3.6.1.4.1.32473.1.1.202` | `string` | binding | multi |  | Principal the store lets use the material (provider id of a role, identity or service account) |
| <a id="a-ciamlastrotated"></a>`ciamLastRotated` | `1.3.6.1.4.1.32473.1.1.204` | `time` | observed | single |  | When the material in this environment was last rotated |
| <a id="a-ciamlastverified"></a>`ciamLastVerified` | `1.3.6.1.4.1.32473.1.1.698` | `time` | observed | single |  | When the store last verified that the object still works where it is used |
| <a id="a-ciammanagedauthority"></a>`ciamManagedAuthority` | `1.3.6.1.4.1.32473.1.1.928` | `string` | observed | single |  | The certification authority (or its template) a certificate manager renews a certificate through, as the manager names it |
| <a id="a-ciammanagedorigin"></a>`ciamManagedOrigin` | `1.3.6.1.4.1.32473.1.1.924` | enum: `discovered`, `added` | observed | single |  | How a certificate came to its manager: discovered (found by a network or agent scan) or added (enrolled through it, imported, or created by someone) |
| <a id="a-ciammanagement"></a>`ciamManagement` | `1.3.6.1.4.1.32473.1.1.923` | enum: `unassigned`, `monitored`, `enrolled`, `provisioned` | observed | single |  | What a certificate manager does for a certificate: unassigned (nothing), monitored (watches its expiry; someone else renews it), enrolled (requests and renews it; someone installs it) or provisioned (renews it and installs it where it is used) |
| <a id="a-ciammanageraction"></a>`ciamManagerAction` | `1.3.6.1.4.1.32473.1.1.900` | `string` | observed | multi |  | What a certificate manager is set to do for a certificate on its own, as the manager says it (a renewal or notification trigger: AutoRenew at 80% of lifetime, EmailContacts 30 days before expiry) |
| <a id="a-ciammanagercontact"></a>`ciamManagerContact` | `1.3.6.1.4.1.32473.1.1.925` | `string` | observed | multi |  | Who a certificate manager notifies about a certificate, as the manager names them (its own identities); metadata only |
| <a id="a-ciammanagerpath"></a>`ciamManagerPath` | `1.3.6.1.4.1.32473.1.1.922` | `string` | observed | single |  | Where a certificate manager files a certificate (a policy folder's object, a vault's certificate name) |
| <a id="a-ciammanagerproblem"></a>`ciamManagerProblem` | `1.3.6.1.4.1.32473.1.1.927` | `string` | observed | multi |  | What a certificate manager reports wrong with a certificate now (a failed renewal or installation, a revocation requested or failed), in its words |
| <a id="a-ciammanualreason"></a>`ciamManualReason` | `1.3.6.1.4.1.32473.1.1.699` | `string` | observed | single |  | Why the store doesn't manage the object's rotation, as the store records it |
| <a id="a-ciammaterialformat"></a>`ciamMaterialFormat` | `1.3.6.1.4.1.32473.1.1.191` | enum: `pem`, `der`, `pkcs12`, `jks`, `jceks`, `jwk`, `raw`, `text`, `other` | intent | single |  | The form the material takes where it is used |
| <a id="a-ciammaterialfrom"></a>`ciamMaterialFrom` | `1.3.6.1.4.1.32473.1.1.206` | `dn` | binding | single |  | The binding in another environment whose material this one holds (carried over, not regenerated) |
| <a id="a-ciammaxvaliditydays"></a>`ciamMaxValidityDays` | `1.3.6.1.4.1.32473.1.1.724` | `int` | observed | single | X-MIN `1` | The longest validity a certificate template issues, in days |
| <a id="a-ciamnextupdate"></a>`ciamNextUpdate` | `1.3.6.1.4.1.32473.1.1.820` | `time` | observed | single |  | When the CRL or OCSP response an endpoint served says newer information will be available by (its nextUpdate); absent when it gave none |
| <a id="a-ciamnotafter"></a>`ciamNotAfter` | `1.3.6.1.4.1.32473.1.1.104` | `time` | meta | single |  | Expires |
| <a id="a-ciamnotbefore"></a>`ciamNotBefore` | `1.3.6.1.4.1.32473.1.1.103` | `time` | meta | single |  | Valid from |
| <a id="a-ciamobjectstate"></a>`ciamObjectState` | `1.3.6.1.4.1.32473.1.1.694` | enum: `active`, `deleted`, `disabled` | observed | single |  | A secret store object's state: deleted (its current version deleted or destroyed, or scheduled for deletion) and disabled objects can't be read by what references them |
| <a id="a-ciamocspstatus"></a>`ciamOcspStatus` | `1.3.6.1.4.1.32473.1.1.825` | enum: `good`, `revoked`, `unknown`, `malformedRequest`, `internalError`, `tryLater`, `sigRequired`, `unauthorized` | observed | single |  | What an OCSP responder said of the certificate it was asked about (ciamSerialNumber): good, revoked or unknown, or the status of a response that wasn't successful (RFC 6960 4.2.1) |
| <a id="a-ciamparentauthority"></a>`ciamParentAuthority` | `1.3.6.1.4.1.32473.1.1.915` | `dn` | observed | single |  | The certification authority (ou=certificate-authorities) that issued a subordinate CA's certificate, as the CA's product says |
| <a id="a-ciampartnercontact"></a>`ciamPartnerContact` | `1.3.6.1.4.1.32473.1.1.108` | `dn` | meta | single |  | Partner to coordinate rotation with |
| <a id="a-ciampasswordrole"></a>`ciamPasswordRole` | `1.3.6.1.4.1.32473.1.1.608` | `string` | meta | single |  | Binding role of the secret holding the password that protects the material where it is kept (a PKCS#12 file's), per environment like the material's own role |
| <a id="a-ciampathlength"></a>`ciamPathLength` | `1.3.6.1.4.1.32473.1.1.997` | `int` | observed | single | X-MIN `0` | The most CA certificates that may follow a CA certificate in a path (its basic constraints' pathLenConstraint); absent: no limit |
| <a id="a-ciampolicymapping"></a>`ciamPolicyMapping` | `1.3.6.1.4.1.32473.1.1.999` | `string` | observed | multi |  | A policy mapping a cross-certificate carries (RFC 5280 4.2.1.5), as <issuerDomainPolicy>=<subjectDomainPolicy>: the issuer's policy OID a relying party under the issuer reads the subject's policy OID as |
| <a id="a-ciamprotectionlevel"></a>`ciamProtectionLevel` | `1.3.6.1.4.1.32473.1.1.198` | enum: `software`, `hsm`, `managed-hsm`, `external` | binding | single |  | How the store protects the material: in software, in an HSM, a managed HSM, or an external key store |
| <a id="a-ciamrefscheme"></a>`ciamRefScheme` | `1.3.6.1.4.1.32473.1.1.616` | `string` | binding | single |  | The ref-uri scheme whose references a secret store holds (vault, aws-sm, azkv, gcp-sm, ...) |
| <a id="a-ciamrefuri"></a>`ciamRefUri` | `1.3.6.1.4.1.32473.1.1.35` | `ref-uri` | secret-ref | single |  | Reference to a secret or key in the environment's store. Never the value |
| <a id="a-ciamrenewalowner"></a>`ciamRenewalOwner` | `1.3.6.1.4.1.32473.1.1.726` | `dn` | meta | single |  | Who renews the certificates a template issues that the record holds no certificate for (a party under ou=owners); a recorded certificate's own owner renews it |
| <a id="a-ciamrenewedas"></a>`ciamRenewedAs` | `1.3.6.1.4.1.32473.1.1.905` | `string` | observed | single |  | An earlier version of a certificate a certificate manager holds: the manager's id (cn) of the certificate that replaced it in the same inventory, as the manager links its versions |
| <a id="a-ciamreplicaregion"></a>`ciamReplicaRegion` | `1.3.6.1.4.1.32473.1.1.201` | `string` | binding | multi |  | Regions the key, secret or managed directory is replicated to (multi-region keys, replicated secrets, a managed directory's further regions) |
| <a id="a-ciamrequester"></a>`ciamRequester` | `1.3.6.1.4.1.32473.1.1.730` | `string` | observed | single |  | Who requested an issued certificate, as its CA records it (an account name) |
| <a id="a-ciamrequiredeku"></a>`ciamRequiredEku` | `1.3.6.1.4.1.32473.1.1.940` | `string` | intent | multi |  | An extended key usage OID a certificate must carry to be accepted under a trust policy (TLS client authentication is 1.3.6.1.5.5.7.3.2) |
| <a id="a-ciamrequiredsignatures"></a>`ciamRequiredSignatures` | `1.3.6.1.4.1.32473.1.1.802` | `int` | observed | single | X-MIN `0` | How many authorized signatures (an enrollment agent's) a certificate template's requests need |
| <a id="a-ciamrevocationcachehours"></a>`ciamRevocationCacheHours` | `1.3.6.1.4.1.32473.1.1.944` | `int` | intent | single |  | How old a cached revocation answer a trust policy's consumers may rely on when checking fails, in hours |
| <a id="a-ciamrevocationfailure"></a>`ciamRevocationFailure` | `1.3.6.1.4.1.32473.1.1.943` | enum: `reject`, `cached`, `allow` | intent | single |  | What a trust policy's consumers do when revocation can't be checked: reject the certificate, accept on a cached answer no older than ciamRevocationCacheHours, or allow it (fail open) |
| <a id="a-ciamrevocationkind"></a>`ciamRevocationKind` | `1.3.6.1.4.1.32473.1.1.727` | enum: `crl`, `delta-crl`, `ocsp`, `ca-issuers` | observed | single |  | What a revocation endpoint serves: a CRL distribution point, a delta CRL (freshest CRL), an OCSP responder, or the CA's own certificate (authority information access, CA issuers) |
| <a id="a-ciamrevocationmode"></a>`ciamRevocationMode` | `1.3.6.1.4.1.32473.1.1.942` | enum: `ocsp`, `crl`, `ocsp-then-crl`, `crl-then-ocsp`, `none` | intent | single |  | How a trust policy's consumers check an accepted certificate's revocation: OCSP, CRLs, one then the other when the first gives no answer, or none |
| <a id="a-ciamrevocationreason"></a>`ciamRevocationReason` | `1.3.6.1.4.1.32473.1.1.732` | `string` | observed | single |  | Why an issued certificate was revoked: the RFC 5280 reason (keyCompromise, superseded, ...), or the CA's value as it is when it is no RFC 5280 reason; present on every revoked certificate |
| <a id="a-ciamrevokedat"></a>`ciamRevokedAt` | `1.3.6.1.4.1.32473.1.1.731` | `time` | observed | single |  | When an issued certificate's revocation takes effect (it may be back- or future-dated) |
| <a id="a-ciamrotationdays"></a>`ciamRotationDays` | `1.3.6.1.4.1.32473.1.1.194` | `int` | intent | single | X-MIN `1` | Rotation policy: the longest the same material may stay in use, in days |
| <a id="a-ciamrotationfunction"></a>`ciamRotationFunction` | `1.3.6.1.4.1.32473.1.1.200` | `string` | binding | single |  | Provider id of the function or job that rotates the material |
| <a id="a-ciamrotationmanaged"></a>`ciamRotationManaged` | `1.3.6.1.4.1.32473.1.1.695` | `bool` | observed | single |  | The store manages the object's rotation itself (a PAM vault's automatic management) |
| <a id="a-ciamrotationrunbook"></a>`ciamRotationRunbook` | `1.3.6.1.4.1.32473.1.1.109` | `dn` | meta | single |  | Work instruction for rotation |
| <a id="a-ciamrotationstatus"></a>`ciamRotationStatus` | `1.3.6.1.4.1.32473.1.1.696` | enum: `success`, `failure`, `in-progress` | observed | single |  | How the store's last management (rotation) of the object went |
| <a id="a-ciamsanemail"></a>`ciamSanEmail` | `1.3.6.1.4.1.32473.1.1.991` | `string` | observed | multi |  | An email address the certificate's subject alternative name carries (rfc822Name), as written |
| <a id="a-ciamsanupn"></a>`ciamSanUpn` | `1.3.6.1.4.1.32473.1.1.990` | `string` | observed | multi |  | A user principal name the certificate's subject alternative name carries (the UPN otherName, 1.3.6.1.4.1.311.20.2.3), exactly as written: what a relying party mapping certificates by UPN (ciamIdentityMapping san-upn) finds the account by |
| <a id="a-ciamsanuri"></a>`ciamSanUri` | `1.3.6.1.4.1.32473.1.1.992` | `string` | observed | multi |  | A URI the certificate's subject alternative name carries (uniformResourceIdentifier), as written |
| <a id="a-ciamserialnumber"></a>`ciamSerialNumber` | `1.3.6.1.4.1.32473.1.1.729` | `string` | meta | single |  | A certificate's serial number, as hex |
| <a id="a-ciamsignaturecheck"></a>`ciamSignatureCheck` | `1.3.6.1.4.1.32473.1.1.823` | enum: `valid`, `invalid`, `other-issuer`, `unauthorized-responder`, `no-ca-certificate`, `unsupported` | observed | single |  | Whether what an endpoint served was signed by the CA the record holds: valid; invalid (its signature doesn't verify with the CA's key); other-issuer (another issuer's); unauthorized-responder (an OCSP response signed by a certificate the CA didn't authorize); no-ca-certificate (the record holds none of the CA's certificates to check it with); unsupported (a signature algorithm the check doesn't verify) |
| <a id="a-ciamsignedby"></a>`ciamSignedBy` | `1.3.6.1.4.1.32473.1.1.824` | `dn` | observed | single |  | The CA certificate in the record (ou=certificates) whose key verified what an endpoint served, directly or through the OCSP responder certificate it issued |
| <a id="a-ciamsigneranchor"></a>`ciamSignerAnchor` | `1.3.6.1.4.1.32473.1.1.934` | `string` | observed | single |  | SHA-256 fingerprint of the root CA certificate a trust bundle's signer chains to |
| <a id="a-ciamstoreauthmount"></a>`ciamStoreAuthMount` | `1.3.6.1.4.1.32473.1.1.619` | `string` | binding | single |  | The secret store auth method mount Kubernetes workloads log in through (a Vault auth mount path) |
| <a id="a-ciamstoreauthrole"></a>`ciamStoreAuthRole` | `1.3.6.1.4.1.32473.1.1.618` | `string` | binding | single |  | The role a Kubernetes workload logs in to a secret store as (a Vault Kubernetes auth role) |
| <a id="a-ciamstoreendpoint"></a>`ciamStoreEndpoint` | `1.3.6.1.4.1.32473.1.1.617` | `url` | binding | single |  | The address workloads reach a secret store at when the reference doesn't say (a Vault server) |
| <a id="a-ciamstorekvversion"></a>`ciamStoreKvVersion` | `1.3.6.1.4.1.32473.1.1.620` | enum: `1`, `2` | binding | single |  | The version of a key/value secret store's engine (Vault KV 1 or 2); 2 when not recorded |
| <a id="a-ciamstoremodified"></a>`ciamStoreModified` | `1.3.6.1.4.1.32473.1.1.697` | `time` | observed | single |  | When the store last changed the object (any write): never evidence of rotation |
| <a id="a-ciamsubject"></a>`ciamSubject` | `1.3.6.1.4.1.32473.1.1.101` | `string` | meta | single |  | Certificate subject |
| <a id="a-ciamsubjectaltname"></a>`ciamSubjectAltName` | `1.3.6.1.4.1.32473.1.1.106` | `fqdn` | contract | multi |  | DNS names the certificate is valid for |
| <a id="a-ciamsubjectfromrequest"></a>`ciamSubjectFromRequest` | `1.3.6.1.4.1.32473.1.1.800` | `bool` | observed | single |  | Whether a certificate template takes the subject and alternative names from the request (the requester names them) instead of building them from the directory |
| <a id="a-ciamsubjectidentifier"></a>`ciamSubjectIdentifier` | `1.3.6.1.4.1.32473.1.1.993` | `string` | observed | multi |  | An identifier the certificate's names carry by a recognised convention, as <form>:<value> (edipi: the 10-digit DoD EDIPI a CAC's UPN of digits at mil begins with); derived from the names recorded (ciamSanUpn), never assumed: a certificate whose names follow no known convention (an ECA subscriber's) has none |
| <a id="a-ciamsubjectkeyid"></a>`ciamSubjectKeyId` | `1.3.6.1.4.1.32473.1.1.994` | `string` | observed | single |  | The certificate's subject key identifier (RFC 5280 4.2.1.2), as lowercase hex |
| <a id="a-ciamtemplateauthority"></a>`ciamTemplateAuthority` | `1.3.6.1.4.1.32473.1.1.890` | `dn` | observed | single |  | The certification authority (ou=certificate-authorities) a CA-scoped certificate template is its own (a Vault PKI role): only that CA issues from it and only its importer replaces it; absent on templates a directory shares with every CA (AD CS's forest templates) |
| <a id="a-ciamtemplatename"></a>`ciamTemplateName` | `1.3.6.1.4.1.32473.1.1.722` | `string` | observed | multi |  | The certificate templates a CA issues from; on an issued certificate, the one it was issued from (its name when the template is known, else the value the CA recorded) |
| <a id="a-ciamtemplateoid"></a>`ciamTemplateOid` | `1.3.6.1.4.1.32473.1.1.723` | `string` | observed | single |  | A certificate template's own OID (not its extended key usages) |
| <a id="a-ciamtemplateversion"></a>`ciamTemplateVersion` | `1.3.6.1.4.1.32473.1.1.803` | `int` | observed | single | X-MIN `1` | A certificate template's schema version, as its directory records it |
| <a id="a-ciamthisupdate"></a>`ciamThisUpdate` | `1.3.6.1.4.1.32473.1.1.819` | `time` | observed | single |  | When the CRL or OCSP response an endpoint served was issued (its thisUpdate) |
| <a id="a-ciamthumbprint"></a>`ciamThumbprint` | `1.3.6.1.4.1.32473.1.1.920` | `string` | observed | single |  | A certificate's SHA-1 thumbprint, as colon-separated hex: what a certificate manager gives when it gives no SHA-256 fingerprint |
| <a id="a-ciamtrustanchor"></a>`ciamTrustAnchor` | `1.3.6.1.4.1.32473.1.1.937` | `dn` | intent | multi |  | A CA certificate (purpose ca, under ou=certificates) a trust policy accepts certificates under: an approved anchor; with its public PEM, what the policy's consumers are given to trust |
| <a id="a-ciamtrustbundleref"></a>`ciamTrustBundleRef` | `1.3.6.1.4.1.32473.1.1.938` | `dn` | intent | multi |  | A trust bundle (under ou=trust-bundles) a trust policy follows: its new roots are proposed as anchors for review and anchors it drops are flagged; its subordinate CAs complete the anchors' chains |
| <a id="a-ciamtrustbundlerelease"></a>`ciamTrustBundleRelease` | `1.3.6.1.4.1.32473.1.1.929` | `string` | observed | single |  | A trust bundle's release as its publisher labels it (DISA's 5.14) |
| <a id="a-ciamtrustenforcedat"></a>`ciamTrustEnforcedAt` | `1.3.6.1.4.1.32473.1.1.964` | enum: `edge`, `product` | intent | single |  | Where a trust policy's certificates are checked: edge (the load balancer in front of its accepting roles validates the client certificate and passes it on in a header only it may set) or product (TLS reaches the product, which validates; the default) |
| <a id="a-ciamtrustpurpose"></a>`ciamTrustPurpose` | `1.3.6.1.4.1.32473.1.1.946` | enum: `client-auth`, `partner-signing`, `server-tls` | intent | single |  | What a trust policy accepts certificates for: authenticating users or partners (CAC/PIV, ECA), verifying partners' signatures, or trusting the servers the platform calls |
| <a id="a-ciamtruststorerole"></a>`ciamTrustStoreRole` | `1.3.6.1.4.1.32473.1.1.965` | `string` | intent | single |  | The binding role of the object store a consumer reads a trust policy's bundle from where it takes it from storage (an AWS load balancer's trust store reads it from S3) |
| <a id="a-ciamusedin"></a>`ciamUsedIn` | `1.3.6.1.4.1.32473.1.1.197` | `dn` | meta | multi |  | Where the credential is configured or used (config files, consumers, integrations, bundles) |
