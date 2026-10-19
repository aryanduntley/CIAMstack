# opsdir-adapter-x509

opsdir adapter for the X.509 standards themselves, CA-neutral: every certification authority the record holds has its revocation endpoints observed (RFC 5280 CRLs and delta CRLs, RFC 6960 OCSP responders) and what each answered checked against the CA certificates the record holds, into the core `pki` domain's revocation observations. A PKI adapter (kind `pki`), declaration-only: it renders nothing, owns no reference scheme, and works for any CA whose importer records its endpoints (`opsdir-adapter-adcs`, `opsdir-adapter-hashicorp-vault`'s PKI inventory). It also gives the CA importers that receive certificates as PEM one CA-neutral reader of their public facts (`certificate_facts`, below), and reads what the record's own certificates say of themselves, recognising the cross-certificates among them (importer `x509/certificates`).

**Applies to** no environment by itself (`applies` is `None`): its collector and importer cover the whole estate's CAs.

**Depends on** `opsdir` and `cryptography` (pyca), 50.0.2 or later: the current release when this adapter was written (2026-09-30), which this package requires; the APIs it uses (`load_der_x509_crl`, `is_signature_valid`, `last_update_utc` / `next_update_utc`, `OCSPRequestBuilder.add_certificate_by_hash`, `load_der_ocsp_response`, `this_update_utc` / `produced_at_utc`, `verify_directly_issued_by`) all exist from 43.0. It is the only opsdir package that depends on a cryptography library directly (others read certificates through it: `opsdir-adapter-hashicorp-vault`): the core judges what this adapter recorded and never parses a CRL itself.

## What it renders

Nothing. No schema, vocabulary, secret patterns, required roles or planner checks of its own: the record's classes (`ciamRevocationObservation`, `ciamEndpointObservation`, `ciamCrossCertificate` and the certificate facts on `ciamCertificate`), the `revocation-endpoints` and `cross-certificates` reports and the planner's actions are the core `pki` domain's (opsdir/README.md, Revocation endpoints observed; Partner trust).

## Observing the endpoints (`opsdir collect x509/revocation`)

An estate collection (no `--env`): one HTTP GET per endpoint, made by opsdir (the core's observing `Request`), read-only and anonymous (CRLs and OCSP responders are public; no credential is resolved; an https endpoint is trusted by the system's store). Whatever an endpoint answers, an error status or nothing at all, is what the export keeps (`<CA name>/<endpoint name>.json`: when, the HTTP status, the content type, the body as base64, or why there was no answer), so an unreachable endpoint never fails the collection; it is what the observation records. Run it from where the relying parties sit: their network decides what they reach.

| Endpoint (`ciamRevocationKind`) | What is fetched |
|---|---|
| `crl`, `delta-crl` | The URL as the CA wrote it into the certificates it issues, its path percent-encoded where it holds spaces |
| `ocsp` | An RFC 6960 request by GET (Appendix A.1: the responder's URL, `/`, the request's DER as base64, URL-encoded) about one certificate the CA issued: a record certificate it issued (its serial, else the serial its inventory found for it), else the newest certificate the CA's inventory holds unrevoked. One CertID hashed with SHA-1 over the CA certificate the record holds (RFC 5019: what responders answer from cache), no nonce, unsigned |
| `ca-issuers` | Not observed |

Not fetched (recorded as not observed, with why): an endpoint whose URL isn't http(s) (an AD CS `ldap:///` distribution point), one whose URL still holds the CA's variables, and an OCSP responder when the record holds no certificate of the CA with its PEM (`ciamCaCertificate`, else a CA certificate named after the CA) or no certificate the CA issued.

**Least privilege**: none beyond network reach to the endpoints. Nothing is written anywhere.

## Reading the observation (importer `x509/revocation`)

`opsdir import --change CHG-… [--at YYYYMMDDhhmmssZ] x509/revocation DIR` replaces `ou=revocation-observations` whole: per CA with a CRL, delta CRL or OCSP endpoint a `ciamRevocationObservation` (made when its first endpoint was observed, else `--at`; complete when every endpoint the observation fetches was in the export, else incomplete naming those missing), and per endpoint a `ciamEndpointObservation` with the URL as recorded:

| Answer (`ciamEndpointAnswer`) | When |
|---|---|
| `unreachable` | No answer (the reason in `ciamInventoryProblem`) |
| `http-error` | A status other than 2xx (`HTTP 404`) |
| `unreadable` | No body, or one that isn't a CRL (DER or PEM) or an OCSP response, or an OCSP response about more than one certificate |
| `answered` | A CRL: `ciamThisUpdate`, `ciamNextUpdate`, `ciamCrlNumber`, a delta CRL's `ciamBaseCrlNumber` (its delta CRL indicator). An OCSP response: its status when it isn't successful (`malformedRequest`, `internalError`, `tryLater`, `sigRequired`, `unauthorized`), else the certificate's (`good`, `revoked`, `unknown`), its serial and update times |
| `not-observed` | Not fetched (above), or not in the export |

**Signatures** (`ciamSignatureCheck`, `ciamSignedBy` the record's CA certificate): a CRL is `valid` when one of the CA's certificates has its issuer's name and its key verifies the signature (and, when the certificate says how its key may be used, it may sign CRLs); `invalid` when the key doesn't verify it; `other-issuer` when no CA certificate has its issuer's name (an indirect CRL included). An OCSP response is `valid` when the CA's key signed it, or a responder certificate in the response that the CA issued directly for OCSP signing (`id-kp-OCSPSigning`), valid when the response was produced, signed it (`ciamInventoryProblem` names the responder); `unauthorized-responder` otherwise. `no-ca-certificate` when the record holds none of the CA's certificates with a PEM; `unsupported` for a signature it can't verify. These checks are evidence of what the endpoint serves, never a trust decision for the platform.

## What certificates say of themselves (importer `x509/certificates`)

`opsdir import --change CHG-… x509/certificates DIR` reads every record certificate (`ou=certificates`) whose PEM the record holds (`ciamCertificatePem`, its first certificate the one `ciamFingerprint` names), and the PEM files in DIR (any names; a file may hold several certificates; DIR may be empty). A file holding a private key isn't read; one holding no PEM certificate is named. A certificate in DIR with a record certificate's fingerprint stands in for the PEM the record lacks (the PEM itself isn't written onto the record certificate).

Each record certificate read gets, entry by entry and nothing else changed (core `pem.with_pem_facts`): `ciamSanUpn`, `ciamSanEmail`, `ciamSanUri`, `ciamSubjectIdentifier`, `ciamSubjectKeyId`, `ciamAuthorityKeyId`, `ciamIsCa`, `ciamPathLength`, `ciamCertPolicyOid`, `ciamExtendedKeyUsage` (the certificate is the source: a fact it doesn't carry is removed), and `ciamSubject`, `ciamIssuer`, `ciamNotBefore`, `ciamSerialNumber` only where the record holds none.

**Cross-certificates**: a CA certificate (basic constraints cA) whose issuer isn't its subject and whose subject is a root the record holds (a self-issued CA certificate under `ou=certificates`, or a root a trust bundle holds), or one already recorded under `ou=cross-certificates` with its fingerprint, is recorded there (`ciamCrossCertificate`: issuer, subject, validity, fingerprint, serial, PEM, policies, policy mappings, key identifiers; named `<subject CN> by <issuer CN>`, or the name already recorded; its `ciamCrossRole` and owners, the record's, kept). One found under `ou=certificates` is named in the notices for removal (the planner says so too). A certificate in DIR that is neither a record certificate nor a cross-certificate is left out, with a notice. Cross-certificates are facts of the graph, never trust: the core reports what they make reachable from the trust policies' anchors and warns where a CA is reached only through them.

**Least privilege**: none: it reads files and the record.

## Reading certificates for other adapters (`certificates.py`)

`certificate_facts(pem)`: the public facts of a PEM's first certificate as the record writes them, for any CA importer whose product gives its issued certificates as PEM rather than as facts (`hashicorp-vault/pki`): `serial` (lowercase hex of even length, `ciamSerialNumber`'s form), `sha256` (colon-separated upper-case hex, `ciamFingerprint`'s form, the core's `pem_fingerprint`), `subject` and `issuer` (RFC 4514 strings, most specific RDN first), `not_before` / `not_after` (GeneralizedTime), `usages` (the extended key usage OIDs, `None` without the extension), `endpoints`, `names`, `policies` (certificate policy OIDs), `upns`, `emails`, `uris` (the alternative names' UPN otherNames, rfc822Names and URIs, in order), `identifiers` (`upn_identifiers`: `edipi:<10 digits>` from a UPN of 10 or 16 digits at `mil`, else none), `ski` / `aki` (lowercase hex, `None` when absent), `ca` / `path_length` (basic constraints; `None` without the extension, `path_length` `None`: no limit), `policy_mappings` (`((issuerDomainPolicy, subjectDomainPolicy), ...)`, read from the extension's DER, which the library doesn't parse); `None` for text holding no certificate. `record_facts(facts)` gives them as the record's attributes (`{attribute: tuple of values}`), for importers that write certificates (bundle, mTLS and CA importers). Public material only: a key is never read.

## Known limits

- **Not run against a CA yet**: the collector and importer are tested on CRLs and OCSP responses the tests generate. Microsoft's documentation doesn't say (Codex research, 2026-10-16) whether the AD CS Online Responder answers GET requests as well as POST, or whether it signs with a delegated responder certificate by default; the first live run settles both.
- **RSA-PSS-signed OCSP responses** aren't verified (`unsupported`): the library doesn't expose their parameters. CRLs signed with RSA-PSS are verified by the library itself; whether AD CS signs CRLs that way (`AlternateSignatureAlgorithm`) is unverified.
- **FIPS**: the `cryptography` wheels bundle their own OpenSSL (4.0.3 in 50.0.2); no FIPS 140 validation is claimed for them or for this adapter's use of them.
- **One certificate per OCSP responder**: the responder is asked about one serial, over the first of the CA's certificates (a CA renewed with a new key may have issued it under another).
- **Not observed**: CA issuers (AIA) endpoints, LDAP distribution points, indirect CRLs (recorded as another issuer), and a CRL's entries (which certificates it lists as revoked is not compared with the CA's inventory yet).
- **EDIPI convention unverified in detail**: DoD PKE documents a CAC's UPN as `EDIPI+6@mil` (Codex research 2026-10-17, §6); the exact digit counts aren't confirmed against a live CAC. The reader accepts a local part of 10 digits (the EDIPI itself) or 16 (the EDIPI followed by 6), at the domain `mil` exactly, and takes the first 10 digits as the EDIPI; any other UPN yields no identifier (an ECA subscriber's never does).
- **Other otherNames** (anything but the UPN, such as a FASC-N or a Kerberos principal name), directory names, registered IDs and IP addresses in the alternative name aren't recorded as typed values (IP addresses stay in `certificate_facts`' `names`).
- **Cross-certificates are recognised by name only**: a cross-certificate to an intermediate (not a root the record holds), and a self-issued key-rollover certificate, aren't recognised: record them by hand. Two unrecorded cross-certificates with the same subject and issuer names in one import would take the same name.
- **CRLs without nextUpdate** can't be produced by the test library; they are read and judged (RFC 5280 requires one; Windows reads such a CRL as final).

## Tests

`tests/test_x509_certificates.py`: a certificate's facts (serial, SHA-256, RFC 4514 names, validity, usages, none without the extension), text without a certificate, typed alternative names, the EDIPI recognised only where a UPN follows the convention, key identifiers, basic constraints, policy mappings (and a malformed extension) and the facts as the record's attributes. `tests/test_x509_record.py`: the certificates importer (facts from the record's PEMs and from given files, stale facts removed, cross-certificates recognised from the files and from `ou=certificates`, a re-import keeping the role and changing nothing, private keys and strays left out). `tests/test_x509_revocation.py`: registration (kind `pki`, declaration-only, the estate collector), what the observation fetches (CRL URLs, the OCSP GET request and its CertID against the library's own, no nonce, why an endpoint isn't fetched), CRLs (valid, numbers and delta indicator, PEM, wrong key, another issuer, no CA certificate, key usage without CRL signing, unreadable), OCSP responses (CA-signed, a delegated responder with and without OCSP signing, a forged signature, revoked, refused, unreadable, RSA), the importer (each answer recorded, unplanned files left out, an endpoint missing from the export, `--at`) and a collection that stays complete when an endpoint can't be reached.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-x509/tests`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `x509`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
