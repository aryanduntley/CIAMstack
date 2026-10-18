# opsdir-adapter-dod-pki

opsdir PKI adapter (kind `pki`, declaration-only) for **DISA's DoD PKE trust bundles**: the PKCS#7 bundles of DoD and External Certification Authority (ECA) CA certificates that relying parties install, plus the JITC and WCF bundles DISA also publishes. It reads a bundle into the core pki domain as a **trust bundle** (`ou=trust-bundles`, `ciamTrustBundle` / `ciamBundleCertificate`, `domains/pki/trust.py`): its release, how its integrity was established, and its CA certificates as public facts.

Being in a bundle never makes a CA trusted. A **trust policy** (`ou=trust-policies`, `ciamTrustPolicy`) says what the platform accepts certificates under, and its anchors are record CA certificates a person approved. The planner proposes each new root in a bundle a policy follows for review: approve it, which records the certificate and makes it an anchor, or decline it.

**Applies to** no environment: it renders nothing, and its importer is used directly. **Depends on** `opsdir` (the pki domain's trust bundles) and `opsdir-adapter-x509` (certificate facts, through the `cryptography` library). The exporter also needs `openssl` on the PATH.

## Getting a bundle in

1. Download the archive from DISA's PKI/PKE tools page on cyber.mil, for example `unclass-certificates_pkcs7_DoD.zip` or `unclass-certificates_pkcs7_ECA.zip`. The archives are public, so no credentials are needed.
2. Export it:
   ```bash
   python -m opsdir_adapter_dod_pki.export unclass-certificates_pkcs7_DoD.zip unclass-certificates_pkcs7_ECA.zip --out export/
   ```
   This writes `export/dod-pki/dod.json` and `export/dod-pki/eca.json`.
3. Import it (under an approved change, as every import is): `opsdir import dod-pki/bundle export/ [--at <when downloaded>]`.

The exporter does what each archive's README tells an administrator to do, and judges nothing:
- it checks the S/MIME (CMS) signature on the manifest `certificates_pkcs7_<version>_<group>.sha256` with `openssl cms -verify`, against the chain the archive ships (`DoD_PKE_CA_chain.pem`, `dod_pke_chain.pem`);
- it takes the manifest's SHA-256 lines and computes every file's own digest;
- it lists the combined DER bundle's certificates (split by `openssl pkcs7 -print_certs`) with the root group each one's per-root file puts it in.

It keeps the SHA-256 fingerprints of the signer's certificate and of the chain's root, plus the root's SHA-1 (the form crl.disa.mil publishes). It never keeps the signer's name, which is a person's.

## Verification

The importer judges each bundle:

| `ciamBundleVerification` | When |
|---|---|
| `verified` | The signature checks, the signer chain is a DoD root (alone, or with the one CA it issued: the DoD archive ships both, the ECA archive the root alone), the combined bundle is in the manifest, every listed file matches its digest, and the chain's root is a CA certificate the record holds (`purpose ca`, matched by SHA-256). |
| `signed-unanchored` | All of the above, except the root isn't in the record yet. Compare the SHA-1 the import notice prints with crl.disa.mil, then approve that root as an anchor (the planner's fix). The next import is `verified`. |
| `failed` | A bad signature, a chain of another shape, a combined bundle the manifest doesn't cover, or a listed file missing or changed. It also fails when openssl wasn't available, because nothing then covers the files. The certificates are recorded, but the planner proposes nothing from the bundle and blocks every policy that follows it. |

The archive's own chain proves only that the archive is consistent. It is the root already in the record (approved by a person, under a change) that makes a bundle `verified`.

## Record

- **Bundle:** `cn=dod,ou=trust-bundles`, named after the publisher's group (`dod`, `eca`, `jitc`, `wcf`). It holds the release (`ciamTrustBundleRelease` 5.14), the archive name and SHA-256, the verification, the signer and signer-root fingerprints, any problems, and the combined bundle's file name (`ciamProviderRef`). Each import replaces the bundle's subtree. Anchors approved from it are record certificates under `ou=certificates` and stay when it changes.
- **Members:** `cn=<subject CN>,cn=dod,ou=trust-bundles`. When two certificates share a CN, the start of the fingerprint is added to the name. Each member holds its fingerprint, subject, issuer, validity, serial, root or subordinate, PEM, certificate policy OIDs (`ciamCertPolicyOid`), and its root group (`ciamBundleGroup`: DoD Root CA 6).

What the planner then says about the trust policies that follow a bundle, and the `trust-bundles` / `trust-policies` reports, are in [opsdir/README.md](../../opsdir/README.md#partner-trust-bundles-and-trust-policies).

## Known limits

- **DoD Root CA 4.** Its signature-algorithm parameters aren't strict DER, and `cryptography` 50 refuses it (and with it any PKCS#7 file that contains it). The exporter therefore splits bundles with openssl, and for a certificate the library refuses it records openssl's reading of its facts (subject, issuer, validity, serial, SHA-256). Such a member has no certificate policy OIDs. Official sources disagree on whether Root CA 4 is active or decommissioned (research 2026-10-17); it is in bundle 5.14, so whether to accept it is the reviewer's decision.
- **SHA-1 manifest signatures.** DISA's manifests (DoD 5.14, ECA 5.12) are signed with SHA-1 digests. openssl still verifies them, but a future openssl security level could refuse them.
- **Signer chain under DoD Root CA 6.** The ECA bundle's manifest is signed by a DoD credential. A policy that follows only `eca` is `verified` only once DoD Root CA 6 is in the record (as any CA certificate, not necessarily an anchor of that policy).
- **No collector.** `opsdir collect` makes text requests, and the archive is binary. Download it with a browser or `curl`.
- **Rendered by the consumers' adapters.** This package imports the bundles; the trust policies built on them are rendered into their consumers (PingFederate, PingAM, PingGateway, load balancers and gateways) by those consumers' own adapters.
- **Live checks** (milestone 7.2 L): confirm each release's archive layout and signer, and an import of JITC and WCF archives, which haven't been tried.
