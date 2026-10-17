# opsdir-adapter-ejbca

opsdir PKI adapter for Keyfactor EJBCA (Community and Enterprise). It reads each CA an EJBCA instance runs into the record's PKI: the core `pki` domain, opsdir/README.md, Certification authorities and issued certificates. It reads the CA, its revocation endpoints, its certificate profiles as the CA's own templates, and the certificates it issued, metadata only. It is declaration-only (kind `pki`) and renders nothing. Its collector reads EJBCA's REST API with a client certificate.

**Applies to** any environment that declares a collection source for `ejbca/inventory`; collecting opts in to it.

**Depends on** `opsdir` and `opsdir-adapter-x509`. Its CA-neutral `certificate_facts` reads each issued certificate and the revocation endpoints it names, using the `cryptography` library.

**Versions:** tested against EJBCA Community **9.6.3** (`keyfactor/ejbca-ce:9.6.3`, the current release, 2026-09-15). EJBCA Enterprise 9.7 serves the same REST resources. The REST v2 certificate search and the certificate profile resource are older than 9.6, but earlier releases weren't run here.

## Inventory (importer `ejbca/inventory`, metadata only)

**Into the record:**

- **CA:** one per CA that GET `/v1/ca` lists and EJBCA runs (an external CA isn't inventoried, and is named).
  - Named after its subject's CN, as an AD CS or Vault CA is; else its EJBCA name.
  - `ciamProviderRef` is its EJBCA name.
  - Two sources listing CAs of the same name: the first is read, the other named.
- **Issued certificates:** under the CA's inventory, `cn` = the serial as EJBCA gives it (upper-case hex).
  - Facts come from `base64Cert` through `certificate_facts`: serial, SHA-256, subject, validity.
  - The template is `'<CA>/<certificate profile>'`.
  - `ciamRequester` is the end entity's username.
  - Revocation is EJBCA's own: status 40 revoked or 60 archived, its date, and the RFC 5280 reason.
  - A certificate whose profile doesn't store certificate data has EJBCA's columns only: no SHA-256, and EJBCA's own DN order for the subject.
- **Templates:** each certificate profile the CA's certificates name, while the profile still offers that CA (`available_cas` names it or `ANY_CA`), is the CA-scoped template `<CA>/<profile>` (`ciamTemplateAuthority`).
  - It carries the profile's validity as `ciamMaxValidityDays`, in EJBCA's notation: a year is 365 days, a month 30.
  - It carries the profile's extended key usages.
  - The description names the end entity profiles its certificates came through.
  - The CA's templates replace the ones the record holds as that CA's. A profile whose answer wasn't saved keeps the record's template.
- **Revocation endpoints:** the CRL distribution point, freshest CRL, OCSP and CA issuer URLs of the most recently issued active certificate the CA issued, other than its own. A root's sub-CA certificates count. That is what the CA is known to publish: EJBCA's REST API doesn't give the CA's own settings (Known limits). Without such a certificate, the record's endpoints are kept, and named.

**Complete, incomplete, denied.** A search the reader isn't allowed to see answers with no certificates rather than a refusal.

- **Denied:** a root CA (self-signed) always holds its own certificate, so an empty root inventory is denied: the role lacks `/ca_functionality/view_certificate/`.
- **Incomplete** when:
  - a search page wasn't saved or isn't an answer;
  - the pages don't hold the total the search counted;
  - the total changed while the pages were read (certificates issued or revoked meanwhile: collect again);
  - EJBCA counts more certificates than the reader saw. `count.json` is read only when the role may read it (`/system_functionality/view_systemconfiguration/`). Certificates of end entity profiles the role may not view are silently left out of every search. Without the count, seeing every profile's certificates is the role's promise, and the import says so.
- Only a complete inventory confirms a record certificate missing (the core's reconciliation).

**Export** (`opsdir collect` saves it; each answer trimmed to what the importer reads):

```
ejbca/<source>/cas.json                               GET /v1/ca
ejbca/<source>/count.json                             GET /v2/certificate/count (optional: refused or absent, nothing)
ejbca/<source>/certificates/<CA id>/page-<n>.json     POST /v2/certificate/search, CA EQUAL <name>, 500 a page,
                                                      sorted by ISSUED_DATE; page 1, then each page its total names
ejbca/<source>/profiles/<name, %-encoded>.json        GET /v2/certificate/profile/<name> (gone: nothing)
```

Importing needs `--at` (when EJBCA was read). The search body is the only POST: it changes nothing, and the collector declares its URL a read-only query. The core refuses any other POST (core.contract Collector `queries`), and the evidence records each search's body.

## Collecting

A collection source binding in the environment:

- `ciamImporter` is `ejbca/inventory`.
- `ciamSourceRef` is `https://<host>:<port>/ejbca`, one per EJBCA instance.
- `ciamCredentialScheme` is `client-certificate`.
- `ciamCredentialRole` names the binding whose reference resolves to a PEM holding the reader's certificate, its chain and its private key. That PEM is loaded into the TLS handshake in memory only, never stored. EJBCA Community takes client certificates only.
- `ciamCaRole` names the certificate EJBCA's TLS server certificate is trusted by.

EJBCA must have the REST protocols **REST Certificate Management** (`/v1/ca`) and **REST Certificate Management V2** (`/v2/certificate`) enabled, under System Configuration, Protocol Configuration. Both are off by default:

```
ejbca.sh config protocols enable --name "REST Certificate Management"
ejbca.sh config protocols enable --name "REST Certificate Management V2"
```

**The reader's role (least privilege).** It is proven against EJBCA 9.6.3 by taking each rule away (tests/test_ejbca_live.py). Grant only these rules:

- `/administrator/`: GET `/v1/ca` is refused without it.
- `/ca/<CA>/`: for each CA to inventory; a search of a CA not granted is refused (unknown CA).
- `/ca_functionality/view_certificate/`: without it, every search answers with nothing.
- `/endentityprofilesrules/<end entity profile>/view_end_entity/`: for each end entity profile. Without it, that profile's certificates are left out of every search, silently.

`/ra_functionality/view_end_entity/` isn't needed, and the certificate profile resource needs no rule. Adding `/system_functionality/view_systemconfiguration/` lets the collector read the total count and confirm the reader saw every certificate. Grant it only when the role reads every CA, since the count covers all of them. The role may not revoke, enroll or edit anything. Map the reader's certificate to the role:

```
ejbca.sh roles addrole --role "Inventory Reader"
ejbca.sh roles addrolemember --role "Inventory Reader" --caname <its issuing CA> \
  --with CertificateAuthenticationToken:WITH_COMMONNAME --value <its CN>
ejbca.sh roles changerule --name "Inventory Reader" --rule "/administrator/" --state ACCEPT
...
```

One collection makes at most the core's call bound, 500 certificates a page.

## Known limits

- **CRL, OCSP and CA issuer settings** aren't in EJBCA's REST API: they are CA settings. ConfigDump, which exports them, is Enterprise-only, and needs `/system_functionality/edit_systemconfiguration/`, far more than a reader. The endpoints recorded are the ones the CA's latest active certificate names. A profile that doesn't use the CA's defaults names its own URLs, and those are what's recorded.
- **Who may request from a profile, and what it lets requesters do,** aren't read: subject DN override, approval profiles, the roles allowed to enroll. Community's REST API exposes neither roles nor approval profiles. The templates' rights are unknown, and the template-risk check can't judge them.
- **End entity profiles** are named only in the template's description: Community's REST API has no end entity profile resource (Enterprise's `/v2/endentity` isn't read).
- **A certificate profile nothing was issued from** isn't listed: the REST API lists no profiles.
- **Client certificates only**: Enterprise's OAuth bearer tokens aren't taken yet.
- **Government use**: neither EJBCA Community nor this collector carries a FedRAMP authorization. Keyfactor's FedRAMP Moderate offering is its CLM service (CLAaaS), not EJBCA. Community 9.6 dropped HSM crypto tokens (Enterprise only).

## Tests

- `tests/test_ejbca_inventory.py`: the importer and the collector, without EJBCA.
  - The importer: CAs, endpoints, templates, certificates with and without their data, completeness, the count, external CAs and duplicate names.
  - The collector: rounds, POST bodies, trimming and source problems.
- `tests/test_ejbca_live.py` (marker `ejbca`): a fresh `keyfactor/ejbca-ce:9.6.3` container set up by `tests/ejbca/setup.sh`.
  - Setup: a CA with CRL/OCSP/CA issuer URLs, a profile pair built with EJBCA's own classes (`Profiles.java`), three certificates (one revoked), and the reader with exactly the role above.
  - The collector runs over mutual TLS through the core's runner and the importer reads both CAs complete. The reader is refused a revocation, and without `/ca_functionality/view_certificate/` the root CAs' inventories are denied.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-ejbca/tests`. For the live tests, add `-m ejbca` after `docker pull keyfactor/ejbca-ce:9.6.3`; they take about four minutes.
