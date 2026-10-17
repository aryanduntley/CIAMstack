# opsdir-adapter-venafi

PKI adapter (kind `pki`, declaration-only) for **CyberArk Certificate Manager – Self-Hosted**, formerly Venafi Trust Protection Platform (TPP); documentation 26.1, and **CyberArk Certificate Manager – SaaS**, formerly Venafi TLS Protect Cloud ([below](#certificate-manager--saas-importer-venafisaas)). Their APIs keep the Venafi paths and hosts (`/vedsdk`, `/vedauth`, `api.venafi.cloud`), and so do their tools (vcert, the Terraform provider, the Ansible collection), so the package keeps the Venafi name. It isn't `opsdir-adapter-cyberark`, which reads the CyberArk PAM vault.

It reads a policy folder's (or a SaaS tenant's) certificates into the core pki domain as a **certificate manager's inventory** (`ou=managed-certificates`, `ciamManagedInventory` / `ciamManagedCertificate`, `domains/pki/managed.py`). Metadata only: never a key, never the certificate itself.

A certificate manager isn't a CA's issuance record. It holds what it discovered on the networks it scans, what it was given, and what it enrolls itself. So a certificate it doesn't hold isn't missing anywhere: the record's certificates it lacks are `not-managed`, never `confirmed-missing`, even when its inventory is complete. A complete inventory says only that the folder was listed in full.

## What it renders

Nothing.

## Collecting a folder (`opsdir collect`, collector `certificates`)

An environment's `ciamCollectionSource` with `ciamImporter: venafi/certificates` names one policy folder; its subfolders are included:

```ldif
dn: cn=venafi-prod,ou=bindings,env=ENV,cloud=CLOUD,ou=environments,dc=ciam-ops
objectClass: ciamCollectionSource
ciamBindingRole: venafi-prod
ciamImporter: venafi/certificates
ciamSourceRef: https://tpp.example.test/VED/Policy/Example Aero
ciamCredentialRole: venafi-reader
ciamCredentialScheme: bearer
ciamCaRole: tpp-ca
```

`ciamSourceRef` is `https://<host>[:<port>]/<folder path>`: the folder's DN with `/` for `\` (`\VED\Policy\Example Aero`). The Web SDK is read at `https://<host>[:<port>]/vedsdk`.

The credential is an OAuth access token. It is the reference the `venafi-reader` role binds, resolved when collecting, never stored, and sent as `Authorization: Bearer`. Certificate Manager issues tokens only by POST: `/vedauth/authorize/oauth` (username and password), `/vedauth/authorize/certificate` (a client certificate) or `/vedauth/authorize/integrated` (Windows). opsdir never POSTs, so getting the token, and refreshing it before it expires, is the operator's. Keep it in the store the reference points at.

`ciamCaRole` is the CA certificate the Web SDK's TLS certificate is trusted by. Without it, the system's trust store is used.

| Call (GET only) | Saved as (under `venafi/<source>/`) |
|---|---|
| `/vedsdk/certificates/?ParentDnRecursive=<folder>&Limit=500&Offset=<n>&OptionalFields=Issuer,Subject` | `certificates-<n>.json`: the first page, then every page its `TotalCount` says there is. Each page holds `DN`, `Guid`, `Name`, `ParentDn`, `SchemaClass`, `CreatedOn` and `X509` (`CN`, `Issuer`, `Subject`, `Serial`, `Thumbprint`, `ValidFrom`, `ValidTo`, `SANS`), with the folder and address |
| `/vedsdk/certificates/{<guid>}` | `details/<guid>.json`: `ManagementType`, `Disabled`, `CreatedBy`, `Contact`, `Consumers`, `CertificateAuthorityDN`, `ProcessingDetails` (`InError`, `InProcess`, `Stage`, `Status`) and `CertificateDetails` (issuer, subject, serial, thumbprint, validity, alternative names, `RevocationStatus`, `RevocationDate`) |
| `/vedsdk/certificates/{<guid>}/PreviousVersions` | `history/<guid>.json`: each earlier version's `VaultId` and `CertificateDetails` (thumbprint, serial, subject, issuer, `CN`, DNS and IP alternative names, validity) |
| `/vedsdk/certificates/{<guid>}/ValidationResults` | `validation/<guid>.json`: where SSL/TLS network validation found it (`SslTls`: `Host`, `IpAddress`, `Port`); `{"SslTls": [], "Validated": false}` when it answers HTTP 204 (no network validation ran) |

Everything else in an answer is dropped before anything sees it, including `CustomFields` and `Approver`.

The three reads per certificate share one budget of 1500 calls per collection, so the pages fit in the core's 2000 calls: details for every listed certificate first (up to 1500), then the previous versions and validation results of as many as the rest allows, in listing order. Up to 500 certificates are read in full; what isn't read leaves the inventory incomplete, with an action naming the script below (which reads all of it), or split the folder into several sources.

A detail, history or validation result that is gone or refused between the listing and its read (404, 403) is nothing to read. Its certificate keeps what the rest says, and the inventory is incomplete. Any other failure fails the collection.

The public certificate is never fetched: `GET /vedsdk/Certificates/Retrieve` needs the `Certificate:Manage` scope and, by its page, Private Key Read.

**Least privilege**:
- **Permissions:** grant the collector's identity **View** and **Read** on the folder. Permissions are inherited by its subfolders and certificates.
- **Applications:** a certificate's associated applications (`Consumers`) show only where the identity has at least View on them.
- **OAuth scope:** register an API Integration with the scope **`certificate`**. It covers the list, detail, `PreviousVersions` and `ValidationResults` calls (each documents View and Read with that scope); `certificate:manage` and `configuration` aren't needed.
- **The docs disagree.** The vendor's pages disagree on what listing needs:
  - GET Certificates' introduction says "the caller must have Read permission", but its Requirements say "Read permission and Private Key Read permission".
  - GET Certificates/{guid} says "View permission and Read permission".
  
  Grant Private Key Read only if View and Read are refused. The importer names this when a listing is refused, as the inventory's problem, and the planner turns it into an action.

## Exporting a large folder (`scripts/export-venafi.sh`)

```sh
VENAFI_TOKEN=... scripts/export-venafi.sh venafi-prod https://tpp.example.test/vedsdk '\VED\Policy\Example Aero' ./export
opsdir import --change CHG-... --at 20261017090000Z venafi/certificates ./export
```

The script uses curl and jq, sends GETs only, and writes the same trimmed answers as the collector (details, previous versions and validation results of every certificate, with no budget). The token is read from `VENAFI_TOKEN` and reaches curl as a header on a pipe, never as an argument. `VENAFI_CA` optionally names the trust anchor (PEM); `VENAFI_LIMIT` sets the page size (500).

A refused listing (401 or 403) is written as the first page's `Error`, so the import records the inventory as `denied`, with what to grant.

## Reading the folder (importer `venafi/certificates`)

A source is one inventory: `cn` is its name, `ciamInventoryPrefix` the folder and `ciamProviderRef` the Web SDK's address. Each certificate's `cn` is its GUID (no braces, lowercase).

| Record | From |
|---|---|
| `ciamSerialNumber`, `ciamSubject`, `ciamIssuer`, `ciamNotBefore`, `ciamNotAfter` | `X509` (`Subject` and `Issuer` through `OptionalFields`), else `CertificateDetails` (which wins when read) |
| `ciamThumbprint` | `Thumbprint`: SHA-1. The Web SDK gives no SHA-256 |
| `ciamCertificateName` | the common name and `SANS` DNS and IP names (wildcards kept) |
| `ciamManagerPath` | `DN` (where it is filed) |
| `ciamManagement` | `ManagementType`: Unassigned → `unassigned`, Monitoring → `monitored`, Enrollment → `enrolled`, Provisioning → `provisioned` (another value is left out and named) |
| `ciamObjectState` | `disabled` when `Disabled`, else `active` (details read) |
| `ciamManagedOrigin` | `discovered` when `CreatedBy` names a discovery (Network, Agent, Onboard Discovery, Web SDK Discovery/Import), else `added` |
| `ciamManagerContact`, `ciamInstalledAt`, `ciamManagedAuthority` | `Contact` (its identities, e.g. `local:{guid}`), `Consumers` (application DNs) then `ValidationResults`' `host:port` (its IP address when no host is named), `CertificateAuthorityDN` |
| `ciamManagerProblem` | `ProcessingDetails` in error (`in error at stage <Stage>: <Status>`); a revocation `Pending` or `Failed` |
| `ciamRevokedAt`, `ciamRevocationReason` | `RevocationStatus` `Complete` or `Confirmed`: `RevocationDate`, reason `unspecified` (none is given) |

Each earlier version a certificate's `PreviousVersions` holds is a certificate of the inventory too (cn `<guid>-v<VaultId>`), with what the history says of it (serial, thumbprint, subject, issuer, validity, names) and `ciamRenewedAs` the certificate's GUID. The documentation says "the most current version appears first" without settling whether the current version is in the list, so a version with the listed certificate's own thumbprint is left out. A record certificate matching an earlier version is renewed exactly as the certificate that replaced it; an earlier version is never in service, so it is never unrecorded.

The inventory's state:
- **denied:** the first page holds an error. The problem says what to grant (above).
- **incomplete:** fewer certificates were listed than `TotalCount`, a page isn't a listing, or some certificates' details, previous versions or validation results weren't read (how each is managed, what it replaced, who it notifies, where it is installed and what is wrong are then unknown).
- **complete:** otherwise.

The record's certificates are reconciled with the inventory by the core (`domains/pki/managed.py`). They are matched by the SHA-1 thumbprint of the PEM the record holds of them, else by serial number and issuer, else by subject and validity. The planner says what is renewed, in error, revoked or disabled, and which certificates for host names the record holds the record lacks; the `managed-certificates` report lists them all.

## Known limits

- **No local validation.** Certificate Manager can't be run here: no instance, trial image or emulator is available.
  - The importer and collector are tested against fixtures shaped as the Web SDK documents its answers.
  - The collector and the script were run end to end only against a local stub answering in those shapes (the script's `PreviousVersions` and `ValidationResults` reads, HTTP 204 included).
  - No SaaS tenant could be reached either: the SaaS collector ran only through the core's collection with answers in the documented shape (pages from 0, the page past the count empty).
  - Before trusting an inventory, run `opsdir collect` once against your instance and compare a few certificates with its console.
- **Permissions are unsettled.** The least privilege isn't settled by the vendor's pages (above): the README's grant is View + Read with the `certificate` scope.
- **Contacts are opaque.** They are Certificate Manager's identities (`local:{guid}`, AD/LDAP identities). They aren't mapped to the record's owners, so they show in the report only.
- **Installations are what Certificate Manager knows.** `Consumers` are the applications a certificate is associated with; `ValidationResults` adds where network validation last found it (`File` validation results aren't read). A certificate no validation ran on has only its applications.
- **Renewal is exact only with a history.** Where `PreviousVersions` wasn't read (beyond the budget), renewal is inferred by subject and issuer: a newer certificate the manager holds for the same subject.
- **SaaS facts are partly unverified.** See [the SaaS section](#certificate-manager--saas-importer-venafisaas): the page size limit, whether `count` is the total, the `versionType` and `certificateStatus` values beyond `CURRENT` and `ACTIVE`, and the owner, contact and revocation fields aren't settled by the vendor's pages.
- **No government authorization found.** No FedRAMP authorization or government region was found for either Certificate Manager product (CyberArk's FedRAMP High covers Endpoint Privilege Manager and Workforce Identity). That is a research limit, not proof of absence. Check it for your boundary.

## Certificate Manager – SaaS (importer `venafi/saas`)

An environment's `ciamCollectionSource` with `ciamImporter: venafi/saas` names one tenant by its regional API address; one inventory holds every certificate the identity can read:

```ldif
dn: cn=Example Aero SaaS,ou=bindings,env=ENV,cloud=CLOUD,ou=environments,dc=ciam-ops
objectClass: ciamCollectionSource
ciamBindingRole: Example Aero SaaS
ciamImporter: venafi/saas
ciamSourceRef: https://api.venafi.cloud
ciamCredentialRole: venafi-saas-reader
ciamCredentialScheme: api-key
```

`ciamSourceRef` is the tenant's API address, with no path: `https://api.venafi.cloud` (US), `https://api.eu.venafi.cloud`, `https://api.au.venafi.cloud`, `https://api.uk.venafi.cloud`, `https://api.sg.venafi.cloud` or `https://api.ca.venafi.cloud`. **The vendor's pages disagree on the EU host:** the API introduction ([developer.venafi.com](https://developer.venafi.com/tlsprotectcloud/reference/tls-protect-overview)) and the VSatellite network page ([docs.venafi.cloud](https://docs.venafi.cloud/vsatellite/r-VSatellite-deployNew-network-connections/)) say `api.eu.venafi.cloud`; vcert's README ([README-CLI-CLOUD.md](https://github.com/Venafi/vcert/blob/master/README-CLI-CLOUD.md)) says `api.venafi.eu`. Both are accepted; use the one your tenant's console shows. No government (FedRAMP) region was found.

The credential is the reference the role binds, resolved when collecting, never stored:
- **`api-key`:** a user API key, sent as the `tppl-api-key` header. Give the user the **Guest** role: read-only access to certificates, requests, TLS endpoints and applications ([user roles](https://docs.venafi.cloud/vaas/user-management/about-user-roles/)). Whether Guest sees every certificate or only its teams' isn't settled by that page: compare the count with the console.
- **`bearer`:** a service account's access token, sent as `Authorization: Bearer`. It lasts 15 minutes and is issued by the token endpoint the service account shows ([service accounts](https://docs.venafi.cloud/vcs-platform/serviceaccounts/t-service-accounts-create-API-integration/)); getting it is the operator's, outside opsdir.

| Call | Saved as (under `venafi-saas/<source>/`) |
|---|---|
| `POST /outagedetection/v1/certificatesearch?excludeSupersededInstances=true` with `{"paging": {"pageNumber": n, "pageSize": 50}}` | `search-<n>.json`: page 0, then every page up to the one past the end its `count` says (it should be empty). Each holds `count` and per certificate `id`, `managedCertificateId`, `versionType`, `certificateStatus`, `fingerprint`, `serialNumber`, `subjectCN`, `subjectDN`, `issuerDN`, `validityStart`, `validityEnd`, `certificateSource`, the DNS and IP alternative names and its `instances` (`hostname`, `ipAddress`, `port`, `deploymentStatus`), with the address and page size |

The search is a POST because its criteria don't fit a URL. It changes nothing; the collector declares it its only read-only query, and the core refuses any other POST. Pages count from 0 and hold 50 certificates, as vcert asks them ([search.go, connector.go](https://github.com/Venafi/vcert/tree/master/pkg/venafi/cloud)); the vendor documents no maximum page size, and its search page shows page 0 in its example while its prose counts from 1 ([searching for certificates](https://docs.venafi.cloud/api/searching-for-certificates/)). No expression is sent (every certificate). The page past the count's end is read so a `count` that isn't the total (no page says) shows: certificates on it leave the inventory incomplete.

| Record | From |
|---|---|
| cn | `id` (lowercase) |
| `ciamThumbprint` | `fingerprint`: SHA-1 (vcert computes it as `sha1.Sum` of the DER, uppercase hex: [cloud.go](https://github.com/Venafi/vcert/blob/master/pkg/venafi/cloud/cloud.go)) |
| `ciamSerialNumber`, `ciamSubject`, `ciamIssuer`, `ciamNotBefore`, `ciamNotAfter` | `serialNumber`, `subjectDN` (else `CN=` its first `subjectCN`), `issuerDN`, `validityStart`, `validityEnd` |
| `ciamCertificateName` | `subjectCN` and the `dNSName` and `iPAddress` alternative names |
| `ciamObjectState` | `certificateStatus`: `ACTIVE` → `active`, `RETIRED` → `disabled` (the tenant no longer watches it), `DELETED` → `deleted`; another value is left out |
| `ciamManagedOrigin` | `certificateSource`: a scan (`USER_SCAN`, anything naming a scan or discovery) → `discovered`, else `added` |
| `ciamInstalledAt` | each instance not `SUPERSEDED`: `hostname:port` (its IP address when no host name) |
| `ciamRenewedAs` | a `versionType` `OLD` certificate: the `id` of the `CURRENT` one with the same `managedCertificateId`, so the record's certificate matching it is renewed exactly |

Left unset: `ciamManagement`, `ciamManagerContact`, `ciamManagerPath`, `ciamManagerAction` and revocation. The search's owner, contact and revocation fields aren't named by the vendor's pages that could be read (the OpenAPI wasn't reachable), so nothing is guessed. Certificates are matched with the record as Self-Hosted's are, by the SHA-1 of the record's PEM, serial and issuer, or subject and validity. That `versionType` values other than `CURRENT` and `OLD` exist, and that renewals keep their `managedCertificateId`, is shown by the examples and vcert's struct, not stated: `OLD` is the only value read as an earlier version.

The inventory is **denied** when the first page holds an `Error` (the search was refused; what to grant is named), **incomplete** when a page isn't a search answer or is missing, fewer certificates were found than `count`, or the page past the count holds certificates, else **complete**.

## Tests

`tests/test_venafi.py`: the importer and its states, reconciliation with the record (exact renewal through `PreviousVersions`, inferred without it), revocation and disabled management from details, validation results as installations, the collector's GETs (paging by the total, details then history and validation within the shared budget, trimming, HTTP 204) and its source problems. `tests/test_venafi_saas.py`: the SaaS importer (facts, earlier versions renewed exactly, the count and the page past it, denied) and its collector (only the declared search POST, paged from 0 past the count, API key or bearer, trimming, source problems). They are fixture-based only.
