# opsdir-adapter-venafi

PKI adapter (kind `pki`, declaration-only) for **CyberArk Certificate Manager – Self-Hosted**, formerly Venafi Trust Protection Platform (TPP); documentation 26.1. Its Web SDK keeps the Venafi paths (`/vedsdk`, `/vedauth`), and so do its tools (vcert, the Terraform provider, the Ansible collection), so the package keeps the Venafi name. It isn't `opsdir-adapter-cyberark`, which reads the CyberArk PAM vault.

It reads a policy folder's certificates into the core pki domain as a **certificate manager's inventory** (`ou=managed-certificates`, `ciamManagedInventory` / `ciamManagedCertificate`, `domains/pki/managed.py`). Metadata only: never a key, never the certificate itself.

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

Everything else in an answer is dropped before anything sees it, including `CustomFields` and `Approver`.

Details are read for at most 1500 certificates per collection, so the pages fit in the core's 2000 calls. A larger folder is exported with the script below, or split into several sources.

A detail that is gone or refused between the listing and its read (404, 403) is nothing to read. Its certificate keeps what the listing says, and the inventory is incomplete. Any other failure fails the collection.

The public certificate is never fetched: `GET /vedsdk/Certificates/Retrieve` needs the `Certificate:Manage` scope and, by its page, Private Key Read.

**Least privilege**:
- **Permissions:** grant the collector's identity **View** and **Read** on the folder. Permissions are inherited by its subfolders and certificates.
- **Applications:** a certificate's associated applications (`Consumers`) show only where the identity has at least View on them.
- **OAuth scope:** register an API Integration with the scope **`certificate`**. It covers the list and detail calls; `certificate:manage` and `configuration` aren't needed.
- **The docs disagree.** The vendor's pages disagree on what listing needs:
  - GET Certificates' introduction says "the caller must have Read permission", but its Requirements say "Read permission and Private Key Read permission".
  - GET Certificates/{guid} says "View permission and Read permission".
  
  Grant Private Key Read only if View and Read are refused. The importer names this when a listing is refused, as the inventory's problem, and the planner turns it into an action.

## Exporting a large folder (`scripts/export-venafi.sh`)

```sh
VENAFI_TOKEN=... scripts/export-venafi.sh venafi-prod https://tpp.example.test/vedsdk '\VED\Policy\Example Aero' ./export
opsdir import --change CHG-... --at 20261017090000Z venafi/certificates ./export
```

The script uses curl and jq, sends GETs only, and writes the same trimmed answers as the collector. The token is read from `VENAFI_TOKEN` and reaches curl as a header on a pipe, never as an argument. `VENAFI_CA` optionally names the trust anchor (PEM); `VENAFI_LIMIT` sets the page size (500).

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
| `ciamManagerContact`, `ciamInstalledAt`, `ciamManagedAuthority` | `Contact` (its identities, e.g. `local:{guid}`), `Consumers` (application DNs), `CertificateAuthorityDN` |
| `ciamManagerProblem` | `ProcessingDetails` in error (`in error at stage <Stage>: <Status>`); a revocation `Pending` or `Failed` |
| `ciamRevokedAt`, `ciamRevocationReason` | `RevocationStatus` `Complete` or `Confirmed`: `RevocationDate`, reason `unspecified` (none is given) |

The inventory's state:
- **denied:** the first page holds an error. The problem says what to grant (above).
- **incomplete:** fewer certificates were listed than `TotalCount`, a page isn't a listing, or some certificates' details weren't read (how each is managed, who it notifies, where it is installed and what is wrong are then unknown).
- **complete:** otherwise.

The record's certificates are reconciled with the inventory by the core (`domains/pki/managed.py`). They are matched by the SHA-1 thumbprint of the PEM the record holds of them, else by serial number and issuer, else by subject and validity. The planner says what is renewed, in error, revoked or disabled, and which certificates for host names the record holds the record lacks; the `managed-certificates` report lists them all.

## Known limits

- **No local validation.** Certificate Manager can't be run here: no instance, trial image or emulator is available.
  - The importer and collector are tested against fixtures shaped as the Web SDK documents its answers.
  - The collector and the script were run end to end only against a local stub answering in those shapes.
  - Before trusting an inventory, run `opsdir collect` once against your instance and compare a few certificates with its console.
- **Permissions are unsettled.** The least privilege isn't settled by the vendor's pages (above): the README's grant is View + Read with the `certificate` scope.
- **Contacts are opaque.** They are Certificate Manager's identities (`local:{guid}`, AD/LDAP identities). They aren't mapped to the record's owners, so they show in the report only.
- **Installations are partial.** `Consumers` are the applications a certificate is associated with. The host:port observations of network validation (`GET /vedsdk/Certificates/{guid}/ValidationResults`) aren't read: deferred.
- **Renewal is inferred.** It is found by subject and issuer: a newer certificate the manager holds for the same subject. The certificate's own history (`GET /vedsdk/Certificates/{guid}/PreviousVersions`) isn't read: deferred.
- **No SaaS.** CyberArk Certificate Manager – SaaS (`api.venafi.cloud` and its regional hosts) isn't read. Its paged inventory is a POST (`/outagedetection/v1/certificatesearch`), and its GET list (`/outagedetection/v1/certificates`) stops at 10000 without paging and has an unverified answer shape: deferred.
- **No government authorization found.** No FedRAMP authorization or government region was found for either Certificate Manager product (CyberArk's FedRAMP High covers Endpoint Privilege Manager and Workforce Identity). That is a research limit, not proof of absence. Check it for your boundary.

## Tests

`tests/test_venafi.py`: the importer and its states, reconciliation with the record, revocation and disabled management from details, the collector's GETs (paging by the total, details within the budget, trimming) and its source problems. They are fixture-based only.
