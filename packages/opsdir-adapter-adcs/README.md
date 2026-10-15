# opsdir-adapter-adcs

opsdir adapter for Microsoft Active Directory Certificate Services (AD CS): each certification authority's issued-certificate inventory, its revocation endpoints and the forest's certificate templates read into the record's PKI (the core `pki` domain), metadata only. A PKI adapter (kind `pki`), declaration-only: it renders nothing and owns no reference scheme. Never a private key: no archived-key column is ever selected or read.

**Applies to** no environment by itself (`applies` is `None`): its importer is used wherever the estate's certificates come from AD CS.

**Depends on** `opsdir`. Producing the export needs a Windows host that reaches the CA, Windows PowerShell 5.1 or PowerShell 7, and the CA's **Read** permission (below).

## What it renders

Nothing. No vocabulary, schema, secret patterns, required roles, collectors or planner checks of its own: the reconciliation and its planner check are the core `pki` domain's (opsdir/README.md, Certification authorities and issued certificates).

## Inventory (importer `adcs/inventory`, metadata only)

`opsdir import --change CHG-… --at YYYYMMDDhhmmssZ adcs/inventory DIR` reads:

| File | What it is |
|---|---|
| `ca/<CA name>.json` | One CA's export, written on the CA host by `scripts/Export-AdcsInventory.ps1` (one file per CA) |
| `templates.ldif` | The forest's certificate templates: `ldifde -f templates.ldif -d "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<forest DN>" -r "(objectClass=pKICertificateTemplate)" -l cn,displayName,msPKI-Cert-Template-OID,pKIExtendedKeyUsage,pKIExpirationPeriod`, or the same search with `ldapsearch` (RFC 2849). Optional: without it, the record's templates resolve what the CAs say |

Into the record:

- `ou=certificate-authorities`: per CA a `ciamCertAuthority` (cn: the CA's name; `ciamProviderRef` its configuration string `COMPUTERNAME\CANAME`; `ciamTemplateName` the templates it issues from), with its revocation endpoints as children (`ciamRevocationEndpoint`, cn `<kind>-<n>`). The operator's own attributes (`ciamCaCertificate`, owners) are kept.
- `ou=issued-certificates`: per CA a `ciamCertInventory` (taken at the export's `exportedAt`, else `--at`; complete, incomplete with why, or denied) and a `ciamIssuedCertificate` per issued or revoked certificate (cn: its request id).
- `ou=certificate-templates` (when `templates.ldif` is there): a `ciamCertTemplate` per template, the whole branch replaced by the forest's list (the operator's `ciamCertPurpose` and `ciamRenewalOwner` kept).

### The export contract (`opsdir-adcs-inventory`, version 1)

This adapter's own JSON, written by the exporter; the importer reads nothing else from the CA. `certutil` text output (`-view csv`, `-getreg`, `-CATemplates`) isn't read: Microsoft documents no serialization for it (header labels, localization, date and time zone, number forms and quoting are unspecified).

| Field | Meaning |
|---|---|
| `format`, `version` | `opsdir-adcs-inventory`, `1`: anything else is left out with a notice |
| `exporter` | The exporter's name and version |
| `exportedAt` | When the export was taken: UTC ISO 8601 with `Z` |
| `config`, `caName`, `dnsName`, `netbiosName` | The CA's configuration string, its name, its host's DNS and NetBIOS names (what fills `%1`, `%2`, `%3`) |
| `complete` | `true` when the exporter read every row; otherwise the inventory is incomplete |
| `error` | The exporter's error (the CA refused it, or COM failed), or `null`: an error makes the inventory denied |
| `templates` | `ICertAdmin2::GetCAProperty(CR_PROP_TEMPLATES)`'s lines: template names and OIDs, each resolved to a template's name (by `cn`, `displayName` or `msPKI-Cert-Template-OID`), else kept as it is |
| `crlPublicationUrls`, `caCertPublicationUrls` | The `CRLPublicationURLs` and `CACertPublicationURLs` registry entries as the CA stores them: `"<decimal flags>:<path or URL template>"` |
| `rows` | One object per certificate the CA issued (`Request.Disposition` 20) or revoked (21), under the CA database's schema names: `RequestID`, `SerialNumber`, `NotBefore`, `NotAfter`, `CertificateTemplate`, `Request.RequesterName`, `Request.Disposition`, `Request.RevokedWhen`, `Request.RevokedEffectiveWhen`, `Request.RevokedReason`; and `SHA256` and `Subject`, computed from the public `RawCertificate` |

Values: times UTC ISO 8601 with `Z` (a time without a zone is refused: the row's problem leaves the inventory incomplete), integers decimal, nothing as JSON `null`, strings as the CA holds them (a serial keeps its leading zeros). A UTF-8 byte order mark (Windows PowerShell 5.1 writes one) is ignored.

Per row: `ciamSerialNumber`, `ciamFingerprint` (the SHA-256, as colon-separated hex), `ciamSubject`, `ciamNotBefore`, `ciamNotAfter`, `ciamTemplateName` (the template's name when the CA recorded a name, display name or OID the templates know, else its value as it is), `ciamRequester`; a revoked row also `ciamRevokedAt` (`Request.RevokedEffectiveWhen`, the time the revocation takes effect, which may be back- or future-dated; else `Request.RevokedWhen`, when the CA processed it) and `ciamRevocationReason` (the RFC 5280 name of codes 0-6 and 8-10; any other value, Microsoft's `-1` / `0xffffffff` release from hold among them, as it is; `unrecorded` when the CA gave none). A row with no request id, or a disposition other than 20 or 21, isn't recorded and leaves the inventory incomplete. A column outside the list is named in a notice and not read; an archived-key column (`RawArchivedKey`, `KeyRecoveryHashes`) is named as never read.

**Revocation endpoints**: the flags (Microsoft's `CSURL_*`) are read in the context of the registry value holding them. In `CRLPublicationURLs`, `0x02` puts the location in issued certificates' CRL distribution points (`crl`) and `0x04` in their freshest CRL (`delta-crl`); in `CACertPublicationURLs`, `0x02` puts it in their authority information access as CA issuers (`ca-issuers`) and `0x20` as OCSP (`ocsp`). Other flags (publish `0x01`, CRL CDP `0x08`, retry `0x10`, delta publish `0x40`, IDP `0x80`) put nothing in issued certificates. An entry is split at its first colon (paths and URLs hold more). Variables filled: `%1` the DNS name, `%2` the NetBIOS name, `%3` the CA's name, `%8` empty (the first CRL key) and `%9` (empty in a CRL location, `+` in a delta CRL one); any other variable stays, and the CA's template is kept with the endpoint (`description`) and named in a notice.

**Templates** from `templates.ldif`: `cn`, `displayName` (`description`), `msPKI-Cert-Template-OID` (`ciamTemplateOid`), `pKIExtendedKeyUsage` (`ciamExtendedKeyUsage`) and `pKIExpirationPeriod` (`ciamMaxValidityDays`): 8 bytes (base64 after `::` in LDIF), a negative interval of 100-nanosecond units, signed little-endian; one that isn't 8 bytes, isn't negative or isn't a whole number of days is left out with a notice, never rounded. Folded lines are joined and base64 values decoded (RFC 2849).

### The exporter (`scripts/Export-AdcsInventory.ps1`)

```powershell
.\Export-AdcsInventory.ps1 -Config "PKI-ISS-02\Example Aero Issuing CA 2" -OutFile ".\ca\Example Aero Issuing CA 2.json"
```

It uses only Microsoft's documented COM interfaces: `ICertView` (`CertificateAuthority.View`: `OpenConnection` with the configuration string, `GetColumnIndex` and `SetResultColumn` by schema name, `SetRestriction` on `Request.Disposition` from 20 to 21, `OpenView`, and each row's `IEnumCERTVIEWCOLUMN.GetName` / `GetValue`, typed values) for the database, and `ICertAdmin2` (`CertificateAuthority.Admin`: `GetConfigEntry` for the two publication URL values, `GetCAProperty` for `CR_PROP_TEMPLATES`) for the configuration. It selects only the columns above and `RawCertificate`, from which it computes the SHA-256 and subject and which it doesn't write. `-DnsName` and `-NetbiosName` default to the host's FQDN and the configuration string's computer name. `certutil -config "HOST\CA" -schema` lists the columns a CA's database has.

**Least privilege**: the CA's **Read** permission is enough to open the database view (MS-CSRA: Administrator, Officer or Read; Issue and Manage Certificates isn't needed), with RPC/DCOM to the CA from the host running it. Templates are readable by Authenticated Users by default; the actual template ACLs govern.

## Known limits

- **The exporter has not been run against a CA** (opsdir is developed without Windows): the importer is tested on its contract only. Before relying on it, the CA team reviews it, runs it once and compares a few rows with `certutil -gmt -view`: the request ids, serials, validity times (the exporter takes the COM `DATE` values as UTC, as the database's CERTTIME is; that the view doesn't convert them to local time is unverified), the template values, and the revocation times and reasons. Also unverified there: the `GetValue` flag it uses for binary columns (`CV_OUT_BASE64`, 0x1), the value of `CR_PROP_TEMPLATES` (0x1d) and the layout of its answer (taken as one template name or OID per line), and that `GetConfigEntry` returns the multi-string values as arrays.
- **`%1` and `%2`**: MS-CSRA's table for CA certificate publication URLs gives `%1` as the NetBIOS name and `%2` as the DNS name, the reverse of its CRL table and of Windows Server's guidance; the importer follows Windows Server's guidance (`%1` DNS, `%2` NetBIOS) and fills them only from the exporter's explicit `dnsName` and `netbiosName`. `%3` is filled with the CA's name as it is: the CA's own encoding of it in URLs (a sanitized name, spaces as `%20`) isn't reproduced. `%4`, `%6`, `%7`, `%10` and `%11` aren't filled (the endpoint keeps the CA's template). What `CSURL_PUBLISHRETRY` (0x10) does isn't documented; it adds no endpoint.
- **`pKIExpirationPeriod`'s sign convention** (a negative interval) is derived from Microsoft's default template values (`00 40 39 87 2E E1 FE FF` = 365 days), not stated by MS-CRTD, which says only that it initializes a FILETIME.
- **Revocation**: `ciamRevokedAt` is the effective time, which the CA lets an officer date ahead or back and change by another revocation: a certificate whose revocation takes effect after the day evaluated is revocation-scheduled (an action), not revoked. A row the CA holds as revoked with reason `-1` (released from hold) is still recorded as revoked, as its disposition says; how a CA records a release from hold isn't verified. MS-CSRA's reason table omits RFC 5280's 9 and 10, which certutil's reference lists: both are read as RFC 5280 names.
- **An exporter error is recorded as denied**, whatever it was (access refused, the CA unreachable, COM not registered): its message is the inventory's problem.
- **Completeness** is the exporter's: a CA whose database was cleaned of old rows (`certutil -deleterow`) no longer lists them, so a record certificate issued before the cleanup reads as confirmed missing.
- **`templates.ldif` replaces `ou=certificate-templates` whole**: it is taken as the forest's complete template list; templates recorded by hand for another CA product leave the record when an AD CS import carries templates (import without `templates.ldif` to keep them).
- **Not covered yet** (follow-up milestone): collecting the templates over LDAP (`opsdir collect`), observing the CRLs and OCSP responders themselves (reachable, current, signed), template risk (an enrollee supplying the subject, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 0x1, with client authentication and broad enrollment rights: ESC1-style), and other CAs (Venafi, EJBCA, cloud private CAs).

## Tests

`tests/test_adcs_inventory.py`: registration through the entry point (kind `pki`, declaration-only), a CA export read into its authority, endpoints (flags, filled and unfilled variables) and inventory (serial with leading zeros, template by OID, revoked row's effective time, reason and fingerprint), templates from LDIF (base64 display name, validity decoded, a fraction of a day refused), unreadable rows (a time without a zone, an unknown disposition, no request id) leaving the inventory incomplete, an archived-key column never read, denied and partial exports, a byte order mark, and a revoked record certificate reconciled through the core.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-adcs/tests`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `adcs`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
