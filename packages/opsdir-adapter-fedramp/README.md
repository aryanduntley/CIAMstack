# opsdir-adapter-fedramp

opsdir compliance adapter for FedRAMP's machine-readable formats. It reads a cloud offering's **Certification Package Overview** (FRC-CSO-PKG, the JSON schema FedRAMP publishes at <https://www.fedramp.gov/schemas/>) into the record as the authorization the estate relies on (core `estate`: `ciamCloudAuthorization`, under `ou=authorizations`).

**Applies to** no environment: it is declaration-only (`kind: compliance`), renders nothing, and its importer is used directly. The authorizations it imports are what environments name (`ciamAuthorizationRef` on their placement) and what the core's estate checks (level, status, services inside the boundary) read.

**Depends on** `opsdir` (the `estate` domain's authorizations, `opsdir.domains.estate.authorizations`; the import machinery). No third-party libraries.

## What it reads back

| Importer | Reads | Into the record |
|---|---|---|
| `fedramp/cpo` | Package overview JSON files: `serviceIdentification` (`fedRampPackageId`, `serviceName`, `providerName`, `certificationType`), `serviceProperties` (`deploymentModel`; `securityCategorization` when a provider adds it, as AWS's do), `cpoMetadata.lastUpdated`, `certifiedServices[].serviceName` | `cn=<package id>,ou=authorizations` (`ciamCloudAuthorization`, matched by the package id): `ciamPackageId`, `ciamOfferingName`, `ciamProviderName`, `ciamCertificationType`, `ciamDeploymentModel`, `ciamInScopeService` (the services inside the boundary, each once), `ciamScopeAsOf` (`lastUpdated`), `ciamRetrievedAt` (the import's `--at`), and `ciamAuthorizationLevel` when stated |

`opsdir import fedramp/cpo PATH --at <YYYYMMDDhhmmssZ>` (PATH an overview file or a directory of them; `--at` when they were taken, default now) previews the change records; with `--change <change id>` they are applied under that approved change. A JSON object with `serviceIdentification.fedRampPackageId` is an overview; every other file is named in a notice and not read; no overview at all refuses the import.

The level is read from the first word of `securityCategorization`: `Low`, `Moderate`, `High` → `fedramp-low`, `fedramp-moderate`, `fedramp-high` (`High (FedRAMP Certification Level Class D)` → `fedramp-high`); without it, a notice asks the operator to record the level (unless the record already holds one).

On a refresh, what the record adds is kept: status, the level when the overview states none, the CRM reference, required customer configurations, evidence, the provider's partition and anything else the importer doesn't own. Notices name the number of services in scope, the services added since the last import and those no longer in scope. Importing the same overview again changes nothing. The importer never sets `ciamSourceUrl`: record where the file came from by hand.

AWS publishes its offerings' overviews on its FedRAMP page (AWS US East/West `AGENCYAMAZONEW`, Class C Moderate; AWS GovCloud (US) `F1603047866`, Class D High; research 2034). FedRAMP requires a package overview of every certified offering (20x from 2026-07-04, Rev5 from 2027-01-01); until a provider publishes one, record its authorization by hand (as LDIF).

It adds no renders, planner checks, required roles, reference schemes, vocabulary, schema or secret patterns: the classes and attributes it writes, and the checks that read them, are the core `estate` domain's.

## Known limits

- The schema states no level or status: the importer reads a provider's `securityCategorization` extension, else the operator records them (from the FedRAMP Marketplace listing). DoD impact levels (`dod-il2`, `il4`, `il5`) are never read: a DoD provisional authorization is recorded by hand.
- The customer responsibility matrix (CIS/CRM workbook) isn't read yet: no column layout is published; operators record control responsibilities (`ciamControlResponsibility`) by hand until a workbook is available to map.
- Not validated against providers other than AWS's published overviews.

## Tests

`tests/test_fedramp_cpo.py`: reading an overview as an authorization with its services and level, a refresh keeping the record's own attributes and naming services added and removed, refusal of files with no overview, the import time given as a datetime, and importing the same overview again changing nothing (the adapter renders nothing, so this is its round-trip guarantee instead of a read-back).

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-fedramp/tests`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `fedramp`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
