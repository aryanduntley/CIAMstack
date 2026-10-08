# opsdir-adapter-fedramp

A compliance adapter for FedRAMP's machine-readable formats. It reads a cloud offering's **Certification Package
Overview** (FRC-CSO-PKG, the JSON schema FedRAMP publishes at <https://www.fedramp.gov/schemas/>) into the record as
the authorization the estate relies on (core `estate`: `ciamCloudAuthorization`, under `ou=authorizations`). It is
declaration-only: it renders nothing and applies to no environment; its importer is used directly.

Depends on: the opsdir core (`estate` domain).

## What it reads

| Importer | Reads | Into the record |
|---|---|---|
| `fedramp/cpo` | Package overview JSON files (`opsdir import fedramp/cpo FILE ... --at <when taken>`): `serviceIdentification` (`fedRampPackageId`, `serviceName`, `providerName`, `certificationType`), `serviceProperties` (`deploymentModel`; `securityCategorization` when a provider adds it, as AWS's do: `High (FedRAMP Certification Level Class D)` → `fedramp-high`), `cpoMetadata.lastUpdated`, `certifiedServices[].serviceName` | `cn=<package id>,ou=authorizations`: `ciamPackageId`, `ciamOfferingName`, `ciamProviderName`, `ciamCertificationType`, `ciamDeploymentModel`, `ciamInScopeService` (the services inside the boundary), `ciamScopeAsOf`, `ciamRetrievedAt` (the import's `--at`), `ciamAuthorizationLevel` when stated. What the record adds (status, level when the overview states none, the CRM reference, required customer configurations, evidence, the provider and partition) is kept on a refresh; the notices name services added and no longer in scope. Files that aren't package overviews are named and not read; none at all refuses the import |

AWS publishes its offerings' overviews on its FedRAMP page (AWS US East/West `AGENCYAMAZONEW`, Class C Moderate; AWS
GovCloud (US) `F1603047866`, Class D High). FedRAMP requires a package overview of every certified offering (20x from
2026-07-04, Rev5 from 2027-01-01); until a provider publishes one, record its authorization by hand.

## Known limits

- The schema states no level or status: the importer reads a provider's `securityCategorization` extension, else the
  operator records them (from the FedRAMP Marketplace listing).
- The customer responsibility matrix (CIS/CRM workbook) isn't read yet: no column layout is published; operators record
  control responsibilities (`ciamControlResponsibility`) by hand until a workbook is available to map.
- Not validated against providers other than AWS's published overviews.

## Tests

`tests/test_fedramp_cpo.py`: reading an overview, a refresh keeping the record's own attributes, refusal of files with
no overview.
