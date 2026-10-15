# opsdir-format-oscal

OSCAL for opsdir: the record's plan of action and milestones, system security plans and assessment results written as NIST's [Open Security Controls Assessment Language](https://pages.nist.gov/OSCAL/) (OSCAL) JSON, and OSCAL POA&Ms, assessment results and catalogs read back. Written against **OSCAL 1.2.3** (`OSCAL_VERSION`); the readers accept any OSCAL 1.x.

**Applies to** no environment by itself. It registers:

| What | Name | Entry point |
|---|---|---|
| Format | `oscal-json`: OSCAL (JSON), `application/json`, `.json`, no comments | `opsdir.formats` |
| Adapter | `oscal`, kind `compliance`, declaration-only: it renders only where a stack declares it | `opsdir.adapters` |

The record it reads is the core `estate` domain's: system boundaries (`ciamSystemBoundary`, `ou=boundaries`), POA&M items (`ciamPoamItem`, `ou=poam`), exceptions (`ciamRiskException`), compliance assessments (`ciamComplianceAssessment`), cloud authorizations and their control responsibilities (`ciamControlResponsibility`). The package defines no schema of its own.

## What it writes

The writers are pure functions of the record, each returning an `OscalDoc` (the document, and the render notes naming what it holds UNBOUND):

| Writer | OSCAL model | From the record |
|---|---|---|
| `poam_document(d, boundary, as_of=None)` | `plan-of-action-and-milestones` | The POA&M items naming an environment inside the boundary: one `poam-item` each (weakness, controls, risk rating, points, how and when found, vendor dependency, environments as opsdir properties) and one `risk` each (`open` or `closed`, `deadline` = `ciamScheduledCompletion`, a planned `remediation` whose tasks are its `ciamMilestone`s, dated ones `on-date`). The boundary's requested and approved exceptions are `deviation-requested` / `deviation-approved` risks (`deadline` = `ciamExpiresAt`), related to the items they belong to (`ciamPoamRef`); rejected and withdrawn ones are left out. `system-id` is the boundary's `ciamSspRef`, else its name. Refused when no item names the boundary's environments (OSCAL requires one). |
| `ssp_document(d, boundary, as_of=None)` | `system-security-plan` | The system (its SSP id and version as `metadata.version`, the environments inside the boundary), a `this-system` component and one component per cloud authorization its environments rely on (`ciamAuthorizationRef`), and one `implemented-requirement` per control the authorizations' control responsibilities name: `by-components` on the provider's component when inherited, on both when shared, on the system when the customer's (its `ciamImplementation`, else the exception or POA&M item covering it with status `alternative` / `planned`, else the `ciamCustomerAction`). Refused when no responsibility applies. |
| `assessment_results_document(d, assessment, as_of=None, evidence=())` | `assessment-results` | One `result`: framework, assessment kind, score, maximum, status and environments as opsdir properties, `start` = `ciamAssessedAt`, all controls reviewed; its `findings` the assessment's open POA&M items (`ciamAssessmentRef` = the assessment's name or its own reference), `not-satisfied`, each targeting its first control. `evidence` (`((path, sha256), ...)`, an evidence package's MANIFEST) and the assessment's `ciamEvidenceRef` are `back-matter` resources (files with their SHA-256). |

Every document is the same every time it is written from the same record: UUIDs are version 5 of the entries' DNs, arrays are sorted, and `last-modified` is the latest date the documented entries hold (reviewed, found, approved; an authorization's scope; when assessed), else the `as_of` day given, else 1970-01-01, never the time of writing. `metadata.version` is the boundary's `ciamSspRef` for an SSP, else `last-modified`.

What OSCAL needs that the record doesn't carry goes in opsdir properties (namespace `urn:opsdir:oscal`): `record-dn` (the entry a part was written from, which the readers match back), `control` (the record's control ref), `risk-rating`, `points`, `discovery-source`, `discovered`, `vendor-dependency`, `environment`, `exception-kind`, `compensating-control`, `responsibility`, `framework`, `assessment-kind`, `score`, `max-score`, `assessment-status`.

**UNBOUND, never invented.** A field OSCAL requires that the record doesn't hold is written `UNBOUND:<what>` and named in a render note (severity `action`, for the owner of the boundary or assessment): each risk's `statement` (the impact on the system), an exception's description without `ciamJustification`, the SSP's `import-profile` href, its information types and operational status, the assessment results' `import-ap` (the assessment plan).

**Control ids.** `framework:control` refs become OSCAL control ids: SP 800-53's (`nist-800-53-*`, `fedramp-*`) lower case with enhancements dotted (`SC-13` → `sc-13`, `AC-2(1)` → `ac-2.1`); a digit-led id (SP 800-171's `3.13.11`) behind `_` (`_3.13.11`), since an OSCAL id can't start with a digit (interim, named in a note per framework); others (CMMC's `SC.L2-3.13.11`) as recorded. A control whose id still isn't an OSCAL token is left out of the SSP or the findings and named in a note.

**The render.** The `oscal` adapter's environment-neutral render, where a stack declares it, writes `oscal/<boundary>/poam.json`, `oscal/<boundary>/ssp.json` (each only when the boundary has one to write; a note says when it doesn't) and `oscal/assessment-results-<assessment>.json`, in format `oscal-json`.

## What it reads back

| Importer | Reads | Into the record |
|---|---|---|
| `oscal/poam` | OSCAL POA&M JSON (`plan-of-action-and-milestones`) | Its `poam-items` as POA&M items of the system boundary its `system-id` names (the boundary's `ciamSspRef` or name; a document naming none is refused: record the boundary first). New items go in `ou=oscal-poam-<system id>,ou=poam` as `cn=oscal-<uuid>` (`ciamFindingRef` `oscal:poam-item:<uuid>`, the boundary's environments unless the item names its own); the item's own risk (its first related risk that isn't a deviation) gives status, deadline and milestones. Deviation risks aren't imported: an exception is approved in the record. |
| `oscal/assessment-results` | OSCAL assessment results JSON | Each result stating its framework and assessment kind (opsdir properties) as a compliance assessment (new: `cn=oscal-<uuid>` in `ou=oscal-ar-<document uuid>,ou=assessments`, `ciamAssessmentRef` `oscal:result:<uuid>`); one without them records none (a notice). Its `not-satisfied` findings as open POA&M items in `ou=oscal-ar-<document uuid>,ou=poam` (`ciamFindingRef` `oscal:finding:<uuid>`, discovered by assessment at the result's start, the result's environments; a finding with no environment to name is a notice), controls from the `control` properties, else the target id under the result's framework. Satisfied findings aren't imported. |
| `oscal/catalog` | An OSCAL catalog JSON | Nothing: each framework whose controls the catalog holds is checked, and a notice names the record's controls it doesn't hold. |

A document's own items live in its container, which each import of it replaces as a whole (an item the document drops is removed). An item the record already holds (its `record-dn` property, as opsdir writes it, or an earlier import's `ciamFindingRef`) is merged in place: the attributes the document states replace the record's, everything else is kept, and a record-owned item is never deleted. Reading back a document opsdir wrote changes nothing. The estate's reports and checks (`opsdir report poam`, `assessments`, the planner's POA&M check) read the whole branch, so they see the containers' items. A value that looks like secret material is withheld and named in a notice. A file that isn't the document the importer reads, or is OSCAL other than 1.x, is named in a notice; none at all refuses the import.

`opsdir import oscal/poam PATH` (or `oscal/assessment-results`, `oscal/catalog`; PATH a file or a directory of them) previews the change records; with `--change <change id>` they are applied under that approved change.

## Known limits

- **OSCAL 1.2.3** is the version written (NIST's current release, 2026-08-07). NIST publishes SP 800-53 Rev. 5 and SP 800-171 Rev. 3 catalogs in OSCAL (oscal-content v1.5.0, which declares OSCAL 1.2.2); no official CMMC catalog in OSCAL exists, so CMMC ids are written as recorded.
- **Not a FedRAMP submission by itself.** FedRAMP's 2026 rules (CR26) require FedRAMP's own JSON schemas; valid OSCAL isn't FedRAMP-compliant output, and the UNBOUND fields above must be completed before any submission.
- SP 800-171 ids are written in an interim form (`_3.13.11`); the Rev. 3 OSCAL catalog names its controls its own way. `oscal/catalog` names the mismatches.
- A finding targets one control (OSCAL's `finding-target`): an item's other controls ride along as `control` properties. Its target is the control itself (`objective-id` = the control id), not a catalog objective (`ac-2_obj`).
- The SSP carries no users, inventory, leveraged authorizations, parameters or statements: the record doesn't hold them.
- The readers don't import exceptions, close record items from satisfied findings, or read another tool's free-form properties: only opsdir's (namespace `urn:opsdir:oscal`, or none).
- Validated against NIST's complete JSON schema (test marker `oscal`), not against a live tool (a GRC system's import, FedRAMP's validators).

## Tests

- `tests/test_writers.py`: the documents' content (items, risks and milestones, deviation risks, who meets each control, results with findings and the evidence package), determinism, UNBOUND notes, control ids in both directions, the render's files and notes.
- `tests/test_readers.py`: reading back opsdir's own documents changes nothing; another tool's items in the document's container, matched again and dropped with the document; record items merged in place and never deleted; the estate's reports and POA&M check seeing the containers' items; a result without framework; refusals and notices; secrets withheld; the catalog check.
- `tests/test_oscal_schema.py` (marker `oscal`): every document the render gives validates against `tools/oscal/1.2.3/oscal_complete_schema.json` (`opsdir/scripts/fetch-tools.sh`); skipped without it. Its token pattern's `\p{L}` / `\p{N}` are given Python's equivalents.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-format-oscal/tests` (with `-m oscal` for the schema test alone).

Installing the package registers it with opsdir (entry points `opsdir.formats`: `oscal-json`; `opsdir.adapters`: `oscal`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
