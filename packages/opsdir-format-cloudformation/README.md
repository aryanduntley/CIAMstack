# opsdir-format-cloudformation

AWS CloudFormation templates for opsdir adapters: a template model with intrinsic functions as data, written as YAML or JSON. A format library: it knows CloudFormation's template anatomy and intrinsic functions, not any AWS service.

**Applies to** no environment by itself: it is not an adapter. It registers two formats with opsdir (entry point `opsdir.formats`), so adapters declare their template files in them and the MANIFEST records which:

| Format | Title | Media type, extensions | Comments |
|---|---|---|---|
| `cloudformation-yaml` | AWS CloudFormation template (YAML) | `application/yaml`, `.yaml`, `.yml`, `.template` | `#`, so a generated-file header |
| `cloudformation-json` | AWS CloudFormation template (JSON) | `application/json`, `.json`, `.template` | none |

Used by opsdir-adapter-aws: its `--target aws=cloudformation` render, translated from its Terraform (milestone 5.6, through opsdir-format-terraform's `native` engine).

**Depends on** `opsdir` only (the core's `Format` contract and YAML and JSON writers). The `cloudformation` tests check the output with cfn-lint 1.57.2, which `opsdir/scripts/fetch-tools.sh` pins.

## What it writes

A renderer builds a `Template(description, resources, parameters, conditions, outputs, metadata, transform)` (`template.py`) of:
- `Resource(logical_id, type, properties, depends_on, condition, deletion_policy, update_replace_policy, metadata)` (policies `Retain`, `Snapshot`, `Delete`, `RetainExceptOnCreate`);
- `Parameter(logical_id, type, default, description, allowed, no_echo)` (a `String`, `Number`, `CommaDelimitedList`, AWS-specific or SSM parameter type; `no_echo` masks it);
- `Output(logical_id, value, description, export)` (an export name for `Fn::ImportValue`);
- conditions as `((name, condition), ...)`;

in the order a person reads them. Values are JSON-shaped. Intrinsic functions are data in CloudFormation's long form (a one-key dict), which YAML and JSON write alike, so one template gives both files: `ref`, `get_att`, `sub` (with variables), `join`, `select`, `split`, `import_value`, `if_`, `equals`, and `resolve(service, reference)` for a dynamic reference (`{{resolve:secretsmanager:...}}`, `ssm`, `ssm-secure`; resolved at deploy time and never stored in the template). The pseudo parameters are constants (`ACCOUNT_ID`, `PARTITION`, `REGION`, `STACK_NAME`, `URL_SUFFIX`, `NO_VALUE`). `logical_id(*parts)` makes a logical id from name parts (`identity_pf` gives `IdentityPf`; letters and digits only, `R` before a leading digit, at most 255 characters; `ValueError` with no letters or digits).

`template_data(t)` is the template document: `AWSTemplateFormatVersion` `2010-09-09`, then its sections in CloudFormation's documented order (Description, Transform, Metadata, Parameters, Conditions, Resources, Outputs), empty ones left out. It refuses a logical id used twice among the resources, parameters or outputs (a `ValueError`). `as_yaml(t)` (block style, long-form functions, keys in the template's order) and `as_json(t)` (indented by two) write it, through the core's YAML and JSON writers. `resource_types(t)` gives each resource type once, for comparing a render's resources with another's.

A template names the regions it is checked for in its own metadata: `lint_metadata(regions)` gives that metadata (cfn-lint's in-template configuration, `{"cfn-lint": {"config": {"regions": [...]}}}`), so a renderer passes the environment's region and a GovCloud template is checked against GovCloud's resource specification (a type GovCloud lacks, such as CloudFront, fails there).

```python
from opsdir_format_cloudformation.template import Output, Parameter, Resource, Template
from opsdir_format_cloudformation.template import get_att, if_, join, logical_id, ref, resolve, sub, template_data
from opsdir_format_cloudformation.template import lint_metadata, resource_types, ACCOUNT_ID, PARTITION, REGION
from opsdir_format_cloudformation.format import as_json, as_yaml
```

Rendered templates are checked by cfn-lint (`opsdir/scripts/validate-cloudformation.sh`: every file a render's MANIFEST declares in either format, errors failing and warnings shown, at the version `opsdir/scripts/fetch-tools.sh` pins; tests marked `cloudformation`).

## What it reads back

Nothing: neither format has a reader here (`read=None`). The AWS adapter reads CloudFormation stacks back with its own importer.

## References, vocabulary and schema

None: no reference schemes, vocabulary, schema, secret patterns, importers or planner checks. It is a library the adapters call.

## Known limits

- **Not deployed live**: cfn-lint checks the output offline (its bundled resource specifications per region); deploying a stack is part of the testing plan (milestone 7.2).
- The model writes the long form only (no `!Ref` short tags), no `Mappings` or `Rules` sections, and only the intrinsic functions above.

## Tests

- `tests/test_template.py`: logical ids as letters and digits (and one needing some); intrinsic functions as long-form data; the template document in CloudFormation's section order with empty ones left out; a logical id used twice refused; JSON and YAML the same template; resource types once each in order; the formats registered.
- `tests/test_cfn_lint.py` (marker `cloudformation`, skipped without `tools/cfn-lint`): a written template (YAML and JSON) passing for its regions, a type its region lacks failing there.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-format-cloudformation/tests` (unit tests); `-m cloudformation` after `opsdir/scripts/fetch-tools.sh`.

Installing the package registers the `cloudformation-yaml` and `cloudformation-json` formats with opsdir (entry point `opsdir.formats`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
