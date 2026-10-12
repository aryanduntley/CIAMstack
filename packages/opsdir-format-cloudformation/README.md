# opsdir-format-cloudformation

AWS CloudFormation templates for opsdir adapters: a template model with intrinsic functions as data, written as YAML or JSON.

A format library shared by adapters that render CloudFormation (milestone 5.6: the AWS adapter, as an alternative to its Terraform). It knows CloudFormation's template anatomy and intrinsic functions, not any AWS service. It registers two formats with opsdir (entry point `opsdir.formats`): `cloudformation-yaml` and `cloudformation-json`, so adapters declare their template files in them and the MANIFEST records which.

A renderer builds a `Template(description, resources, parameters, conditions, outputs, metadata, transform)` of `Resource(logical_id, type, properties, depends_on, condition, deletion_policy, update_replace_policy, metadata)`, `Parameter(logical_id, type, default, description, allowed, no_echo)` and `Output(logical_id, value, description, export)`, in the order a person reads them. Values are JSON-shaped. Intrinsic functions are data in CloudFormation's long form, which YAML and JSON write alike: `ref`, `get_att`, `sub`, `join`, `select`, `split`, `import_value`, `if_`, `equals`, and `resolve(service, reference)` for a dynamic reference (`{{resolve:secretsmanager:...}}`, resolved at deploy time and never stored in the template). The pseudo parameters are constants (`ACCOUNT_ID`, `PARTITION`, `REGION`, `STACK_NAME`, `URL_SUFFIX`, `NO_VALUE`). `logical_id(*parts)` makes a logical id from name parts (`identity_pf` gives `IdentityPf`; letters and digits only).

`template_data(t)` is the template document, its sections in CloudFormation's documented order and empty ones left out. It refuses a logical id used twice in a section (a `ValueError`). `as_yaml(t)` and `as_json(t)` write it, through the core's YAML and JSON writers. `resource_types(t)` gives each resource type once, for comparing a render's resources with another's.

```python
from opsdir_format_cloudformation.template import Output, Parameter, Resource, Template
from opsdir_format_cloudformation.template import get_att, logical_id, ref, resolve, sub, template_data
from opsdir_format_cloudformation.format import as_json, as_yaml
```

Rendered templates are checked by cfn-lint (`opsdir/scripts/validate-cloudformation.sh`, at the version `opsdir/scripts/fetch-tools.sh` pins; tests marked `cloudformation`). A template names the regions it is checked for in its own metadata: `lint_metadata(regions)` gives that metadata (cfn-lint's in-template configuration), so a renderer passes the environment's region and a GovCloud template is checked against GovCloud's resource specification (a type GovCloud lacks, such as CloudFront, fails there).

In this repository: `opsdir/scripts/dev-install.sh`.
