# opsdir-format-arm

Azure Resource Manager templates for opsdir adapters: one template model, written as ARM template JSON or as Bicep. A format library: it knows ARM templates and Bicep, not any Azure service.

**Applies to** no environment by itself: it is not an adapter. It registers two formats with opsdir (entry point `opsdir.formats`), so adapters declare their files in them and the MANIFEST records which:

| Format | Title | Media type, extensions | Comments |
|---|---|---|---|
| `arm-json` | Azure Resource Manager template (JSON) | `application/json`, `.json` | none (JSON has none) |
| `bicep` | Bicep | `text/plain`, `.bicep` | `//`, so a generated-file header |

Used by opsdir-adapter-azure: its `--target azure=bicep,arm` render, translated from its Terraform (milestone 5.6, through opsdir-format-terraform's `native` engine).

**Depends on** `opsdir` only (the core's `Format` contract and JSON writer). No Bicep CLI to write; the `bicep` tests check the output with the Bicep CLI 0.48.1 that `opsdir/scripts/fetch-tools.sh` pins.

## What it writes

A renderer builds an `ArmTemplate(scope, description, resources, parameters, outputs, comments, modules)` deployed at one scope (`resourceGroup`, `subscription`, `managementGroup`, `tenant`: a Bicep file has one `targetScope`; another scope needs a template of its own, or a module). Its parts, in the order the renderer gives them (`template.py`):

- `ArmResource(symbol, type, api_version, name, parent, fields, properties, depends_on, existing, resource_group, scope, comment)`. The symbol is the Bicep identifier (`symbol(*parts)` makes one: lowercase, other characters `_`, `r_` before a leading digit; `ValueError` with no letters or digits). The name is the resource's own segment; a child names its parent's symbol. `fields` are the top-level ones in order (`location`, `kind`, `sku`, `identity`, `tags`, `zones`, ...). An `existing` resource is only read, optionally in another resource group (`resource_group`; a child of an existing resource is in its parent's). An extension resource (a role assignment, diagnostic setting, lock) names the symbol it applies to in `scope`. `depends_on` names what must finish first where no reference already says so; `comment` is the lines the Bicep file writes above it.
- `ArmModule(symbol, name, template, subscription, resource_group, params, file, depends_on, comment)`: a template of its own (a resource group's, without modules of its own) deployed at the group the `subscription` and `resource_group` expressions name, its parameters given `params`; what an extension resource on a resource in another group needs (a role assignment on a registry an input names by ID). `file` is the stem of the Bicep file its template is written to. A resource's `depends_on` may name a module.
- `ArmParameter(name, type, default, description, allowed, secure)` (a `secure` one is `securestring` / `secureObject`, `@secure()`) and `ArmOutput(name, type, value)`.

Values are JSON-shaped, or expressions as data:
- `Param(name)`: a parameter's value;
- `ResourceId(symbol)` and `ResourceName(symbol)`: a template resource's id and its name;
- `Prop(symbol, path)`: one of its runtime properties (`principalId`, `primaryEndpoints.blob`);
- `Field(symbol, path)`: a top-level runtime value of a template resource (`location`, `identity.principalId`);
- `Call(function, args)`: an ARM template function both syntaxes share, such as `resourceId`, `subscriptionResourceId`, `guid`, `subscription`, `resourceGroup`;
- `Member(value, path)`: a member of a value, such as a function's result (`resourceGroup().location`);
- `Interp(parts)`: a string of literal parts and expressions;
- `Index(value, index)`: an element of an array value (`split(id, '/')[4]`).

An object's key may be an expression too (a user-assigned identity's id under `userAssignedIdentities`).

`indexed(t)` checks a template before either writer writes it (`ValueError`): an unknown scope, a symbol used twice, a parent, scope or dependency the template doesn't hold, a parent of a type that isn't its child type, a module as a parent or scope, a module's template at another scope or with modules (each module's template checked too). `resource_types(t)` gives each deployed resource type once (existing ones left out), for comparing a render's resources with another's.

`as_bicep(t)` writes the Bicep file:
- `//` template comments at the top, `targetScope` (when not a resource group), `metadata description`;
- parameters with their decorators (`@description`, `@allowed`, `@secure()`);
- resources: `existing` ones (in another group with `scope: resourceGroup(...)`), `parent:` and `scope:` by symbol, `dependsOn` by symbol, each resource's `//` comment;
- modules, after the resources: `module <symbol> './modules/<file>.bicep' = { name, scope: resourceGroup(subscription, group), params, dependsOn }`; `as_bicep(t, module_path)` names each module's file, and `bicep_files(t, path)` gives the template at `path` and its modules' templates under `modules/` beside it, each distinct template once (`module_files`: a later different template of the same `file` numbered `-2`, `-3`, ...);
- outputs;
- objects and arrays one entry per line, two spaces deep, as `bicep format` lays them out; strings single-quoted and escaped as Bicep reads them (`\`, `'`, line breaks, `$`); an interpolation as one string with `${...}`; a key that isn't an identifier quoted.

`as_arm_json(t)` writes the ARM template JSON that `bicep build` compiles that file to (language version 1.0, which every Azure cloud deploys; the `$schema` of the template's scope). Existing resources aren't deployed, so they're left out of the resources array and appear only in expressions. Ids (`resourceId`, `subscriptionResourceId`, `managementGroupResourceId`, `tenantResourceId` by scope; `extensionResourceId` for an extension resource and for an existing resource in another group), child names (`format('{0}/{1}', ...)`), `reference()` for properties and fields, `format()` for interpolations, and the inferred `dependsOn` (from the name, parent, scope, fields, properties and explicit `depends_on`, deployed ones only, sorted by symbol) are written as Bicep writes them. A literal string ARM would read as an expression (`[...]`) is escaped (`[[`). So the two files are one deployment, and the `bicep`-marked test holds them equal: `bicep build` of the Bicep gives the ARM JSON exactly, except for Bicep's generator stamp. Template comments are the Bicep file's only, because JSON has none.

```python
from opsdir_format_arm.template import ArmModule, ArmOutput, ArmParameter, ArmResource, ArmTemplate, symbol
from opsdir_format_arm.template import Call, Field, Index, Interp, Member, Param, Prop, ResourceId, ResourceName
from opsdir_format_arm.template import indexed, resource_types
from opsdir_format_arm.bicep import as_bicep, bicep_files
from opsdir_format_arm.arm_json import as_arm_json
```

Rendered Bicep is checked with the Bicep CLI (`opsdir/scripts/validate-bicep.sh`: `bicep build` and `bicep lint`, where errors fail and warnings are shown; tests marked `bicep`), at the version `opsdir/scripts/fetch-tools.sh` pins.

A module is, in ARM JSON, the nested deployment `bicep build` compiles it to: `Microsoft.Resources/deployments` at `2025-04-01` with `subscriptionId` and `resourceGroup`, `expressionEvaluationOptions.scope` `inner`, mode `Incremental`, its parameters as `{"value": ...}` and its template inline, after the template's resources; what depends on it names it by `extensionResourceId(format('/subscriptions/{0}/resourceGroups/{1}', ...), 'Microsoft.Resources/deployments', name)`. Bicep stamps each template it compiles, a module's included, with its own generator and hash; the writer doesn't, so tests compare them without the stamps.

## What it reads back

Nothing: neither format has a reader here (`read=None`). The Azure adapter reads ARM and Bicep deployments back with its own importer.

## References, vocabulary and schema

None: no reference schemes, vocabulary, schema, secret patterns, importers or planner checks. It is a library the adapters call.

## Known limits

- **Not deployed live**: `bicep build` and `bicep lint` check the output offline; `az deployment ... what-if` against a real subscription is part of the testing plan (milestone 7.2).
- One scope per template: what another scope deploys needs a template of its own or a module. Modules deploy only at a resource group (not a subscription, management group or tenant), hold no modules of their own, and give no outputs back.
- ARM JSON language version 1.0 only (no symbolic-name `languageVersion 2.0` output); no loops or conditions in the model.

## Tests

- `tests/test_writers.py`: symbols as Bicep identifiers; a template checked before it is written; ARM JSON as Bicep compiles the same template; dependencies sorted by symbol, existing ones skipped; subscription-scope ids and schema; Bicep strings and values; the Bicep file; resource types leaving existing ones out; the formats registered; an existing child reading its parent's group and a literal name as text.
- `tests/test_writers.py` also: a module as a nested deployment after the resources, named by its group; modules of one template sharing one Bicep file beside the template (another template of the same name numbered); a module checked too. The module sample is `tests/conftest.py`'s `module_sample` fixture.
- `tests/test_bicep_build.py` (marker `bicep`, skipped without `tools/bin/bicep`): `bicep build` of the Bicep writer's file gives the ARM JSON writer's template (generator stamps aside, at every level), at resource-group and subscription scope, and for a template with modules from their shared file.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-format-arm/tests` (unit tests); `-m bicep` after `opsdir/scripts/fetch-tools.sh`.

Installing the package registers the `arm-json` and `bicep` formats with opsdir (entry point `opsdir.formats`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
