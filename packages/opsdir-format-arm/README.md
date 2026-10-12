# opsdir-format-arm

Azure Resource Manager templates for opsdir adapters: one template model, written as ARM template JSON or as Bicep.

A format library shared by adapters that render ARM templates (milestone 5.6: the Azure adapter, as an alternative to its Terraform). It knows ARM templates and Bicep, not any Azure service. It registers two formats with opsdir (entry point `opsdir.formats`): `arm-json` and `bicep`, so adapters declare their files in them and the MANIFEST records which.

A renderer builds an `ArmTemplate(scope, description, resources, parameters, outputs, comments)` deployed at one scope (`resourceGroup`, `subscription`, `managementGroup`, `tenant`: a Bicep file has one `targetScope`; another scope needs a template of its own, or a module). Its parts:

- `ArmResource(symbol, type, api_version, name, parent, fields, properties, depends_on, existing, resource_group, scope, comment)`. The symbol is the Bicep identifier (`symbol(*parts)` makes one). The name is the resource's own segment; a child names its parent's symbol. `fields` are the top-level ones in order (`location`, `kind`, `sku`, `identity`, `tags`, `zones`, ...). An `existing` resource is only read, optionally in another resource group (a child of an existing resource is in its parent's). An extension resource (a role assignment, diagnostic setting, lock) names the symbol it applies to in `scope`.
- `ArmParameter(name, type, default, description, allowed, secure)` and `ArmOutput(name, type, value)`.

Values are JSON-shaped, or expressions as data:
- `Param(name)`: a parameter's value;
- `ResourceId(symbol)` and `ResourceName(symbol)`: a template resource's id and its own name;
- `Prop(symbol, path)`: one of its runtime properties;
- `Call(function, args)`: an ARM template function both syntaxes share, such as `resourceId`, `subscriptionResourceId`, `guid`, `subscription`;
- `Interp(parts)`: a string of literal parts and expressions.

`indexed(t)` checks a template: unknown scope, a symbol used twice, a parent, scope or dependency the template doesn't hold, a parent of a type that isn't its child type. `resource_types(t)` gives each deployed resource type once, for comparing a render's resources with another's.

`as_bicep(t)` writes the Bicep file:
- `targetScope`, `metadata description`;
- parameters with their decorators;
- `resource ... existing`, `parent:` and `scope:`;
- outputs and `//` comments;
- objects and arrays one entry per line, strings escaped as Bicep reads them.

`as_arm_json(t)` writes the ARM template JSON that `bicep build` compiles that file to (language version 1.0, which every Azure cloud deploys). Existing resources aren't deployed, so they're left out of the resources array and appear only in expressions. The ids, names, `reference()`, `format()` and the inferred `dependsOn` (sorted by symbol) are written as Bicep writes them. So the two files are one deployment, and the `bicep`-marked test holds them equal: `bicep build` of the Bicep gives the ARM JSON exactly, except for Bicep's generator stamp. Template comments are the Bicep file's only, because JSON has none.

```python
from opsdir_format_arm.template import ArmOutput, ArmParameter, ArmResource, ArmTemplate, symbol
from opsdir_format_arm.template import Call, Interp, Param, Prop, ResourceId, ResourceName
from opsdir_format_arm.bicep import as_bicep
from opsdir_format_arm.arm_json import as_arm_json
```

Rendered Bicep is checked with the Bicep CLI (`opsdir/scripts/validate-bicep.sh`: `bicep build` and `bicep lint`, where errors fail and warnings are shown; tests marked `bicep`), at the version `opsdir/scripts/fetch-tools.sh` pins. Bicep refuses some things that ARM JSON can't flag, such as an extension resource on a resource in another resource group, which needs a module.

In this repository: `opsdir/scripts/dev-install.sh`.
