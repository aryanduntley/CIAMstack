"""An ArmTemplate as ARM template JSON, written the way `bicep build` writes the Bicep writer's file of the same
template (language version 1.0: every Azure cloud deploys it), so the two are one deployment and a test can hold them
equal. Pure.

As Bicep compiles them: existing resources aren't deployed, so they aren't in the resources array, only in the
expressions that use them. A resource's id is resourceId (in a resource-group template; subscriptionResourceId,
managementGroupResourceId, tenantResourceId at the other scopes) of its type and name segments; an existing resource in
another resource group is an extension of that group's id; an extension resource's id is extensionResourceId on what
it applies to. A child is named format('{0}/{1}', parent, child). A runtime property is reference(id, apiVersion).path.
An interpolation is format() with literal braces doubled. Each resource depends on the template resources its name,
parent, scope, fields, properties and explicit depends_on refer to, sorted by symbol (as Bicep orders them). A literal
string ARM would read as an expression (starting with '[' and ending with ']') is escaped ('[['). Template comments are
the Bicep file's only: JSON has none (the MANIFEST records the file as generated). A module is a nested deployment
(Microsoft.Resources/deployments, inner expression scope, its template inline, its parameters given as values) after
the template's resources; what depends on it names it by extensionResourceId on the group it deploys into.
"""
from opsdir.core.jsondata import indented
from .template import (Call, Field, Index, Interp, Member, Param, Prop, ResourceId, ResourceName, indexed,
                       is_expression, is_module, name_segments)

SCHEMAS = {"resourceGroup": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
           "subscription": "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#",
           "managementGroup":
               "https://schema.management.azure.com/schemas/2019-08-01/managementGroupDeploymentTemplate.json#",
           "tenant": "https://schema.management.azure.com/schemas/2019-08-01/tenantDeploymentTemplate.json#"}
ID_FUNCTIONS = {"resourceGroup": "resourceId", "subscription": "subscriptionResourceId",
                "managementGroup": "managementGroupResourceId", "tenant": "tenantResourceId"}
GROUP_ID = "format('/subscriptions/{0}/resourceGroups/{1}', subscription().subscriptionId, %s)"
MODULE_GROUP_ID = "format('/subscriptions/{0}/resourceGroups/{1}', %s, %s)"
DEPLOYMENTS = ("Microsoft.Resources/deployments", "2025-04-01")      # what bicep build (0.48) writes a module as


def _literal(s):
    return "'" + s.replace("'", "''") + "'"


def _existing_group(index, r):
    """The resource group an existing resource is in: its own, else its (existing) parent's; None: the template's."""
    if not r.existing:
        return None
    return r.resource_group or (_existing_group(index, index[r.parent]) if r.parent in index else None)


def _id(index, scope, r):
    if is_module(r):
        group = MODULE_GROUP_ID % (arm_expr(index, scope, r.subscription), arm_expr(index, scope, r.resource_group))
        return f"extensionResourceId({group}, {_literal(DEPLOYMENTS[0])}, {arm_expr(index, scope, r.name)})"
    args = ", ".join((_literal(r.type), *(arm_expr(index, scope, s) for s in name_segments(index, r))))
    group = _existing_group(index, r)
    if r.scope:
        return f"extensionResourceId({_id(index, scope, index[r.scope])}, {args})"
    if group:
        return f"extensionResourceId({GROUP_ID % arm_expr(index, scope, group)}, {args})"
    return f"{ID_FUNCTIONS[scope]}({args})"


def _format(index, scope, parts):
    """format() of literal parts and expressions (a literal's quote doubled, its braces doubled)."""
    exprs = [p for p in parts if not isinstance(p, str)]
    numbered = iter(range(len(exprs)))
    text = "".join(p.replace("{", "{{").replace("}", "}}") if isinstance(p, str) else "{%d}" % next(numbered)
                   for p in parts)
    return f"format({', '.join((_literal(text), *(arm_expr(index, scope, e) for e in exprs)))})"


def arm_expr(index, scope, v):
    """A value inside an ARM template expression (no brackets), as Bicep compiles it."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null()"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        return _literal(v)
    if isinstance(v, Param):
        return f"parameters({_literal(v.name)})"
    if isinstance(v, ResourceId):
        return _id(index, scope, index[v.symbol])
    if isinstance(v, ResourceName):
        return arm_expr(index, scope, index[v.symbol].name)
    if isinstance(v, Prop):
        r = index[v.symbol]
        return f"reference({_id(index, scope, r)}, {_literal(r.api_version)}).{v.path}"
    if isinstance(v, Call):
        return f"{v.function}({', '.join(arm_expr(index, scope, a) for a in v.args)})"
    if isinstance(v, Interp):
        return _format(index, scope, v.parts) if any(not isinstance(p, str) for p in v.parts) else \
            _literal("".join(v.parts))
    if isinstance(v, Member):
        return f"{arm_expr(index, scope, v.value)}.{v.path}"
    if isinstance(v, Field):
        if v.path.startswith("properties."):                  # as Bicep compiles it: the properties' reference()
            return arm_expr(index, scope, Prop(v.symbol, v.path[len("properties."):]))
        r = index[v.symbol]
        return f"reference({_id(index, scope, r)}, {_literal(r.api_version)}, 'full').{v.path}"
    if isinstance(v, Index):
        return f"{arm_expr(index, scope, v.value)}[{arm_expr(index, scope, v.index)}]"
    if isinstance(v, (list, tuple)):
        return "createArray(" + ", ".join(arm_expr(index, scope, x) for x in v) + ")"
    if isinstance(v, dict):
        return "createObject(" + ", ".join(f"{_literal(k)}, {arm_expr(index, scope, x)}" for k, x in v.items()) + ")"
    raise TypeError(f"not an ARM template value: {v!r}")


def arm_value(index, scope, v):
    """A value as ARM template JSON: an expression as a bracket string (a literal-only one as its string), a literal
    string ARM would take for an expression ('[...]') escaped, objects and arrays element by element."""
    if isinstance(v, Interp) and all(isinstance(p, str) for p in v.parts):
        return arm_value(index, scope, "".join(v.parts))
    if isinstance(v, ResourceName):                         # its name as it is written (a literal one as text)
        return arm_value(index, scope, index[v.symbol].name)
    if is_expression(v):
        return "[" + arm_expr(index, scope, v) + "]"
    if isinstance(v, str):
        return "[" + v if v.startswith("[") and v.endswith("]") else v
    if isinstance(v, dict):
        return {_arm_key(index, scope, k): arm_value(index, scope, x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [arm_value(index, scope, x) for x in v]
    if v is None or isinstance(v, (bool, int, float)):
        return v
    raise TypeError(f"not an ARM template value: {v!r}")


def _arm_key(index, scope, k):
    """An object key as Bicep compiles it: text as it is, an expression as a format() expression string."""
    if not is_expression(k):
        return k
    parts = k.parts if isinstance(k, Interp) else (k,)
    return "[" + _format(index, scope, parts) + "]"


def referenced(v):
    """The symbols a value refers to (ids, names, properties), in order of first mention."""
    if isinstance(v, (ResourceId, ResourceName, Prop, Field)):
        return (v.symbol,)
    if isinstance(v, Call):
        return tuple(s for a in v.args for s in referenced(a))
    if isinstance(v, Interp):
        return tuple(s for p in v.parts for s in referenced(p))
    if isinstance(v, Member):
        return referenced(v.value)
    if isinstance(v, Index):
        return (*referenced(v.value), *referenced(v.index))
    if isinstance(v, dict):
        return tuple(s for k, x in v.items() for s in (*referenced(k), *referenced(x)))
    if isinstance(v, (list, tuple)) and not is_expression(v):
        return tuple(s for x in v for s in referenced(x))
    return ()


def dependencies(index, r):
    """The template resources (and modules) a resource or module must follow, as Bicep infers them from its
    declaration: those its name, parent, scope, fields, properties (a module's scope and params) and explicit
    depends_on refer to; deployed ones only, never itself, sorted by symbol (Bicep's order)."""
    mentioned = (*referenced(r.name), *r.depends_on, *(
        (*referenced(r.subscription), *referenced(r.resource_group), *referenced(r.params)) if is_module(r) else
        (*((r.parent,) if r.parent else ()), *((r.scope,) if r.scope else ()), *referenced(r.fields),
         *referenced(r.properties))))
    return tuple(sorted(s for s in set(mentioned)
                        if s != r.symbol and (is_module(index[s]) or not index[s].existing)))


def _name(index, scope, r):
    segments = name_segments(index, r)
    if len(segments) == 1:
        return arm_value(index, scope, r.name)
    placeholders = "/".join("{%d}" % i for i in range(len(segments)))
    return f"[format({', '.join((_literal(placeholders), *(arm_expr(index, scope, s) for s in segments)))})]"


def _resource(index, scope, r):
    after = dependencies(index, r)
    return {"type": r.type, "apiVersion": r.api_version,
            **({"scope": "[" + _id(index, scope, index[r.scope]) + "]"} if r.scope else {}),
            "name": _name(index, scope, r),
            **{k: arm_value(index, scope, v) for k, v in r.fields.items()},
            **({"properties": arm_value(index, scope, r.properties)} if r.properties is not None else {}),
            **({"dependsOn": ["[" + _id(index, scope, index[s]) + "]" for s in after]} if after else {})}


def _module(index, scope, m):
    """A module as the nested deployment bicep build compiles it to."""
    after = dependencies(index, m)
    return {"type": DEPLOYMENTS[0], "apiVersion": DEPLOYMENTS[1], "name": arm_value(index, scope, m.name),
            "subscriptionId": arm_value(index, scope, m.subscription),
            "resourceGroup": arm_value(index, scope, m.resource_group),
            "properties": {"expressionEvaluationOptions": {"scope": "inner"}, "mode": "Incremental",
                           "parameters": {k: {"value": arm_value(index, scope, v)} for k, v in m.params.items()},
                           "template": template_doc(m.template)},
            **({"dependsOn": ["[" + _id(index, scope, index[s]) + "]" for s in after]} if after else {})}


def _parameter(index, scope, p):
    kind = {"string": "securestring", "object": "secureObject"}.get(p.type, p.type) if p.secure else p.type
    return {"type": kind, **({"defaultValue": arm_value(index, scope, p.default)} if p.default is not None else {}),
            **({"allowedValues": list(p.allowed)} if p.allowed else {}),
            **({"metadata": {"description": p.description}} if p.description else {})}


def template_doc(t):
    """The ARM template document of a template, as `bicep build` gives it for the Bicep writer's file (but for the
    generator stamp Bicep adds to metadata)."""
    index = indexed(t)
    return {"$schema": SCHEMAS[t.scope], "contentVersion": "1.0.0.0",
            **({"metadata": {"description": t.description}} if t.description else {}),
            **({"parameters": {p.name: _parameter(index, t.scope, p) for p in t.parameters}} if t.parameters else {}),
            "resources": [*(_resource(index, t.scope, r) for r in t.resources if not r.existing),
                          *(_module(index, t.scope, m) for m in t.modules)],
            **({"outputs": {o.name: {"type": o.type, "value": arm_value(index, t.scope, o.value)}
                            for o in t.outputs}} if t.outputs else {})}


def as_arm_json(t):
    """A template as ARM template JSON text (indented by two, newline-terminated)."""
    return indented(template_doc(t))
