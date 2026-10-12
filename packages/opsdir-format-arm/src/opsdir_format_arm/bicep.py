"""An ArmTemplate as a Bicep file: targetScope (when not a resource group), parameters with their decorators,
resources (existing ones read, a child under parent:, an extension resource with scope:), outputs, and // comments.
`bicep build` of it gives the template the ARM JSON writer gives. Pure.

Objects and arrays are written one entry per line, two spaces deep, as `bicep format` lays them out. A string is a
single-quoted Bicep string ('\\', '\\'', the line breaks and '${' escaped); an interpolation is one string with its
expressions in ${...}. A key that isn't an identifier is quoted.
"""
import re
from collections import namedtuple

from .template import Call, Field, Interp, Member, Param, Prop, ResourceId, ResourceName, indexed, is_expression

# A bare symbol the writer puts after parent:, scope: and in dependsOn (written as it is; never a value of the model)
_Symbol = namedtuple("_Symbol", ("name",))
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ESCAPES = {"\\": "\\\\", "'": "\\'", "\n": "\\n", "\r": "\\r", "\t": "\\t", "$": "\\$"}


def _chars(s):
    return "".join(_ESCAPES.get(c, c) for c in s)


def bicep_string(s):
    """A Bicep string literal."""
    return "'" + _chars(s) + "'"


def _key(k):
    """An object key: an identifier as it is, other text quoted, an expression interpolated ('${expr}')."""
    if is_expression(k):
        return bicep_expr(k) if isinstance(k, Interp) else "'${" + bicep_expr(k) + "}'"
    return k if _IDENTIFIER.fullmatch(k) else bicep_string(k)


def bicep_expr(v):
    """An expression (or a scalar) in Bicep syntax."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        return bicep_string(v)
    if isinstance(v, Param):
        return v.name
    if isinstance(v, ResourceId):
        return f"{v.symbol}.id"
    if isinstance(v, ResourceName):
        return f"{v.symbol}.name"
    if isinstance(v, Prop):
        return f"{v.symbol}.properties.{v.path}"
    if isinstance(v, Call):
        return f"{v.function}({', '.join(bicep_value(a) for a in v.args)})"
    if isinstance(v, Interp):
        return "'" + "".join(_chars(p) if isinstance(p, str) else "${" + bicep_expr(p) + "}" for p in v.parts) + "'"
    if isinstance(v, Member):
        return f"{bicep_expr(v.value)}.{v.path}"
    if isinstance(v, Field):
        return f"{v.symbol}.{v.path}"
    raise TypeError(f"not a Bicep expression: {v!r}")


def bicep_value(v, indent=0):
    """A value in Bicep syntax: objects and arrays one entry per line, nested two spaces deeper."""
    pad = "  " * (indent + 1)
    if is_expression(v):                        # before tuples: an expression is a namedtuple
        return bicep_expr(v)
    if isinstance(v, dict):
        return "{\n" + "".join(f"{pad}{_key(k)}: {bicep_value(x, indent + 1)}\n" for k, x in v.items()) + \
            "  " * indent + "}" if v else "{}"
    if isinstance(v, (list, tuple)):
        return "[\n" + "".join(f"{pad}{bicep_value(x, indent + 1)}\n" for x in v) + "  " * indent + "]" if v else "[]"
    if v is None or isinstance(v, (str, bool, int, float)):
        return bicep_expr(v)
    raise TypeError(f"not a Bicep value: {v!r}")


def _parameter(p):
    decorators = (*((f"@description({bicep_string(p.description)})",) if p.description else ()),
                  *((f"@allowed({bicep_value(list(p.allowed))})",) if p.allowed else ()),
                  *(("@secure()",) if p.secure else ()))
    default = f" = {bicep_value(p.default)}" if p.default is not None else ""
    return "\n".join((*decorators, f"param {p.name} {p.type}{default}"))


def _resource(r):
    body = {"name": r.name,
            **({"scope": Call("resourceGroup", (r.resource_group,))} if r.existing and r.resource_group else {}),
            **({"parent": _Symbol(r.parent)} if r.parent else {}),
            **({"scope": _Symbol(r.scope)} if r.scope else {}),
            **r.fields,
            **({"properties": r.properties} if r.properties is not None else {}),
            **({"dependsOn": [_Symbol(s) for s in r.depends_on]} if r.depends_on else {})}
    head = f"resource {r.symbol} {bicep_string(r.type + '@' + r.api_version)}{' existing' if r.existing else ''} = "
    lines = "".join(f"  {_key(k)}: {_symbolic(x, 1)}\n" for k, x in body.items())
    return "\n".join((*(f"// {c}" for c in (r.comment.split("\n") if r.comment else ())), head + "{\n" + lines + "}"))


def _symbolic(v, indent):
    if isinstance(v, _Symbol):
        return v.name
    if isinstance(v, list) and v and all(isinstance(x, _Symbol) for x in v):
        pad = "  " * (indent + 1)
        return "[\n" + "".join(f"{pad}{x.name}\n" for x in v) + "  " * indent + "]"
    return bicep_value(v, indent)


def as_bicep(t):
    """A template as a Bicep file (sections a blank line apart, a final newline)."""
    indexed(t)
    sections = (*(("\n".join(f"// {c}" for c in t.comments),) if t.comments else ()),
                *((f"targetScope = {bicep_string(t.scope)}",) if t.scope != "resourceGroup" else ()),
                *((f"metadata description = {bicep_string(t.description)}",) if t.description else ()),
                *(_parameter(p) for p in t.parameters),
                *(_resource(r) for r in t.resources),
                *(f"output {o.name} {o.type} = {bicep_value(o.value)}" for o in t.outputs))
    return "\n\n".join(sections) + "\n"
