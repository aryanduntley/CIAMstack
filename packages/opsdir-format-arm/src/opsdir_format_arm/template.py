"""Azure Resource Manager templates as data: what a renderer builds, written as ARM JSON or as Bicep from the same
model. A format library: it knows ARM templates and Bicep, not any Azure service. Pure.

A template deploys at one scope (resourceGroup, subscription, managementGroup or tenant: a Bicep file has one
targetScope). It holds its parameters, resources and outputs in the order a renderer gives them. A resource has a
symbol (its symbolic name: the Bicep identifier, and the key of an ARM JSON languageVersion 2.0 template's resources),
its type and API version, its own name segment (a child resource also names its parent's symbol: ARM JSON writes
'parent/child', Bicep writes parent:), its top-level fields (location, kind, sku, identity, tags, zones, ...) and its
properties. An existing resource is only read (Bicep existing; ARM JSON, as Bicep compiles it, leaves it out of the
resources and names it only in expressions), optionally in another resource group. A module deploys a template of its
own at another scope (a resource group named by expressions: what an extension resource on a resource in another group
needs): Bicep's module (its template a file of its own), ARM JSON's nested deployment.

Values are JSON-shaped (dict, list or tuple, str, int, float, bool, None) or expressions: a parameter, a template
resource's id, name or runtime property, an ARM template function call (the functions Bicep shares: resourceId,
subscriptionResourceId, subscription, resourceGroup, ...) and string interpolation. Each writer writes them in its own
syntax.
"""
import re
from collections import namedtuple

SCOPES = ("resourceGroup", "subscription", "managementGroup", "tenant")

# A parameter: type (string, int, bool, object, array), default (None: the deployer must give one), what it is, the
# values allowed (() for any) and whether it is secure (never logged or shown: securestring / @secure()).
ArmParameter = namedtuple("ArmParameter", ("name", "type", "default", "description", "allowed", "secure"),
                          defaults=(None, None, (), False))
# A resource: symbol, type (Microsoft.X/y[/child]), api_version, name (its own segment), parent (the parent's symbol,
# for a child type), fields (top-level fields in order: location, kind, sku, identity, tags, zones, ...), properties
# (a dict; None: none), depends_on (symbols of template resources the deployment must finish first, where no reference
# already says so), existing (only read), resource_group (an existing resource's resource group, when not the
# deployment's), scope (an extension resource's: the symbol of the template resource it applies to, such as a role
# assignment on a key vault), comment (the lines, newline-separated, the Bicep writes above it).
ArmResource = namedtuple("ArmResource", ("symbol", "type", "api_version", "name", "parent", "fields", "properties",
                                         "depends_on", "existing", "resource_group", "scope", "comment"),
                         defaults=(None, {}, None, (), False, None, None, None))
# An output: its type and value.
ArmOutput = namedtuple("ArmOutput", ("name", "type", "value"))
# A module: symbol, name (the deployment's name), template (the ArmTemplate it deploys, at resourceGroup scope),
# subscription and resource_group (expressions naming the group it deploys into), params ({the template's parameter:
# value}), file (the stem of the Bicep file its template is written to; templates of the same content share one),
# depends_on (symbols of template resources or modules to finish first, where no reference already says so), comment.
ArmModule = namedtuple("ArmModule", ("symbol", "name", "template", "subscription", "resource_group", "params", "file",
                                     "depends_on", "comment"), defaults=((), None))
# A whole template: its scope, description, resources, parameters, outputs, comments (Bicep // lines at the top; the
# Bicep file's only: ARM JSON, having no comments, leaves them out), and modules (deployed after its resources, as
# Bicep compiles them).
ArmTemplate = namedtuple("ArmTemplate", ("scope", "description", "resources", "parameters", "outputs", "comments",
                                         "modules"), defaults=((), (), (), ()))

# Expressions. Param: a parameter's value. ResourceId: a template resource's id. ResourceName: its name (a child's
# whole name, parent/child). Prop: one of its runtime properties, path under properties ('principalId',
# 'primaryEndpoints.blob'). Call: an ARM template function both syntaxes write the same way (args are values).
# Interp: a string of literal parts and expressions. Member: a member of a value (a function's result:
# resourceGroup().location, subscription().id), path dotted. Field: a top-level runtime value of a template resource
# (location, identity.principalId), path dotted. An object's key may be an expression too (a user-assigned identity's
# id under userAssignedIdentities). Index: an element of an array value (split(id, '/')[4]).
Param = namedtuple("Param", ("name",))
ResourceId = namedtuple("ResourceId", ("symbol",))
ResourceName = namedtuple("ResourceName", ("symbol",))
Prop = namedtuple("Prop", ("symbol", "path"))
Call = namedtuple("Call", ("function", "args"))
Interp = namedtuple("Interp", ("parts",))
Member = namedtuple("Member", ("value", "path"))
Field = namedtuple("Field", ("symbol", "path"))
Index = namedtuple("Index", ("value", "index"))
EXPRESSIONS = (Param, ResourceId, ResourceName, Prop, Call, Interp, Member, Field, Index)


def symbol(*parts):
    """A symbolic name from name parts ('nsg', 'pf-admin' -> 'nsg_pf_admin'): a Bicep identifier, lower case."""
    found = re.sub(r"[^a-z0-9_]+", "_", "_".join(str(p) for p in parts).lower()).strip("_")
    if not found:
        raise ValueError(f"no letters or digits for a symbol in {parts!r}")
    return found if found[0].isalpha() else "r_" + found


def is_expression(v):
    return isinstance(v, EXPRESSIONS)


def is_module(x):
    return isinstance(x, ArmModule)


def indexed(t):
    """The template's resources and modules by symbol; ValueError on a symbol used twice, a parent, scope or dependency
    it doesn't hold (a module is never a parent or a scope), a scope it doesn't know, a parent of a top-level type, or
    a module's template that isn't a resource group's (each checked too)."""
    if t.scope not in SCOPES:
        raise ValueError(f"unknown template scope {t.scope!r} (one of {', '.join(SCOPES)})")
    found = {}
    for r in (*t.resources, *t.modules):
        if r.symbol in found:
            raise ValueError(f"resource symbol used more than once: {r.symbol}")
        found[r.symbol] = r
    for r in t.resources:
        missing = [s for s in (r.parent, r.scope, *r.depends_on) if s and s not in found]
        if missing:
            raise ValueError(f"resource {r.symbol} names symbols the template doesn't hold: {', '.join(missing)}")
        if any(is_module(found[s]) for s in (r.parent, r.scope) if s):
            raise ValueError(f"resource {r.symbol}: a module is neither a parent nor a scope")
        if r.parent and found[r.parent].type.count("/") + 1 != r.type.count("/"):
            raise ValueError(f"resource {r.symbol}: {r.type} isn't a child type of {found[r.parent].type}")
    for m in t.modules:
        missing = [s for s in m.depends_on if s not in found]
        if missing:
            raise ValueError(f"module {m.symbol} names symbols the template doesn't hold: {', '.join(missing)}")
        if m.template.scope != "resourceGroup" or m.template.modules:
            raise ValueError(f"module {m.symbol}: its template must be a resource group's, without modules")
        indexed(m.template)
    return found


def name_segments(index, r):
    """The name segments of a resource, its parents' first (a child's whole name is them joined by '/')."""
    return (*name_segments(index, index[r.parent]), r.name) if r.parent else (r.name,)


def resource_types(t):
    """Each resource type the template deploys (existing ones left out) once, in order: what a comparison with
    another render's types asks."""
    return tuple(dict.fromkeys(r.type for r in t.resources if not r.existing))
