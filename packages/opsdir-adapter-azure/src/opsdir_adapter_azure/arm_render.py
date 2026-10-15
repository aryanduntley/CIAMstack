"""Azure Resource Manager templates (Bicep and ARM JSON, format-arm) translated from the Azure render's Terraform data
(5.6, decisions 2565, 2592, 2605): the ARM target on format-terraform's native engine. Each Terraform root becomes one
template per deployment scope (decision 2592): a resource group's resources in that group's template, values passed
between templates as parameters and outputs; what ARM has no form for (or what a later stage translates) stays in a
small Terraform root beside them, with each one's reason.

Lookups become existing resources (a key vault, a subnet of its network) read by id, name or property; the
deployment's own resource group and subscription are resourceGroup() and subscription(); an ephemeral secret becomes a
secure parameter the deployment fills from Key Vault. A child resource names its parent by id or name in Terraform:
here it is the parent's child (parent:), the parent a template resource, an existing lookup, or an existing resource
read from a literal ARM id. Anything the table doesn't know is refused, by name.

An extension resource scoped by an input naming a resource by its ID (input_scopes: a check job's grant on the
Application Insights resource or a registry it is given) is deployed in a module, in the template of the resource it
grants to (the first template resource it reads): the module deploys at the group the ID names (resourceGroup of its
subscription and group segments) and holds the resource on that ID's resource (existing, by the name segment); what
the resource reads of the template is the module's parameters, so equal ones share one module file. Pure.
"""
import json
import posixpath
import re
from collections import namedtuple
from functools import reduce
from types import MappingProxyType

from opsdir.core.manifest import header
from opsdir_format_arm.arm_json import as_arm_json
from opsdir_format_arm.arm_json import referenced
from opsdir_format_arm.bicep import as_bicep, module_files
from opsdir_format_arm.format import ARM_FORMAT, BICEP_FORMAT
from opsdir_format_arm.template import (ArmModule, ArmOutput, ArmParameter, ArmResource, ArmTemplate, Call, Field,
                                        Index, Interp, Member, Param, Prop, ResourceId, ResourceName, is_expression,
                                        symbol)
from opsdir_format_terraform import native
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir_format_terraform.hcl import TfBlock, TfFile
from opsdir_format_terraform.native import (Cx, Forms, Layout, Placement, Table, comments, depends, fields,  # noqa: F401
                                            group_refs, leading, obj, own, placements, placements_document,
                                            read_root, resolver)
from opsdir_format_terraform.translate import (address, no_native_note, output_variable, ref_address, ref_text, roots,
                                               template_parts, value_refs)

LANGUAGE = "ARM"
# Why a resource whose deployment scope (resource group) isn't known statically stays Terraform (Layout.unplaced)
UNPLACED = ("what names its ARM deployment scope (resource group) isn't known statically (unbound in the record, or "
            "an input)")
# How a Terraform resource type is deployed (Native.type of an ARM table row). type: the ARM type; api_version;
# parent: Parent (how Terraform names its parent) or None for a top-level resource; name: the Terraform attribute
# holding its name (segment), or Fixed (a name the type always has, such as a management policy's 'default');
# extends: for an extension resource (a lock, a data collection rule association), the Terraform attribute holding the
# id of the resource it applies to (a template resource: its template, scope: that resource; the subscription or a
# resource group itself: that scope's template, no scope:); fields: the body keys that are top-level fields (default
# FIELDS; a workspace's sku is a property); deploy: 'subscription' or 'tenant' for a type always deployed at that
# scope. name may also be (Fields, Cx) -> the name (a role assignment's guid()); type, (Fields) -> (ARM type, API
# version) for a type each block names (an azapi resource).
Arm = namedtuple("Arm", ("type", "api_version", "parent", "name", "extends", "fields", "deploy"),
                 defaults=(None, "name", None, None, None))
# How a child names its parent: attribute (holding the parent's id, or its name when by is "name": a reference, a
# lookup's id or a literal ARM id), type (the parent's ARM type, for an existing parent), via (the suffix of the
# parent's expansion the child is under, such as a storage account's blobServices 'default': "blob").
Parent = namedtuple("Parent", ("attribute", "type", "by", "via"), defaults=("id", None))
Fixed = namedtuple("Fixed", ("value",))
# What the data table answers for a lookup's attribute (beside values: Member expressions on resourceGroup() or
# subscription(), literals): a Lookup (the existing resource it reads, and what of it: "id", "name" or a property
# path), or a Secure parameter (an ephemeral secret: the deployment fills it from Key Vault).
Existing = namedtuple("Existing", ("type", "api_version", "name", "resource_group", "parent"), defaults=(None, None))
# (an Existing's parent: another Existing, or the symbol of a template resource it is a child of)
Lookup = namedtuple("Lookup", ("existing", "read"))
Secure = namedtuple("Secure", ("description",))
# The top-level fields of an ARM resource: a translated body's keys among them are fields, the rest properties.
FIELDS = ("location", "kind", "sku", "identity", "zones", "tags", "plan", "extendedLocation")


def _concat(*values):
    """Values written one after another: one string, the one value, or an Interp (others' parts spliced in)."""
    values = tuple(v for v in values if v != "")
    if all(isinstance(v, str) for v in values):
        return "".join(values)
    if len(values) == 1:
        return values[0]
    parts = tuple(p for v in values for p in (v.parts if isinstance(v, Interp) else (v,)))
    merged = []
    for p in parts:
        merged[-1:] = [merged[-1] + p] if merged and isinstance(p, str) and isinstance(merged[-1], str) else \
            [*merged[-1:], p]
    return Interp(tuple(merged))


def _trim_prefix(v, prefix):
    """Terraform's trimprefix: a literal, or an interpolation whose leading literal holds the prefix; refused when
    what the value starts with is known only at deploy time."""
    if isinstance(v, str):
        return v.removeprefix(prefix)
    if isinstance(v, Interp) and isinstance(v.parts[0], str) and v.parts[0].startswith(prefix):
        return _concat(v.parts[0][len(prefix):], *v.parts[1:])
    raise SystemExit(f"no ARM form for trimprefix of {v!r}: what it starts with is known only at deploy time")


ARM = native.Target(LANGUAGE, _concat, lambda separator, values: Call("join", (values, separator)), _trim_prefix)


# ------------------------------------------------------------------ resource groups and ids

_ID = re.compile(r"^/subscriptions/(?P<sub>[^/]+)/resourceGroups/(?P<rg>[^/]+)/providers/(?P<ns>[^/]+)/(?P<rest>.+)$")


def parse_id(text):
    """(resource group, ARM type, (name segments)) of a literal ARM resource id in a resource group, else None."""
    m = _ID.match(text) if isinstance(text, str) else None
    parts = m.group("rest").split("/") if m else ()
    if not m or len(parts) % 2:
        return None
    return m.group("rg"), "/".join((m.group("ns"), *parts[0::2])), tuple(parts[1::2])


def _single_ref(v):
    """The one reference a value is (a whole '${...}' interpolation), else None."""
    parts = template_parts(v) if isinstance(v, str) else ()
    return parts[0] if len(parts) == 1 and not isinstance(parts[0], str) and hasattr(parts[0], "kind") else None


def _rg_key(v, by_address):
    """The resource group a resource_group_name value names, statically: its literal name, the name a
    data.azurerm_resource_group block holds, or ('var', name) for a variable's; None when unknown."""
    if isinstance(v, str) and "${" not in v:
        return v
    r = _single_ref(v)
    if r is None:
        return None
    if r.kind == "data" and r.type == "azurerm_resource_group" and r.attr == "name":
        name = fields(by_address[ref_address(r)].body).get("name")
        return name if isinstance(name, str) and "${" not in name else None
    return ("var", r.name) if r.kind == "var" else None


_GROUP_ID = re.compile(r"^/subscriptions/[^/]+/resourceGroups/(?P<rg>[^/]+)/?$")
_SUBSCRIPTION_ID = re.compile(r"^/subscriptions/[^/]+/?$")


def _base(v):
    """(the reference a value starts with, the literal path after it) of an interpolation '${ref}/path' (or of one
    reference, path ''), else None."""
    parts = template_parts(v) if isinstance(v, str) else ()
    if parts and not isinstance(parts[0], str) and hasattr(parts[0], "kind") and \
            all(isinstance(x, str) for x in parts[1:]):
        return parts[0], "".join(parts[1:])
    return None


def named(v, by_address, placed_group, seen=()):
    """(deployment scope key, whether v names that scope itself) of what an id value names, statically: the
    subscription (data.azurerm_subscription's id, a literal subscription id), a resource group itself (a
    data.azurerm_resource_group's id, a literal group id), else the group of the resource it names (a template
    resource's, a lookup's, a literal id's, the resource a path starts from); None when unknown."""
    if isinstance(v, str) and _SUBSCRIPTION_ID.match(v):
        return ("subscription", None), True
    if isinstance(v, str) and _GROUP_ID.match(v):
        return ("resourceGroup", _GROUP_ID.match(v).group("rg")), True
    parsed = parse_id(v)
    if parsed:
        return ("resourceGroup", parsed[0]), False
    found = _base(v)
    r, path = found if found else (None, "")
    target = by_address.get(ref_address(r)) if r is not None else None
    if target is None or ref_address(r) in seen:
        return None
    if r.kind == "data" and r.type == "azurerm_subscription" and r.attr in ("id", "subscription_id"):
        return ("subscription", None), not path
    if r.kind == "data" and r.type == "azurerm_resource_group" and r.attr == "id":
        key = _rg_key(fields(target.body).get("name"), by_address)
        return (("resourceGroup", key), not path) if key is not None else None
    if r.kind == "var" and r.name == "subscription_id":
        return ("subscription", None), not path
    if r.kind == "resource":
        key = placed_group(target, (*seen, ref_address(r)))
        return (key, False) if key is not None else None
    found_fields = fields(target.body)
    if "resource_group_name" in found_fields:
        key = _rg_key(found_fields["resource_group_name"], by_address)
        return (("resourceGroup", key), False) if key is not None else None
    if "resource_id" in found_fields:                                   # an azapi lookup by id
        return named(found_fields["resource_id"], by_address, placed_group, (*seen, ref_address(r)))
    parent_ref = next((_single_ref(x) for x in found_fields.values() if _single_ref(x) is not None), None)
    return named("${" + ref_text(parent_ref) + "}", by_address, placed_group, (*seen, ref_address(r))) \
        if parent_ref is not None else None


def input_scope(v, input_scopes):
    """(the input's name, its resource's ARM type, API version) when a value is one input naming a resource by its ID
    (input_scopes: {name pattern: (ARM type, API version)}), else None."""
    r = _single_ref(v)
    found = next((t for pattern, t in input_scopes.items() if re.fullmatch(pattern, r.name)), None) \
        if r is not None and r.kind == "var" else None
    return (r.name, *found) if found else None


def _input_scoped(b, arm, input_scopes):
    """The input_scope of an extension resource's target, else None."""
    return input_scope(fields(b.body).get(arm.extends), input_scopes) if arm is not None and arm.extends else None


def _grantee_group(b, arm, by_address, placed_group, seen):
    """The scope of the first template resource an input-scoped extension resource reads (its principal's identity,
    say), its depends_on and target aside: the template its module is deployed from; None when it reads none."""
    reads = (r for k, v in b.body if k not in ("depends_on", arm.extends) for r in value_refs(v)
             if r.kind == "resource" and ref_address(r) in by_address and ref_address(r) not in seen)
    return next((g for r in reads for g in (placed_group(by_address[ref_address(r)], (*seen, address(b))),)
                 if g is not None), None)


def _group(b, types, by_address, placed_group, seen=(), input_scopes=MappingProxyType({})):
    """A resource's deployment scope: the scope its type always deploys at; ('resourceGroup', its group's key) by its
    resource_group_name; an input-scoped extension resource's grantee's (_grantee_group); else the scope of what its
    parent attribute or (an extension resource) its target names; None when unknown statically."""
    f = fields(b.body)
    row = types.get(b.labels[0])
    arm = row.type if row is not None and isinstance(row.type, Arm) else None
    if arm is not None and arm.deploy:
        return (arm.deploy, None)
    if "resource_group_name" in f and arm is not None:
        key = _rg_key(f["resource_group_name"], by_address)
        return ("resourceGroup", key) if key is not None else None
    if _input_scoped(b, arm, input_scopes):
        return _grantee_group(b, arm, by_address, placed_group, seen)
    v = f.get(arm.parent.attribute) if arm and arm.parent else f.get(arm.extends) if arm and arm.extends else None
    found = named(v, by_address, placed_group, seen) if v is not None else None
    return found[0] if found else None


def _short(type_):
    return type_.split("_", 1)[1] if "_" in type_ else type_


def _layout_of(types, input_scopes):
    def layout_of(items):
        by_address = {address(b): b for b in items if isinstance(b, TfBlock) and address(b)}

        def group(b, seen=()):
            return _group(b, types, by_address, group, seen, input_scopes)
        return Layout(group, lambda key: None, lambda type_, name: symbol(_short(type_), name),
                      lambda b: UNPLACED if group(b) is None else None)
    return layout_of


def template_name(key):
    """A deployment scope's template file stem: the resource group's name, a variable's name, or the scope."""
    if key is None:
        return "unplaced"
    scope, rg = key
    if scope != "resourceGroup":
        return scope
    return rg[1] if isinstance(rg, tuple) else rg


def _concrete(arm, f):
    """An Arm with its type and API version fixed (a type each block names given by its function)."""
    return arm._replace(type=arm.type(f)[0], api_version=arm.type(f)[1]) if callable(arm.type) else arm


# ------------------------------------------------------------------ a scope's template

def _existing_symbol(e):
    return symbol(e.type.split("/")[-1], e.name if isinstance(e.name, str) else "x")


def _grouped(e, by_address):
    """An Existing (and its parents) with its resource group as a group key: the name its resource_group_name value
    gives statically (a literal, a data.azurerm_resource_group's name, ('var', name)), None for the template's own."""
    if not isinstance(e, Existing):
        return e
    key = _rg_key(e.resource_group, by_address) if e.resource_group is not None else None
    return e._replace(resource_group=key, parent=_grouped(e.parent, by_address))


def _existing_resources(e, here):
    """The existing ArmResources an Existing is read through (its parents first: existing ones, or a template
    resource's symbol), in the template of resource group here (another group's named, a variable's as its
    parameter)."""
    parent = _existing_resources(e.parent, here) if isinstance(e.parent, Existing) else ()
    other = None if e.resource_group in (None, here) or e.parent is not None else e.resource_group
    group = Param(other[1]) if isinstance(other, tuple) else other
    parent_symbol = _existing_symbol(e.parent) if isinstance(e.parent, Existing) else e.parent
    return (*parent, ArmResource(_existing_symbol(e), e.type, e.api_version, e.name, parent=parent_symbol,
                                 existing=True, resource_group=group))


def _read(sym, read):
    """What a reference reads of a resource: its id, its name, a top-level field (location, identity.principalId) or
    a property path."""
    if read in ("id", "name"):
        return ResourceId(sym) if read == "id" else ResourceName(sym)
    return Field(sym, read) if read.split(".")[0] in FIELDS else Prop(sym, read)


def _parameter_name(r):
    return re.sub(r"[^A-Za-z0-9_]", "_", output_variable(r))


# A value with what it reads that its template declares (existing resources, secure parameters), as a lookup answers
# while a template's resources are built; _declarations takes the markers out and collects what they carry.
Declared = namedtuple("Declared", ("declarations", "value"))


def _declarations(v):
    """(v without Declared markers, the declarations they carry, in order): a template's resources and outputs as
    written, and the existing resources and secure parameters the template declares besides them."""
    if isinstance(v, Declared):
        value, inner = _declarations(v.value)
        return value, (*v.declarations, *inner)
    if isinstance(v, (Interp, Call)):
        found = tuple(_declarations(x) for x in (v.parts if isinstance(v, Interp) else v.args))
        values = tuple(x for x, _ in found)
        return (Interp(values) if isinstance(v, Interp) else Call(v.function, values)), \
            tuple(d for _, ds in found for d in ds)
    if isinstance(v, Member):
        value, inner = _declarations(v.value)
        return Member(value, v.path), inner
    if is_expression(v):
        return v, ()
    if isinstance(v, dict):
        found = tuple((_declarations(k), _declarations(x)) for k, x in v.items())
        return {k: x for (k, _), (x, _) in found}, tuple(d for (_, dk), (_, dx) in found for d in (*dk, *dx))
    if isinstance(v, (list, tuple)):
        found = tuple(_declarations(x) for x in v)
        values = tuple(x for x, _ in found)
        return (list(values) if isinstance(v, list) else values), tuple(d for _, ds in found for d in ds)
    return v, ()


def _forms(rg, by_address, value, deployed=lambda type_, name: None):
    """ARM's Forms for the template of resource group rg: a lookup's answer and a secure parameter's are Declared,
    carrying the existing resource (and its parent's) or the parameter the template declares; value(Terraform value)
    -> ARM value (a lookup's parent named by a reference, such as a key's vault); deployed(ARM type, name) -> the
    symbol of a resource the template deploys with them, which a lookup of it in the template's own group reads
    instead (no existing declared beside it)."""
    def answer(r, found):
        if isinstance(found, Lookup):
            parent = found.existing.parent
            named_parent, carried = _declarations(value(parent)) if isinstance(parent, str) and "${" in parent \
                else (None, ())
            if named_parent is not None and not isinstance(named_parent, (ResourceId, ResourceName)):
                raise SystemExit(f"{ref_text(r)}: no ARM form for its parent {parent!r}")
            existing = _grouped(found.existing._replace(parent=named_parent.symbol) if named_parent is not None
                                else found.existing, by_address)
            own = deployed(existing.type, existing.name) if existing.parent is None and \
                existing.resource_group in (None, rg) and isinstance(existing.name, str) else None
            if own is not None:
                return _read(own, found.read)
            return Declared((*carried, existing), _read(_existing_symbol(existing), found.read))
        if isinstance(found, Secure):
            name = _parameter_name(r)
            return Declared((ArmParameter(name, "string", None, found.description, secure=True),), Param(name))
        return found(rg) if callable(found) else found
    return Forms(lambda sym, form: _read(sym, form), lambda r: Param(_parameter_name(r)), lambda name: Param(name),
                 answer)


def _variable_parameter(name, b):
    f = fields(b.body)
    kind = str(f.get("type", "${string}"))[2:-1].replace(" ", "")
    arm = {"number": "int", "bool": "bool", "list(string)": "array"}.get(kind, "string")
    default = f.get("default")
    return ArmParameter(name, arm, default if isinstance(default, (str, int, float, bool, list)) else None,
                        f.get("description"), secure=bool(f.get("sensitive")))


def _api(apis, type_, where):
    if type_ not in apis:
        raise SystemExit(f"{where}: no API version known for existing {type_} (add it to the table's APIS)")
    return apis[type_]


def _deployed(root, group, type_, name, parent=None):
    """The symbol of a resource the template of group deploys with that ARM type and name (and parent symbol, for a
    child), else None: what a literal id or a path names when the template deploys it itself."""
    return next((q.id for q in root.placed.values() if q.target is None and q.group == group
                 and isinstance(q.native.type, Arm) and q.native.type.type == type_
                 and fields(root.by_address[q.address].body).get("name") == name), None)


def _target_symbol(p, attribute, v, cx, root, parent_type, apis, by="id"):
    """(symbol, declarations) of the resource a value names by id (or by name): a template resource's (also one a
    literal id names), or an existing one (a lookup's, a literal id's, one named by a value; its API version the
    table's for its type), with the existing resources the template declares for it."""
    parsed = parse_id(v) if isinstance(v, str) and by == "id" else None
    if parsed and len(parsed[2]) == 1 and _deployed(root, p.group, parsed[1], parsed[2][0]):
        return _deployed(root, p.group, parsed[1], parsed[2][0]), ()
    if parsed:
        e = Existing(parsed[1], _api(apis, parsed[1], p.address), parsed[2][-1], parsed[0])
        return _existing_symbol(e), (e,)
    r = _single_ref(v)
    if r is not None and r.kind == "resource" and ref_address(r) in root.placed:
        return root.placed[ref_address(r)].id, ()
    value, carried = _declarations(cx.value(v))
    if isinstance(value, (ResourceId, ResourceName)):
        return value.symbol, carried
    if by == "name" and parent_type:
        e = Existing(parent_type, _api(apis, parent_type, p.address), value)
        return _existing_symbol(e), (*carried, e)
    raise SystemExit(f"{p.address}: no ARM form for {attribute} = {v!r}")


def _types_of(root, declarations):
    """{symbol: ARM type} of the template resources and the existing resources among declarations."""
    placed = {p.id: p.native.type.type for p in root.placed.values()
              if p.target is None and isinstance(p.native.type, Arm) and not callable(p.native.type.type)}
    return {**placed, **{_existing_symbol(e): e.type for e in declarations if isinstance(e, Existing)}}


def _scope(p, v, cx, root, apis):
    """(symbol, declarations) of an extension resource's scope: (None when it applies to the subscription or a
    resource group itself, deployed in that scope's template): a template resource, a lookup, a literal id's existing
    resource, or the child a path names under one of those (a key vault secret, a container), a template resource of
    that type and name when there is one; with the existing resources the template declares for it."""
    found = named(v, root.by_address, lambda b, seen=(): root.layout.group(b, seen))
    if found is not None and found[1]:
        return None, ()
    base = _base(v)
    if base is None or not base[1]:
        return _target_symbol(p, p.native.type.extends, v, cx, root, None, apis)
    ref, path = base
    start, carried = _declarations(cx.value("${" + ref_text(ref) + "}"))
    segments = path.strip("/").split("/")
    if segments[0] == "providers":                                      # a resource under a group's id
        rg = found[0][1] if found else None
        type_ = "/".join((segments[1], *segments[2::2]))
        e = Existing(type_, _api(apis, type_, p.address), segments[3], rg)
        return _existing_symbol(e), (*carried, e)
    if not isinstance(start, (ResourceId, ResourceName)):
        raise SystemExit(f"{p.address}: no ARM form for the scope {v!r}")

    def step(at, segment):
        """(symbol, type, declarations) one path segment further: a template resource or an expansion of that type
        and name, else an existing child of what came before."""
        parent, kind, declared = at
        here = f"{kind}/{segment[0]}"
        match = _deployed(root, p.group, here, segment[1]) or _expansion(root, parent, here, segment[1], cx)
        e = None if match else Existing(here, _api(apis, here, p.address), segment[1], None, parent)
        return (match, here, declared) if match else (_existing_symbol(e), here, (*declared, e))
    sym, _, declared = reduce(step, zip(segments[0::2], segments[1::2]),
                              (start.symbol, _types_of(root, carried).get(start.symbol), carried))
    return sym, declared


def _expansion(root, sym, type_, name, cx):
    """The symbol of what a template resource expands into with that ARM type and name (a storage account's
    blobServices 'default'), else None."""
    p = next((q for q in root.placed.values() if q.id == sym and q.target is None and q.native.expand), None)
    if p is None:
        return None
    f = fields(root.by_address[p.address].body)
    return next((f"{sym}_{x[0]}" for x in p.native.expand(sym, f, cx._replace(where=p.address))
                 if x[1].type == type_ and (x[1].name.value if isinstance(x[1].name, Fixed) else x[2].get("name"))
                 == name), None)


def _parent(p, f, cx, root, apis):
    """(symbol, declarations) of a child's parent (or of the expansion of it the child is under, Parent.via)."""
    arm = p.native.type
    found, declared = _target_symbol(p, arm.parent.attribute, f.get(arm.parent.attribute), cx, root, arm.parent.type,
                                     apis, arm.parent.by)
    return (f"{found}_{arm.parent.via}" if arm.parent.via else found), declared


def _body(p, root, cx):
    """(fields, properties, declarations) of a placed resource with what merges into it: its translated body split at
    FIELDS, its tags among the fields; what it reads that the template declares."""
    f = fields(root.by_address[p.address].body)
    here = cx._replace(where=p.address)
    own_props = (obj(own(f), here, p.native.properties) if isinstance(p.native.properties, dict)
                 else p.native.properties(f, here))
    merged = reduce(lambda props, m: m.native.merge.into(props, fields(root.by_address[m.address].body),
                                                         cx._replace(where=m.address)),
                    (m for m in root.placed.values() if m.target == p.address), own_props)
    props = p.native.finish(merged) if p.native.finish else merged
    tags = f.get("tags")
    if tags and p.native.tags is None:
        raise SystemExit(f"{p.address}: tagged in Terraform, but its ARM type takes no tags")
    key = "tags" if p.native.tags_key == "Tags" else p.native.tags_key   # ARM's tags; a row may name another key
    body, declared = _declarations({**props, **({key: _tags_over(props.get(key), cx.value(tags))} if tags else {})})
    return (*_split(body, p.native.type), declared)


def _tags_over(own_tags, tags):
    """Terraform's tags over the tags a row writes itself (a web test's hidden-link): merged, by union() when either
    is an expression."""
    if not own_tags:
        return tags
    return {**own_tags, **tags} if isinstance(own_tags, dict) and isinstance(tags, dict) and \
        not is_expression(own_tags) and not is_expression(tags) else Call("union", (own_tags, tags))


def _split(body, arm):
    """(fields, properties) of a translated body: its top-level keys (Arm.fields, else FIELDS) and the rest."""
    top = arm.fields if arm.fields is not None else FIELDS
    return {k: v for k, v in body.items() if k in top}, {k: v for k, v in body.items() if k not in top}


def _unself(v, sym, own_id, name):
    """v with a resource's references to itself as Bicep allows them inside its own declaration: its id as
    resourceId() of its type and name, its name as the value; its runtime properties refused (it has none yet)."""
    if isinstance(v, ResourceId) and v.symbol == sym:
        return own_id
    if isinstance(v, ResourceName) and v.symbol == sym:
        return name
    if isinstance(v, Prop) and v.symbol == sym:
        raise SystemExit(f"{sym}: reads its own runtime property {v.path}, which ARM can't")
    if isinstance(v, Interp):
        return _concat(*(_unself(x, sym, own_id, name) for x in v.parts))
    if isinstance(v, Call):
        return Call(v.function, tuple(_unself(x, sym, own_id, name) for x in v.args))
    if isinstance(v, Member):
        return Member(_unself(v.value, sym, own_id, name), v.path)
    if is_expression(v):
        return v
    if isinstance(v, dict):
        return {k: _unself(x, sym, own_id, name) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_unself(x, sym, own_id, name) for x in v]
    return v


def _expanded(p, x):
    """(the ArmResource an expansion of resource p is (a storage account's blob service), its declarations)."""
    suffix, sub, raw = x[:3]
    body, declared = _declarations(raw)
    top, rest = _split({k: v for k, v in body.items() if k != "name"}, sub)
    return ArmResource(f"{p.id}_{suffix}", sub.type, sub.api_version,
                       sub.name.value if isinstance(sub.name, Fixed) else body["name"], p.id if sub.parent else None,
                       top, rest or None), declared


def _resource(p, root, members, cx, notes_above, apis, ids):
    """(the ArmResources of one standalone member (a child under its parent) with what merges into it, and what it
    expands into; what they read that the template declares)."""
    b = root.by_address[p.address]
    f = fields(b.body)
    arm = _concrete(p.native.type, f)
    field_values, props, body_declared = _body(p, root, cx)
    parent, parent_declared = _parent(p, f, cx, root, apis) if arm.parent else (None, ())
    scope, scope_declared = _scope(p, f.get(arm.extends), cx, root, apis) if arm.extends else (None, ())
    name, name_declared = _declarations(arm.name.value if isinstance(arm.name, Fixed) else
                                        arm.name(f, cx._replace(where=p.address)) if callable(arm.name) else
                                        cx.value(f[arm.name]))
    merged = tuple(m for m in members if m.target == p.address)
    notes = (*notes_above.get(p.address, ()), *comments(b.body),
             *(c for m in merged for c in (*notes_above.get(m.address, ()),
                                            *comments(root.by_address[m.address].body))))
    after = tuple(dict.fromkeys(d for m in (p, *(m for m in merged if m.native.merge.ordering))
                                for d in depends(root, m, ids)))
    own_id = Call("resourceId", (arm.type, name)) if parent is None and scope is None else None
    top, rest = (_unself(field_values, p.id, own_id, name), _unself(props, p.id, own_id, name)) \
        if own_id is not None else (field_values, props)
    expansions = tuple(_expanded(p, x) for x in (p.native.expand(p.id, f, cx._replace(where=p.address))
                                                  if p.native.expand else ()))
    return ((ArmResource(p.id, arm.type, arm.api_version, name, parent, top, rest or None, after, scope=scope,
                         comment="; ".join(notes) or None), *(r for r, _ in expansions)),
            (*body_declared, *parent_declared, *scope_declared, *name_declared,
             *(d for _, ds in expansions for d in ds)))


_CONTEXT = ("resourceGroup", "subscription", "deployment", "tenant", "managementGroup")


def _outer(v):
    """Whether a value reads the template a module is deployed from (its resources, parameters or deployment
    context): what the module takes as a parameter."""
    if isinstance(v, Call) and v.function in _CONTEXT:
        return True
    if isinstance(v, (Call, Interp, Member, Index)):
        return any(_outer(x) for x in (v.args if isinstance(v, Call) else v.parts if isinstance(v, Interp) else
                                       (v.value,) if isinstance(v, Member) else (v.value, v.index)))
    if isinstance(v, dict):
        return any(_outer(k) or _outer(x) for k, x in v.items())
    if isinstance(v, (list, tuple)) and not is_expression(v):
        return any(_outer(x) for x in v)
    return bool(referenced(v)) or bool(_params(v))


def _lifted(v, path):
    """(v with each value that reads the outer template a parameter of the module, named by its key path; {parameter:
    the outer value})."""
    whole = is_expression(v) or (isinstance(v, dict) and any(_outer(k) for k in v))   # an expression key: all of it
    if whole and _outer(v):
        name = "_".join(path)
        return Param(name), {name: v}
    if isinstance(v, dict):
        parts = {k: _lifted(x, (*path, str(k))) for k, x in v.items()}
        return {k: x for k, (x, _) in parts.items()}, {n: o for _, (_, g) in parts.items() for n, o in g.items()}
    if isinstance(v, (list, tuple)) and not is_expression(v):
        parts = [_lifted(x, (*path, str(i))) for i, x in enumerate(v)]
        return [x for x, _ in parts], {n: o for _, given in parts for n, o in given.items()}
    return v, {}


def _kebab(type_):
    return re.sub(r"(?<!^)(?=[A-Z])", "-", type_.split("/")[-1]).lower()


def _module(p, root, members, cx, notes_above, ids, scoped):
    """(the ArmModule deploying input-scoped extension resource p at the group its input's ID names: the resource on
    that ID's resource (existing, by its name segment), what it reads of the template its parameters; what it reads
    that the template declares)."""
    variable, target_type, target_api = scoped
    b = root.by_address[p.address]
    f = fields(b.body)
    arm = _concrete(p.native.type, f)
    field_values, props, declared = _body(p, root, cx)
    name, name_declared = _declarations(arm.name.value if isinstance(arm.name, Fixed) else
                                        arm.name(f, cx._replace(where=p.address)) if callable(arm.name) else
                                        cx.value(f[arm.name]))
    (inner_name, inner_fields, inner_props), given = (
        lambda parts: (tuple(x for x, _ in parts), {n: o for _, g in parts for n, o in g.items()}))(
        (_lifted(name, ("name",)), _lifted(field_values, ()), _lifted(props, ())))
    part = lambda i: Index(Call("split", (Param(variable), "/")), i)                       # noqa: E731
    template = ArmTemplate("resourceGroup", None, (
        ArmResource("target", target_type, target_api, Param("targetName"), existing=True),
        ArmResource(symbol(_kebab(arm.type)), arm.type, arm.api_version, inner_name, None, inner_fields,
                    inner_props or None, scope="target")),
        tuple(ArmParameter(n, "string") for n in (*given, "targetName")))
    notes = (*notes_above.get(p.address, ()), *comments(b.body))
    return ArmModule(p.id, p.id[:64], template, part(2), part(4), {**given, "targetName": part(8)},
                     f"{_kebab(arm.type)}-{_kebab(target_type)}", depends(root, p, ids),
                     "; ".join(notes) or None), (*declared, *name_declared)


def _resources(root, members, cx, notes_above, apis, input_scopes):
    """(the ArmResources of a scope's template: each standalone member (a child under its parent) with what merges
    into it, and what it expands into; what they read that the template declares, in order; the ArmModules of its
    input-scoped extension resources)."""
    ids = {p.id for p in members}
    scoped = {p.address: _input_scoped(root.by_address[p.address], p.native.type, input_scopes) for p in members
              if p.target is None and isinstance(p.native.type, Arm)}
    built = tuple(_resource(p, root, members, cx, notes_above, apis, ids) for p in members
                  if p.target is None and not scoped.get(p.address))
    modules = tuple(_module(p, root, members, cx, notes_above, ids, scoped[p.address]) for p in members
                    if p.target is None and scoped.get(p.address))
    return (tuple(r for rs, _ in built for r in rs), (*(d for _, ds in built for d in ds),
                                                       *(d for _, ds in modules for d in ds)),
            tuple(mod for mod, _ in modules))


def _scope_template(m, root, key, table, what, apis, main, input_scopes):
    """The ArmTemplate of one deployment scope of the root."""
    members = tuple(p for p in root.placed.values() if p.group == key)
    rg = key[1] if key[0] == "resourceGroup" else None
    resolve = resolver(root, key, table, ARM, _forms(rg, root.by_address, lambda v: native.translate(v, resolve, ARM),
                                                     lambda type_, name: _deployed(root, key, type_, name)))
    cx = Cx(lambda v: native.translate(v, resolve, ARM), root.by_address.get, None, lambda a: root.placed[a].id,
            lambda name: Param(name), lambda alias: None, "", LANGUAGE)
    notes_above, loose = leading(root.split.native)
    refs = group_refs(root, members, table.data)
    resources, declared, modules = _resources(root, members, cx, notes_above, apis, input_scopes)
    written = tuple((o, *_declarations(o.value)) for o in _outputs(root, key, members, resolve, table.data))
    outputs = tuple(o._replace(value=v) for o, v, _ in written)
    declarations = (*declared, *(d for _, _, ds in written for d in ds))
    variables = tuple(_variable_parameter(r.name, root.by_address[ref_address(r)]) for r in refs if r.kind == "var")
    crossing = tuple(r for r in refs if r.kind == "resource" and root.placed[ref_address(r)].group != key)
    cross = tuple(ArmParameter(_parameter_name(r), "string", None, f"{ref_text(r)}: an output of template "
                               f"{template_name(root.placed[ref_address(r)].group)} (deployed first)")
                  for r in crossing)
    existing = tuple({r.symbol: r for e in declarations if isinstance(e, Existing)
                      for r in _existing_resources(e, rg)}.values())
    secure = tuple(e for e in declarations if isinstance(e, ArmParameter))
    used = _params((*existing, *resources, *modules)) | _params(tuple(o.value for o in outputs))
    parameters = tuple({p.name: p for p in (*variables, *cross, *secure) if p.name in used}.values())
    where = f"resource group {template_name(key)}" if key[0] == "resourceGroup" else f"the {key[0]}"
    return ArmTemplate(key[0], f"{what} ({m.label}): the Terraform root {root.directory} as ARM, {where}",
                       (*existing, *resources), parameters, outputs, tuple(loose) if main else (), modules)


def _params(v):
    """The names of the parameters a value (resources, a body) reads; a variable naming only the resource group a
    template deploys into is none of them (the deployment names the group)."""
    if isinstance(v, Param):
        return frozenset((v.name,))
    if isinstance(v, ArmResource):
        return _params((v.name, v.fields, v.properties))
    if isinstance(v, ArmModule):
        return _params((v.name, v.subscription, v.resource_group, v.params))
    if isinstance(v, Index):
        return _params((v.value, v.index))
    if isinstance(v, (Interp, Call)):
        return _params(v.parts if isinstance(v, Interp) else v.args)
    if isinstance(v, Member):
        return _params(v.value)
    if isinstance(v, dict):
        return frozenset(n for k, x in v.items() for n in (*_params(k), *_params(x)))
    if isinstance(v, (list, tuple)) and not is_expression(v):
        return frozenset(n for x in v for n in _params(x))
    return frozenset()


def _outputs(root, key, members, resolve, data):
    """The template's outputs: values of its resources the side Terraform root or another template reads."""
    others = tuple(r for p in root.placed.values() if p.group != key for r in group_refs(root, (p,), data)
                   if r.kind == "resource" and root.placed.get(ref_address(r)) in members)
    wanted = tuple(dict.fromkeys((*(r for r in root.split.outputs if root.placed[ref_address(r)] in members),
                                  *others)))
    return tuple(ArmOutput(_parameter_name(r), "string", resolve(r)) for r in wanted)


def native_directory(directory, target):
    """Where a Terraform root's templates go for a target (bicep, arm): terraform/<rest> -> <target>/<rest>."""
    rest = directory.split("/", 1)[1] if "/" in directory else ""
    return posixpath.join(target, rest) if rest else target


# An environment's translation: templates {(root directory, scope key): ArmTemplate}, side {root directory: TfFile
# body items and NOTE} (as (head, items)), placements {root directory: {address: Placement}} by scope key.
Translation = namedtuple("Translation", ("templates", "side", "placements"))


def _root_translation(m, root, table, what, apis, input_scopes):
    unknown = sorted(p.address for p in root.placed.values() if p.group is None)
    if unknown:
        raise SystemExit(f"{', '.join(unknown)}: the deployment scope (resource group) isn't known statically: what "
                         "names it is neither a literal, a lookup nor a resource the root writes")
    keys = sorted(dict.fromkeys(p.group for p in root.placed.values()), key=lambda k: str(k))
    counts = {k: sum(p.group == k for p in root.placed.values()) for k in keys}
    main = max(keys, key=lambda k: (counts[k], k[0] == "resourceGroup")) if keys else None   # the root's notes' home
    templates = {(root.directory, k): _scope_template(m, root, k, table, what, apis, k == main, input_scopes)
                 for k in keys}
    side = (no_native_note(root.split, "Azure Resource Manager", root.reasons), root.split.side) \
        if root.split.side else None
    return templates, side, placements(root, {k: template_name(k) for k in keys}, "terraform/main.tf")


def translation(m, files, types, no_native, data, what, kept=None, apis=None, input_scopes=None):
    """The ARM Translation of environment m's Azure Terraform render by a table: per root, one template per
    deployment scope, the side Terraform root (with each kept resource's reason) and where each resource went; apis:
    {ARM type: API version} of the existing resources read by literal id or by name; input_scopes: {input name
    pattern: (ARM type, API version)} of the inputs naming a resource by its ID (input_scope)."""
    table = Table(types, no_native, data, lambda type_, region: False, kept or {})
    scopes = input_scopes or MappingProxyType({})
    parts = {d: _root_translation(m, read_root(d, rf, table, LANGUAGE, _layout_of(types, scopes)), table, what,
                                  apis or {}, scopes)
             for d, rf in roots(files).items()}
    return Translation({k: v for t, _, _ in parts.values() for k, v in t.items()},
                       {d: s for d, (_, s, _) in parts.items() if s is not None},
                       {d: p for d, (_, _, p) in parts.items()})


def _bicep_modules(m, what, templates):
    """({module symbol: path its module statement names}, {path: text}) of the module files of one root's templates
    (bicep/<rest>/modules/, each distinct template once, for all its templates together)."""
    stems, texts = module_files(tuple(mod for t in templates.values() for mod in t.modules))
    return ({sym: f"./modules/{stem}.bicep" for sym, stem in stems.items()},
            {f"modules/{stem}.bicep": header(m, f"{what}: ARM (module {stem}.bicep)", BICEP_FORMAT) + text
             for stem, text in texts.items()})


def translated(m, files, types, no_native, data, what, targets, kept=None, apis=None, input_scopes=None):
    """{path: TfFile | text} of environment m's ARM templates for each target asked (bicep: .bicep files under bicep/,
    with their modules' files under modules/ beside them; arm: ARM JSON under arm/, modules inline), each with its side
    Terraform root and its placements.json (where each Terraform resource went, the files named as that target writes
    them)."""
    t = translation(m, files, types, no_native, data, what, kept, apis, input_scopes)
    by_root = {d: {k: x for (d2, k), x in t.templates.items() if d2 == d}
               for d in dict.fromkeys(d for d, _ in t.templates)}
    modules = {d: _bicep_modules(m, what, ts) for d, ts in by_root.items()}
    writers = {"bicep": (".bicep", BICEP_FORMAT, lambda x, d: as_bicep(x, lambda mod: modules[d][0][mod.symbol])),
               "arm": (".json", ARM_FORMAT, lambda x, d: as_arm_json(x))}
    out = {}
    for target in targets:
        ext, fmt, write = writers[target]
        if target == "bicep":
            out.update({posixpath.join(native_directory(d, target), p): text for d, (_, files_) in modules.items()
                        for p, text in files_.items()})
        for (directory, key), template in t.templates.items():
            path = posixpath.join(native_directory(directory, target), template_name(key) + ext)
            out[path] = header(m, f"{what}: ARM ({posixpath.basename(path)})", fmt) + write(template, directory)
        for directory, (head, items) in t.side.items():
            out[posixpath.join(native_directory(directory, target), "terraform", "main.tf")] = \
                TfFile(header(m, f"{what}: what ARM has no form for", HCL) + head, items)
        for directory, places in t.placements.items():
            out[posixpath.join(native_directory(directory, target), "placements.json")] = json.dumps(
                placements_document(places, lambda where, ext=ext: where if where.endswith(".tf") else where + ext),
                indent=2) + "\n"
    return out
