"""AWS CloudFormation translated from the AWS render's Terraform data (5.6, decision 2565): each Terraform root becomes
a template (one per provider: a resource on an aliased provider runs in another region or account, so in another
stack), what CloudFormation has no form for stays in a small Terraform root beside it (format-terraform translate),
and the lookups Terraform makes become parameters (the record's ids as defaults) or pseudo parameters.

The engine is generic over a table of Natives (cfn_types holds AWS's): how each Terraform resource type is written,
which attributes a reference reads, which resources merge into another (an S3 bucket's settings into the bucket) or
expand into several (a route table's routes). Anything the table doesn't know is refused, by name: a translation
never drops or guesses. Pure.
"""
import json
import posixpath
import re
from collections import namedtuple

from opsdir.core.manifest import header
from opsdir_format_cloudformation.format import YAML_FORMAT, as_yaml
from opsdir_format_cloudformation.template import Output, Parameter, Resource, Template, get_att, lint_metadata, \
    logical_id, ref, select, sub
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir_format_terraform.hcl import Block, TfBlock, TfFile
from opsdir_format_terraform.translate import Raw, TfRef, address, is_quoted_string, no_native_note, output_variable, \
    parse_ref, ref_address, ref_text, root_items, roots, split_root, template_parts, value_refs

# How one Terraform resource type is written in CloudFormation. type: its CloudFormation type (None: merged into
# another resource, see merge). properties: a spec (see obj) of its attributes, or (Fields, Cx) -> the resource's
# properties (its tags, depends_on and provider are the engine's). refs:
# {Terraform attribute: "Ref" | a GetAtt attribute name | (logical id) -> value}: what a reference to it reads.
# identifier: the property naming an existing one for a resource import (its Terraform import id the value), or
# (Terraform import id) -> {property: value}; None when CloudFormation can't import it from what Terraform imports it
# by (an adopted one then stays Terraform, beside the template). tags: how the resource's tags (with the provider's
# default tags under them) are written: "list" ([{Key, Value}]) or "map", under tags_key; None when the type takes no
# tags (a block with tags is then refused). merge: Merge, for a type that is part of another resource. expand:
# (logical id, Fields, Cx) -> ((logical id suffix, type, properties[, (the parent's import id) -> its import
# identifier]), ...): further resources it is written as (an adopted parent's expansions are imported with it, so each
# must say how). parameters: (Fields, Cx) -> Parameters it needs the deployer to give (what Terraform looks up and
# CloudFormation can't). finish: (properties) -> properties, once what merges into it is in.
Native = namedtuple("Native", ("type", "properties", "refs", "identifier", "tags", "merge", "expand", "parameters",
                               "tags_key", "finish"),
                    defaults=(None, {}, None, None, None, None, None, "Tags", None))
# A Terraform resource type that is part of another resource natively. via: its attribute referencing that resource;
# into: (the target's properties, Fields, Cx) -> the target's properties with this one's merged in. refs: what a
# reference to the merged resource reads, of the target ({attribute: as Native.refs}). ordering: whether its depends_on
# orders the target (False where the native resource does what the ordering was for).
Merge = namedtuple("Merge", ("via", "into", "refs", "ordering"), defaults=({}, True))
# What the data table answers for an attribute of a data source (data[type](Fields, attribute)): a pseudo parameter
# (Pseudo: its name), a Parameter the deployer gives (its logical_id a suffix to the one made from the block's
# address, '' for none; the record's id as its default where the record holds one), a value derived from such a
# parameter (Derived: make(the parameter's Ref) -> value), any other value as it is, or None when the attribute has
# no native form.
Pseudo = namedtuple("Pseudo", ("name",))
Derived = namedtuple("Derived", ("parameter", "make"))
# What a mapping function is given beside a block's Fields: value(Terraform value) -> the CloudFormation value;
# block(address) -> the root's TfBlock at that address (a data source a resource reads, say), or None; region: the
# region of the template the resource is in; logical(address) -> the logical id of a resource the root writes
# natively; param(name) -> the Ref of a Parameter this resource's parameters() declare, by its logical id;
# provider_region(alias) -> the region of the root's provider with that alias; where: the address of the block being
# translated (for refusals).
Cx = namedtuple("Cx", ("value", "block", "region", "logical", "param", "provider_region", "where"),
                defaults=("",))
# A spec of a block's attributes (obj): {Terraform key: a CloudFormation name (the value translated), a Nest (nested
# blocks as an object, or a list of objects when many), a Custom (make(Terraform value, Cx) -> {CloudFormation name:
# value}, any number of them), or None (a Terraform-only attribute, deliberately not written)}.
Nest = namedtuple("Nest", ("name", "spec", "many"), defaults=(False,))
Custom = namedtuple("Custom", ("make",))
# The attributes the engine writes itself, never a spec's.
ENGINE_KEYS = ("tags", "depends_on", "provider")


def fields(body):
    """A block body as {key: value}, a nested block's key giving a tuple of its blocks' Fields (in order, repeated
    blocks each one); comments left out."""
    keys = dict.fromkeys(k for k, _ in body if k != "#")
    return {k: (tuple(fields(v.body) for kk, v in body if kk == k)
                if any(isinstance(v, Block) for kk, v in body if kk == k)
                else next(v for kk, v in body if kk == k)) for k in keys}


def one(f, key):
    """The single nested block under key, as Fields ({} when there is none)."""
    blocks = f.get(key) or ()
    return blocks[0] if blocks else {}


def comments(body, path=""):
    """Every comment inside a block body, nested blocks' ones prefixed with where they are."""
    return tuple(c for k, v in body
                 for c in ((f"{path}{v}",) if k == "#" else
                           comments(v.body, f"{path}{k}: ") if isinstance(v, Block) else ()))


def tag_list(tags):
    """{key: value} as CloudFormation's Tags list."""
    return [{"Key": k, "Value": v} for k, v in tags.items()]


def pascal(key):
    """A Terraform attribute name as CloudFormation's (snake_case to PascalCase), for the many that only differ so."""
    return "".join(w[:1].upper() + w[1:] for w in key.split("_"))


def obj(f, cx, spec, where=None):
    """Fields as a CloudFormation object by a spec; refuses an attribute the spec doesn't name (a translation never
    drops what it doesn't know) and more than one block where the spec takes one."""
    where = where or cx.where
    unknown = sorted(k for k in f if k not in spec)
    if unknown:
        raise SystemExit(f"{where}: no CloudFormation form for {', '.join(unknown)}")

    def part(k, v):
        form = spec[k]
        if form is None:
            return {}
        if isinstance(form, str):
            return {form: cx.value(v)}
        if isinstance(form, Custom):
            return form.make(v, cx)
        objects = [obj(b, cx, form.spec, f"{where}.{k}") for b in v]
        if not form.many and len(objects) != 1:
            raise SystemExit(f"{where}.{k}: one block expected, found {len(objects)}")
        return {form.name: objects if form.many else objects[0]}
    return {n: x for k, v in f.items() for n, x in part(k, v).items()}


def own(f):
    """A block's Fields without the attributes the engine writes."""
    return {k: v for k, v in f.items() if k not in ENGINE_KEYS}


# ------------------------------------------------------------------ values

def _sub_text(text):
    """Literal text inside Fn::Sub: '${' written '${!' so it stays text."""
    return text.replace("${", "${!")


def _sub_part(expr, n):
    """(text, variables) of a resolved reference inside Fn::Sub: ${Name} / ${Name.Attribute}, a literal as itself, any
    other function under a variable of its own (V<n>)."""
    if isinstance(expr, str):
        return _sub_text(expr), {}
    if set(expr) == {"Ref"}:
        return "${" + expr["Ref"] + "}", {}
    if set(expr) == {"Fn::GetAtt"}:
        return "${" + ".".join(expr["Fn::GetAtt"]) + "}", {}
    return "${V" + str(n) + "}", {f"V{n}": expr}


_INDEXED = re.compile(r"^(?:tolist\((?P<a>[^()]+)\)|(?P<b>[^()\[\]]+))\[(?P<i>\d+)\]$")


def _raw(raw, resolve):
    """A CloudFormation value for an expression that is more than one reference: a quoted template string, a
    jsonencode() document (its strings translated in turn), an element of a list a reference reads (tolist(x)[0],
    x[0]: the reference with that index). Refused otherwise, naming it."""
    text = raw.text.strip()
    if is_quoted_string(text):
        return translate(json.loads(text), resolve, quoted=True)
    if text.startswith("jsonencode(") and text.endswith(")"):
        return _document(json.loads(text[len("jsonencode("):-1]), resolve)
    m = _INDEXED.match(text)
    r = parse_ref((m.group("a") or m.group("b")).strip()) if m else None
    if r is not None:
        return resolve(r._replace(attr=f"{r.attr}[{m.group('i')}]"))
    raise SystemExit(f"no CloudFormation form for the Terraform expression {text!r}")


def _raw_refs(raw):
    """The references an expression's translation (_raw) resolves: a jsonencode() document's, an indexed reference
    with its index."""
    text = raw.text.strip()
    if is_quoted_string(text):
        return translated_refs(json.loads(text), quoted=True)
    if text.startswith("jsonencode(") and text.endswith(")"):
        return translated_refs(json.loads(text[len("jsonencode("):-1]), quoted=True)
    m = _INDEXED.match(text)
    r = parse_ref((m.group("a") or m.group("b")).strip()) if m else None
    return (r._replace(attr=f"{r.attr}[{m.group('i')}]"),) if r is not None else raw.refs


def translated_refs(v, quoted=False):
    """Every reference translate() resolves in a value (a body, through nested blocks), in order, each once; quoted:
    strings are a quoted template's content (see template_parts)."""
    if isinstance(v, str):
        return tuple(dict.fromkeys(r for p in template_parts(v, quoted)
                                   for r in ((p,) if isinstance(p, TfRef) else _raw_refs(p) if isinstance(p, Raw)
                                             else ())))
    if isinstance(v, Block):
        return translated_refs(v.body, quoted)
    if isinstance(v, dict):
        return translated_refs(tuple(v.values()), quoted)
    if isinstance(v, (list, tuple)):
        return tuple(dict.fromkeys(r for x in v for r in translated_refs(x, quoted)))
    return ()


def _document(v, resolve):
    """A JSON document (from jsonencode) with its strings' interpolations translated."""
    if isinstance(v, str):
        return translate(v, resolve, quoted=True)
    if isinstance(v, dict):
        return {k: _document(x, resolve) for k, x in v.items()}
    if isinstance(v, list):
        return [_document(x, resolve) for x in v]
    return v


def translate(v, resolve, quoted=False):
    """A Terraform value as CloudFormation's: a reference through resolve (TfRef -> value), an interpolated string as
    Fn::Sub, a jsonencode() document as the document, lists and objects element by element; literals as they are.
    quoted: strings are a quoted template's content (see template_parts)."""
    if isinstance(v, str):
        parts = template_parts(v, quoted)
        if all(isinstance(p, str) for p in parts):
            return v
        values = tuple(p if isinstance(p, str) else resolve(p) if isinstance(p, TfRef) else _raw(p, resolve)
                       for p in parts)
        if len(values) == 1:
            return values[0]
        if all(isinstance(x, str) for x in values):
            return "".join(values)
        found = tuple(_sub_text(x) if isinstance(p, str) else _sub_part(x, i)
                      for i, (p, x) in enumerate(zip(parts, values)))
        text = "".join(x if isinstance(x, str) else x[0] for x in found)
        variables = {k: e for x in found if not isinstance(x, str) for k, e in x[1].items()}
        return sub(text, variables or None)
    if isinstance(v, (list, tuple)):
        return [translate(x, resolve) for x in v]
    if isinstance(v, dict):
        return {k: translate(x, resolve) for k, x in v.items()}
    if isinstance(v, Block):
        raise TypeError("a nested block is the mapping's to translate")
    return v


# ------------------------------------------------------------------ a root as templates

Stack = namedtuple("Stack", ("alias", "region", "provider"))
# Where a resource the root writes natively is: its stack (provider alias, None for the default provider), logical
# id, Native, and for a merged one the address it merges into.
Placed = namedtuple("Placed", ("address", "stack", "logical_id", "native", "target"))


def _alias(b):
    """The provider alias a block names (provider = aws.<alias>), or None."""
    p = dict(b.body).get("provider")
    text = p[2:-1] if isinstance(p, str) and p.startswith("${") else p
    return text.split(".", 1)[1] if isinstance(text, str) and "." in text else None


def _stacks(items):
    """{alias or None: Stack} of the root's provider blocks (the default provider's under None)."""
    providers = tuple(b for b in items if isinstance(b, TfBlock) and b.kind == "provider")
    return {dict(b.body).get("alias"): Stack(dict(b.body).get("alias"), dict(b.body).get("region"), b)
            for b in providers}


def _short(type_):
    return type_.split("_", 1)[1] if "_" in type_ else type_


def _placed(resources, types, by_address):
    """{address: Placed} for the root's natively written resources: standalone ones in their provider's stack, merged
    ones with the resource they merge into (its stack). Refuses a merge whose target the root doesn't write."""
    standalone = {address(b): Placed(address(b), _alias(b), logical_id(_short(b.labels[0]), b.labels[1]),
                                     types[b.labels[0]], None)
                  for b in resources if types[b.labels[0]].type}

    def target(b):
        via = dict(b.body).get(types[b.labels[0]].merge.via)
        refs = value_refs(via) if via is not None else ()
        found = next((ref_address(r) for r in refs if ref_address(r) in standalone), None)
        if found is None:
            raise SystemExit(f"{address(b)} merges into the resource its {types[b.labels[0]].merge.via} names, which "
                             "this root doesn't write in CloudFormation")
        return found

    merged = {address(b): standalone[t]._replace(address=address(b), native=types[b.labels[0]], target=t)
              for b in resources if not types[b.labels[0]].type for t in (target(b),)}
    return {**standalone, **merged}


def _form(native, attr, lid, where):
    refs = native.merge.refs if native.merge else native.refs
    form = refs.get(attr)
    if form is None:
        raise SystemExit(f"{where}: no CloudFormation form for attribute {attr!r} (known: {', '.join(refs) or 'none'})")
    return ref(lid) if form == "Ref" else form(lid) if callable(form) else get_att(lid, form)


def _variable_parameter(lid, b):
    f = fields(b.body)
    kind = str(f.get("type", "${string}"))[2:-1].replace(" ", "")
    type_ = {"number": "Number", "list(string)": "CommaDelimitedList"}.get(kind, "String")
    default = f.get("default")
    default = ",".join(default) if isinstance(default, (list, tuple)) else default
    return Parameter(lid, type_, None if default is None else str(default) if type_ != "Number" else default,
                     f.get("description"), no_echo=bool(f.get("sensitive")))


def _cross_id(r):
    return logical_id(output_variable(r))


Root = namedtuple("Root", ("directory", "items", "split", "by_address", "placed", "stacks", "reasons"))


def _adopted(items):
    """{address: Terraform import id} of the resources a root adopts (its import blocks)."""
    imports = (dict(b.body) for b in items if isinstance(b, TfBlock) and b.kind == "import")
    return {ref_address(parse_ref(body["to"][2:-1])): body["id"] for body in imports}


def _root(directory, files, types, no_native, unavailable):
    """The root read and split (a resource stays Terraform when its type has no native form, in general or in the
    region its provider runs in); refuses resource types the table neither maps nor lists as having no native
    form."""
    items = root_items(files)
    stacks = _stacks(items)
    unknown = sorted({b.labels[0] for b in items if isinstance(b, TfBlock) and b.kind == "resource"
                      and b.labels[0] not in types and b.labels[0] not in no_native})
    if unknown:
        raise SystemExit(f"Terraform root {directory}: no CloudFormation mapping for {', '.join(unknown)} (render it "
                         "as Terraform, or add the type to the mapping)")
    adopted = _adopted(items)
    by_address = {address(b): b for b in items if isinstance(b, TfBlock) and address(b)}

    def why(b):
        """Why a resource stays Terraform, or None when it is written natively."""
        t = b.labels[0]
        region = getattr(stacks.get(_alias(b)), "region", None)
        if t not in types:
            return "no CloudFormation type"
        if unavailable(t, region):
            return f"no CloudFormation type in {region}"
        if address(b) in adopted and types[t].identifier is None and types[t].merge is None:
            return "adopted (an import block): CloudFormation can't import it by its Terraform import id"
        if types[t].merge is None:
            return None
        via = dict(b.body).get(types[t].merge.via)
        targets = tuple(by_address[ref_address(r)] for r in (value_refs(via) if via is not None else ())
                        if ref_address(r) in by_address and by_address[ref_address(r)].kind == "resource")
        if not targets:
            return f"part of a resource natively, and its {types[t].merge.via} names none here"
        return None if why(targets[0]) is None else f"part of {address(targets[0])} natively, which stays Terraform"
    split = split_root(items, lambda b: why(b) is None)
    reasons = {address(b): why(b) for b in items if isinstance(b, TfBlock) and b.kind == "resource"
               and why(b) is not None}
    if split.unresolved:
        raise SystemExit(f"Terraform root {directory}: resources written in CloudFormation read ones that stay "
                         "Terraform: " + "; ".join(f"{a} reads {ref_text(r)}" for a, r in split.unresolved))
    blocks = tuple(x for x in split.native if isinstance(x, TfBlock))
    resources = tuple(b for b in blocks if b.kind == "resource")
    return Root(directory, items, split, by_address, _placed(resources, types, by_address), stacks, reasons)


def _resolver(root, stack, data):
    """resolve(TfRef) -> CloudFormation value, for resources in the stack: references to its own resources as
    Ref/GetAtt, to another stack's as the parameter carrying that stack's output, to data sources as the data table
    says, to variables as their parameters, path.module as the template's own folder."""
    def resolve(r):
        a = ref_address(r)
        if r.kind == "resource":
            p = root.placed.get(a)
            if p is None:
                raise SystemExit(f"{ref_text(r)}: not a resource this root writes in CloudFormation")
            if not r.attr:
                raise SystemExit(f"{ref_text(r)}: a whole resource has no CloudFormation value")
            if p.stack != stack:
                return ref(_cross_id(r))
            return _form(p.native, r.attr, p.logical_id, ref_text(r))
        if r.kind == "data":
            return _data_value(r, root.by_address[a], data)
        if r.kind == "var":
            return ref(logical_id(r.name))
        if r.kind == "path":
            return "."
        raise SystemExit(f"{ref_text(r)}: no CloudFormation form")
    return resolve


def _data_answer(r, b, data):
    handler = data.get(b.labels[0])
    if handler is None:
        raise SystemExit(f"{ref_text(r)}: no CloudFormation form for data source {b.labels[0]}")
    found = handler(fields(b.body), r.attr)
    if found is None:
        raise SystemExit(f"{ref_text(r)}: no CloudFormation form for attribute {r.attr!r} of {b.labels[0]}")
    return found


def _data_id(r, p):
    return logical_id(_short(r.type), r.name) + p.logical_id


def _data_value(r, b, data):
    found = _data_answer(r, b, data)
    if isinstance(found, Pseudo):
        return ref(found.name)
    if isinstance(found, Parameter):
        return ref(_data_id(r, found))
    if isinstance(found, Derived):
        return found.make(ref(_data_id(r, found.parameter)))
    return found


def _data_parameters(root, refs, data):
    """The Parameters the data sources the stack reads become (pseudo parameters and literal values need none; an
    attribute without an answer is refused when a value is translated, not here: a mapping may drop the attribute)."""
    blocks = ((r, root.by_address[ref_address(r)]) for r in refs if r.kind == "data")
    answers = ((r, data[b.labels[0]](fields(b.body), r.attr) if b.labels[0] in data else None) for r, b in blocks)
    return tuple(p._replace(logical_id=_data_id(r, p)) for r, found in answers
                 for p in ((found,) if isinstance(found, Parameter) else
                           (found.parameter,) if isinstance(found, Derived) else ()))


def _stack_refs(root, members):
    """Every reference the stack's resources (and what merges into them) make, depends_on aside."""
    return tuple(dict.fromkeys(r for p in members for r in translated_refs(tuple(
        kv for kv in root.by_address[p.address].body if kv[0] not in ("depends_on", "provider")))))


def _depends(root, p, stack_ids):
    """The logical ids a resource's (and its merged resources') depends_on name, in the same template."""
    names = tuple(r for kv in root.by_address[p.address].body if kv[0] == "depends_on" for r in value_refs(kv[1]))
    ids = (root.placed[ref_address(r)].logical_id for r in names
           if ref_address(r) in root.placed and root.placed[ref_address(r)].stack == p.stack)
    return tuple(i for i in dict.fromkeys(ids) if i != p.logical_id and i in stack_ids)


def _default_tags(stack):
    default = fields(stack.provider.body).get("default_tags") if stack.provider else None
    return dict(default[0].get("tags", {})) if default else {}


def _tagged(native, f, props, default, cx, where):
    """props with the resource's tags (the provider's default tags under its own) as the type takes them."""
    own = f.get("tags") or {}
    if not own and not default:
        return props
    if native.tags is None:
        if own:
            raise SystemExit(f"{where}: tagged in Terraform, but its CloudFormation type takes no tags")
        return props
    tags = cx.value({**default, **own})
    return {**props, native.tags_key: tag_list(tags) if native.tags == "list" else tags}


def _cx(root, stack, resolve):
    def logical(a):
        return root.placed[a].logical_id
    def provider_region(alias):
        if alias not in root.stacks:
            raise SystemExit(f"Terraform root {root.directory}: no provider with alias {alias}")
        return root.stacks[alias].region
    return Cx(lambda v: translate(v, resolve), root.by_address.get, stack.region if stack else None, logical, ref,
              provider_region)


def _import_entry(type_, lid, identifier):
    return {"ResourceType": type_, "LogicalResourceId": lid, "ResourceIdentifier": identifier}


def _resources(root, stack, members, default, cx, imported, leading):
    """(the stack's Resources, its resource import entries): each standalone resource with what merges into it, the
    resources it expands into; an adopted one (and its expansions) kept on deletion and listed for import."""
    ids = {p.logical_id for p in members}
    out, entries = [], []
    for p in (p for p in members if p.target is None):
        b = root.by_address[p.address]
        f = fields(b.body)
        here = cx._replace(where=p.address)
        props = (obj(own(f), here, p.native.properties) if isinstance(p.native.properties, dict)
                 else p.native.properties(f, here))
        merged = tuple(m for m in members if m.target == p.address)
        for m in merged:
            props = m.native.merge.into(props, fields(root.by_address[m.address].body), cx._replace(where=m.address))
        props = p.native.finish(props) if p.native.finish else props
        props = _tagged(p.native, f, props, default, cx, p.address)
        notes = (*leading.get(p.address, ()), *comments(b.body),
                 *(c for m in merged
                   for c in (*leading.get(m.address, ()), *comments(root.by_address[m.address].body))))
        depends = tuple(dict.fromkeys(d for m in (p, *(m for m in merged if m.native.merge.ordering))
                                      for d in _depends(root, m, ids)))
        adopted = imported.get(p.address)
        kept = "Retain" if adopted is not None else None
        out.append(Resource(p.logical_id, p.native.type, props, depends, None, kept, kept,
                            {"Comments": list(notes)} if notes else None))
        identifier = p.native.identifier
        entries.extend(() if adopted is None else (_import_entry(p.native.type, p.logical_id, identifier(adopted)
                                                                 if callable(identifier) else {identifier: adopted}),))
        for x in (p.native.expand(p.logical_id, f, here) if p.native.expand else ()):
            lid = f"{p.logical_id}{x[0]}"
            if adopted is not None and len(x) < 4:
                raise SystemExit(f"{p.address} is adopted, but CloudFormation can't import its {x[1]} {lid}")
            out.append(Resource(lid, x[1], x[2], (), None, kept, kept))
            entries.extend((_import_entry(x[1], lid, x[3](adopted)),) if adopted is not None else ())
    return tuple(out), tuple(entries)


def _leading(items):
    """{address: the comments directly above the block}, and the comments above blocks that aren't resources."""
    out, loose, pending = {}, [], []
    for x in items:
        if isinstance(x, TfBlock):
            if x.kind == "resource":
                out[address(x)] = tuple(pending)
            else:
                loose.extend(pending)
            pending = []
        else:
            pending.append(x[1])
    return out, tuple((*loose, *pending))


def _imports(root, members):
    """{address: Terraform import id} of the stack's resources the root adopts (import blocks); refused for one
    merged into another (it is imported with the resource it is part of, so it can't be adopted on its own)."""
    found = {a: i for a, i in _adopted(root.split.native).items()
             if root.placed.get(a) is not None and root.placed[a] in members}
    merged = sorted(a for a in found if root.placed[a].target is not None)
    if merged:
        raise SystemExit(f"adopted, but part of another resource natively: {', '.join(merged)}")
    return found


def _stack_template(m, root, stack, data, what):
    """(Template, its resource import entries) of one stack of the root."""
    members = tuple(p for p in root.placed.values() if p.stack == stack.alias)
    refs = _stack_refs(root, members)
    resolve = _resolver(root, stack.alias, data)
    cx = _cx(root, stack, resolve)
    leading, loose = _leading(root.split.native)
    imported = _imports(root, members)
    resources, entries = _resources(root, stack, members, _default_tags(stack), cx, imported, leading)
    own = tuple(q for p in members if p.native.parameters for q in p.native.parameters(
        fields(root.by_address[p.address].body), cx))
    variables = tuple(_variable_parameter(logical_id(r.name), root.by_address[ref_address(r)]) for r in refs
                      if r.kind == "var")
    crossing = tuple(r for r in refs if r.kind == "resource" and root.placed[ref_address(r)].stack != stack.alias)
    cross = tuple(Parameter(_cross_id(r), "String", None,
                            f"{ref_text(r)}: an output of template {_template_name(root.placed[ref_address(r)].stack)}"
                            " (deployed first)") for r in crossing)
    parameters = tuple({p.logical_id: p for p in (*_data_parameters(root, refs, data), *variables, *cross, *own)}
                       .values())
    outputs = _outputs(root, stack, members, resolve)
    notes = {"Notes": list(loose)} if loose and stack.alias is None else {}
    template = Template(f"{what} ({m.label}): the Terraform root {root.directory} as CloudFormation"
                        + (f", provider {stack.alias}" if stack.alias else ""),
                        resources, parameters, (), outputs,
                        {**(lint_metadata([stack.region]) if stack.region else {}), **notes})
    _clashes(template)
    return template, entries


def _clashes(t):
    ids = [*(r.logical_id for r in t.resources), *(p.logical_id for p in t.parameters)]
    twice = sorted({i for n, i in enumerate(ids) if i in ids[:n]})
    if twice:
        raise SystemExit(f"logical ids used twice in a template: {', '.join(twice)}")


def _outputs(root, stack, members, resolve):
    """The stack's Outputs: values of its resources the side Terraform root or another template reads."""
    others = tuple(r for p in root.placed.values() if p.stack != stack.alias
                   for r in _stack_refs(root, (p,)) if r.kind == "resource"
                   and root.placed.get(ref_address(r)) in members)
    wanted = tuple(dict.fromkeys((*(r for r in root.split.outputs if root.placed[ref_address(r)] in members), *others)))
    return tuple(Output(_cross_id(r), resolve(r), f"{ref_text(r)}, for the Terraform root beside this template "
                        f"(variable {output_variable(r)}) or another template") for r in wanted)


def _template_name(alias):
    return "template.yaml" if alias is None else f"template.{alias}.yaml"


def native_directory(directory):
    """Where a Terraform root's CloudFormation goes: terraform/<rest> -> cloudformation/<rest>."""
    rest = directory.split("/", 1)[1] if "/" in directory else ""
    return posixpath.join("cloudformation", rest) if rest else "cloudformation"


# Where a Terraform resource of a root went: kind "template" (where: the template's path; detail: its logical id),
# "merged" (where: the template's path; detail: the address of the resource it is part of) or "terraform" (where: the
# path of the Terraform root kept beside the template; detail: why it stays Terraform).
Placement = namedtuple("Placement", ("kind", "where", "detail"))
# An environment's translation: templates {path: Template}, imports {path: resource import entries}, side {path:
# TfFile} (the Terraform roots kept beside templates), placements {root directory: {address: Placement}}, packaged
# {path: text} (the files a root packages, copied beside its templates).
Translation = namedtuple("Translation", ("templates", "imports", "side", "placements", "packaged"))


def _root_translation(m, root, data, what):
    """(templates, imports, side roots, placements) of one root."""
    out_dir = native_directory(root.directory)
    aliases = dict.fromkeys(p.stack for p in root.placed.values())
    stacks = sorted((root.stacks.get(a) or Stack(a, None, None) for a in aliases),
                    key=lambda s: (s.alias is not None, s.alias or ""))
    built = tuple((posixpath.join(out_dir, _template_name(s.alias)), *_stack_template(m, root, s, data, what))
                  for s in stacks)
    side_path = posixpath.join(out_dir, "terraform", "main.tf")
    side = {side_path: TfFile(header(m, f"{what}: what CloudFormation has no form for", HCL) +
                              no_native_note(root.split, "AWS CloudFormation", root.reasons), root.split.side)} \
        if root.split.side else {}
    by_stack = {s.alias: path for s, (path, _, _) in zip(stacks, built)}
    placements = {**{a: (Placement("template", by_stack[p.stack], p.logical_id) if p.target is None else
                         Placement("merged", by_stack[p.stack], p.target)) for a, p in root.placed.items()},
                  **{a: Placement("terraform", side_path, why) for a, why in root.reasons.items()}}
    return ({path: t for path, t, _ in built},
            {path.replace(".yaml", ".resources-to-import.json"): e for path, _, e in built if e}, side, placements)


def translation(m, files, types, no_native, data, what, unavailable=lambda type_, region: False):
    """The Translation of environment m's Terraform render ({path: TfFile | text}) into CloudFormation by a table of
    Natives: each Terraform root's templates, resource import entries and side Terraform root under cloudformation/,
    where each Terraform resource went, and the other files a root packages (scripts) copied beside them."""
    parts = {d: _root_translation(m, _root(d, rf, types, no_native, unavailable), data, what)
             for d, rf in roots(files).items()}
    packaged = {posixpath.join("cloudformation", p.split("/", 1)[1]): text for p, text in files.items()
                if p.startswith("terraform/") and not isinstance(text, TfFile) and not p.endswith(".tf")}
    return Translation({k: v for t, _, _, _ in parts.values() for k, v in t.items()},
                       {k: v for _, i, _, _ in parts.values() for k, v in i.items()},
                       {k: v for _, _, side, _ in parts.values() for k, v in side.items()},
                       {d: p for d, (_, _, _, p) in parts.items()}, packaged)


def translated(m, files, types, no_native, data, what, unavailable=lambda type_, region: False):
    """{path: TfFile | text} of environment m's CloudFormation (translation, written): each template as YAML under
    its generated-file header, each import file as JSON, the side Terraform roots as TfFiles, the packaged files."""
    t = translation(m, files, types, no_native, data, what, unavailable)
    return {**{path: header(m, f"{what}: CloudFormation ({posixpath.basename(path)})", YAML_FORMAT) + as_yaml(template)
               for path, template in t.templates.items()},
            **{path: json.dumps(list(entries), indent=2) + "\n" for path, entries in t.imports.items()},
            **t.side, **t.packaged}
