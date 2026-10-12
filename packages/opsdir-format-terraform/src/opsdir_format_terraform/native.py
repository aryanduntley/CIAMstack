"""Terraform translated to a cloud's native IaC language by a table (5.6, decisions 2565 and 2592): the target-neutral
engine the CloudFormation (adapter-aws) and ARM/Bicep (adapter-azure) translations run on. It knows Terraform only.

A table says, per Terraform resource type, how the target writes it (Native: its native type, a spec of its
attributes, what a reference to it reads, what merges into it or what it expands into), what each data source's
attributes are natively, and which types have no native form. The engine reads a root (its blocks, comments and
import blocks), splits it into what is written natively and what stays Terraform beside it (format-terraform
translate's split_root), with each kept resource's reason, places every native resource in a group (the target's
deployment unit: a CloudFormation stack per provider, an ARM template per scope), and translates values: references,
interpolations, jsonencode() documents, indexed lookups and the few Terraform functions an expression may call (join,
trimprefix), over the target's value forms (Target) and reference forms (Forms). Anything the table doesn't know is
refused, by name: a translation never drops or guesses. Pure.
"""
import json
import re
from collections import namedtuple

from .hcl import Block, TfBlock
from .translate import Raw, TfRef, address, is_quoted_string, parse_ref, ref_address, ref_text, root_items, \
    split_root, template_parts, value_refs

# How one Terraform resource type is written natively. type: its native type (None: merged into another resource, see
# merge). properties: a spec (see obj) of its attributes, or (Fields, Cx) -> the resource's properties (its tags,
# depends_on and provider are the engine's). refs: {Terraform attribute: a target reference form (a name the target's
# Forms.attribute reads) | (native id) -> value | Attribute}: what a reference to it reads. identifier: how an
# existing one is imported (the target's), None when the target can't import it from what Terraform imports it by (an
# adopted one then stays Terraform, beside the template). tags: how the resource's tags (with the provider's default
# tags under them) are written ("list" or "map", under tags_key); None when the type takes no tags. merge: Merge, for
# a type that is part of another resource. expand: (native id, Fields, Cx) -> ((id suffix, type, properties[, (the
# parent's import id) -> its import identifier]), ...): further resources it is written as. parameters: (Fields, Cx)
# -> what the deployer must give (the target's declarations). finish: (properties) -> properties, once what merges
# into it is in. adoptable: (Fields) -> None, or why an adopted one can't be imported with what it expands into (it
# then stays Terraform). ready: the id suffix of the expansion making it usable (a gateway's attachment): the resources
# of its template that reference it wait for that one. keep: (Fields, block(address) -> TfBlock|None) -> None, or why
# this block stays Terraform (what it reads has no native form here: an initiative the table has no id for).
Native = namedtuple("Native", ("type", "properties", "refs", "identifier", "tags", "merge", "expand", "parameters",
                               "tags_key", "finish", "adoptable", "ready", "keep"),
                    defaults=(None, {}, None, None, None, None, None, "Tags", None, None, None, None))
# A Terraform resource type that is part of another resource natively. via: its attribute referencing that resource;
# into: (the target's properties, Fields, Cx) -> the target's properties with this one's merged in. refs: what a
# reference to the merged resource reads, of the target ({attribute: as Native.refs}). ordering: whether its depends_on
# orders the target (False where the native resource does what the ordering was for). target: the Terraform type of
# the resource it is part of, when via names others too (a depends_on list); None: the first resource via names.
Merge = namedtuple("Merge", ("via", "into", "refs", "ordering", "target"), defaults=({}, True, None))
# A reference form (Native.refs) for an attribute the target has no attribute for but the block sets: the resource's
# own Terraform attribute name, translated (an Aurora cluster's engine, read by its instances).
Attribute = namedtuple("Attribute", ("name",))
# A reference form (Native.refs) built from the resource's own block: make(native id, Fields) -> value (a load
# balancer's frontend configuration id, from the configuration's name).
FromBlock = namedtuple("FromBlock", ("make",))
# What the data table answers for an attribute of a data source (data[type](Fields, attribute)), beside the target's
# own answers (Forms.answer): a value derived from a declared lookup (Derived: the declaration, make(its value) ->
# value), a value built from the data block's own body (Computed: make(Fields, value) -> value, value translating a
# Terraform value of the body: a policy document, an ARN built from another lookup), any other value as it is, or None
# when the attribute has no native form.
Derived = namedtuple("Derived", ("parameter", "make"))
Computed = namedtuple("Computed", ("make",))
# What a mapping function is given beside a block's Fields: value(Terraform value) -> the native value; block(address)
# -> the root's TfBlock at that address (a data source a resource reads, say), or None; region: the region of the
# group the resource is in; logical(address) -> the native id of a resource the root writes natively; param(name) ->
# the value of a declaration this resource's parameters() make, by its id; provider_region(alias) -> the region of the
# root's provider with that alias; where: the address of the block being translated; language: the target's name
# (both for refusals).
Cx = namedtuple("Cx", ("value", "block", "region", "logical", "param", "provider_region", "where", "language"),
                defaults=("", "the native language"))
# A spec of a block's attributes (obj): {Terraform key: a native name (the value translated), a Nest (nested blocks as
# an object, or a list of objects when many), a Custom (make(Terraform value, Cx) -> {native name: value}, any number
# of them), or None (a Terraform-only attribute, deliberately not written)}.
Nest = namedtuple("Nest", ("name", "spec", "many"), defaults=(False,))
Custom = namedtuple("Custom", ("make",))
# The attributes the engine writes itself, never a spec's.
ENGINE_KEYS = ("tags", "depends_on", "provider")
# A target's value forms: language (its name, in refusals), concat(*values) (values written one after another: one
# string, or the target's interpolation), join(separator, values) (Terraform's join of a list a function gives; a
# literal list is concatenated), trim_prefix(value, prefix) (Terraform's trimprefix).
Target = namedtuple("Target", ("language", "concat", "join", "trim_prefix"))
# How a target reads what a reference names: attribute(native id, form) (a resource's attribute by a refs name),
# cross(TfRef) (a resource of another group of the root: its value passed in), variable(name) (a Terraform variable),
# answer(TfRef, found) (a data table answer that isn't Computed).
Forms = namedtuple("Forms", ("attribute", "cross", "variable", "answer"))
# How a target lays out a root: group(TfBlock) -> the key of the group (deployment unit) a resource goes in; region(key)
# -> that group's region or None; name(Terraform type, name) -> a resource's native id.
Layout = namedtuple("Layout", ("group", "region", "name"))


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


def pascal(key):
    """A Terraform attribute name as PascalCase (CloudFormation's names), for the many that only differ so."""
    return "".join(w[:1].upper() + w[1:] for w in key.split("_"))


def obj(f, cx, spec, where=None):
    """Fields as a native object by a spec; refuses an attribute the spec doesn't name (a translation never drops what
    it doesn't know) and more than one block where the spec takes one."""
    where = where or cx.where
    unknown = sorted(k for k in f if k not in spec)
    if unknown:
        raise SystemExit(f"{where}: no {cx.language} form for {', '.join(unknown)}")

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

# The Terraform functions an expression may call (the evaluator's), by the Target form that writes each.
FUNCTIONS = {"join": "join", "trimprefix": "trim_prefix"}
_NAME = re.compile(r"[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*|\.\d+|\[\d+\])*")
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?(?![\w.])")


def _join(target, separator, values):
    """Terraform's join: a literal list's values with the separator between them (concat), a list a function gives
    by the target's join."""
    if not isinstance(values, list):
        return target.join(separator, values)
    return target.concat(*(x for i, v in enumerate(values) for x in ((separator, v) if i else (v,))))


def _skip(text, i):
    while i < len(text) and text[i].isspace():
        i += 1
    return i


def _refused(text, language):
    return SystemExit(f"no {language} form for the Terraform expression {text!r}")


def _items(text, i, close, language):
    """(nodes, end) of a comma-separated list of expressions up to close (']' or ')')."""
    i = _skip(text, i)
    if text[i:i + 1] == close:
        return (), i + 1
    node, i = _parse(text, i, language)
    i = _skip(text, i)
    if text[i:i + 1] == close:
        return (node,), i + 1
    if text[i:i + 1] != ",":
        raise _refused(text, language)
    rest, end = _items(text, i + 1, close, language)
    return (node, *rest), end


def _parse(text, i, language):
    """(node, end) of the expression at text[i:]: ("str", its quoted text), ("num", text), ("list", nodes),
    ("call", name, nodes) or ("ref", traversal)."""
    i = _skip(text, i)
    if text[i:i + 1] == '"':
        _, end = json.JSONDecoder().raw_decode(text, i)
        return ("str", text[i:end]), end
    if text[i:i + 1] == "[":
        items, end = _items(text, i + 1, "]", language)
        return ("list", items), end
    m = _NUMBER.match(text, i)
    if m:
        return ("num", m.group(0)), m.end()
    m = _NAME.match(text, i)
    if m is None:
        raise _refused(text, language)
    j = _skip(text, m.end())
    if text[j:j + 1] == "(":
        args, end = _items(text, j + 1, ")", language)
        return ("call", m.group(0), args), end
    return ("ref", m.group(0)), m.end()


def _evaluate(node, resolve, target, text):
    """The native value of a parsed expression (text: the whole one, for refusals)."""
    kind = node[0]
    if kind == "str":
        return translate(json.loads(node[1]), resolve, target, quoted=True)
    if kind == "num":
        return json.loads(node[1])
    if kind == "list":
        return [_evaluate(x, resolve, target, text) for x in node[1]]
    if kind == "ref" and parse_ref(node[1]) is not None:
        return resolve(parse_ref(node[1]))
    if kind == "call" and node[1] in FUNCTIONS:
        args = tuple(_evaluate(a, resolve, target, text) for a in node[2])
        return _join(target, *args) if node[1] == "join" else target.trim_prefix(*args)
    raise _refused(text, target.language)


def _called(text, language):
    """The expression parsed when it is one call of an evaluator function (join, trimprefix), else None."""
    m = re.match(r"([A-Za-z_]\w*)\s*\(", text)
    if m is None or m.group(1) not in FUNCTIONS:
        return None
    node, end = _parse(text, 0, language)
    return node if _skip(text, end) == len(text) else None


_INDEXED = re.compile(r"^(?:tolist\((?P<a>[^()]+)\)|(?P<b>[^()\[\]]+))\[(?P<i>\d+)\]$")


def _raw(raw, resolve, target):
    """A native value for an expression that is more than one reference: a quoted template string, a jsonencode()
    document (its strings translated in turn), an element of a list a reference reads (tolist(x)[0], x[0]: the
    reference with that index), a call of the evaluator's functions (join, trimprefix). Refused otherwise, naming
    it."""
    text = raw.text.strip()
    if is_quoted_string(text):
        return translate(json.loads(text), resolve, target, quoted=True)
    if text.startswith("jsonencode(") and text.endswith(")"):
        return _document(json.loads(text[len("jsonencode("):-1]), resolve, target)
    m = _INDEXED.match(text)
    r = parse_ref((m.group("a") or m.group("b")).strip()) if m else None
    if r is not None:
        return resolve(r._replace(attr=f"{r.attr}[{m.group('i')}]"))
    called = _called(text, target.language)
    if called is not None:
        return _evaluate(called, resolve, target, text)
    raise _refused(text, target.language)


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


def _document(v, resolve, target):
    """A JSON document (from jsonencode) with its strings' interpolations translated."""
    if isinstance(v, str):
        return translate(v, resolve, target, quoted=True)
    if isinstance(v, dict):
        return {k: _document(x, resolve, target) for k, x in v.items()}
    if isinstance(v, list):
        return [_document(x, resolve, target) for x in v]
    return v


def translate(v, resolve, target, quoted=False):
    """A Terraform value as the target's: a reference through resolve (TfRef -> value), an interpolated string by the
    target's concat, a quoted template or jsonencode() document translated in turn, an indexed lookup as the indexed
    reference, a call of join / trimprefix by the target's forms, lists and objects element by element; literals as
    they are; SystemExit for an expression with no native form. quoted: strings are a quoted template's content (see
    template_parts)."""
    if isinstance(v, str):
        parts = template_parts(v, quoted)
        if all(isinstance(p, str) for p in parts):
            return v
        values = tuple(p if isinstance(p, str) else resolve(p) if isinstance(p, TfRef) else _raw(p, resolve, target)
                       for p in parts)
        return values[0] if len(values) == 1 else target.concat(*values)
    if isinstance(v, (list, tuple)):
        return [translate(x, resolve, target) for x in v]
    if isinstance(v, dict):
        return {k: translate(x, resolve, target) for k, x in v.items()}
    if isinstance(v, Block):
        raise TypeError("a nested block is the mapping's to translate")
    return v


# ------------------------------------------------------------------ a root

# Where a resource the root writes natively is: its group (Layout.group), native id, Native, and for a merged one the
# address of the resource it is part of.
Placed = namedtuple("Placed", ("address", "group", "id", "native", "target"))
# A root read for translation: its directory, items, split (format-terraform Split), blocks by address, placed
# resources {address: Placed}, reasons {address: why it stays Terraform}, and its Layout.
Root = namedtuple("Root", ("directory", "items", "split", "by_address", "placed", "reasons", "layout"))
# A table: types {Terraform type: Native}, no_native (the types with no native form), data {data source or ephemeral
# resource type: (Fields, attribute) -> answer}, unavailable(type, region) (no native form in that region), kept
# {Terraform type: why it stays Terraform} (types the target leaves to Terraform for a stated reason).
Table = namedtuple("Table", ("types", "no_native", "data", "unavailable", "kept"),
                   defaults=(lambda type_, region: False, {}))


def _merge_refs(b, merge):
    """The references a merged resource's via attribute makes to resources of the type it is part of."""
    via = dict(b.body).get(merge.via)
    return tuple(r for r in (value_refs(via) if via is not None else ())
                 if r.kind == "resource" and (merge.target is None or r.type == merge.target))


def _placed(resources, types, layout, language):
    """{address: Placed} for the root's natively written resources: standalone ones in their group, merged ones with
    the resource they merge into (its group). Refuses a merge whose target the root doesn't write."""
    standalone = {address(b): Placed(address(b), layout.group(b), layout.name(b.labels[0], b.labels[1]),
                                     types[b.labels[0]], None)
                  for b in resources if types[b.labels[0]].type}

    def target(b):
        refs = _merge_refs(b, types[b.labels[0]].merge)
        found = next((ref_address(r) for r in refs if ref_address(r) in standalone), None)
        if found is None:
            raise SystemExit(f"{address(b)} merges into the resource its {types[b.labels[0]].merge.via} names, which "
                             f"this root doesn't write in {language}")
        return found

    merged = {address(b): standalone[t]._replace(address=address(b), native=types[b.labels[0]], target=t)
              for b in resources if not types[b.labels[0]].type for t in (target(b),)}
    return {**standalone, **merged}


def adopted(items):
    """{address: Terraform import id} of the resources a root adopts (its import blocks)."""
    imports = (dict(b.body) for b in items if isinstance(b, TfBlock) and b.kind == "import")
    return {ref_address(parse_ref(body["to"][2:-1])): body["id"] for body in imports}


def read_root(directory, files, table, language, layout_of):
    """A root read and split for translation (Root): a resource stays Terraform when its type has no native form (in
    general or in its group's region), when it is adopted and the target can't import it as Terraform does (or with
    what it expands into), or when it is part of a resource that stays; each one's reason kept. Refuses resource types
    the table neither maps nor lists as having no native form, and native resources reading ones that stay.
    layout_of(items) -> the root's Layout."""
    items = root_items(files)
    layout = layout_of(items)
    types = table.types
    unknown = sorted({b.labels[0] for b in items if isinstance(b, TfBlock) and b.kind == "resource"
                      and b.labels[0] not in types and b.labels[0] not in table.no_native
                      and b.labels[0] not in table.kept})
    if unknown:
        raise SystemExit(f"Terraform root {directory}: no {language} mapping for {', '.join(unknown)} (render it as "
                         "Terraform, or add the type to the mapping)")
    imports = adopted(items)
    by_address = {address(b): b for b in items if isinstance(b, TfBlock) and address(b)}

    def why(b):
        """Why a resource stays Terraform, or None when it is written natively."""
        t = b.labels[0]
        if t in table.kept:
            return table.kept[t]
        region = layout.region(layout.group(b))
        if t not in types:
            return f"no {language} type"
        if table.unavailable(t, region):
            return f"no {language} type in {region}"
        held = types[t].keep(fields(b.body), by_address.get) if types[t].keep else None
        if held:
            return held
        if address(b) in imports and types[t].identifier is None and types[t].merge is None:
            return f"adopted (an import block): {language} can't import it by its Terraform import id"
        unimportable = types[t].adoptable(fields(b.body)) if address(b) in imports and types[t].adoptable else None
        if unimportable:
            return f"adopted (an import block): {unimportable}"
        waits = next((address(by_address[ref_address(r)]) for kv in b.body if kv[0] == "depends_on"
                      for r in value_refs(kv[1]) if r.kind == "resource" and ref_address(r) in by_address
                      and why(by_address[ref_address(r)]) is not None), None)
        if waits:
            return f"waits for {waits} (depends_on), which stays Terraform, applied after the template"
        if types[t].merge is not None:
            targets = tuple(by_address[ref_address(r)] for r in _merge_refs(b, types[t].merge)
                            if ref_address(r) in by_address)
            if not targets:
                return f"part of a resource natively, and its {types[t].merge.via} names none here"
            if why(targets[0]) is not None:
                return f"part of {address(targets[0])} natively, which stays Terraform"
            def part_of_target(dep):
                """Whether a resource merges into the same target (its order among the target's parts isn't a
                cycle)."""
                row = types.get(dep.labels[0])
                return row is not None and row.merge is not None and any(
                    ref_address(r) == address(targets[0]) for r in _merge_refs(dep, row.merge))
            cycle = next((address(by_address[ref_address(r)]) for kv in b.body if kv[0] == "depends_on"
                          for r in value_refs(kv[1]) if ref_address(r) in by_address
                          and not part_of_target(by_address[ref_address(r)])
                          and address(targets[0]) in {ref_address(x) for x in value_refs(tuple(
                              y for y in by_address[ref_address(r)].body if y[0] != "depends_on"))}), None)
            if cycle:
                return (f"part of {address(targets[0])} natively, but waits for {cycle}, which reads it: a cycle "
                        "there, so it stays Terraform, applied after the template")
        reads = next((address(by_address[ref_address(r)]) for r in value_refs(tuple(
            kv for kv in b.body if kv[0] not in ("depends_on", "provider")))
            if r.kind == "resource" and ref_address(r) in by_address and by_address[ref_address(r)] is not b
            and why(by_address[ref_address(r)]) is not None), None)
        return f"reads {reads}, which stays Terraform" if reads else None
    split = split_root(items, lambda b: why(b) is None)
    checks = {address(b): f"a check (its lifecycle conditions), which {language} can't make" for b in split.side
              if isinstance(b, TfBlock) and b.kind == "data" and any(k == "lifecycle" for k, _ in b.body)}
    reasons = {**{address(b): why(b) for b in items if isinstance(b, TfBlock) and b.kind == "resource"
                  and why(b) is not None}, **checks}
    if split.unresolved:
        raise SystemExit(f"Terraform root {directory}: resources written in {language} read ones that stay "
                         "Terraform: " + "; ".join(f"{a} reads {ref_text(r)}" for a, r in split.unresolved))
    resources = tuple(x for x in split.native if isinstance(x, TfBlock) and x.kind == "resource")
    return Root(directory, items, split, by_address, _placed(resources, types, layout, language), reasons, layout)


def _form(native, attr, nid, where, own_attribute, own_fields, forms, language):
    """What a reference to attribute attr of a resource reads natively; own_attribute(name): the resource's own
    Terraform attribute translated (an Attribute form); own_fields(): its block's Fields (a FromBlock form)."""
    refs = native.merge.refs if native.merge else native.refs
    form = refs.get(attr)
    if form is None:
        raise SystemExit(f"{where}: no {language} form for attribute {attr!r} (known: {', '.join(refs) or 'none'})")
    if isinstance(form, Attribute):
        return own_attribute(form.name)
    if isinstance(form, FromBlock):
        return form.make(nid, own_fields())
    return form(nid) if callable(form) else forms.attribute(nid, form)


def data_answer(r, b, data, language):
    """The data table's answer for the attribute a reference reads of data source block b; refused when the table has
    none."""
    handler = data.get(b.labels[0])
    if handler is None:
        raise SystemExit(f"{ref_text(r)}: no {language} form for data source {b.labels[0]}")
    found = handler(fields(b.body), r.attr)
    if found is None:
        raise SystemExit(f"{ref_text(r)}: no {language} form for attribute {r.attr!r} of {b.labels[0]}")
    return found


def resolver(root, group, table, target, forms):
    """resolve(TfRef) -> native value, for resources in the group: references to its own resources by the table's
    refs forms, to another group's through forms.cross, to data sources as the data table answers (Computed answers
    built here, others by forms.answer), to variables through forms.variable, path.module as the template's own
    folder."""
    language = target.language

    def resolve(r):
        a = ref_address(r)
        if r.kind == "resource":
            p = root.placed.get(a)
            if p is None:
                raise SystemExit(f"{ref_text(r)}: not a resource this root writes in {language}")
            if not r.attr:
                raise SystemExit(f"{ref_text(r)}: a whole resource has no {language} value")
            if p.group != group:
                return forms.cross(r)

            def own_attribute(name):
                f = fields(root.by_address[p.address].body)
                if name not in f:
                    raise SystemExit(f"{ref_text(r)}: {p.address} doesn't set {name}, which {language} can't read")
                return translate(f[name], resolve, target)
            return _form(p.native, r.attr, p.id, ref_text(r), own_attribute,
                         lambda: fields(root.by_address[p.address].body), forms, language)
        if r.kind in ("data", "ephemeral"):
            b = root.by_address[a]
            found = data_answer(r, b, table.data, language)
            if isinstance(found, Computed):
                return found.make(fields(b.body), lambda v: translate(v, resolve, target))
            return forms.answer(r, found)
        if r.kind == "var":
            return forms.variable(r.name)
        if r.kind == "path":
            return "."
        raise SystemExit(f"{ref_text(r)}: no {language} form")
    return resolve


def _computed_refs(root, refs, data, seen=frozenset()):
    """refs with the references of the data sources whose answer is Computed (built from their own body: what that
    body reads is read too), transitively."""
    def inner(r):
        b = root.by_address.get(ref_address(r)) if r.kind in ("data", "ephemeral") else None
        handler = data.get(b.labels[0]) if b is not None else None
        if handler is None or r in seen or not isinstance(handler(fields(b.body), r.attr), Computed):
            return ()
        return _computed_refs(root, translated_refs(tuple(kv for kv in b.body if kv[0] != "provider")), data,
                              seen | {r})
    return tuple(dict.fromkeys((*refs, *(x for r in refs for x in inner(r)))))


def group_refs(root, members, data):
    """Every reference the members (placed resources, with what merges into them) make, depends_on aside, with those
    of the computed lookups they read."""
    return _computed_refs(root, tuple(dict.fromkeys(r for p in members for r in translated_refs(tuple(
        kv for kv in root.by_address[p.address].body if kv[0] not in ("depends_on", "provider"))))), data)


def depends(root, p, ids):
    """The native ids a resource's (or a merged resource's) depends_on names, in the same group (among ids)."""
    names = tuple(r for kv in root.by_address[p.address].body if kv[0] == "depends_on" for r in value_refs(kv[1]))
    found = (root.placed[ref_address(r)].id for r in names
             if ref_address(r) in root.placed and root.placed[ref_address(r)].group == p.group)
    return tuple(i for i in dict.fromkeys(found) if i != p.id and i in ids)


def leading(items):
    """({address: the comments directly above the resource block}, the comments above blocks that aren't
    resources and after the last block)."""
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


# Where a Terraform resource of a root went: kind "template" (where: the template's path; detail: its native id),
# "merged" (where: the template's path; detail: the address of the resource it is part of) or "terraform" (where: the
# path of the Terraform root kept beside the template; detail: why it stays Terraform).
Placement = namedtuple("Placement", ("kind", "where", "detail"))


def placements(root, where, side_path):
    """{address: Placement} of a root's resources; where: {group: its template's path}."""
    return {**{a: (Placement("template", where[p.group], p.id) if p.target is None else
                   Placement("merged", where[p.group], p.target)) for a, p in root.placed.items()},
            **{a: Placement("terraform", side_path, why) for a, why in root.reasons.items()}}
