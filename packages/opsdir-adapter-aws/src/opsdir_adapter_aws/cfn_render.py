"""AWS CloudFormation translated from the AWS render's Terraform data (5.6, decision 2565): each Terraform root becomes
a template (one per provider: a resource on an aliased provider runs in another region or account, so in another
stack), what CloudFormation has no form for stays in a small Terraform root beside it (format-terraform translate),
applied after it, or before it (BEFORE_ROOT) what the template reads (task 591: an ALB trust store's bundle object),
and the lookups Terraform makes become parameters (the record's ids as defaults) or pseudo parameters.

The engine is format-terraform's native one (decision 2592), over a table of Natives (cfn_types holds AWS's); this
module is its CloudFormation part: the value forms (Ref, Fn::GetAtt, Fn::Sub, documents with computed keys as JSON
text), the stacks and their templates, resource import entries. Anything the table doesn't know is refused, by name:
a translation never drops or guesses. Pure.
"""
import json
import posixpath
import re
from collections import namedtuple

from opsdir.core.manifest import header
from opsdir_format_cloudformation.format import YAML_FORMAT, as_yaml
from opsdir_format_cloudformation.template import Output, Parameter, Resource, Template, get_att, lint_metadata, \
    logical_id, ref, sub
from opsdir_format_terraform import native
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir_format_terraform.hcl import TfBlock, TfFile
from opsdir_format_terraform.native import (ENGINE_KEYS, Attribute, Computed, Custom, Cx, Derived, Forms, Layout,  # noqa: F401 (the table's API)
                                            Merge, Native, Nest, Placement, Table, comments, depends, fields,
                                            group_refs, leading, obj, one, own, pascal, placements,
                                            placements_document, read_root,
                                            resolver, translated_refs)
from opsdir_format_terraform.translate import before_note, no_native_note, output_variable, ref_address, ref_text, \
    roots, template_parts

# A data table answer only CloudFormation has: a pseudo parameter (its name: AWS::AccountId, AWS::Region, ...).
Pseudo = namedtuple("Pseudo", ("name",))
LANGUAGE = "CloudFormation"


def tag_list(tags):
    """{key: value} as CloudFormation's Tags list."""
    return [{"Key": k, "Value": v} for k, v in tags.items()]


# ------------------------------------------------------------------ values

def _sub_text(text):
    """Literal text inside Fn::Sub: '${' written '${!' so it stays text."""
    return text.replace("${", "${!")


def _sub_body(v):
    """(text, variables) of an Fn::Sub value, or None for any other value."""
    body = v.get("Fn::Sub") if isinstance(v, dict) and set(v) == {"Fn::Sub"} else None
    return None if body is None else (body, {}) if isinstance(body, str) else (body[0], body[1])


def _sub_piece(v, n):
    """(text, variables) of one value inside Fn::Sub: a literal as itself, ${Name} / ${Name.Attribute} for a Ref /
    GetAtt, another Fn::Sub's text inline (its variables renamed V<n><name>), any other function under a variable of
    its own (V<n>)."""
    if isinstance(v, str):
        return _sub_text(v), {}
    if isinstance(v, dict) and set(v) == {"Ref"}:
        return "${" + v["Ref"] + "}", {}
    if isinstance(v, dict) and set(v) == {"Fn::GetAtt"}:
        return "${" + ".".join(v["Fn::GetAtt"]) + "}", {}
    inner = _sub_body(v)
    if inner is not None:
        names = {k: f"V{n}{k}" for k in inner[1]}
        return (re.sub(r"\$\{([^!}][^}]*)\}", lambda m: "${" + names.get(m.group(1), m.group(1)) + "}", inner[0]),
                {names[k]: x for k, x in inner[1].items()})
    return "${V" + str(n) + "}", {f"V{n}": v}


def concat(*values):
    """CloudFormation values (literals and functions) written one after another: the text when all are literal, the
    one value when alone, else one Fn::Sub (a Ref / GetAtt as ${...}, another Fn::Sub inline)."""
    values = tuple(v for v in values if v != "")
    if all(isinstance(v, str) for v in values):
        return "".join(values)
    if len(values) == 1:
        return values[0]
    found = tuple(_sub_piece(v, i) for i, v in enumerate(values))
    variables = {k: x for _, vs in found for k, x in vs.items()}
    return sub("".join(t for t, _ in found), variables or None)


def _plain(text, variables):
    """Fn::Sub text as the simplest value it is: a literal, one Ref or GetAtt, else the Fn::Sub."""
    if not variables:
        m = re.fullmatch(r"\$\{([\w:]+)\}", text)
        if m:
            return ref(m.group(1))
        m = re.fullmatch(r"\$\{(\w+)\.([\w.]+)\}", text)
        if m:
            return get_att(m.group(1), m.group(2))
        if "${" not in text.replace("${!", ""):
            return text.replace("${!", "${")
    return sub(text, variables or None)


def trim_prefix(v, prefix):
    """Terraform's trimprefix of a CloudFormation value: a literal without the prefix (when it has it), an Fn::Sub
    without it at the start of its text (unchanged when its text starts with other literal text); refused when what
    v starts with isn't known (a Ref, a GetAtt, text starting with one)."""
    if isinstance(v, str):
        return v.removeprefix(prefix)
    found = _sub_body(v)
    lead = _sub_text(prefix)
    if found is not None and found[0].startswith(lead):
        return _plain(found[0][len(lead):], found[1])
    literal = re.match(r"(?:[^$]|\$(?!\{)|\$\{!)*", found[0]).group(0) if found is not None else ""
    if literal and not lead.startswith(literal):
        return v
    raise SystemExit(f"no CloudFormation form for trimprefix({json.dumps(v)}, {json.dumps(prefix)}): what the value "
                     "starts with is known only at deploy time")


def _join(separator, values):
    """Terraform's join: a literal list's values with the separator between them (concat), a list a function gives
    as Fn::Join."""
    if not isinstance(values, list):
        return {"Fn::Join": [separator, values]}
    return concat(*(x for i, v in enumerate(values) for x in ((separator, v) if i else (v,))))


# An object key a document computes (a CloudFormation function), held as the function's JSON text so the object stays
# a dict (see object_key, json_document).
ComputedKey = namedtuple("ComputedKey", ("text",))


def object_key(v):
    """v as a document's object key: a literal as it is, a CloudFormation function as a ComputedKey."""
    return v if isinstance(v, str) else ComputedKey(json.dumps(v, sort_keys=True))


def _function(v):
    """Whether v is a CloudFormation function (Ref, Fn::*)."""
    key = next(iter(v)) if isinstance(v, dict) and len(v) == 1 else None
    return isinstance(key, str) and (key == "Ref" or key.startswith("Fn::"))


def _keys_computed(v):
    if isinstance(v, dict) and not _function(v):
        return any(isinstance(k, ComputedKey) or _keys_computed(x) for k, x in v.items())
    return isinstance(v, list) and any(_keys_computed(x) for x in v)


def _json_pieces(v):
    """A document's JSON text as literal text and CloudFormation functions (each inside its string's quotes)."""
    if isinstance(v, ComputedKey):
        return '"', json.loads(v.text), '"'
    if _function(v):
        return '"', v, '"'
    if isinstance(v, dict):
        return ("{", *(p for i, (k, x) in enumerate(v.items())
                       for p in ((", ",) if i else ()) + _json_pieces(k) + (": ",) + _json_pieces(x)), "}")
    if isinstance(v, list):
        return "[", *(p for i, x in enumerate(v) for p in ((", ",) if i else ()) + _json_pieces(x)), "]"
    return (json.dumps(v),)


def json_document(v):
    """A JSON document (an IAM policy) as CloudFormation takes it: as it is when every object key is literal, else
    its JSON text as one Fn::Sub (CloudFormation computes a string's parts, never an object's keys: an IRSA trust
    policy's condition keys name the cluster's OIDC issuer)."""
    return concat(*_json_pieces(v)) if _keys_computed(v) else v


_PLACE = r"\$\{([^!}][^}]*)\}"


def _part_of(text, variables):
    """A string of a document parsed from Fn::Sub as the value it stands for: one whole variable as its value, else
    the text with only the variables it uses (_plain: a literal, one Ref / GetAtt, or an Fn::Sub)."""
    whole = re.fullmatch(_PLACE, text)
    if whole and whole.group(1) in variables:
        return variables[whole.group(1)]
    used = dict.fromkeys(n for n in re.findall(_PLACE, text) if n in variables)
    return _plain(text, {n: variables[n] for n in used})


def _parsed(v, variables):
    if isinstance(v, str):
        return _part_of(v, variables)
    if isinstance(v, dict):
        return {object_key(_part_of(k, variables)): _parsed(x, variables) for k, x in v.items()}
    if isinstance(v, list):
        return [_parsed(x, variables) for x in v]
    return v


def document_of(v):
    """A JSON document as json_document wrote it, parsed back: an Fn::Sub of a document's JSON text as the document,
    each string or key holding ${...} as the CloudFormation value it stands for (a computed key as a ComputedKey,
    literal ${!...} text unescaped), so the string form can be read, checked or rewritten into another form; any
    other value (a document already an object, a Sub of other text) as it is."""
    found = _sub_body(v)
    try:
        data = json.loads(found[0]) if found is not None else None
    except ValueError:
        return v
    return _parsed(data, found[1]) if isinstance(data, (dict, list)) else v


# The CloudFormation value forms the engine writes values with.
CLOUDFORMATION = native.Target(LANGUAGE, lambda *values: concat(*values),
                               lambda separator, values: {"Fn::Join": [separator, values]},
                               lambda v, prefix: trim_prefix(v, prefix))


def translate(v, resolve, quoted=False):
    """A Terraform value as CloudFormation's (format-terraform native.translate with CloudFormation's forms): a
    reference through resolve, an interpolated string as one Fn::Sub, a jsonencode() document as the document, join /
    trimprefix calls, lists and objects element by element; literals as they are."""
    return native.translate(v, resolve, CLOUDFORMATION, quoted)


# ------------------------------------------------------------------ a root as templates

Stack = namedtuple("Stack", ("alias", "region", "provider"))


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


def _layout(items):
    """CloudFormation's Layout of a root: a stack per provider alias (its region the provider's), logical ids from the
    type and name."""
    stacks = _stacks(items)
    return Layout(_alias, lambda alias: getattr(stacks.get(alias), "region", None),
                  lambda type_, name: logical_id(_short(type_), name))


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


def _literal(b, attr):
    """A block's attribute when it is set to literal text (the default of the parameter the template reads it
    through: the value the root applied first outputs), else None."""
    v = fields(b.body).get(attr)
    return v if isinstance(v, str) and all(isinstance(p, str) for p in template_parts(v)) else None


def _data_id(r, p):
    return logical_id(_short(r.type), r.name) + p.logical_id


def _answer(r, found):
    """A data table answer as CloudFormation reads it: a pseudo parameter's Ref, a Parameter's Ref (its id made from
    the block's address), a Derived value of one, any other value as it is."""
    if isinstance(found, Pseudo):
        return ref(found.name)
    if isinstance(found, Parameter):
        return ref(_data_id(r, found))
    if isinstance(found, Derived):
        return found.make(ref(_data_id(r, found.parameter)))
    return found


# How CloudFormation reads what a reference names: "Ref" or a GetAtt attribute; another stack's value through the
# parameter carrying its output; a variable's parameter; data answers (_answer); a value of the Terraform root applied
# before the template through the parameter carrying its output.
FORMS = Forms(lambda lid, form: ref(lid) if form == "Ref" else get_att(lid, form), lambda r: ref(_cross_id(r)),
              lambda name: ref(logical_id(name)), _answer, lambda r: ref(_cross_id(r)))


def _data_parameters(root, refs, data):
    """The Parameters the data sources the stack reads become (pseudo parameters and literal values need none; an
    attribute without an answer is refused when a value is translated, not here: a mapping may drop the attribute)."""
    blocks = ((r, root.by_address[ref_address(r)]) for r in refs if r.kind == "data")
    answers = ((r, data[b.labels[0]](fields(b.body), r.attr) if b.labels[0] in data else None) for r, b in blocks)
    return tuple(p._replace(logical_id=_data_id(r, p)) for r, found in answers
                 for p in ((found,) if isinstance(found, Parameter) else
                           (found.parameter,) if isinstance(found, Derived) else ()))


def _default_tags(stack):
    default = fields(stack.provider.body).get("default_tags") if stack.provider else None
    return dict(default[0].get("tags", {})) if default else {}


def _tagged(native_type, f, props, default, cx, where):
    """props with the resource's tags (the provider's default tags under its own) as the type takes them."""
    tags = f.get("tags") or {}
    if not tags and not default:
        return props
    if native_type.tags is None:
        if tags:
            raise SystemExit(f"{where}: tagged in Terraform, but its CloudFormation type takes no tags")
        return props
    found = cx.value({**default, **tags})
    form = native_type.tags
    return {**props, native_type.tags_key: form(found) if callable(form) else tag_list(found) if form == "list"
            else found}


def _cx(root, stack, resolve):
    stacks = _stacks(root.items)

    def logical(a):
        return root.placed[a].id

    def provider_region(alias):
        if alias not in stacks:
            raise SystemExit(f"Terraform root {root.directory}: no provider with alias {alias}")
        return stacks[alias].region
    return Cx(lambda v: translate(v, resolve), root.by_address.get, stack.region if stack else None, logical, ref,
              provider_region, "", LANGUAGE)


def referenced_ids(v):
    """The logical ids (and parameter or pseudo parameter names) a CloudFormation value reads: through Ref,
    Fn::GetAtt and Fn::Sub's ${...} (what CloudFormation already orders a resource after)."""
    if isinstance(v, list):
        return frozenset(i for x in v for i in referenced_ids(x))
    if not isinstance(v, dict):
        return frozenset()
    if set(v) == {"Ref"}:
        return frozenset((v["Ref"],))
    if set(v) == {"Fn::GetAtt"}:
        return frozenset((v["Fn::GetAtt"][0],))
    found = _sub_body(v)
    if found is not None:
        names = frozenset(m.split(".")[0] for m in re.findall(r"\$\{([^!}][^}]*)\}", found[0]))
        return (names - set(found[1])) | referenced_ids(list(found[1].values()))
    return frozenset(i for x in v.values() for i in referenced_ids(x))


def _ready(root, members, cx):
    """{logical id: the logical id of the expansion making it usable} of the stack's resources with a ready
    expansion (Native.ready) that they expand into here (a gateway attached to a VPC)."""
    def expanded(p):
        f = fields(root.by_address[p.address].body)
        return {x[0] for x in p.native.expand(p.id, f, cx._replace(where=p.address))}
    return {p.id: f"{p.id}{p.native.ready}" for p in members
            if p.target is None and p.native.ready and p.native.ready in expanded(p)}


def _import_entry(type_, lid, identifier):
    return {"ResourceType": type_, "LogicalResourceId": lid, "ResourceIdentifier": identifier}


def _resources(root, members, default, cx, imported, notes_above):
    """(the stack's Resources, its resource import entries): each standalone resource with what merges into it, the
    resources it expands into; an adopted one (and its expansions) kept on deletion and listed for import."""
    ids = {p.id for p in members}
    out, entries = [], []
    ready = _ready(root, members, cx)

    def waits(lid, props):
        """The expansions making what props reference usable (ready), but for a resource's own."""
        return tuple(r for i, r in ready.items() if i in referenced_ids(props) and lid not in (i, r))
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
        notes = (*notes_above.get(p.address, ()), *comments(b.body),
                 *(c for m in merged
                   for c in (*notes_above.get(m.address, ()), *comments(root.by_address[m.address].body))))
        implied = referenced_ids(props)
        depends_on = tuple(dict.fromkeys((*(d for m in (p, *(m for m in merged if m.native.merge.ordering))
                                            for d in depends(root, m, ids) if d not in implied),
                                          *waits(p.id, props))))
        adopted = imported.get(p.address)
        kept = "Retain" if adopted is not None else None
        out.append(Resource(p.id, p.native.type, props, depends_on, None, kept, kept,
                            {"Comments": list(notes)} if notes else None))
        identifier = p.native.identifier
        entries.extend(() if adopted is None else (_import_entry(p.native.type, p.id, identifier(adopted)
                                                                 if callable(identifier) else {identifier: adopted}),))
        for x in (p.native.expand(p.id, f, here) if p.native.expand else ()):
            lid = f"{p.id}{x[0]}"
            if adopted is not None and len(x) < 4:
                raise SystemExit(f"{p.address} is adopted, but CloudFormation can't import its {x[1]} {lid}")
            out.append(Resource(lid, x[1], x[2], waits(lid, x[2]), None, kept, kept))
            entries.extend((_import_entry(x[1], lid, x[3](adopted)),) if adopted is not None else ())
    return tuple(out), tuple(entries)


def _imports(root, members):
    """{address: Terraform import id} of the stack's resources the root adopts (import blocks); refused for one
    merged into another (it is imported with the resource it is part of, so it can't be adopted on its own)."""
    found = {a: i for a, i in native.adopted(root.split.native).items()
             if root.placed.get(a) is not None and root.placed[a] in members}
    merged = sorted(a for a in found if root.placed[a].target is not None)
    if merged:
        raise SystemExit(f"adopted, but part of another resource natively: {', '.join(merged)}")
    return found


def _stack_template(m, root, stack, table, what):
    """(Template, its resource import entries) of one stack of the root."""
    members = tuple(p for p in root.placed.values() if p.group == stack.alias)
    refs = group_refs(root, members, table.data)
    resolve = resolver(root, stack.alias, table, CLOUDFORMATION, FORMS)
    cx = _cx(root, stack, resolve)
    notes_above, loose = leading(root.split.native)
    imported = _imports(root, members)
    resources, entries = _resources(root, members, _default_tags(stack), cx, imported, notes_above)
    deployer = tuple(q for p in members if p.native.parameters for q in p.native.parameters(
        fields(root.by_address[p.address].body), cx))
    variables = tuple(_variable_parameter(logical_id(r.name), root.by_address[ref_address(r)]) for r in refs
                      if r.kind == "var")
    crossing = tuple(r for r in refs if r.kind == "resource" and ref_address(r) in root.placed
                     and root.placed[ref_address(r)].group != stack.alias)
    cross = tuple(Parameter(_cross_id(r), "String", None,
                            f"{ref_text(r)}: an output of template {_template_name(root.placed[ref_address(r)].group)}"
                            " (deployed first)") for r in crossing)
    first = tuple(Parameter(_cross_id(r), "String", _literal(root.by_address[ref_address(r)], r.attr),
                            f"{ref_text(r)}: an output of the Terraform root applied before this template "
                            f"({BEFORE_ROOT}/)")
                  for r in refs if r.kind == "resource" and ref_address(r) in root.before)
    parameters = tuple({p.logical_id: p for p in (*_data_parameters(root, refs, table.data), *variables, *cross,
                                                  *first, *deployer)}.values())
    outputs = _outputs(root, stack, members, resolve, table.data)
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


def _outputs(root, stack, members, resolve, data):
    """The stack's Outputs: values of its resources the side Terraform root or another template reads."""
    others = tuple(r for p in root.placed.values() if p.group != stack.alias
                   for r in group_refs(root, (p,), data) if r.kind == "resource"
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


# An environment's translation: templates {path: Template}, imports {path: resource import entries}, side {path:
# TfFile} (the Terraform roots kept beside templates: terraform/, applied after them, and BEFORE_ROOT/, applied before
# them), placements {root directory: {address: Placement}}, packaged {path: text} (the files a root packages, copied
# beside its templates).
Translation = namedtuple("Translation", ("templates", "imports", "side", "placements", "packaged"))
# The folder (beside a root's templates) of the Terraform root applied before them: what they read that CloudFormation
# has no form for (an ALB trust store's CA bundle object in S3)
BEFORE_ROOT = "terraform-before"


def _root_translation(m, root, table, what):
    """(templates, imports, side roots, placements) of one root."""
    out_dir = native_directory(root.directory)
    stacks_found = _stacks(root.items)
    aliases = dict.fromkeys(p.group for p in root.placed.values())
    stacks = sorted((stacks_found.get(a) or Stack(a, None, None) for a in aliases),
                    key=lambda s: (s.alias is not None, s.alias or ""))
    built = tuple((posixpath.join(out_dir, _template_name(s.alias)), *_stack_template(m, root, s, table, what))
                  for s in stacks)
    side_path = posixpath.join(out_dir, "terraform", "main.tf")
    before_path = posixpath.join(out_dir, BEFORE_ROOT, "main.tf")
    side = {side_path: TfFile(header(m, f"{what}: what CloudFormation has no form for", HCL) +
                              no_native_note(root.split, "AWS CloudFormation", root.reasons), root.split.side)} \
        if root.split.side else {}
    before = {before_path: TfFile(header(m, f"{what}: what the CloudFormation templates read, applied before them",
                                         HCL) + before_note(root.split, "AWS CloudFormation", root.reasons),
                                  root.split.before)} if root.split.before else {}
    by_stack = {s.alias: path for s, (path, _, _) in zip(stacks, built)}
    return ({path: t for path, t, _ in built},
            {path.replace(".yaml", ".resources-to-import.json"): e for path, _, e in built if e}, {**side, **before},
            placements(root, by_stack, side_path, before_path))


def translation(m, files, types, no_native, data, what, unavailable=lambda type_, region: False, before=frozenset()):
    """The Translation of environment m's Terraform render ({path: TfFile | text}) into CloudFormation by a table of
    Natives: each Terraform root's templates, resource import entries and side Terraform roots under cloudformation/
    (before: the types with no native form applied before the templates that read them), where each Terraform resource
    went, and the other files a root packages (scripts) copied beside them."""
    table = Table(types, no_native, data, unavailable, before=before)
    parts = {d: _root_translation(m, read_root(d, rf, table, LANGUAGE, _layout), table, what)
             for d, rf in roots(files).items()}
    packaged = {posixpath.join("cloudformation", p.split("/", 1)[1]): text for p, text in files.items()
                if p.startswith("terraform/") and not isinstance(text, TfFile) and not p.endswith(".tf")}
    return Translation({k: v for t, _, _, _ in parts.values() for k, v in t.items()},
                       {k: v for _, i, _, _ in parts.values() for k, v in i.items()},
                       {k: v for _, _, side, _ in parts.values() for k, v in side.items()},
                       {d: p for d, (_, _, _, p) in parts.items()}, packaged)


def translated(m, files, types, no_native, data, what, unavailable=lambda type_, region: False, before=frozenset()):
    """{path: TfFile | text} of environment m's CloudFormation (translation, written): each template as YAML under
    its generated-file header, each import file as JSON, each root's placements.json (where each Terraform resource
    went), the side Terraform roots as TfFiles, the packaged files."""
    t = translation(m, files, types, no_native, data, what, unavailable, before)
    return {**{path: header(m, f"{what}: CloudFormation ({posixpath.basename(path)})", YAML_FORMAT) + as_yaml(template)
               for path, template in t.templates.items()},
            **{path: json.dumps(list(entries), indent=2) + "\n" for path, entries in t.imports.items()},
            **{posixpath.join(out, "placements.json"): json.dumps(placements_document(
                places, lambda where, out=out: posixpath.relpath(where, out)), indent=2) + "\n"
               for directory, places in t.placements.items() for out in (native_directory(directory),)},
            **t.side, **t.packaged}
