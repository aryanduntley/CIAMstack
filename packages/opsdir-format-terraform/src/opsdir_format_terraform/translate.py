"""Terraform data read for translation into another infrastructure-as-code language (a cloud's own templates): a
rendered root's blocks, the references their values make, and the split of a root into what the other language
writes and what stays Terraform because it has no form there.
A format library: it knows Terraform's references and roots, not any cloud provider or target language. The cloud
adapters hold the mapping of their resource types and write the target language from what this gives them.
"""
import posixpath
import re
from typing import NamedTuple

from .hcl import Block, TfBlock, TfFile, tf_block, tf_name

# A reference an expression makes: kind resource | data | var | local | module | path | self | each | count |
# terraform; type: the resource or data source type ('' for the other kinds); name: the block's name (the variable's,
# the module's, path's 'module', ...); attr: the rest of the traversal as written ('id', 'arns[0]', '' when none).
TfRef = NamedTuple("TfRef", [("kind", str), ("type", str), ("name", str), ("attr", str)])
# An interpolation that is more than one reference (a function call, an operator, a literal object): its expression
# text as written, and the references it makes.
Raw = NamedTuple("Raw", [("text", str), ("refs", tuple)])
# A root split for translation. native: the root's items the other language writes (the resources with a form there,
# their imports, the data, variable, provider and terraform blocks they or those read, the comments above them).
# side: the items of the Terraform root kept beside the template (the terraform and provider blocks, the resources with
# no form there, their imports, the data and variable blocks they read, the comments above them, and a variable for
# each value of a natively written resource they read). outputs: the references to natively written resources the
# side root reads (the template outputs them; the side root takes each as the variable output_variable names).
# unresolved: (address, TfRef) for each natively written block reading a resource that stays Terraform.
Split = NamedTuple("Split", [("native", tuple), ("side", tuple), ("outputs", tuple), ("unresolved", tuple)])

_SEGMENT = r"(?:\.[A-Za-z_][\w-]*|\.\d+|\.\*|\[(?:\d+|\"[^\"]*\"|\*)\])"
_TRAVERSAL = re.compile(r"[A-Za-z_][\w-]*" + _SEGMENT + "+")
_NAMED = ("var", "local", "module", "path", "self", "each", "count", "terraform")
_RESOURCE_TYPE = re.compile(r"^[a-z][a-z0-9]*_[a-z0-9_]+$")


def _string_end(text, i):
    """The index just past the string literal opening at text[i] ('"'), its escapes and interpolations skipped."""
    j = i + 1
    while j < len(text) and text[j] != '"':
        j = _interpolation_end(text, j + 2) if text.startswith("${", j) else j + (2 if text[j] == "\\" else 1)
    return j + 1


def _interpolation_end(text, i):
    """The index just past the '}' closing the expression that starts at text[i] (after its '${' or '{'), nested
    braces and string literals skipped."""
    depth, j = 1, i
    while depth:
        if j >= len(text):
            raise ValueError(f"unclosed interpolation: {text!r:.80}")
        c = text[j]
        depth += (c == "{") - (c == "}")
        j = _string_end(text, j) if c == '"' else j + 1
    return j


def is_quoted_string(text):
    """Whether an expression is exactly one quoted string (a template such as "${a},${b}")."""
    text = text.strip()
    return len(text) > 1 and text[0] == '"' and text[-1] == '"' and _string_end(text, 0) == len(text)


def parse_ref(text):
    """The reference an expression is when it is exactly one traversal (aws_vpc.main.id, data.aws_region.current.name,
    var.region, path.module, ...), else None."""
    text = text.strip()
    if not _TRAVERSAL.fullmatch(text):
        return None
    head, _, rest = text.partition(".")
    if head == "data":
        type_, _, rest = rest.partition(".")
        name, attr = _split_name(rest)
        return TfRef("data", type_, name, attr) if name else None
    if head in _NAMED:
        name, attr = _split_name(rest)
        return TfRef(head, "", name, attr)
    if _RESOURCE_TYPE.match(head):
        name, attr = _split_name(rest)
        return TfRef("resource", head, name, attr)
    return None


def _split_name(rest):
    """(the first segment, the traversal after it) of what follows a reference's head."""
    m = re.match(r"([A-Za-z_][\w-]*|\d+|\*)", rest)
    if not m:
        return "", ""
    after = rest[m.end():]
    return m.group(1), after[1:] if after.startswith(".") else after


def expression_refs(text):
    """Every reference an expression makes, in order, each once: its traversals that name a block (not function
    names, not object keys, not a for expression's own symbols), and those inside its string literals' interpolations.
    """
    found, i = [], 0
    while i < len(text):
        if text[i] == '"':
            end = _string_end(text, i)
            found.extend(r for part in template_parts(text[i + 1:end - 1]) for r in _part_refs(part))
            i = end
            continue
        m = _TRAVERSAL.match(text, i) if (i == 0 or not re.match(r"[\w.\]]", text[i - 1])) else None
        if m:
            called = text[m.end():].lstrip().startswith("(")
            r = None if called else parse_ref(m.group(0))
            found.extend((r,) if r else ())
            i = m.end()
            continue
        i += 1
    return tuple(dict.fromkeys(found))


def _part_refs(part):
    if isinstance(part, TfRef):
        return (part,)
    return part.refs if isinstance(part, Raw) else ()


def _expression(text):
    """An interpolation's expression as a TfRef when it is one reference, else as Raw."""
    r = parse_ref(text)
    return r if r else Raw(text, expression_refs(text))


def template_parts(s, quoted=False):
    """A string value of a block's body as parts, as hcl() writes it: a raw expression ('${...}' whole) is one part;
    a quoted string is its literal text and its interpolations in order. A part is literal text (str), a TfRef (an
    interpolation that is one reference) or a Raw (any other). quoted: s is a quoted string's content (inside an
    expression or a jsonencode() document), so a template throughout."""
    if not quoted and s.startswith("${") and s.endswith("}"):
        return (_expression(s[2:-1]),)
    parts, i = [], 0
    while True:
        j = s.find("${", i)
        if j < 0:
            return tuple(parts + ([s[i:]] if s[i:] else []))
        end = _interpolation_end(s, j + 2)
        parts.extend(([s[i:j]] if j > i else []) + [_expression(s[j + 2:end - 1])])
        i = end


def value_refs(v):
    """Every reference a body value makes (through nested blocks, lists and objects), in order, each once."""
    if isinstance(v, str):
        return tuple(dict.fromkeys(r for part in template_parts(v) for r in _part_refs(part)))
    if isinstance(v, Block):
        return value_refs(v.body)
    if isinstance(v, dict):
        return value_refs(tuple(v.values()))
    if isinstance(v, (list, tuple)):
        return tuple(dict.fromkeys(r for x in v for r in value_refs(x)))
    return ()


def ref_text(r):
    """A reference as Terraform writes it (aws_vpc.main.id, data.aws_region.current.name, var.region)."""
    head = {"resource": r.type, "data": f"data.{r.type}"}.get(r.kind, r.kind)
    attr = "" if not r.attr else r.attr if r.attr.startswith("[") else f".{r.attr}"
    return f"{head}.{r.name}{attr}"


def address(item):
    """The address of a top-level block, as references name it: type.name (resource), data.type.name, var.name,
    module.name; other blocks (provider, terraform, import) and comments have none (None)."""
    if not isinstance(item, TfBlock):
        return None
    if item.kind == "resource":
        return ".".join(item.labels[:2])
    prefix = {"data": "data", "variable": "var", "module": "module"}.get(item.kind)
    return ".".join((prefix, *item.labels[:2])) if prefix else None


def ref_address(r):
    """The address of the block a reference reads (resource, data source, variable, module), else None (path, self,
    each, count, terraform, local)."""
    if r.kind == "resource":
        return f"{r.type}.{r.name}"
    if r.kind == "data":
        return f"data.{r.type}.{r.name}"
    return {"var": f"var.{r.name}", "module": f"module.{r.name}"}.get(r.kind)


def roots(files):
    """{directory: ((path, TfFile), ...)} of the Terraform roots among an adapter's rendered files ({path: TfFile |
    text}): each directory's TfFiles in path order; files that aren't Terraform data are left out."""
    tf = sorted((p, f) for p, f in files.items() if isinstance(f, TfFile))
    return {d: tuple((p, f) for p, f in tf if posixpath.dirname(p) == d)
            for d in dict.fromkeys(posixpath.dirname(p) for p, _ in tf)}


def root_items(root):
    """A root's items (its files' TfBlocks and comments) in file order: what a translation reads."""
    return tuple(x for _, f in root for x in f.items)


def _groups(items):
    """(comments, block) pairs: each block with the comments directly above it; comments after the last block form a
    group with None."""
    out, pending = [], []
    for x in items:
        if isinstance(x, TfBlock):
            out.append((tuple(pending), x))
            pending = []
        else:
            pending.append(x)
    return tuple(out) + (((tuple(pending), None),) if pending else ())


def _import_target(b):
    """The address an import block adopts into."""
    to = dict(b.body).get("to")
    r = parse_ref(to[2:-1]) if isinstance(to, str) and to.startswith("${") else None
    return ref_address(r) if r else None


def _closure(blocks, by_address):
    """The addresses of the data, variable and module blocks the blocks read, and those those read, transitively."""
    seen, todo = set(), [r for b in blocks for r in value_refs(b.body)]
    while todo:
        a = ref_address(todo.pop())
        if a and a not in seen and a in by_address and by_address[a].kind != "resource":
            seen.add(a)
            todo.extend(value_refs(by_address[a].body))
    return seen


def output_variable(r):
    """The name of the variable a side root reads a natively written resource's value through."""
    return re.sub("_+", "_", tf_name(f"{r.type}_{r.name}_{r.attr}")).rstrip("_")


def _reads(b):
    """The references a block's body makes, its depends_on aside (an ordering, not a value)."""
    return value_refs(tuple(kv for kv in b.body if kv[0] != "depends_on"))


def _rewritten_part(part, native):
    if isinstance(part, TfRef):
        return "${" + (f"var.{output_variable(part)}" if ref_address(part) in native else ref_text(part)) + "}"
    if isinstance(part, Raw):
        text = part.text
        for r in (r for r in part.refs if ref_address(r) in native):
            text = re.sub(rf"(?<![\w.]){re.escape(ref_text(r))}(?![\w\[.-])", f"var.{output_variable(r)}", text)
        return "${" + text + "}"
    return part


def _rewritten(v, native):
    """A body value with every reference to a natively written resource (native: their addresses) read through its
    output variable."""
    if isinstance(v, str):
        if not any(ref_address(r) in native for r in value_refs(v)):
            return v
        return "".join(_rewritten_part(p, native) for p in template_parts(v))
    if isinstance(v, Block):
        return Block(_rewritten(v.body, native))
    if isinstance(v, dict):
        return {k: _rewritten(x, native) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return type(v)(_rewritten(x, native) for x in v)
    return v


def _side_pair(kv, native):
    """A body pair of a block kept in the side root: its references to natively written resources read through
    their output variables, a depends_on naming one losing that entry (the template is applied first); None when
    nothing is left of it."""
    k, v = kv
    if k != "depends_on":
        return k, _rewritten(v, native)
    kept = tuple(x for x in v if not any(ref_address(r) in native for r in value_refs(x)))
    return (k, kept) if kept else None


def _side_block(b, native):
    return b._replace(body=tuple(kv for kv in (_side_pair(kv, native) for kv in b.body) if kv))


def _output_variables(outputs):
    return tuple(tf_block("variable", [output_variable(r)], [
        ("description", f"{ref_text(r)}: an output of the template this root is applied after")]) for r in outputs)


def split_root(items, has_native):
    """A root's items split for translation (Split); has_native(resource block): whether the other language has a
    form for the resource. Data sources, variables and modules go to whichever side reads them (both, when both do;
    the template's, when neither does); both sides keep the provider and terraform blocks."""
    groups = _groups(items)
    blocks = tuple(b for _, b in groups if b is not None)
    by_address = {address(b): b for b in blocks if address(b)}
    stays = {address(b) for b in blocks if b.kind == "resource" and not has_native(b)}

    def on_side(b):
        return (b.kind == "resource" and address(b) in stays) or (b.kind == "import" and _import_target(b) in stays)

    shared = tuple(b for b in blocks if b.kind in ("provider", "terraform"))
    side_blocks = tuple(b for b in blocks if on_side(b))
    native_blocks = tuple(b for b in blocks if b.kind in ("resource", "import") and not on_side(b))
    native_reads, side_reads = _closure((*native_blocks, *shared), by_address), _closure((*side_blocks, *shared),
                                                                                         by_address)
    written = {address(b) for b in native_blocks if b.kind == "resource"}
    outputs = tuple(dict.fromkeys(r for b in (*side_blocks, *(by_address[a] for a in side_reads)) for r in _reads(b)
                                  if ref_address(r) in written))
    unresolved = tuple((address(b) or b.kind, r) for b in (*native_blocks, *(by_address[a] for a in native_reads))
                       for r in _reads(b) if ref_address(r) in stays)

    def kept(b, side):
        if b is None or b.kind in ("provider", "terraform"):
            return b is not None or not side
        if b.kind in ("resource", "import"):
            return on_side(b) == side
        return address(b) in side_reads if side else address(b) in native_reads or address(b) not in side_reads

    native = tuple(x for comments, b in groups if kept(b, False) for x in (*comments, *((b,) if b else ())))
    side = tuple(x for comments, b in groups if kept(b, True) for x in (*comments, _side_block(b, written)))
    return Split(native, (*side, *_output_variables(outputs)) if side_blocks else (), outputs, unresolved)


def no_native_note(split, language, reasons=None):
    """The NOTE heading a side root (comment lines): the resources it keeps in Terraform, each by address, because
    the language (its title) has no form for them (or, reasons: {address: why}, for the reason given); that it is
    applied after the template, and reads the template's outputs when it does."""
    reasons = reasons or {}
    kept = [address(b) for b in split.side if isinstance(b, TfBlock) and b.kind == "resource"]
    reads = ", its variables taking the template's outputs" if split.outputs else ""
    head = (f"# NOTE: these resources stay Terraform beside the {language} template; this root manages them, applied "
            f"after the template{reads}:\n" if reasons else
            f"# NOTE: {language} has no form for these resources; this Terraform root manages them, applied "
            f"after the template{reads}:\n")
    return "".join((head, *(f"#   {a}{': ' + reasons[a] if a in reasons else ''}\n" for a in kept)))
