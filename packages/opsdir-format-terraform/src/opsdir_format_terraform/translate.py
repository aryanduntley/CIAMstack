"""Terraform data read for translation into another infrastructure-as-code language (a cloud's own templates): a
rendered root's blocks, the references their values make, the split of a root into what the other language
writes and what stays Terraform because it has no form there, and the partition of a root among several Terraform
roots (each keeper's, a scoped slice), each complete with the inputs it reads from the others.
A format library: it knows Terraform's references and roots, not any cloud provider or target language. The cloud
adapters hold the mapping of their resource types and write the target language from what this gives them.
"""
import posixpath
import re
from typing import NamedTuple

from .hcl import ANCHOR, Block, TfBlock, TfFile, tf_block, tf_name

# A reference an expression makes: kind resource | data | ephemeral | var | local | module | path | self | each |
# count | terraform; type: the resource, data source or ephemeral resource type ('' for the other kinds); name: the
# block's name (the variable's, the module's, path's 'module', ...); attr: the rest of the traversal as written ('id',
# 'arns[0]', '' when none).
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
    ephemeral.azurerm_key_vault_secret.admin.value, var.region, path.module, ...), else None."""
    text = text.strip()
    if not _TRAVERSAL.fullmatch(text):
        return None
    head, _, rest = text.partition(".")
    if head in ("data", "ephemeral"):
        type_, _, rest = rest.partition(".")
        name, attr = _split_name(rest)
        return TfRef(head, type_, name, attr) if name else None
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
    head = {"resource": r.type, "data": f"data.{r.type}", "ephemeral": f"ephemeral.{r.type}"}.get(r.kind, r.kind)
    attr = "" if not r.attr else r.attr if r.attr.startswith("[") else f".{r.attr}"
    return f"{head}.{r.name}{attr}"


def address(item):
    """The address of a top-level block, as references name it: type.name (resource), data.type.name,
    ephemeral.type.name, var.name, module.name; other blocks (provider, terraform, import) and comments have none
    (None)."""
    if not isinstance(item, TfBlock):
        return None
    if item.kind == "resource":
        return ".".join(item.labels[:2])
    prefix = {"data": "data", "ephemeral": "ephemeral", "variable": "var", "module": "module"}.get(item.kind)
    return ".".join((prefix, *item.labels[:2])) if prefix else None


def ref_address(r):
    """The address of the block a reference reads (resource, data source, ephemeral resource, variable, module), else
    None (path, self, each, count, terraform, local)."""
    if r.kind == "resource":
        return f"{r.type}.{r.name}"
    if r.kind in ("data", "ephemeral"):
        return f"{r.kind}.{r.type}.{r.name}"
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


def _checks(b):
    """Whether a data block checks something (lifecycle pre/postconditions): the other language can't, so the side
    root keeps it."""
    return b.kind == "data" and any(k == "lifecycle" for k, _ in b.body)


def split_root(items, has_native):
    """A root's items split for translation (Split); has_native(resource block): whether the other language has a
    form for the resource. Data sources, variables and modules go to whichever side reads them (both, when both do;
    the template's, when neither does); a data source that checks something (lifecycle conditions) is the side
    root's too, as only Terraform makes the check; both sides keep the provider and terraform blocks."""
    groups = _groups(items)
    blocks = tuple(b for _, b in groups if b is not None)
    by_address = {address(b): b for b in blocks if address(b)}
    stays = {address(b) for b in blocks if b.kind == "resource" and not has_native(b)}

    def on_side(b):
        return (b.kind == "resource" and address(b) in stays) or (b.kind == "import" and _import_target(b) in stays)

    shared = tuple(b for b in blocks if b.kind in ("provider", "terraform"))
    side_blocks = tuple(b for b in blocks if on_side(b))
    native_blocks = tuple(b for b in blocks if b.kind in ("resource", "import") and not on_side(b))
    checking = tuple(b for b in blocks if _checks(b))
    native_reads = _closure((*native_blocks, *shared), by_address)
    side_reads = _closure((*side_blocks, *shared, *checking), by_address) | {address(b) for b in checking}
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
    return Split(native, (*side, *_output_variables(outputs)) if side_blocks or checking else (), outputs, unresolved)


# A root's items partitioned among Terraform roots (partition). roots: {root: items}, in the order they apply, each
# complete: its resources and imports, every provider and terraform block, the data, ephemeral, variable and module
# blocks it reads, the comments above each; a value of a resource another root writes read through an input variable
# (output_variable names it) and output by that root. inputs, outputs: {root: (TfRef, ...)}, for the roots that have
# any; order: the roots, each after every root it reads.
Partition = NamedTuple("Partition", [("roots", dict), ("inputs", dict), ("outputs", dict), ("order", tuple)])


def _apply_order(names, reads_from):
    """names in an order where each comes after every root it reads (reads_from: {root: {root, ...}}), else stable;
    ValueError naming two roots that read each other (directly or through others)."""
    done, out = set(), []

    def visit(r, path):
        if r in path:
            loop = path[path.index(r):]
            raise ValueError(f"roots {loop[0]!r} and {loop[-1]!r} read each other's resources ("
                             f"{' -> '.join((*loop, r))}): no order applies them")
        if r not in done:
            for w in sorted(reads_from.get(r, ()), key=names.index):
                visit(w, (*path, r))
            done.add(r)
            out.append(r)
    for n in names:
        visit(n, ())
    return tuple(out)


def _outputs_of(refs, sensitive):
    return tuple(tf_block("output", [output_variable(r)], [
        ("value", "${" + ref_text(r) + "}"), *((("sensitive", True),) if sensitive(r) else ())]) for r in refs)


def _inputs_of(refs, writer, sensitive, label):
    return tuple(tf_block("variable", [output_variable(r)], [
        ("description", f"{ref_text(r)}: {label(writer[r])}"),
        *((("sensitive", True),) if sensitive(r) else ())]) for r in refs)


def _applied_before(root):
    return f"an output of root {root}, applied before this one"


def partition(items, place, default, sensitive=lambda r: False, label=_applied_before):
    """A root's items partitioned among roots (Partition). place(resource block): the root it goes to (by its origin,
    hcl.from_entry), None for the default root; an import block goes with the resource it adopts, an anchor (and the
    comments above it) where place puts it. Each root takes
    every provider and terraform block and the data, ephemeral, variable and module blocks it reads (several roots
    when several do; the default root's when none does), and the trailing comments go to the default root; with
    everything placed in the default root it is the items unchanged. A reference to a resource another root writes is
    read through an input variable, the writing root outputting it (sensitive(ref): marked sensitive on both sides;
    label(root): what the variable's description says of the root it comes from);
    a depends_on naming one loses that entry (the order applies it first). ValueError when two roots read each other,
    an input's name is a variable the root has already, or one resource address is placed in two roots (a renderer
    wrote it twice: each root would hold both)."""
    groups = _groups(items)
    blocks = tuple(b for _, b in groups if b is not None)
    by_address = {address(b): b for b in blocks if address(b)}
    placed_in = tuple((address(b), place(b) or default) for b in blocks if b.kind == "resource")
    writes = dict(placed_in)
    twice = sorted({a for a, r in placed_in if writes[a] != r})
    if twice:
        raise ValueError(f"resources placed in two roots: {', '.join(twice)} (render each once, read it across roots)")

    def root_of(b):
        if b.kind == ANCHOR:
            return place(b) or default
        return writes[address(b)] if b.kind == "resource" else writes.get(_import_target(b), default)

    shared = tuple(b for b in blocks if b.kind in ("provider", "terraform"))
    placed = tuple(b for b in blocks if b.kind in ("resource", "import", ANCHOR))
    names = tuple(dict.fromkeys((default, *(root_of(b) for b in placed))))
    reads = {r: _closure((*(b for b in placed if root_of(b) == r), *shared), by_address) for r in names}
    unread = {address(b) for b in blocks if b.kind not in ("resource", "import", "provider", "terraform")
              and not any(address(b) in reads[r] for r in names)}
    reads[default] = reads[default] | unread

    def kept(b, r):
        if b is None or b.kind in ("provider", "terraform"):
            return b is not None or r == default
        return root_of(b) == r if b.kind in ("resource", "import", ANCHOR) else address(b) in reads[r]

    def foreign(r):
        return {a for a, w in writes.items() if w != r}

    reading = {r: (*shared, *(b for b in blocks if b.kind not in ("provider", "terraform") and kept(b, r)))
               for r in names}
    inputs = {r: tuple(dict.fromkeys(ref for b in reading[r] for ref in _reads(b) if ref_address(ref) in foreign(r)))
              for r in names}
    writer = {ref: writes[ref_address(ref)] for refs in inputs.values() for ref in refs}
    clash = sorted(f"{r}: {a}" for r in names for ref in inputs[r] for a in (f"var.{output_variable(ref)}",)
                   if a in by_address and kept(by_address[a], r))
    if clash:
        raise ValueError(f"an input a root reads another root's resource through is named like a variable it has: "
                         f"{', '.join(clash)}")
    after = {r: {writes[ref_address(ref)] for b in reading[r] for ref in value_refs(b.body)
                 if ref_address(ref) in foreign(r)} for r in names}       # values and depends_on alike
    trailing = bool(groups) and groups[-1][1] is None
    # a root with nothing of its own but the providers and what they read is left out
    held = {r: any(root_of(b) == r for b in placed) or (r == default and bool(unread or trailing)) for r in names}
    order = tuple(r for r in _apply_order(names, after) if held[r])
    outputs = {w: tuple(dict.fromkeys(ref for r in order for ref in inputs[r] if writer[ref] == w)) for w in order}
    roots = {r: (*(x for comments, b in groups if kept(b, r) for x in (*comments, *(() if b is None else (
                 _side_block(b, foreign(r)) if after[r] else b,)))),
                 *_inputs_of(inputs[r], writer, sensitive, label), *_outputs_of(outputs[r], sensitive)) for r in order}
    return Partition(roots, {r: inputs[r] for r in order if inputs[r]}, {r: v for r, v in outputs.items() if v},
                     order)


def no_native_note(split, language, reasons=None):
    """The NOTE heading a side root (comment lines): the resources it keeps in Terraform, each by address, because
    the language (its title) has no form for them (or, reasons: {address: why}, for the reason given); that it is
    applied after the template, and reads the template's outputs when it does."""
    reasons = reasons or {}
    kept = [address(b) for b in split.side if isinstance(b, TfBlock) and (b.kind == "resource" or _checks(b))]
    reads = ", its variables taking the template's outputs" if split.outputs else ""
    head = (f"# NOTE: these resources stay Terraform beside the {language} template; this root manages them, applied "
            f"after the template{reads}:\n" if reasons else
            f"# NOTE: {language} has no form for these resources; this Terraform root manages them, applied "
            f"after the template{reads}:\n")
    return "".join((head, *(f"#   {a}{': ' + reasons[a] if a in reasons else ''}\n" for a in kept)))
