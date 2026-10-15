"""An environment's Terraform render placed in roots (5.7, decision 2732). The render comes as parts, each the items of
one file name, all one root before placement. Each block is placed by its origin (hcl.from_entry) through
translate.partition into the roots a place function gives. Each root's items are regrouped into the files they came
from: a variable or output the partition adds goes in providers.tf. The aliased providers and required providers a
root doesn't use are left out. The roots named(root) says belong to a named keeper (asked, not rendered) are left out
and their resources listed. place_roots is the format alone: who keeps what, and so where a block goes, is the
caller's. The keeper_* functions compose it with the core's keepers (governance.keepers) for the cloud renderers: an
environment's roots by who keeps what, their files' headers, and what a keeper keeps of the network plumbing.
"""
import posixpath
import re
from typing import NamedTuple

from opsdir.core.directory import is_kind
from opsdir.core.manifest import header
from opsdir.domains.governance.keepers import (SLICE, asked_lines, in_scope, named_keeper, placement, root_keeper,
                                             scope_title, source_label)
from opsdir.domains.network.plumbing import LANDING_ZONE, NETWORK_FILE
from .format import FORMAT as HCL
from .hcl import ANCHOR, Block, TfBlock, TfFile, comment, distinct, from_entry
from .translate import _import_target, _reads, address, partition, ref_address

PROVIDERS = "providers.tf"
STACK = "terraform"           # the stack's own root
# a path a root reads beside its own .tf files (a source_dir, a file() argument)
_MODULE_PATH = re.compile(r"\$\{path\.module\}/([\w./-]+)")
MAIN = "main.tf"
# blocks several renderers may write alike: one copy is kept (a resource or import is never merged)
_SHARED = ("data", "ephemeral", "variable", "provider", "terraform")

# files: {root: {file name: items}} of the rendered roots, in the order they apply; named: {root: ((origin, address),
# ...)} of the roots left out, the resources each holds and the entry each renders; inputs, outputs: {root: (TfRef,
# ...)} (translate.Partition), the rendered and named roots alike; order: every root, each after the roots it reads
Placed = NamedTuple("Placed", [("files", dict), ("named", dict), ("inputs", dict), ("outputs", dict), ("order", tuple)])
# What a cloud renders of a plumbing binding, or of all a keeper keeps. blocks: what the binding renders; variables:
# inputs only its keeper knows; shared: data sources and resources rendered once in the root, however many bindings
# use them
Rendered = NamedTuple("Rendered", [("blocks", tuple), ("variables", tuple), ("shared", tuple)])


def _key(b):
    return b.kind, b.labels, _import_target(b) if b.kind == "import" else b.origin if b.kind == ANCHOR else None


def _merged(parts):
    """(items, {block key: file name}): the parts' items in order, a shared block written alike by several renderers
    kept once, and the file each block came from first. A part is (file name, items) or (file name, items, origin):
    comments followed by no block that is placed itself (a lookup, a variable, a provider, or the part's end) are closed
    by an anchor of the part's origin (None: the default root's), so they stay with the part rather than travel with a
    lookup to wherever it is read."""
    items, kept, file_of = [], [], {}
    for part in parts:
        name, part_items, origin = (*part, None)[:3]
        pending = []
        for x in part_items:
            if not isinstance(x, TfBlock):
                pending.append(x)
                continue
            if pending and x.kind not in ("resource", "import", ANCHOR):
                items.extend((*pending, TfBlock(ANCHOR, (name,), (), origin)))
                file_of.setdefault(_key(items[-1]), name)
                pending = []
            if x.kind in _SHARED:
                if x in kept:
                    continue
                kept.append(x)
            file_of.setdefault(_key(x), name)
            items.extend((*pending, x))
            pending = []
        if pending:
            items.extend((*pending, TfBlock(ANCHOR, (name,), (), origin)))
            file_of.setdefault(_key(items[-1]), name)
    return tuple(items), file_of


def _strings(v):
    """Every string in a body value, through nested blocks, lists and objects."""
    if isinstance(v, str):
        return (v,)
    if isinstance(v, Block):
        return _strings(v.body)
    if isinstance(v, dict):
        return _strings(tuple(v.values()))
    if isinstance(v, (list, tuple)):
        return tuple(s for x in v for s in _strings(x))
    return ()


def _used_providers(items):
    """(local names, aliases as name.alias) the blocks of a root use: their types' provider prefix (aws_instance:
    aws), and the provider = name.alias references."""
    blocks = tuple(x for x in items if isinstance(x, TfBlock) and x.kind not in ("provider", "terraform"))
    names = {b.labels[0].split("_", 1)[0] for b in blocks if b.kind in ("resource", "data", "ephemeral") and b.labels}
    aliases = {s[2:-1] for b in blocks for k, v in b.body if k == "provider" for s in _strings(v)
               if s.startswith("${") and s.endswith("}")}
    return names, aliases


def _pruned(items):
    """A root's items without the provider blocks nothing in it uses (no block of the provider's types; an alias no
    provider = name.alias names) and the required providers no block in it belongs to (or configures)."""
    names, aliases = _used_providers(items)

    def alias(b):
        return next((v for k, v in b.body if k == "alias"), None)
    out = tuple(x for x in items if not (isinstance(x, TfBlock) and x.kind == "provider" and (
        x.labels[0] not in names or alias(x) and f"{x.labels[0]}.{alias(x)}" not in aliases)))
    wanted = names | {x.labels[0] for x in out if isinstance(x, TfBlock) and x.kind == "provider"}

    def required(kv):
        k, v = kv
        return (k, Block(tuple(p for p in v.body if p[0] in wanted))) \
            if k == "required_providers" and isinstance(v, Block) else kv
    return tuple(x._replace(body=tuple(required(kv) for kv in x.body))
                 if isinstance(x, TfBlock) and x.kind == "terraform" else x for x in out)


def _first_readers(items, file_of):
    """{address: file name} of the data and ephemeral blocks of a root: the file of the first block there reading it
    that isn't a lookup itself (a resource, import or anchor), directly or through other lookups, so a lookup several
    renderers write sits beside what reads it in each root."""
    blocks = tuple(x for x in items if isinstance(x, TfBlock) and x.kind not in ("provider", "terraform"))
    lookup = {address(b): b for b in blocks if b.kind in ("data", "ephemeral")}
    found = {}

    def reach(a, name):
        if a in lookup and a not in found:
            found[a] = name
            for r in _reads(lookup[a]):
                reach(ref_address(r), name)
    for b in blocks:
        if b.kind not in ("data", "ephemeral", "variable") and _key(b) in file_of:
            for r in _reads(b):
                reach(ref_address(r), file_of[_key(b)])
    return found


def _files(items, file_of):
    """{file name: items} of a root: each block in the file it came from (a data or ephemeral block in the file of the
    first block there reading it; one the partition added, a variable or an output, in providers.tf; any other in
    main.tf), the comments above it with it, trailing comments in main.tf."""
    out, pending, readers = {}, [], _first_readers(items, file_of)
    for x in items:
        if not isinstance(x, TfBlock):
            pending.append(x)
            continue
        name = readers.get(address(x)) or file_of.get(_key(x)) or (
            PROVIDERS if x.kind in ("variable", "output", "provider", "terraform") else MAIN)
        out.setdefault(name, []).extend((*pending, *(() if x.kind == ANCHOR else (x,))))     # anchors aren't written
        pending = []
    if pending:
        out.setdefault(MAIN, []).extend(pending)
    return {name: tuple(xs) for name, xs in out.items()}


def place_roots(parts, place, default, named=lambda root: None, adjust=lambda root, items: items,
                sensitive=lambda ref: False, label=None):
    """An environment's Terraform render placed in roots (Placed). parts: ((file name, items[, origin]), ...) of the
    render as one root (origin: where the part's loose comments belong, _merged); place(origin): the root of a block
    of that origin, None for default (the stack's); named(root): the keeper a root names when it is asked of them
    rather than rendered, else None; adjust(root, items): a root's items
    as its provider configuration wants them (before unused providers are left out); sensitive(ref): whether a value
    read across roots is sensitive; label(root): what an input's description says of the root it comes from.
    ValueError as translate.partition."""
    items, file_of = _merged(parts)
    opts = {"label": label} if label else {}
    p = partition(items, lambda b: place(b.origin), default, sensitive, **opts)
    files = {r: _files(_pruned(adjust(r, p.roots[r])), file_of) for r in p.order if named(r) is None}
    left = {r: tuple((b.origin, address(b)) for b in p.roots[r] if isinstance(b, TfBlock) and b.kind == "resource")
            for r in p.order if named(r) is not None}
    return Placed(files, left, p.inputs, p.outputs, p.order)


def carried_files(roots, files, default):
    """{path: text} of the files the roots other than default read beside them: each file of files under
    <default>/<rel> that a string in a root's blocks names as ${path.module}/<rel> (a script's source_dir, a workflow's
    file()), copied to <root>/<rel>. roots: {path: TfFile} as placed; files: the render's other files ({path: text})."""
    wanted = {(posixpath.dirname(path), rel) for path, f in roots.items() if isinstance(f, TfFile)
              and posixpath.dirname(path) != default for x in f.items if isinstance(x, TfBlock)
              for s in _strings(x.body) for rel in _MODULE_PATH.findall(s)}
    return {f"{root}/{p[len(default) + 1:]}": text for root, rel in sorted(wanted) for p, text in files.items()
            if p == f"{default}/{rel}" or p.startswith(f"{default}/{rel}/")}


def keeper_head(m, root, name, keeper, cloud):
    """The header of file name in a keeper's root (keeper: who keeps it; root: the landing zone's or another
    party's; cloud: the cloud's name as the headers write it)."""
    if name == PROVIDERS:
        return header(m, "Providers and inputs (landing zone)", HCL)
    if name == NETWORK_FILE:
        what = (f"{cloud} network kept by {keeper} for the CIAM platform: applied by them, not by the platform's "
                "pipeline")
    elif root == LANDING_ZONE:
        what = (f"{cloud} landing zone for the CIAM platform, kept by {keeper}: applied by the landing zone, not by "
                "the platform's pipeline")
    else:
        what = (f"{cloud} infrastructure kept by {keeper} for the CIAM platform: applied by them, not by the "
                "platform's pipeline")
    return header(m, what, HCL)


def keeper_placed(m, parts, landing_dns, adjust=lambda root, items: items):
    """Placed of environment m's render parts by who keeps what (governance.keepers.placement; landing_dns: the
    landing zone's entries): the stack's root, each keeper's, a named keeper's left out; adjust as place_roots."""
    return place_roots(parts, placement(m, landing_dns), STACK, named=named_keeper, adjust=adjust, label=source_label)


def keeper_roots(m, parts, landing_dns, stack_head, cloud, adjust=lambda root, items: items,
                 providers=lambda placed: lambda root, items: items):
    """{path: TfFile} of environment m's Terraform roots: its render parts placed by who keeps what (keeper_placed):
    the stack's root (stack_head(file name): its files' headers), a slice's, each keeper's that takes generated
    infrastructure (keeper_head; cloud: the cloud's name as the headers write it), and in the stack's main.tf a
    comment for each entry asked of a keeper instead. adjust(root, items): as place_roots; providers(placed): a
    function (root, items) giving each root's providers.tf items as the cloud writes them."""
    placed = keeper_placed(m, parts, landing_dns, adjust)
    written = providers(placed)

    def head(root, name, files):
        if root == STACK:
            return stack_head(name)
        if root == SLICE:
            return header(m, "Providers and inputs (a slice)" if name == PROVIDERS else
                          f"{cloud} infrastructure for the CIAM platform, {scope_title(m)}: a slice rendered on "
                          "request, applied after the roots it reads", HCL)
        return keeper_head(m, root, name, root_keeper(m, (b.origin for items in files.values() for b in items
                                                          if isinstance(b, TfBlock)), landing_dns), cloud)
    notes = tuple(comment(line) for line in asked_lines(m, placed.named))
    return {f"{root}/{name}": TfFile(head(root, name, files), (
        *(written(root, items) if name == PROVIDERS else items), *(notes if (root, name) == (STACK, MAIN) else ())))
        for root, files in placed.files.items() if in_scope(m, root) for name, items in files.items()}


def keeper_rendered(m, keeper, renderers, data):
    """Rendered of what a keeper keeps of environment m's plumbing (opsdir.domains.network.plumbing.Keeper): data (the
    cloud's network data sources) and what bindings share first, inputs unique by name; each binding's blocks stamped
    with its entry, what they share with the keeper's first (hcl.from_entry: the render places them in its root).
    renderers: ((object class, fn(m, binding, the keeper's DNs) -> Rendered), ...), the first whose class a binding
    has renders it."""
    here = {b.dn for b in keeper.bindings}
    parts = tuple((b, next(fn for oc, fn in renderers if is_kind(m.d, b, oc))(m, b, here)) for b in keeper.bindings)
    return Rendered(tuple(x for b, p in parts for x in from_entry(b.dn, p.blocks)),
                    distinct(tuple(v for _, p in parts for v in p.variables)),
                    (*data, *from_entry(keeper.bindings[0].dn, distinct(tuple(x for _, p in parts for x in p.shared)))))
