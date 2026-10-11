"""Terraform state (format version 4) built from a root's configuration as data (TfBlocks, hcl_reader): what
`terraform apply` would record, so an importer of state can read a render back without applying it (the round trip,
milestone 5.5c). Pure. A format library: it knows Terraform, not any cloud provider.

Each resource and data block is one instance (one per index with a literal count), its attributes those the block
configures, evaluated:
  - literals as written; lists; objects (keys unquoted); nested blocks as lists of objects, as the state keeps them;
  - meta-arguments (count, depends_on, lifecycle, provider, ...) are not attributes;
  - references (type.name.attr, data.type.name.attr, [N] indexes into counts and lists), var.*, count.index, quoted
    ${} templates, jsonencode(...) of a JSON document (its strings' ${} interpolated; Terraform's compact JSON, keys
    in order), tolist / tostring.
What the configuration doesn't say, the caller does: assigned(mode, type, name, index, configured) gives the attributes
the provider assigns (ids, ARNs, addresses) or a data source returns (from the record the render came from), merged
under what the block configures; without it each instance gets a synthetic id. Variables come from the caller, else the
variable's default. An expression it can't evaluate leaves its attribute out and is named in the notices, never guessed.
"""
import json
import re
from typing import NamedTuple

from .hcl import Block, TfBlock
from .hcl_reader import read_hcl

META = frozenset({"count", "for_each", "depends_on", "lifecycle", "provider", "provisioner", "connection"})
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.S)
_INTERPOLATION = re.compile(r"\$\{([^{}]*)\}")
_JSON = re.compile(r"jsonencode\((.*)\)", re.S)
_CONVERSION = re.compile(r"(tolist|toset|tostring|tonumber)\((.*)\)((?:\[\d+\])*)", re.S)
_REFERENCE = re.compile(r"[A-Za-z_][\w-]*(?:\[\d+\])?(?:\.[A-Za-z_][\w-]*(?:\[\d+\])?)*")
_STEP = re.compile(r"[A-Za-z_][\w-]*|\[\d+\]")

# Why a value could not be evaluated (left out of the state, named in the notices).
Unresolved = NamedTuple("Unresolved", [("why", str)])
# What evaluating one block sees: the root's resource and data blocks by (mode, type, name), the variables, the
# caller's assigned(), the instance index (None without count) and the addresses being evaluated (cycles).
_Scope = NamedTuple("_Scope", [("found", dict), ("variables", dict), ("assigned", object), ("index", object),
                               ("seen", tuple)])


def _raw(v):
    return v[2:-1] if isinstance(v, str) and v.startswith("${") and v.endswith("}") else None


def _unquote(s):
    return re.sub(r"\\(.)", r"\1", s[1:-1], flags=re.S) if _STRING.fullmatch(s) else s


def synthetic(mode, type_, name, index, configured):
    """The default assigned(): an id naming the instance, when the block configures none."""
    return {} if "id" in configured else {"id": f"{type_}.{name}" + (f"[{index}]" if index is not None else "")}


def _text(v):
    """A value as a template writes it."""
    return ("true" if v else "false") if isinstance(v, bool) else v if isinstance(v, str) else json.dumps(v)


def _walk(value, steps, where):
    if not steps:
        return value
    step = steps[0]
    if step.startswith("["):
        n = int(step[1:-1])
        ok = isinstance(value, list) and n < len(value)
        return _walk(value[n], steps[1:], where) if ok else Unresolved(f"{where} has no element {n}")
    ok = isinstance(value, dict) and step in value
    return _walk(value[step], steps[1:], f"{where}.{step}") if ok else Unresolved(f"{where} has no {step}")


def _reference(text, scope):
    steps = _STEP.findall(text)
    head = steps[0]
    if head == "var":
        name = steps[1] if len(steps) > 1 else ""
        value = scope.variables.get(name, Unresolved(f"no value for var.{name}"))
        return _walk(value, steps[2:], f"var.{name}") if not isinstance(value, Unresolved) else value
    if head == "count" and steps[1:] == ["index"]:
        return scope.index if scope.index is not None else Unresolved("count.index outside a counted block")
    if head in ("local", "each", "path", "terraform", "ephemeral", "module", "self"):
        return Unresolved(f"{head}.* is not evaluated here" + (" (never in state)" if head == "ephemeral" else ""))
    mode, rest = ("data", steps[1:]) if head == "data" else ("managed", steps)
    if len(rest) < 2 or rest[0].startswith("[") or rest[1].startswith("["):
        return Unresolved(f"not a reference: {text}")
    address = (mode, rest[0], rest[1])
    counted = rest[2:3] and rest[2].startswith("[")
    index, path = (int(rest[2][1:-1]), rest[3:]) if counted else (None, rest[2:])
    attributes = _instance(address, index, scope)
    label = ("data." if mode == "data" else "") + f"{rest[0]}.{rest[1]}" + (f"[{index}]" if counted else "")
    return attributes if isinstance(attributes, Unresolved) else _walk(attributes, path, label)


def _expression(text, scope):
    s = text.strip()
    if _STRING.fullmatch(s):
        pieces = _INTERPOLATION.split(_unquote(s))      # literal, expression, literal, ...
        values = [p if k % 2 == 0 else _expression(p, scope) for k, p in enumerate(pieces)]
        missing = next((v for v in values if isinstance(v, Unresolved)), None)
        return missing or "".join(_text(v) for v in values)
    encoded = _JSON.fullmatch(s)
    if encoded:
        try:
            document = _interpolated(json.loads(encoded.group(1)), scope)
        except ValueError:
            return Unresolved("jsonencode of something other than a JSON document")
        return document if isinstance(document, Unresolved) else \
            json.dumps(document, separators=(",", ":"), sort_keys=True)
    converted = _CONVERSION.fullmatch(s)
    if converted:
        inner = _expression(converted.group(2), scope)
        if isinstance(inner, Unresolved):
            return inner
        name = converted.group(1)
        listed, scalar = isinstance(inner, list), isinstance(inner, (str, int, float)) and not isinstance(inner, bool)
        if (name in ("tolist", "toset") and not listed) or (name in ("tostring", "tonumber") and not scalar):
            return Unresolved(f"{name} of a {type(inner).__name__}")
        value = list(inner) if listed else str(inner) if name == "tostring" else float(inner)
        return _walk(value, _STEP.findall(converted.group(3)), name)
    if _REFERENCE.fullmatch(s):
        return _reference(s, scope)
    return Unresolved(f"not evaluated: {s.splitlines()[0][:60]}")


def _interpolated(v, scope):
    """A JSON document's strings with their ${...} interpolations evaluated (HCL interpolates the strings of a
    jsonencode() argument): a template string as _expression evaluates it."""
    if isinstance(v, str):
        return _expression(json.dumps(v), scope) if "${" in v else v
    if isinstance(v, list):
        items = [_interpolated(x, scope) for x in v]
        return next((x for x in items if isinstance(x, Unresolved)), items)
    if isinstance(v, dict):
        items = {k: _interpolated(x, scope) for k, x in v.items()}
        return next((x for x in items.values() if isinstance(x, Unresolved)), items)
    return v


def _value(v, scope):
    raw = _raw(v)
    if raw is not None:
        return _expression(raw, scope)
    if isinstance(v, (tuple, list)):
        items = [_value(x, scope) for x in v]
        return next((x for x in items if isinstance(x, Unresolved)), items)
    if isinstance(v, dict):
        items = {_unquote(k): _value(x, scope) for k, x in v.items()}
        return next((x for x in items.values() if isinstance(x, Unresolved)), items)
    return v


def _attributes(body, scope, where):
    """(attributes, problems) of a body: values evaluated, nested blocks as lists of objects; problems: (path, why)."""
    kept = tuple((k, v) for k, v in body if k != "#" and k not in META)
    nested = {k: tuple(_attributes(v.body, scope, f"{where}.{k}") for kk, v in kept if kk == k)
              for k, v in kept if isinstance(v, Block)}
    values = {k: _value(v, scope) for k, v in kept if not isinstance(v, Block)}
    return ({**{k: v for k, v in values.items() if not isinstance(v, Unresolved)},
             **{k: [a for a, _ in found] for k, found in nested.items()}},
            (*((f"{where}.{k}", v.why) for k, v in values.items() if isinstance(v, Unresolved)),
             *(p for found in nested.values() for _, ps in found for p in ps)))


def _count(block, scope):
    given = next((v for k, v in block.body if k == "count"), None)
    value = None if given is None else _value(given, scope)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _evaluated(address, index, scope):
    """(attributes, problems) of one instance: what its block configures, under what assigned() gives."""
    block = scope.found[address]
    inner = scope._replace(index=index, seen=(*scope.seen, (address, index)))
    where = ("data." if address[0] == "data" else "") + f"{address[1]}.{address[2]}" + \
        (f"[{index}]" if index is not None else "")
    configured, problems = _attributes(block.body, inner, where)
    return {**scope.assigned(*address, index, configured), **configured}, problems


def _instance(address, index, scope):
    if address not in scope.found:
        return Unresolved(f"no {'data.' if address[0] == 'data' else ''}{address[1]}.{address[2]} in this root")
    if (address, index) in scope.seen:
        return Unresolved("a reference cycle")
    count = _count(scope.found[address], scope)
    if (count is None) != (index is None) or (count is not None and index >= count):
        return Unresolved(f"{address[1]}.{address[2]}: no instance {index}")
    return _evaluated(address, index, scope)[0]


def _providers(blocks):
    """{local provider name: source} from the root's required_providers."""
    required = (v for b in blocks if b.kind == "terraform" for k, v in b.body if k == "required_providers")
    return {_unquote(name): _unquote(spec.get("source", "")) for r in required for name, spec in r.body
            if name != "#" and isinstance(spec, dict)}


def _provider(block, sources):
    local = block.labels[0].split("_", 1)[0]
    chosen = _raw(next((v for k, v in block.body if k == "provider"), None)) or ""
    alias = chosen.split(".", 1)[1] if "." in chosen else ""
    return f'provider["registry.terraform.io/{sources.get(local, f"hashicorp/{local}")}"]' + \
        (f".{alias}" if alias else "")


def tf_state(blocks, assigned=None, variables=None):
    """(state text, notices): the version 4 state of one Terraform root (its TfBlocks, all files) as `terraform apply`
    would record it. assigned(mode, type, name, index, configured) -> the attributes the provider assigns or a data
    source returns (default: synthetic, an id); variables: {name: value}, else each variable's default."""
    found = {("data" if b.kind == "data" else "managed", b.labels[0], b.labels[1]): b for b in blocks
             if b.kind in ("resource", "data") and len(b.labels) == 2}
    bare = _Scope(found, {}, assigned or synthetic, None, ())
    defaults = {b.labels[0]: _value(v, bare) for b in blocks if b.kind == "variable" and b.labels
                for k, v in b.body if k == "default"}
    scope = bare._replace(variables={**{k: v for k, v in defaults.items() if not isinstance(v, Unresolved)},
                                     **(variables or {})})
    sources = _providers(blocks)
    counts = {address: _count(block, scope) for address, block in found.items()}
    evaluated = {address: tuple((i, _evaluated(address, i, scope)) for i in
                                (range(counts[address]) if counts[address] is not None else (None,)))
                 for address in found}
    resources = [{"mode": mode, "type": type_, "name": name, "provider": _provider(found[(mode, type_, name)], sources),
                  "instances": [{**({"index_key": i} if i is not None else {}), "schema_version": 0,
                                 "attributes": attributes, "sensitive_attributes": []}
                                for i, (attributes, _) in evaluated[(mode, type_, name)]]}
                 for mode, type_, name in found]
    notices = tuple(f"{where}: {why}" for instances in evaluated.values() for _, (_, problems) in instances
                    for where, why in problems)
    document = {"version": 4, "terraform_version": "0.0.0-opsdir-round-trip", "serial": 1,
                "lineage": "opsdir-round-trip", "outputs": {}, "resources": resources}
    return json.dumps(document, indent=2), notices


def root_states(files, environment, assigned_for=None, variables=None):
    """{state path: state text} of the Terraform roots among files ({path: .tf text}, under the environment's folder):
    each folder's files are one root, its state named after the folder below the environment's (the environment's own
    folder: terraform.tfstate; <env>/landing-zone/: landing-zone.tfstate), placed in the environment's folder.
    assigned_for(blocks) -> the root's assigned() (see tf_state), from what the cloud adapter knows; default
    synthetic. variables: {name: value} for inputs an operator gives at apply (no default), the same for every root."""
    folders = sorted({p.rsplit("/", 1)[0] for p in files if p.endswith(".tf")})
    roots = {f: tuple(b for p in sorted(files) if p.endswith(".tf") and p.rsplit("/", 1)[0] == f
                      for b in read_hcl(files[p]) if isinstance(b, TfBlock)) for f in folders}
    named = {f: (f[len(environment) + 1:] if f.startswith(environment + "/") else
                 "" if f == environment else f).replace("/", "-") or "terraform" for f in folders}
    return {f"{environment}/{named[f]}.tfstate": tf_state(blocks, assigned_for(blocks) if assigned_for else None,
                                                          variables)[0]
            for f, blocks in roots.items()}
