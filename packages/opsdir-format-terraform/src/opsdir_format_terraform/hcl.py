"""Terraform HCL formatting: names, expressions and blocks laid out like `terraform fmt`.
A format library: it knows HCL, not any cloud provider or product.
"""
import json
import re
from itertools import groupby
from typing import NamedTuple


def tf_name(s):
    n = re.sub(r"[^a-z0-9_]", "_", s.lower())
    return n if n[0].isalpha() else "r_" + n


# ------------------------------------------------------------------ HCL
# A nested HCL block, rendered under its key: ("root_block_device", Block(body)).
Block = NamedTuple("Block", [("body", tuple)])


def hcl(v, indent=0):
    """Render a Python value as an HCL expression. Strings starting with '${' are raw expressions."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        if v.startswith("${") and v.endswith("}"):
            return v[2:-1]
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(hcl(x) for x in v) + "]"
    if isinstance(v, dict):
        pad = "  " * (indent + 1)
        w = max(len(k) for k in v)
        body = "\n".join(f"{pad}{k.ljust(w)} = {hcl(x, indent + 1)}" for k, x in v.items())
        return "{\n" + body + "\n" + "  " * indent + "}"
    raise TypeError(v)


def _single_line(kv):
    return kv[0] != "#" and not isinstance(kv[1], (Block, dict)) and "\n" not in hcl(kv[1])


def _key_widths(body):
    """Like `terraform fmt`: '=' is aligned within runs of single-line attributes. Blocks, comments
    and multi-line values (a dict, a jsonencode() document) break a run. Returns {body index: key width} for run
    members."""
    runs = [tuple(g) for single, g in groupby(enumerate(body), key=lambda ikv: _single_line(ikv[1])) if single]
    return {i: max(len(k) for _, (k, _) in run) for run in runs for i, _ in run}


def _body_line(k, v, pad, indent, width):
    if k == "#":
        return f"{pad}  # {v}"
    if isinstance(v, Block):
        return block(k, (), v.body, indent + 1)
    return f"{pad}  {k.ljust(width)} = {hcl(v, indent + 1)}"


def block(kind, labels, body, indent=0):
    """HCL block. body: (key, value) pairs, where a value may be a nested Block, or ("#", comment)."""
    pad = "  " * indent
    widths = _key_widths(body)
    head = pad + kind + "".join(f' "{lab}"' for lab in labels) + " {"
    lines = (_body_line(k, v, pad, indent, widths.get(i, len(k))) for i, (k, v) in enumerate(body))
    return "\n".join((head, *lines, pad + "}"))


def ref(expr):
    return "${" + expr + "}"


def import_block(address, id_):
    """An import block adopting an existing object into the resource at address (type.name) by its provider id."""
    return block("import", [], [("to", ref(address)), ("id", id_)])


def jsonencoded(v):
    """A JSON document as a Terraform jsonencode() expression (JSON's objects and arrays are HCL expressions), keys
    and values spaced as `terraform fmt` writes them ("key" : value)."""
    return ref("jsonencode(" + json.dumps(v, indent=2, separators=(",", " : ")).replace("\n", "\n  ") + ")")


def unbound_comments(roles):
    """HCL comment lines naming each required role an environment doesn't bind."""
    return "".join(f"# UNBOUND: required role '{r}' has no binding in this environment\n" for r in roles)
