"""YAML as opsdir writes it: JSON-shaped values (mappings, lists, strings, numbers, true, false, null) as block-style
YAML, the same text for the same value, without a YAML library. Pure.

Mappings keep the value's key order (renderers build manifests in the order people read them: apiVersion, kind,
metadata, spec); lists sit at their key's indent, as kubectl writes them. A string is plain only when no YAML 1.1 or
1.2 reader can take it for anything else (a boolean, null, a number, a date, an indicator); otherwise it is written as
JSON writes it, which is a valid YAML double-quoted scalar. Multi-line strings are literal blocks (|, |-, |+). Where a
reader wants short lines (yamllint, ansible-lint), a dump can be given a width: a one-line string that would run past
it is written folded (>-), broken only at single spaces, which folding reads back as the same string.
"""
import json
import math
import re

_PLAIN = re.compile(r"[A-Za-z_/][A-Za-z0-9_./@+=:,()~ -]*")
_RESERVED = {"y", "n", "yes", "no", "true", "false", "on", "off", "null"}
_BLOCK_LINE = re.compile(r"[^\x00-\x08\x0b-\x1f\x7f]*")


def _plain(s):
    return bool(_PLAIN.fullmatch(s)) and s.lower() not in _RESERVED and not s.endswith((" ", ":")) \
        and ": " not in s and " #" not in s


def scalar(v):
    """One scalar or mapping key as YAML: null, true, false, a number as JSON writes it, a string plain when safe,
    else JSON-quoted."""
    if v is None or isinstance(v, bool):
        return {None: "null", True: "true", False: "false"}[v]
    if isinstance(v, (int, float)):
        if isinstance(v, float) and not math.isfinite(v):
            raise ValueError(f"YAML: not a finite number: {v!r}")
        return json.dumps(v)
    if isinstance(v, str):
        return v if _plain(v) else json.dumps(v)
    raise TypeError(f"YAML: not a scalar: {type(v).__name__}")


def _block(s):
    """A multi-line string as a literal block header and its lines, or None when it can't be one exactly."""
    body = s.rstrip("\n")
    lines = body.split("\n")
    if "\n" not in body or lines[0].startswith(" ") or not all(_BLOCK_LINE.fullmatch(x) for x in lines) \
            or any(x != x.rstrip(" ") for x in lines):
        return None
    trailing = len(s) - len(body)
    return {0: "|-", 1: "|"}.get(trailing, "|+"), (*lines, *([""] * (trailing - 1)))


def _folded(s, width):
    """A one-line string's folded block lines, each at most width characters where its words allow; None when it can't
    be folded exactly (line breaks, leading, trailing or double spaces, control characters) or fits on one line."""
    words = s.split(" ")
    if width is None or "\n" in s or "" in words or not _BLOCK_LINE.fullmatch(s):
        return None
    lines = []
    for w in words:
        lines = [*lines[:-1], f"{lines[-1]} {w}"] if lines and len(lines[-1]) + 1 + len(w) <= width \
            else [*lines, w]
    return lines if len(lines) > 1 else None


def _is_nested(v):
    return isinstance(v, (dict, list, tuple)) and len(v) > 0


def _inline(v):
    if isinstance(v, dict):
        return "{}"
    if isinstance(v, (list, tuple)):
        return "[]"
    return scalar(v)


def _value_lines(v, indent, prefix, seq=0, width=None):
    """Lines of a value placed after prefix ('key:' or '-') at the given indent; seq: how far a list under a key is
    indented (0, or 2 where a linter wants sequences indented); width: the longest line wanted (None: any)."""
    pad = " " * indent
    if isinstance(v, str) and _block(v):
        header, lines = _block(v)
        return [f"{pad}{prefix} {header}", *(f"{pad}  {x}" if x else "" for x in lines)]
    if not _is_nested(v):
        line = f"{pad}{prefix} {_inline(v)}"
        folded = _folded(v, width - indent - 2) if isinstance(v, str) and width and len(line) > width else None
        return [f"{pad}{prefix} >-", *(f"{pad}  {x}" for x in folded)] if folded else [line]
    if prefix == "-":
        inner = _lines(v, indent + 2, seq, width)
        return [f"{pad}- {inner[0].lstrip(' ')}", *inner[1:]]
    return [f"{pad}{prefix}", *_lines(v, indent + (seq if isinstance(v, (list, tuple)) else 2), seq, width)]


def _lines(value, indent, seq=0, width=None):
    if isinstance(value, dict):
        return [line for k, v in value.items() for line in _value_lines(v, indent, f"{scalar(k)}:", seq, width)]
    if isinstance(value, (list, tuple)):
        return [line for v in value for line in _value_lines(v, indent, "-", seq, width)]
    raise TypeError(f"YAML: not a mapping or list: {type(value).__name__}")


def dump(value, indent_sequences=False, width=None):
    """YAML text of a JSON-shaped value, newline-terminated; indent_sequences: lists under a key indented by two (as
    yamllint's indent-sequences and ansible-lint want), else at the key's column; width: one-line strings that would
    run past it folded (None: never)."""
    if not _is_nested(value):
        return _inline(value) + "\n"
    return "\n".join(_lines(value, 0, 2 if indent_sequences else 0, width)) + "\n"


def documents(values):
    """A multi-document YAML stream: each value dumped, separated by '---' lines."""
    return "---\n".join(dump(v) for v in values)
