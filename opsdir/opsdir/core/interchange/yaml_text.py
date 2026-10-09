"""YAML as opsdir writes it: JSON-shaped values (mappings, lists, strings, numbers, true, false, null) as block-style
YAML, the same text for the same value, without a YAML library. Pure.

Mappings keep the value's key order (renderers build manifests in the order people read them: apiVersion, kind,
metadata, spec); lists sit at their key's indent, as kubectl writes them. A string is plain only when no YAML 1.1 or
1.2 reader can take it for anything else (a boolean, null, a number, a date, an indicator); otherwise it is written as
JSON writes it, which is a valid YAML double-quoted scalar. Multi-line strings are literal blocks (|, |-, |+).
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


def _is_nested(v):
    return isinstance(v, (dict, list, tuple)) and len(v) > 0


def _inline(v):
    if isinstance(v, dict):
        return "{}"
    if isinstance(v, (list, tuple)):
        return "[]"
    return scalar(v)


def _value_lines(v, indent, prefix):
    """Lines of a value placed after prefix ('key:' or '-') at the given indent."""
    pad = " " * indent
    if isinstance(v, str) and _block(v):
        header, lines = _block(v)
        return [f"{pad}{prefix} {header}", *(f"{pad}  {x}" if x else "" for x in lines)]
    if not _is_nested(v):
        return [f"{pad}{prefix} {_inline(v)}"]
    if prefix == "-":
        inner = _lines(v, indent + 2)
        return [f"{pad}- {inner[0].lstrip(' ')}", *inner[1:]]
    return [f"{pad}{prefix}", *_lines(v, indent + (0 if isinstance(v, (list, tuple)) else 2))]


def _lines(value, indent):
    if isinstance(value, dict):
        return [line for k, v in value.items() for line in _value_lines(v, indent, f"{scalar(k)}:")]
    if isinstance(value, (list, tuple)):
        return [line for v in value for line in _value_lines(v, indent, "-")]
    raise TypeError(f"YAML: not a mapping or list: {type(value).__name__}")


def dump(value):
    """YAML text of a JSON-shaped value, newline-terminated."""
    if not _is_nested(value):
        return _inline(value) + "\n"
    return "\n".join(_lines(value, 0)) + "\n"


def documents(values):
    """A multi-document YAML stream: each value dumped, separated by '---' lines."""
    return "---\n".join(dump(v) for v in values)
