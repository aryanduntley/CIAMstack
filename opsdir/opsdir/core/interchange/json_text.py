"""JSON files as captured settings (core.capture): every scalar (string, number, true, false, null) is a setting
located by its JSON Pointer (RFC 6901); braces, brackets, keys, commas, whitespace and comments (// and /* */, as
many product configs write them) are layout.

A string's value is the decoded string; any other scalar's value is its literal text (8080, true, null). A changed
value keeps the original's type: a string is written as a JSON string, anything else must itself be a JSON literal.
"""
import json
import re
from itertools import accumulate

from ..contract import Codec
from .lines import first_gap, line_col

_TOKEN = re.compile(r'(\s+|//[^\n]*|/\*.*?\*/)|("(?:[^"\\]|\\.)*")'
                    r'|(-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)'
                    r"|([{}\[\]:,])", re.DOTALL)


def _pointer_step(key):
    return "/" + str(key).replace("~", "~0").replace("/", "~1")


def _path(stack):
    """Pointer of the value about to be read: each frame is (kind, pointer, key or index or None)."""
    if not stack:
        return ""
    _, pointer, slot = stack[-1]
    return pointer + _pointer_step(slot)


def _frame(punct, stack):
    return ("o", _path(stack), None) if punct == "{" else ("a", _path(stack), 0)


def _is_key(stack, m):
    return bool(m.group(2)) and bool(stack) and stack[-1][0] == "o" and stack[-1][2] is None


def _advance(stack, m):
    """The frame stack after a token: each frame is (kind, pointer, key or index or None)."""
    punct, top = m.group(4), stack[-1] if stack else None
    if punct in ("{", "["):
        return stack + (_frame(punct, stack),)
    if punct in ("}", "]"):
        return stack[:-1]
    if punct == ",":
        return stack[:-1] + ((top[0], top[1], None if top[0] == "o" else top[2] + 1),)
    if _is_key(stack, m):
        return stack[:-1] + ((top[0], top[1], json.loads(m.group(2))),)
    return stack


def _part(stack, m):
    """A scalar value as a (pointer, raw) setting; everything else (keys included) as literal text."""
    scalar = (m.group(2) or m.group(3)) and not _is_key(stack, m)
    return (_path(stack), m.group(0)) if scalar else m.group(0)


def split(text):
    tokens = tuple(_TOKEN.finditer(text))
    gap = first_gap(text, [m.span() for m in tokens])
    if gap is not None:
        raise ValueError("line %d, column %d: not JSON here" % line_col(text, gap))
    return tuple(_part(stack, m) for stack, m in zip(accumulate(tokens, _advance, initial=()), tokens))


def decode(raw):
    return json.loads(raw) if raw.startswith('"') else raw


def encode(value, raw):
    if raw.startswith('"'):
        return json.dumps(value, ensure_ascii="\\u" in raw)
    try:
        parsed = json.loads(value)
    except ValueError:
        parsed = value
    if isinstance(parsed, (str, list, dict)):
        raise ValueError(f"{value!r} is not a JSON number, true, false or null, which this setting holds")
    return value


CODEC = Codec(split, decode, encode)
