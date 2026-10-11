"""Terraform HCL read back into data: the subset hcl.py writes (block(), hcl()), as the TfBlocks and comments of a file.
Pure. A format library: it knows HCL, not any cloud provider or product.

What it reads is what block() and hcl() write:
  - top-level blocks with quoted labels, `# comment` lines between them;
  - in a body: `key = value`, nested blocks `key { ... }` (no labels) and `# comment` lines;
  - values as hcl() writes them: quoted strings (\\ and \" escaped), numbers, true / false, lists on one line,
    objects one `key = value` per line; any other expression (a reference, a function call, a conditional, a quoted
    template interpolating ${...}, jsonencode(...) over several lines) is kept as its text, '${...}', the way block()
    takes a raw expression.
So block(*tf_block) writes a block read from its output back as it was. What the reader can't place is a ValueError
naming the line, never a guess.
"""
from itertools import accumulate
import re

from .hcl import Block, TfBlock

# What decides where a logical line ends: strings and comments (their brackets don't count), brackets, commas, newlines
_TOKENS = re.compile(r'"(?:[^"\\]|\\.)*"|#[^\n]*|[\[\](){},]|\n', re.S)
_DEPTH = {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1}
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.S)
_NUMBER = re.compile(r"-?\d+(\.\d+)?([eE][-+]?\d+)?")
_HEADER = re.compile(r'([A-Za-z_][\w-]*)((?:[ \t]+"(?:[^"\\]|\\.)*")*)[ \t]*\{\n(?:(.*)\n)?\}', re.S)
_KEY = r'("(?:[^"\\]|\\.)*"|[^\s="{}]+)'
_ATTRIBUTE = re.compile(_KEY + r"[ \t]*=[ \t]*(.*)", re.S)
_NESTED = re.compile(_KEY + r"[ \t]*\{\n(?:(.*)\n)?[ \t]*\}", re.S)


def _marks(text):
    """(position, token, depth after it) of each token deciding the structure of text."""
    found = tuple((m.start(), m.group()) for m in _TOKENS.finditer(text))
    depths = accumulate(_DEPTH.get(t, 0) for _, t in found)
    return tuple((at, t, depth) for (at, t), depth in zip(found, depths))


def _cut(text, separator):
    """text cut at each separator token ('\\n' or ',') outside strings, comments and brackets: (start, piece) pairs."""
    cuts = (at for at, t, depth in _marks(text) if t == separator and depth == 0)
    bounds = (-1, *cuts, len(text))
    return tuple((bounds[k] + 1, text[bounds[k] + 1:bounds[k + 1]]) for k in range(len(bounds) - 1))


def _unquote(s):
    return re.sub(r"\\(.)", r"\1", s[1:-1], flags=re.S)


def _fail(where, what):
    raise ValueError(f"line {where}: {what}")


def value_of(text):
    """The model value of an HCL expression as hcl() writes it: str (a literal), int, float, bool, a tuple (a list),
    a dict (an object: keys as written) or '${<expression>}' (anything else, kept as its text; a quoted template with
    ${...} interpolation too, quotes included, since a str starting with '${' and ending with '}' is raw to hcl())."""
    s = text.strip()
    if _STRING.fullmatch(s) and "${" not in s:
        return _unquote(s)
    if s in ("true", "false"):
        return s == "true"
    if _NUMBER.fullmatch(s):
        return float(s) if any(c in s for c in ".eE") else int(s)
    if s.startswith("[") and s.endswith("]") and "\n" not in s:
        inner = s[1:-1]
        return tuple(value_of(piece) for _, piece in _cut(inner, ",")) if inner.strip() else ()
    if s.startswith("{\n") and s.endswith("}"):
        return dict(_pairs(s[2:s.rindex("\n")], 0, nested=False))
    return "${" + s + "}"


def _pair(piece, line, nested):
    s = piece.strip()
    if s.startswith("#"):
        return "#", s[1:].strip()
    attribute = _ATTRIBUTE.fullmatch(s)
    if attribute:
        return attribute.group(1), value_of(attribute.group(2))
    block = _NESTED.fullmatch(s) if nested else None
    if block:
        return block.group(1), Block(_pairs(block.group(2) or "", line, nested=True))
    return _fail(line, f"not an attribute{', nested block' if nested else ''} or comment: {s.splitlines()[0][:60]}")


def _pairs(text, line, nested=True):
    """(key, value) pairs of a body (nested blocks and comments when nested) or of an object's lines; line: the
    line text starts on, for errors."""
    return tuple(_pair(piece, line + text.count("\n", 0, at), nested) for at, piece in _cut(text, "\n")
                 if piece.strip())


def _top(piece, line):
    s = piece.strip()
    if s.startswith("#"):
        return "#", s[1:].strip()
    header = _HEADER.fullmatch(s)
    if not header:
        return _fail(line, f"not a block or comment: {s.splitlines()[0][:60]}")
    labels = tuple(_unquote(lab) for lab in _STRING.findall(header.group(2)))
    return TfBlock(header.group(1), labels, _pairs(header.group(3) or "", line + 1))


def read_hcl(text):
    """The top-level items of a Terraform file as hcl.py writes it, in order: TfBlocks and ('#', comment) lines
    (blank lines dropped). ValueError naming the line on anything it can't read."""
    marks = _marks(text)
    if any(depth < 0 for _, _, depth in marks) or (marks and marks[-1][2] != 0):
        raise ValueError("unbalanced brackets")
    return tuple(_top(piece, text.count("\n", 0, at) + 1) for at, piece in _cut(text, "\n") if piece.strip())
