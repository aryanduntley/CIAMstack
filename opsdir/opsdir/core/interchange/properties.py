"""Java properties files as captured settings (core.capture): each key's value is a setting located by its key.

Comments (# or !) and blank lines are layout. A logical line continues onto the next physical line while it ends
with an odd number of backslashes. The key ends at the first unescaped '=', ':' or whitespace; the separator is that
character with the whitespace around it; the value's raw text runs to the end of the logical line.
"""
import re
from itertools import accumulate, groupby

from ..contract import Codec
from .lines import body_and_end, physical_lines

_KEY = re.compile(r"([ \t\f]*)((?:\\.|[^=:\s\\])+)([ \t\f]*[=:]?[ \t\f]*)", re.DOTALL)
_ESCAPE = re.compile(r"\\(u[0-9a-fA-F]{4}|\r?\n[ \t\f]*|.)", re.DOTALL)
_ESCAPED = {"t": "\t", "n": "\n", "r": "\r", "f": "\f"}


def _continues(line):
    body, _ = body_and_end(line)
    return not _is_layout(line) and (len(body) - len(body.rstrip("\\"))) % 2 == 1


def _is_layout(line):
    stripped = line.lstrip(" \t\f")
    return not stripped.strip() or stripped.startswith(("#", "!"))


def _logical(lines):
    """Physical lines grouped into logical lines (continuations joined), each group's text."""
    starts = (1, *(0 if _continues(prev) else 1 for prev in lines[:-1]))
    ids = accumulate(starts)
    return tuple("".join(line for _, line in group) for _, group in groupby(zip(ids, lines), key=lambda x: x[0]))


def _unescape(m):
    s = m.group(1)
    if s.startswith("u") and len(s) == 5:
        return chr(int(s[1:], 16))
    return "" if s[0] in "\r\n" else _ESCAPED.get(s, s)


def decode(raw):
    """A value's raw text as its value: escapes resolved, continuations joined."""
    return _ESCAPE.sub(_unescape, raw)


def encode(value, raw):
    """A value as raw text: backslash, control characters and a leading space escaped; non-ASCII as \\uXXXX when the
    original raw text used such escapes."""
    text = (value.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
            .replace("\f", "\\f"))
    text = "\\" + text if text.startswith(" ") else text
    return "".join(f"\\u{ord(c):04x}" if ord(c) > 127 else c for c in text) if "\\u" in raw else text


def _parts(group):
    m = None if _is_layout(group) else _KEY.match(group)
    if m is None:
        return (group,)
    body, end = body_and_end(group)
    return (group[:m.end()], (decode(m.group(2)), body[m.end():]), end)


def split(text):
    return tuple(p for group in _logical(physical_lines(text)) for p in _parts(group))


CODEC = Codec(split, decode, encode)
