"""INI files as captured settings (core.capture): each `key = value` (or `key: value`) is a setting located by
section.key (just key before the first section).

Comments (; or #), blank lines and section headers are layout. An indented line after a setting continues its value
(as Python's configparser reads it). Values are taken as written: INI has no standard escaping.
"""
import re
from itertools import accumulate, groupby

from ..contract import Codec
from .lines import body_and_end, physical_lines

_SECTION = re.compile(r"\s*\[([^\]]*)\]")
_SETTING = re.compile(r"([ \t]*)([^\s=:;#][^=:]*?)([ \t]*[=:][ \t]*)")


def _is_layout(line):
    stripped = line.strip()
    return not stripped or stripped.startswith((";", "#"))


def _kind(prev, line):
    """(section, kind) of a line given the (section, kind) of the line before: kind is layout, header, setting or
    continuation (an indented line after a setting)."""
    section, before = prev
    header = _SECTION.match(line)
    if before in ("setting", "continuation") and line[:1] in " \t" and not _is_layout(line):
        return section, "continuation"
    if _is_layout(line):
        return section, "layout"
    if header:
        return header.group(1).strip(), "header"
    return section, "setting" if _SETTING.match(body_and_end(line)[0]) else "layout"


def _parts(section, kind, lines):
    """A setting line and its continuation lines as key text, (locator, raw value) and the line end; others literal."""
    if kind != "setting":
        return ("".join(lines),)
    text = "".join(lines)
    body, end = body_and_end(text)
    m = _SETTING.match(body)
    key = m.group(2)
    return body[:m.end()], (f"{section}.{key}" if section else key, body[m.end():]), end


def split(text):
    lines = physical_lines(text)
    kinds = tuple(accumulate(lines, _kind, initial=("", "layout")))[1:]
    ids = accumulate(0 if kind == "continuation" else 1 for _, kind in kinds)
    groups = groupby(zip(ids, kinds, lines), key=lambda x: x[0])
    return tuple(p for _, group in groups for p in _group_parts(tuple(group)))


def _group_parts(group):
    _, (section, kind), _ = group[0]
    return _parts(section, kind, [line for _, _, line in group])


def decode(raw):
    return raw


def encode(value, raw):
    return value


CODEC = Codec(split, decode, encode)
