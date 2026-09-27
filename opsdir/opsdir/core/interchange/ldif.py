"""Minimal LDIF (RFC 2849) reader/writer: content records and change records.

Supports comments, line folding, base64 values (attr:: value), and changetype add/modify/delete.
"""
import base64
import re
from itertools import accumulate, groupby
from typing import NamedTuple

# attrs: {name: (values…)} in file order (content records); mods: ((op, attr, (values…)), …) (modify records)
LdifRecord = NamedTuple("LdifRecord", [("dn", str), ("changetype", str), ("attrs", dict), ("mods", tuple)])


def _unfold(text):
    """Drop comment lines and join each folded continuation line (leading space) onto the line before it."""
    lines = [raw for raw in text.splitlines() if not raw.startswith("#")]
    logical = accumulate(0 if raw.startswith(" ") else 1 for raw in lines)
    return [group[0][1] + "".join(raw[1:] for _, raw in group[1:])
            for group in (tuple(g) for _, g in groupby(zip(logical, lines), key=lambda il: il[0]))]


def _records(text):
    """Records: runs of non-blank lines separated by blank lines."""
    return (tuple(g) for filled, g in groupby(_unfold(text), key=lambda line: bool(line.strip())) if filled)


def _split(line):
    m = re.match(r"^([A-Za-z0-9;-]+)(::?)\s?(.*)$", line)
    if not m:
        raise ValueError(f"bad LDIF line: {line!r}")
    name, sep, value = m.groups()
    return name, base64.b64decode(value).decode() if sep == "::" else value


def _attrs(lines):
    pairs = [_split(line) for line in lines]
    return {name: tuple(v for n, v in pairs if n == name) for name in dict.fromkeys(n for n, _ in pairs)}


def _mods(lines):
    """Modify blocks separated by '-': the first line names the op and attribute, the rest are values."""
    blocks = (tuple(g) for sep, g in groupby(lines, key=lambda line: line == "-") if not sep)
    return tuple(_mod([_split(line) for line in block]) for block in blocks)


def _mod(pairs):
    (op, attr), rest = pairs[0], pairs[1:]
    return op.lower(), attr, tuple(v for _, v in rest)


def _record(lines):
    name, dn = _split(lines[0])
    if name.lower() != "dn":
        raise ValueError(f"record does not start with dn: {lines[0]!r}")
    has_type = len(lines) > 1 and lines[1].lower().startswith("changetype:")
    changetype = _split(lines[1])[1].strip().lower() if has_type else "add"
    body = lines[2:] if has_type else lines[1:]
    if changetype == "modify":
        return LdifRecord(dn, changetype, {}, _mods(body))
    return LdifRecord(dn, changetype, _attrs(body), ())


def parse(text):
    """LdifRecord for each content or change record in the text."""
    return (_record(lines) for lines in _records(text))


def _needs_b64(v):
    return v != v.strip() or v.startswith((":", "<")) or any(ord(c) > 126 or c in "\r\n" for c in v)


def fold(line, width):
    """RFC 2849 folding: the first physical line holds `width` chars, continuations a space + width-1."""
    if len(line) <= width:
        return (line,)
    rest = line[width:]
    return (line[:width], *(" " + rest[i:i + width - 1] for i in range(0, len(rest), width - 1)))


def _attr_line(name, v):
    return f"{name}:: {base64.b64encode(v.encode()).decode()}" if _needs_b64(v) else f"{name}: {v}"


def write_entry(dn, object_classes, attrs, width=78):
    """One entry as LDIF: naming attributes first, base64 where needed, folded at `width` columns."""
    naming_first = sorted(attrs, key=lambda n: (n.lower() not in ("cn", "ou", "dc", "env", "cloud", "snap"), n))
    lines = (f"dn: {dn}", *(f"objectClass: {oc}" for oc in object_classes),
             *(physical for name in naming_first for v in attrs[name] for physical in fold(_attr_line(name, v), width)))
    return "\n".join(lines) + "\n"
