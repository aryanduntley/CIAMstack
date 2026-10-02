"""Minimal LDIF (RFC 2849) reader/writer: content records and change records, and LDIF files as captured settings
(core.capture).

Supports comments, line folding, base64 values (attr:: value), and changetype add/modify/delete. content_entries reads
directory data (an ldapsearch or export stream) lazily and tolerantly, for counting it without keeping it.
"""
import base64
import binascii
import re
from itertools import accumulate, groupby, tee
from operator import itemgetter
from typing import NamedTuple

from ..contract import Codec
from .lines import physical_lines

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


def _naming_first(names):
    return sorted(names, key=lambda n: (n.lower() not in ("cn", "ou", "dc", "env", "cloud", "snap"), n))


def _value_lines(name, values, width):
    return tuple(physical for v in values for physical in fold(_attr_line(name, v), width))


def _entry_lines(object_classes, attrs, width):
    return (*(f"objectClass: {oc}" for oc in object_classes),
            *(line for name in _naming_first(attrs) for line in _value_lines(name, attrs[name], width)))


def write_entry(dn, object_classes, attrs, width=78):
    """One entry as LDIF: naming attributes first, base64 where needed, folded at `width` columns."""
    return "\n".join((f"dn: {dn}", *_entry_lines(object_classes, attrs, width))) + "\n"


def _record_body(r, width):
    if r.changetype == "add":
        return _entry_lines(r.attrs.get("objectClass", ()),
                            {k: v for k, v in r.attrs.items() if k != "objectClass"}, width)
    if r.changetype == "modify":
        return tuple(line for op, attr, vals in r.mods for line in (f"{op}: {attr}", *_value_lines(attr, vals, width), "-"))
    return ()


def write_record(r, width=78):
    """One change record (add / modify / delete) as LDIF, the form `parse` reads back."""
    return "\n".join((f"dn: {r.dn}", f"changetype: {r.changetype}", *_record_body(r, width))) + "\n"


def write_records(records, width=78):
    """Change records as one LDIF text, blank-line separated."""
    return "\n".join(write_record(r, width) for r in records)


# ------------------------------------------------------------------ capture (core.capture)
# In content records every attribute value is a setting, located by "<dn>|<attribute>" (repeats numbered by the
# capture engine: mail, mail#2). Its raw text runs from the colon after the attribute name to the end of the logical
# line, folds included (": value", ":: base64"). dn, changetype, version, comments, URL values (":<") and change
# records are layout.
_ATTR_LINE = re.compile(r"([A-Za-z0-9][A-Za-z0-9;.-]*)(?=::?(?!<))")


def _logical_lines(text):
    """Physical lines grouped into logical lines (a line starting with one space continues the one before)."""
    lines = physical_lines(text)
    ids = accumulate(0 if line.startswith(" ") and k else 1 for k, line in enumerate(lines))
    return tuple("".join(line for _, line in group) for _, group in groupby(zip(ids, lines), key=lambda x: x[0]))


def _record_state(state, line):
    """(dn of the current record, whether it is a change record) after a logical line."""
    dn, change = state
    if not line.strip():
        return None, False
    name = line.split(":", 1)[0].lower()
    if name == "dn":
        return _decode_value(line[2:].rstrip("\r\n")), False
    return dn, change or name == "changetype"


def _decode_value(raw):
    unfolded = re.sub(r"\r?\n ", "", raw)
    return base64.b64decode(unfolded[2:].strip()).decode() if unfolded.startswith("::") else unfolded[1:].lstrip(" ")


def _capture_parts(state, line):
    dn, change = state
    m = _ATTR_LINE.match(line)
    if dn is None or change or m is None or line.startswith("#") or m.group(1).lower() in ("dn", "changetype"):
        return (line,)
    end = len(line) - len(line.rstrip("\r\n"))
    return m.group(1), (f"{dn}|{m.group(1)}", line[m.end():len(line) - end]), line[len(line) - end:]


def capture_split(text):
    logical = _logical_lines(text)
    after = tuple(accumulate(logical, _record_state, initial=(None, False)))[1:]      # state after each line
    return tuple(p for state, line in zip(after, logical) for p in _capture_parts(state, line))


def capture_encode(value, raw):
    """A changed value as ": value", or ":: base64" when the original was base64 or the value needs it."""
    if raw.startswith("::") or _needs_b64(value):
        return ":: " + base64.b64encode(value.encode()).decode()
    return ": " + value


CODEC = Codec(capture_split, _decode_value, capture_encode)


# ------------------------------------------------------------------ directory data, streamed
_DATA_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9;.-]*)(::|:<|:)\s?(.*)$")


def _stream_logical(lines):
    """Logical lines of an LDIF line stream, lazily: comments dropped, folded continuation lines joined."""
    kept, again = tee(raw.rstrip("\r\n") for raw in lines if not raw.startswith("#"))
    starts = accumulate(0 if raw.startswith(" ") else 1 for raw in kept)
    return (g[0][1] + "".join(raw[1:] for _, raw in g[1:])
            for g in (tuple(run) for _, run in groupby(zip(starts, again), key=itemgetter(0))))


def _data_value(sep, raw):
    if sep == ":<":
        return b""                                       # a URL: never fetched
    if sep == "::":
        try:
            return base64.b64decode(raw.strip())
        except (binascii.Error, ValueError):
            return b""
    return raw


def _data_entry(record):
    parts = tuple(m.groups() for m in map(_DATA_LINE.match, record) if m)
    if not parts or parts[0][0].lower() != "dn":
        return None
    dn = _data_value(parts[0][1], parts[0][2])
    attrs = tuple((name.split(";", 1)[0], _data_value(sep, raw)) for name, sep, raw in parts[1:])
    names = dict.fromkeys(n.lower() for n, _ in attrs)
    return (dn.decode("utf-8", "replace") if isinstance(dn, bytes) else dn,
            {n: tuple(v for a, v in attrs if a.lower() == n) for n in names})


def content_entries(lines):
    """(dn, {attribute: values}) of each entry in an LDIF line stream (ldapsearch output, an export), read lazily and
    tolerantly: attribute names lowercase with options dropped (cn;lang-fr counts as cn), base64 values as bytes (never
    decoded as text), URL values (:<) empty; records without a dn (version, ldapsearch's search and result lines) and
    lines that aren't LDIF are skipped."""
    records = (tuple(run) for filled, run in groupby(_stream_logical(lines), key=lambda line: bool(line.strip()))
               if filled)
    return (e for e in map(_data_entry, records) if e is not None)
