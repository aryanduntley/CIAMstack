"""Minimal LDIF (RFC 2849) reader/writer: content records and change records.

Supports comments, line folding, base64 values (attr:: value), and changetype add/modify/delete.
"""
import base64
import re


def _unfold(text):
    lines = []
    for raw in text.splitlines():
        if raw.startswith("#"):
            continue
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    return lines


def _records(text):
    rec = []
    for line in _unfold(text):
        if not line.strip():
            if rec:
                yield rec
                rec = []
        else:
            rec.append(line)
    if rec:
        yield rec


def _split(line):
    m = re.match(r"^([A-Za-z0-9;-]+)(::?)\s?(.*)$", line)
    if not m:
        raise ValueError(f"bad LDIF line: {line!r}")
    name, sep, value = m.groups()
    if sep == "::":
        value = base64.b64decode(value).decode()
    return name, value


def parse(text):
    """Yield dicts: {"dn", "changetype", "attrs": {name: [values]}, "mods": [(op, attr, [values])]}"""
    for lines in _records(text):
        name, dn = _split(lines[0])
        if name.lower() != "dn":
            raise ValueError(f"record does not start with dn: {lines[0]!r}")
        changetype, attrs, mods, i = "add", {}, [], 1
        if i < len(lines) and lines[i].lower().startswith("changetype:"):
            changetype = _split(lines[i])[1].strip().lower()
            i += 1
        if changetype == "modify":
            cur = None                       # (op, attr, values) for the current "-" block
            for line in lines[i:]:
                if line == "-":
                    cur = None
                    continue
                name, value = _split(line)
                if cur is None:
                    cur = (name.lower(), value, [])
                    mods.append(cur)
                else:
                    cur[2].append(value)
        else:
            for line in lines[i:]:
                name, value = _split(line)
                attrs.setdefault(name, []).append(value)
        yield {"dn": dn, "changetype": changetype, "attrs": attrs, "mods": mods}


def _needs_b64(v):
    return v != v.strip() or v.startswith((":", "<")) or any(ord(c) > 126 or c in "\r\n" for c in v)


def write_entry(dn, object_classes, attrs, fold=78):
    out = [f"dn: {dn}"] + [f"objectClass: {oc}" for oc in object_classes]
    for name in sorted(attrs, key=lambda n: (n.lower() not in ("cn", "ou", "dc", "env", "cloud", "snap"), n)):
        for v in attrs[name]:
            line = f"{name}:: {base64.b64encode(v.encode()).decode()}" if _needs_b64(v) else f"{name}: {v}"
            while len(line) > fold:
                out.append(line[:fold])
                line = " " + line[fold:]
            out.append(line)
    return "\n".join(out) + "\n"
