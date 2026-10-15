"""Splunk .conf files (indexes.conf, savedsearches.conf, inputs.conf) written and read as stanzas. Pure.

A file is stanzas, each `[name]` followed by `key = value` lines; `#` starts a comment line; a line ending in a
backslash continues on the next (its value then holds the newline). Settings before the first stanza belong to
`default`, as Splunk reads them. A stanza is (name, ((key, value), ...)) in file order; a key given twice in one
stanza keeps its last value, as Splunk does.
"""


def write_conf(head, stanzas):
    """A .conf file's text: head (comment text, written as is) then each stanza, a blank line between them; a value
    holding a newline is written over continued lines."""
    def value(v):
        return str(v).replace("\n", "\\\n")
    blocks = ("\n".join((f"[{name}]", *(f"{k} = {value(v)}" for k, v in pairs))) for name, pairs in stanzas)
    return head + "\n\n".join(blocks) + ("\n" if stanzas else "")


def _logical(text):
    lines, held = [], ""
    for raw in text.splitlines():
        line = held + raw
        if line.endswith("\\"):
            held = line[:-1] + "\n"
            continue
        held = ""
        lines.append(line)
    return lines + ([held] if held else [])


def read_conf(text):
    """The stanzas of a .conf file's text, in file order: ((name, ((key, value), ...)), ...); comments and blank lines
    left out, one stanza per name (a name repeated adds to the first)."""
    order, found, name = [], {}, "default"
    for line in _logical(text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            name = stripped[1:-1].strip()
            if name not in found:
                order.append(name)
                found[name] = {}
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        if name not in found:
            order.append(name)
            found[name] = {}
        found[name][key.strip()] = value.strip()
    return tuple((n, tuple(found[n].items())) for n in order)


def setting(stanza, key, default=None):
    """A stanza's value of key, or default."""
    return dict(stanza[1]).get(key, default)
