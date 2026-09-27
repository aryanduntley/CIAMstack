"""RFC 4512 schema definition parser (attributeTypes / objectClasses), including X- extensions."""
import re

_TOKEN = re.compile(r"\(|\)|'[^']*'|\$|[^\s()$']+")
FLAGS = frozenset({"SINGLE-VALUE", "ABSTRACT", "STRUCTURAL", "AUXILIARY", "OBSOLETE", "COLLECTIVE",
                   "NO-USER-MODIFICATION"})


def _unescape(s):
    return re.sub(r"\\([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), s)


def _tokens(defn):
    return [_unescape(t[1:-1]) if t.startswith("'") else t for t in _TOKEN.findall(defn)]


def _value(toks, i):
    """A single token, or a parenthesized '$'-separated list; returns (value, position after it)."""
    if toks[i] != "(":
        return toks[i], i + 1
    end = toks.index(")", i)
    return tuple(t for t in toks[i + 1:end] if t != "$"), end + 1


def _fields(toks, i):
    """KEYWORD value pairs and bare flags from position i to the end (a later keyword wins)."""
    if i >= len(toks):
        return {}
    key = toks[i]
    if key in FLAGS:
        return {key: True, **_fields(toks, i + 1)}
    value, nxt = _value(toks, i + 1)
    return {key: value, **_fields(toks, nxt)}


def _parse(defn):
    toks = _tokens(defn)
    if toks[0] != "(" or toks[-1] != ")":
        raise ValueError(f"bad schema definition: {defn[:60]}")
    body = toks[1:-1]
    return {"oid": body[0], **_fields(body, 1)}


def _list(v):
    return list(v) if isinstance(v, tuple) else ([v] if v else [])


def attribute_type(defn):
    d = _parse(defn)
    names = _list(d["NAME"])
    return {
        "name": names[0], "oid": d["oid"], "syntax_oid": d.get("SYNTAX"), "equality": d.get("EQUALITY"),
        "value_type": d.get("X-VALUE-TYPE", "string"), "portability": d.get("X-PORTABILITY", "meta"),
        "single_value": bool(d.get("SINGLE-VALUE")), "description": d.get("DESC"), "origin": d.get("X-ORIGIN"),
    }


def object_class(defn):
    d = _parse(defn)
    kind = next((k for k in ("ABSTRACT", "STRUCTURAL", "AUXILIARY") if d.get(k)), "STRUCTURAL")
    return {
        "name": _list(d["NAME"])[0], "oid": d["oid"], "sup": (_list(d.get("SUP")) or [None])[0], "kind": kind,
        "must": _list(d.get("MUST")), "may": _list(d.get("MAY")), "description": d.get("DESC"),
        "origin": d.get("X-ORIGIN"),
    }


# ------------------------------------------------------------------ writing definitions
def quote(text):
    """A qdstring value: backslash and quote escaped as \\5C and \\27."""
    return text.replace("\\", "\\5C").replace("'", "\\27")


def name_list(names):
    """oids: a single name, or ( a $ b )."""
    return names[0] if len(names) == 1 else "( " + " $ ".join(names) + " )"


def attribute_type_definition(oid, name, desc, equality, syntax, single_value, extensions):
    """An attributeTypes definition; extensions is ((X-NAME, value), ...) in output order."""
    xs = "".join(f" {k} '{quote(v)}'" for k, v in extensions)
    return (f"( {oid} NAME '{name}' DESC '{quote(desc)}' EQUALITY {equality} SYNTAX {syntax}"
            f"{' SINGLE-VALUE' if single_value else ''}{xs} )")


def object_class_definition(oid, name, desc, sup, kind, must, may, extensions):
    """An objectClasses definition; sup, must and may are optional."""
    xs = "".join(f" {k} '{quote(v)}'" for k, v in extensions)
    return (f"( {oid} NAME '{name}' DESC '{quote(desc)}'" + (f" SUP {sup}" if sup else "") + f" {kind}"
            + (f" MUST {name_list(must)}" if must else "") + (f" MAY {name_list(may)}" if may else "") + f"{xs} )")
