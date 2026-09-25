"""RFC 4512 schema definition parser (attributeTypes / objectClasses), including X- extensions."""
import re

_TOKEN = re.compile(r"\(|\)|'[^']*'|\$|[^\s()$']+")


def _unescape(s):
    return re.sub(r"\\([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), s)


def _tokens(defn):
    return [_unescape(t[1:-1]) if t.startswith("'") else t for t in _TOKEN.findall(defn)]


def _parse(defn):
    toks = _tokens(defn)
    if toks[0] != "(" or toks[-1] != ")":
        raise ValueError(f"bad schema definition: {defn[:60]}")
    toks = toks[1:-1]
    out = {"oid": toks[0]}
    i = 1

    def value():
        nonlocal i
        if toks[i] == "(":
            vals = []
            i += 1
            while toks[i] != ")":
                if toks[i] != "$":
                    vals.append(toks[i])
                i += 1
            i += 1
            return vals
        v = toks[i]
        i += 1
        return v

    flags = {"SINGLE-VALUE", "ABSTRACT", "STRUCTURAL", "AUXILIARY", "OBSOLETE", "COLLECTIVE",
             "NO-USER-MODIFICATION"}
    while i < len(toks):
        key = toks[i]
        i += 1
        if key in flags:
            out[key] = True
        else:
            out[key] = value()
    return out


def _list(v):
    return v if isinstance(v, list) else ([v] if v else [])


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
