"""LDAP search over a directory snapshot: an RFC 4515 filter subset compiled to predicates."""
import re

from .directory import classes_with_supers, in_scope, norm_dn, sorted_by_dn, value_type, values


def search(d, base, filt, scope="sub"):
    f = parse_filter(filt)
    return sorted_by_dn(e for e in in_scope(d, base, scope) if f(d, e))


# ------------------------------------------------------------------ RFC 4515 filters (subset)
# A filter compiles to a predicate f(directory, entry). Recursive descent over (text, position):
# each step returns the compiled node and the position just after it.
def parse_filter(s):
    f, _ = _node(s.strip(), 0)
    return f


def _node(s, pos):
    if s[pos] != "(":
        raise ValueError(f"filter: expected '(' at {pos} in {s}")
    op = s[pos + 1]
    if op in "&|":
        kids, end = _node_list(s, pos + 2)
        combine = all if op == "&" else any
        return (lambda d, e: combine(k(d, e) for k in kids)), end + 1
    if op == "!":
        k, end = _node(s, pos + 2)
        return (lambda d, e: not k(d, e)), end + 1
    end = s.index(")", pos + 1)
    return _item(s[pos + 1:end]), end + 1


def _node_list(s, pos):
    """Consecutive '(…)' nodes starting at pos; returns them and the position after the last."""
    if s[pos] != "(":
        return (), pos
    k, nxt = _node(s, pos)
    rest, end = _node_list(s, nxt)
    return (k, *rest), end


def _item_values(d, e, attr):
    if attr.lower() == "objectclass":
        return tuple(classes_with_supers(d, e)), "string"
    name = d.lower_types.get(attr.lower(), attr)
    return values(e, name), value_type(d, name) or "string"


def _item(item):
    m = re.match(r"^([A-Za-z0-9-]+)(>=|<=|=)(.*)$", item)
    if not m:
        raise ValueError(f"filter item: {item}")
    attr, op, val = m.groups()

    def test(d, e):
        vals, vt = _item_values(d, e, attr)
        if op == "=" and val == "*":
            return bool(vals)
        return any(_cmp(vt, op, v, val) for v in vals)

    return test


def _key(vt, v):
    if vt in ("int", "port"):
        return int(v)
    if vt in ("dn", "extdn"):
        return norm_dn(v)
    return v.lower()


def _cmp(vt, op, v, val):
    if op == "=" and "*" in val:
        rx = "^" + ".*".join(re.escape(p) for p in val.lower().split("*")) + "$"
        return re.match(rx, v.lower()) is not None
    a, b = _key(vt, v), _key(vt, val)
    return a == b if op == "=" else (a >= b if op == ">=" else a <= b)
