"""Database access: init, load, modify, export, and an in-memory view of the directory."""
import json
import os
import pathlib
import re

import psycopg

from . import ldif, schema

ROOT = pathlib.Path(__file__).resolve().parent.parent
SUFFIX = "dc=ciam-ops"


def connect():
    dsn = os.environ.get("OPSDIR_DSN")
    if not dsn:
        raise SystemExit("OPSDIR_DSN is not set (eval \"$(scripts/pg-local.sh start)\")")
    conn = psycopg.connect(dsn, autocommit=True)   # explicit transactions only
    conn.execute("set search_path = opsdir")
    return conn


def norm_dn(dn):
    return re.sub(r"\s*([=,])\s*", r"\1", dn.strip()).lower()


# ------------------------------------------------------------------ setup
def init(conn):
    with conn.transaction():
        conn.execute("drop schema if exists opsdir cascade")
        for f in sorted((ROOT / "sql").glob("*.sql")):
            conn.execute(f.read_text())
        conn.execute("set search_path = opsdir")
        load_schema(conn, ROOT / "schema" / "ciam-ops.schema.ldif")
        conn.execute("insert into suffix values (%s)", (SUFFIX,))


def load_schema(conn, path):
    (rec,) = list(ldif.parse(path.read_text()))
    ats = [schema.attribute_type(d) for d in rec["attrs"].get("attributeTypes", [])]
    ocs = [schema.object_class(d) for d in rec["attrs"].get("objectClasses", [])]
    known = {a["name"] for a in ats}
    for a in ats:
        conn.execute(
            "insert into attribute_type (name, oid, syntax_oid, equality, value_type, portability, single_value,"
            " description, origin) values (%(name)s, %(oid)s, %(syntax_oid)s, %(equality)s, %(value_type)s,"
            " %(portability)s, %(single_value)s, %(description)s, %(origin)s)", a)
    # insert superclasses first
    done = set()
    while len(done) < len(ocs):
        for o in ocs:
            if o["name"] in done or (o["sup"] and o["sup"] not in done):
                continue
            missing = [x for x in o["must"] + o["may"] if x not in known]
            if missing:
                raise SystemExit(f"schema: class {o['name']} uses undefined attributes {missing}")
            conn.execute(
                "insert into object_class (name, oid, sup, kind, must, may, description, origin)"
                " values (%(name)s, %(oid)s, %(sup)s, %(kind)s, %(must)s, %(may)s, %(description)s, %(origin)s)", o)
            done.add(o["name"])


# ------------------------------------------------------------------ writes
def _canon(conn):
    return {r[0].lower(): r[0] for r in conn.execute("select name from attribute_type")}


def _split_record(canon, attrs):
    ocs, out = [], {}
    for name, vals in attrs.items():
        if name.lower() == "objectclass":
            ocs += vals
        else:
            out.setdefault(canon.get(name.lower(), name), []).extend(vals)
    return ocs, out


def load_ldif(conn, paths, change_id="BOOTSTRAP"):
    """Load content records in one transaction. Parents are inserted before children;
    DN references are checked at commit, so file order doesn't matter."""
    canon = _canon(conn)
    recs = [r for p in paths for r in ldif.parse(pathlib.Path(p).read_text())]
    recs.sort(key=lambda r: norm_dn(r["dn"]).count(","))
    with conn.transaction():
        conn.execute("select set_config('opsdir.change_id', %s, true)", (change_id,))
        for r in recs:
            ocs, attrs = _split_record(canon, r["attrs"])
            conn.execute("insert into entry (dn, object_classes, attrs, change_id) values (%s, %s, %s, %s)",
                         (r["dn"], ocs, json.dumps(attrs), change_id))
    return len(recs)


def apply_changes(conn, path, change_id):
    """Apply LDIF change records (add / modify / delete) under one change id, atomically."""
    canon = _canon(conn)
    applied = []
    with conn.transaction():
        conn.execute("select set_config('opsdir.change_id', %s, true)", (change_id,))
        for r in ldif.parse(pathlib.Path(path).read_text()):
            dn, ct = r["dn"], r["changetype"]
            if ct == "add":
                ocs, attrs = _split_record(canon, r["attrs"])
                conn.execute("insert into entry (dn, object_classes, attrs, change_id) values (%s, %s, %s, %s)",
                             (dn, ocs, json.dumps(attrs), change_id))
            elif ct == "delete":
                cur = conn.execute("delete from entry where dn_norm = %s", (norm_dn(dn),))
                if cur.rowcount == 0:
                    raise SystemExit(f"no such entry: {dn}")
            elif ct == "modify":
                row = conn.execute("select object_classes, attrs from entry where dn_norm = %s",
                                   (norm_dn(dn),)).fetchone()
                if not row:
                    raise SystemExit(f"no such entry: {dn}")
                ocs, attrs = list(row[0]), dict(row[1])
                for op, attr, vals in r["mods"]:
                    if attr.lower() == "objectclass":
                        ocs = _modify_list(ocs, op, vals)
                        continue
                    name = canon.get(attr.lower(), attr)
                    new = _modify_list(attrs.get(name, []), op, vals)
                    if new:
                        attrs[name] = new
                    else:
                        attrs.pop(name, None)
                conn.execute("update entry set object_classes = %s, attrs = %s where dn_norm = %s",
                             (ocs, json.dumps(attrs), norm_dn(dn)))
            else:
                raise SystemExit(f"unsupported changetype {ct}")
            applied.append(f"{ct} {dn}")
    return applied


def _modify_list(cur, op, vals):
    if op == "add":
        return cur + [v for v in vals if v not in cur]
    if op == "replace":
        return list(vals)
    if op == "delete":
        return [] if not vals else [v for v in cur if v not in vals]
    raise SystemExit(f"unsupported modify op {op}")


# ------------------------------------------------------------------ reads
class Entry:
    def __init__(self, dn, classes, attrs):
        self.dn, self.classes, self.attrs = dn, list(classes), attrs
        self.norm = norm_dn(dn)

    def one(self, name, default=None):
        v = self.attrs.get(name)
        return v[0] if v else default

    def all(self, name):
        return list(self.attrs.get(name, []))

    def is_a(self, oc):
        return oc in self.classes

    @property
    def name(self):
        return self.dn.split(",", 1)[0].split("=", 1)[1]

    def __repr__(self):
        return f"<Entry {self.dn}>"


class Directory:
    """Whole-directory snapshot for renderers and planners (the demo estate is small)."""

    def __init__(self, conn):
        self.types = {r[0]: {"value_type": r[1], "portability": r[2]} for r in
                      conn.execute("select name, value_type, portability from attribute_type")}
        self.lower_types = {k.lower(): k for k in self.types}
        self.supers = dict(conn.execute("select name, sup from object_class").fetchall())
        self.entries = {}
        for dn, classes, attrs in conn.execute("select dn, object_classes, attrs from entry"):
            e = Entry(dn, classes, attrs)
            self.entries[e.norm] = e

    def get(self, dn):
        return self.entries.get(norm_dn(dn))

    def ref(self, e, name):
        v = e.one(name)
        return self.get(v) if v else None

    def refs(self, e, name):
        return [self.get(v) for v in e.all(name)]

    def classes_with_supers(self, e):
        out = set()
        for c in e.classes:
            while c:
                out.add(c)
                c = self.supers.get(c)
        return out

    def scope(self, base, scope="sub"):
        b = norm_dn(base)
        for n, e in self.entries.items():
            if scope == "base" and n == b:
                yield e
            elif scope == "one" and n.endswith("," + b) and n.count(",") == b.count(",") + 1:
                yield e
            elif scope == "sub" and (n == b or n.endswith("," + b)):
                yield e

    def children(self, base, oc=None):
        return sorted((e for e in self.scope(base, "one") if oc is None or e.is_a(oc)), key=lambda e: e.dn)

    def subtree(self, base, oc=None):
        return sorted((e for e in self.scope(base, "sub") if oc is None or e.is_a(oc)), key=lambda e: e.dn)

    def search(self, base, filt, scope="sub"):
        f = parse_filter(filt)
        return sorted((e for e in self.scope(base, scope) if f(self, e)), key=lambda e: e.dn)

    def referrers(self, target, attr=None):
        t = target.norm if isinstance(target, Entry) else norm_dn(target)
        for e in self.entries.values():
            for name, vals in e.attrs.items():
                if (attr is None or name == attr) and self.types.get(name, {}).get("value_type") == "dn" \
                        and any(norm_dn(v) == t for v in vals):
                    yield name, e


# ------------------------------------------------------------------ RFC 4515 filters (subset)
def parse_filter(s):
    s = s.strip()
    pos = 0

    def node():
        nonlocal pos
        if s[pos] != "(":
            raise ValueError(f"filter: expected '(' at {pos} in {s}")
        pos += 1
        op = s[pos]
        if op in "&|":
            pos += 1
            kids = []
            while s[pos] == "(":
                kids.append(node())
            pos += 1
            return (lambda d, e: all(k(d, e) for k in kids)) if op == "&" else \
                (lambda d, e: any(k(d, e) for k in kids))
        if op == "!":
            pos += 1
            k = node()
            pos += 1
            return lambda d, e: not k(d, e)
        end = s.index(")", pos)
        item = s[pos:end]
        pos = end + 1
        return _item(item)

    f = node()
    return f


def _item(item):
    m = re.match(r"^([A-Za-z0-9-]+)(>=|<=|=)(.*)$", item)
    if not m:
        raise ValueError(f"filter item: {item}")
    attr, op, val = m.groups()

    def test(d, e):
        if attr.lower() == "objectclass":
            vals = list(d.classes_with_supers(e))
            vt = "string"
        else:
            name = d.lower_types.get(attr.lower(), attr)
            vals = e.all(name)
            vt = d.types.get(name, {}).get("value_type", "string")
        if op == "=" and val == "*":
            return bool(vals)
        for v in vals:
            if _cmp(vt, op, v, val):
                return True
        return False

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
