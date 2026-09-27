"""The Postgres store: init, load, modify, and reading the directory snapshot.

Pure functions prepare everything (schema rows, entry rows, modified entries); the few functions
that take a connection only execute what was prepared. Nothing here knows any product or cloud.
"""
import json
import os
import pathlib
from functools import reduce

import psycopg

from ..core.directory import make_directory, norm_dn
from ..core.interchange import ldif, rfc4512
from ..core.naming import SUFFIX
from ..core.paths import ROOT

INSERT_ATTRIBUTE_TYPE = (
    "insert into attribute_type (name, oid, syntax_oid, equality, value_type, portability, single_value,"
    " description, origin) values (%(name)s, %(oid)s, %(syntax_oid)s, %(equality)s, %(value_type)s,"
    " %(portability)s, %(single_value)s, %(description)s, %(origin)s)")
INSERT_OBJECT_CLASS = (
    "insert into object_class (name, oid, sup, kind, must, may, description, origin)"
    " values (%(name)s, %(oid)s, %(sup)s, %(kind)s, %(must)s, %(may)s, %(description)s, %(origin)s)")
INSERT_ENTRY = "insert into entry (dn, object_classes, attrs, change_id) values (%s, %s, %s, %s)"
UPDATE_ENTRY = "update entry set object_classes = %s, attrs = %s where dn_norm = %s"


def connect():
    """Effect: connection to OPSDIR_DSN (autocommit; writes use explicit transactions)."""
    dsn = os.environ.get("OPSDIR_DSN")
    if not dsn:
        raise SystemExit("OPSDIR_DSN is not set (eval \"$(scripts/pg-local.sh start)\")")
    conn = psycopg.connect(dsn, autocommit=True)
    conn.execute("set search_path = opsdir")
    return conn


def set_as_of(conn, as_of):
    """Effect: the date the SQL views evaluate expiry and ages against (opsdir.as_of)."""
    conn.execute("select set_config('opsdir.as_of', %s, false)", (as_of.isoformat(),))



# ------------------------------------------------------------------ schema: pure preparation
def _placed(placed, name):
    return any(p["name"] == name for p in placed)


def _superclasses_first(ocs, placed=()):
    """Object classes ordered so every superclass precedes its subclasses: repeated passes in file
    order, each placing every class whose superclass is already placed."""
    if len(placed) == len(ocs):
        return placed
    ready = reduce(lambda acc, o: acc if _placed(acc, o["name"]) or (o["sup"] and not _placed(acc, o["sup"]))
                   else (*acc, o), ocs, placed)
    if len(ready) == len(placed):
        stuck = [o["name"] for o in ocs if not _placed(placed, o["name"])]
        raise SystemExit(f"schema: classes with an unknown or cyclic superclass: {stuck}")
    return _superclasses_first(ocs, ready)


def schema_rows(text):
    """Registry rows from an RFC 4512 schema LDIF: (attribute types, object classes superclasses-first)."""
    (rec,) = tuple(ldif.parse(text))
    ats = tuple(rfc4512.attribute_type(d) for d in rec.attrs.get("attributeTypes", ()))
    ocs = tuple(rfc4512.object_class(d) for d in rec.attrs.get("objectClasses", ()))
    known = {a["name"] for a in ats}
    undefined = [(o["name"], [x for x in o["must"] + o["may"] if x not in known]) for o in ocs]
    bad = next(((name, missing) for name, missing in undefined if missing), None)
    if bad:
        raise SystemExit(f"schema: class {bad[0]} uses undefined attributes {bad[1]}")
    return ats, _superclasses_first(ocs)


# ------------------------------------------------------------------ entries: pure preparation
def split_record(canon, attrs):
    """LDIF attributes → (object classes, {canonical attribute name: [values]})."""
    is_oc = lambda name: name.lower() == "objectclass"  # noqa: E731
    classes = [v for name, vals in attrs.items() if is_oc(name) for v in vals]
    canonical = [(canon.get(name.lower(), name), vals) for name, vals in attrs.items() if not is_oc(name)]
    return classes, {c: [v for n, vals in canonical if n == c for v in vals] for c in dict.fromkeys(n for n, _ in canonical)}


def entry_rows(canon, records):
    """(dn, object classes, attrs) per content record, parents before children (by DN depth).
    DN references are checked at commit, so the order between siblings doesn't matter."""
    ordered = sorted(records, key=lambda r: norm_dn(r.dn).count(","))
    return tuple((r.dn, *split_record(canon, r.attrs)) for r in ordered)


def _modify_list(cur, op, vals):
    if op == "add":
        return cur + [v for v in vals if v not in cur]
    if op == "replace":
        return list(vals)
    if op == "delete":
        return [] if not vals else [v for v in cur if v not in vals]
    raise SystemExit(f"unsupported modify op {op}")


def _apply_mod(canon, entry, mod):
    classes, attrs = entry
    op, attr, vals = mod
    if attr.lower() == "objectclass":
        return _modify_list(classes, op, vals), attrs
    name = canon.get(attr.lower(), attr)
    new = _modify_list(attrs.get(name, []), op, vals)
    return classes, ({**attrs, name: new} if new else {k: v for k, v in attrs.items() if k != name})


def apply_mods(canon, classes, attrs, mods):
    """An entry's (object classes, attrs) after LDAP modify operations, applied in order."""
    return reduce(lambda entry, mod: _apply_mod(canon, entry, mod), mods, (list(classes), dict(attrs)))


# ------------------------------------------------------------------ effects: execute prepared work
def init(conn, sql_files, ref_schemes):
    """Effect: drop and recreate the opsdir SQL schema from sql_files (in order), load the LDAP schema,
    register the suffix and the reference schemes the adapters own."""
    ats, ocs = schema_rows((ROOT / "schema" / "ciam-ops.schema.ldif").read_text())
    with conn.transaction():
        conn.execute("drop schema if exists opsdir cascade")
        for f in sql_files:
            conn.execute(f.read_text())
        conn.execute("set search_path = opsdir")
        load_schema(conn, ats, ocs)
        conn.execute("insert into suffix values (%s)", (SUFFIX,))
        for scheme in ref_schemes:
            conn.execute("insert into ref_scheme values (%s)", (scheme,))


def load_schema(conn, ats, ocs):
    """Effect: insert prepared registry rows."""
    for a in ats:
        conn.execute(INSERT_ATTRIBUTE_TYPE, a)
    for o in ocs:
        conn.execute(INSERT_OBJECT_CLASS, o)


def registry_counts(conn):
    """Effect: (attribute types, object classes) in the registry."""
    return conn.execute("select (select count(*) from attribute_type), (select count(*) from object_class)").fetchone()


def reference_count(conn):
    """Effect: number of verified DN references."""
    return conn.execute("select count(*) from entry_ref").fetchone()[0]


def _canon(conn):
    return {r[0].lower(): r[0] for r in conn.execute("select name from attribute_type")}


def _begin_change(conn, change_id):
    conn.execute("select set_config('opsdir.change_id', %s, true)", (change_id,))


def _insert(conn, change_id, row):
    dn, classes, attrs = row
    conn.execute(INSERT_ENTRY, (dn, classes, json.dumps(attrs), change_id))


def read_ldif_files(paths):
    """Effect: parse every LDIF file into records."""
    return tuple(r for p in paths for r in ldif.parse(pathlib.Path(p).read_text()))


def load_ldif(conn, paths, change_id="BOOTSTRAP"):
    """Effect: load content records in one transaction under a change id."""
    rows = entry_rows(_canon(conn), read_ldif_files(paths))
    with conn.transaction():
        _begin_change(conn, change_id)
        for row in rows:
            _insert(conn, change_id, row)
    return len(rows)


def _apply_record(conn, canon, change_id, r):
    """Effect: apply one change record inside the caller's transaction; returns what was done."""
    if r.changetype == "add":
        _insert(conn, change_id, (r.dn, *split_record(canon, r.attrs)))
    elif r.changetype == "delete":
        if conn.execute("delete from entry where dn_norm = %s", (norm_dn(r.dn),)).rowcount == 0:
            raise SystemExit(f"no such entry: {r.dn}")
    elif r.changetype == "modify":
        row = conn.execute("select object_classes, attrs from entry where dn_norm = %s", (norm_dn(r.dn),)).fetchone()
        if not row:
            raise SystemExit(f"no such entry: {r.dn}")
        classes, attrs = apply_mods(canon, row[0], row[1], r.mods)
        conn.execute(UPDATE_ENTRY, (classes, json.dumps(attrs), norm_dn(r.dn)))
    else:
        raise SystemExit(f"unsupported changetype {r.changetype}")
    return f"{r.changetype} {r.dn}"


def apply_changes(conn, path, change_id):
    """Effect: apply LDIF change records (add / modify / delete) under one change id, atomically."""
    canon = _canon(conn)
    records = read_ldif_files([path])
    with conn.transaction():
        _begin_change(conn, change_id)
        return [_apply_record(conn, canon, change_id, r) for r in records]


# ------------------------------------------------------------------ reads
def fetch_directory_rows(conn):
    """Effect: read the schema registry and every entry."""
    return (conn.execute("select name, value_type, portability from attribute_type").fetchall(),
            conn.execute("select name, sup from object_class").fetchall(),
            conn.execute("select dn, object_classes, attrs from entry").fetchall())


def load_directory(conn):
    return make_directory(*fetch_directory_rows(conn))
