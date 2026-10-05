"""The Postgres store: connecting, loading and modifying entries, and reading the directory snapshot.
(Creating and upgrading the SQL schema is store/migrations.py.)

Pure functions prepare everything (schema rows, entry rows, modified entries); the few functions
that take a connection only execute what was prepared. Nothing here knows any product or cloud.
"""
import json
import os
import pathlib
from functools import reduce
from typing import Callable, NamedTuple

import psycopg

from ..core.directory import make_directory, norm_dn, within
from ..core.interchange import ldif, rfc4512

INSERT_ENTRY = "insert into entry (dn, object_classes, attrs, change_id) values (%s, %s, %s, %s)"
UPDATE_ENTRY = "update entry set object_classes = %s, attrs = %s where dn_norm = %s"
INVALID_SQL = ("select dn, p from (select id, dn, entry_problem(dn, object_classes, attrs) p from entry) x"
               " where p is not null order by id limit 20")
ROWS_OF_CLASSES_SQL = "select dn, object_classes, attrs from entry where object_classes && %s::text[] order by id"

# Entries under `branch` define part of the schema itself (custom fields and record types). A write that touches them
# re-syncs the schema registry with `sync(conn)` (the caller composes the schema), and every stored entry is checked
# again against it, in the same transaction.
SchemaSync = NamedTuple("SchemaSync", [("branch", str), ("sync", Callable)])


def connect(dsn=None):
    """Effect: connection to dsn, else OPSDIR_DSN (autocommit; writes use explicit transactions)."""
    dsn = dsn or os.environ.get("OPSDIR_DSN")
    if not dsn:
        raise SystemExit("OPSDIR_DSN is not set (./opsdir.sh sets the local dev database; see README, Database)")
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


def _on_path(dn, branch):
    """The entry is the branch, under it, or one of its ancestors (which must exist before it)."""
    return within(dn, branch) or within(branch, dn)


def schema_phases(records, branch):
    """(definition adds and modifies, every other record, definition deletes): definitions (with the branch's
    ancestors) change first so the rest of the change can use them, and go last so the rest can stop using them
    first. Order is kept within a phase."""
    defining = tuple(r for r in records if _on_path(r.dn, branch))
    return (tuple(r for r in defining if r.changetype != "delete"),
            tuple(r for r in records if not _on_path(r.dn, branch)),
            tuple(r for r in defining if r.changetype == "delete"))


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


def _after(canon, rows, r):
    n = norm_dn(r.dn)
    if r.changetype == "add":
        return {**rows, n: (r.dn, *split_record(canon, r.attrs))}
    if r.changetype == "delete" or n not in rows:      # a modify of no entry: refused when applied
        return {k: v for k, v in rows.items() if k != n}
    dn, classes, attrs = rows[n]
    return {**rows, n: (dn, *apply_mods(canon, classes, attrs, r.mods))}


def entries_after(canon, current, records):
    """(dn, object classes, attrs) of each entry the change records leave, applied in order to current ({normalized
    dn: (dn, object classes, attrs)}, the entries they touch as stored); deleted entries are not among them."""
    touched = {norm_dn(r.dn) for r in records}
    return tuple(v for k, v in reduce(lambda acc, r: _after(canon, acc, r), records, dict(current)).items()
                 if k in touched)


# ------------------------------------------------------------------ effects: execute prepared work
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


def load_ldif(conn, paths, change_id="BOOTSTRAP", schema_sync=None):
    """Effect: load the content records of LDIF files in one transaction under a change id."""
    return load_records(conn, read_ldif_files(paths), change_id, schema_sync)


def invalid_entries(conn):
    """Effect: (dn, problem) for stored entries the registry no longer accepts (at most 20)."""
    return conn.execute(INVALID_SQL).fetchall()


def revalidate(conn):
    """Effect: refuse (inside the caller's transaction) when stored entries break the registry as it now is."""
    bad = invalid_entries(conn)
    if bad:
        raise SystemExit("the schema would no longer accept stored entries: " + "; ".join(p for _, p in bad))


def rows_of_classes(conn, classes):
    """Effect: (dn, object classes, attrs) of the entries of any of these classes, in the order they were added."""
    return conn.execute(ROWS_OF_CLASSES_SQL, (list(classes),)).fetchall()


def _touches(records, schema_sync):
    return schema_sync is not None and any(within(r.dn, schema_sync.branch) for r in records)


def _insert_all(conn, change_id, records):
    for row in entry_rows(_canon(conn), records):
        _insert(conn, change_id, row)


def load_records(conn, records, change_id="BOOTSTRAP", schema_sync=None):
    """Effect: load content records in one transaction under a change id; returns how many. Definitions of the schema
    itself (schema_sync.branch) load first and are composed into the registry before the rest."""
    records = tuple(records)
    with conn.transaction():
        _begin_change(conn, change_id)
        if _touches(records, schema_sync):
            defining, rest, _ = schema_phases(records, schema_sync.branch)
            _insert_all(conn, change_id, defining)
            schema_sync.sync(conn)
            _insert_all(conn, change_id, rest)
            revalidate(conn)
        else:
            _insert_all(conn, change_id, records)
    return len(records)


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


def record_problems(conn, records):
    """Effect (reads the record): what the store would refuse in the entries change records leave (entry_problem:
    value types, SINGLE-VALUE, vocabularies, value rules, the classes' attributes, the secret guard), without writing
    anything; empty when it would take them. References and governance are checked when they are applied."""
    records = tuple(records)
    rows = conn.execute("select dn_norm, dn, object_classes, attrs from entry where dn_norm = any(%s)",
                        (list({norm_dn(r.dn) for r in records}),)).fetchall()
    after = entries_after(_canon(conn), {n: (dn, classes, attrs) for n, dn, classes, attrs in rows}, records)
    found = (conn.execute("select entry_problem(%s, %s, %s::jsonb)", (dn, classes, json.dumps(attrs))).fetchone()[0]
             for dn, classes, attrs in after)
    return tuple(p for p in found if p)


def last_change(conn, dns, excluded=()):
    """Effect (reads history): when any of the entries at dns last changed under a change other than BOOTSTRAP (the
    record as first loaded) and the excluded change ids; None when none did."""
    return conn.execute("select max(at) from entry_history where norm_dn(dn) = any(%s) and change_id <> all(%s)",
                        ([norm_dn(dn) for dn in dns], ["BOOTSTRAP", *excluded])).fetchone()[0]


def _apply_all(conn, change_id, records):
    canon = _canon(conn)
    return [_apply_record(conn, canon, change_id, r) for r in records]


def apply_records(conn, records, change_id, schema_sync=None):
    """Effect: apply change records (add / modify / delete) under one change id, atomically. A change to definitions
    of the schema itself (schema_sync.branch) is applied in phases (schema_phases), the registry re-synced after the
    definitions change and again at the end, and every stored entry checked against the result."""
    records = tuple(records)
    with conn.transaction():
        _begin_change(conn, change_id)
        if not _touches(records, schema_sync):
            return _apply_all(conn, change_id, records)
        defining, rest, dropping = schema_phases(records, schema_sync.branch)
        done = _apply_all(conn, change_id, defining)
        schema_sync.sync(conn)
        done = [*done, *_apply_all(conn, change_id, rest), *_apply_all(conn, change_id, dropping)]
        schema_sync.sync(conn)
        revalidate(conn)
        return done


def apply_changes(conn, path, change_id, schema_sync=None):
    """Effect: apply an LDIF file of change records under one change id, atomically."""
    return apply_records(conn, read_ldif_files([path]), change_id, schema_sync)


# ------------------------------------------------------------------ reads
def fetch_directory_rows(conn):
    """Effect: read the schema registry and every entry, entries in the order they were added (so every reader of
    the snapshot sees the same order the in-memory directory built from the same files has)."""
    return (conn.execute("select name, value_type, portability from attribute_type").fetchall(),
            conn.execute("select name, sup from object_class").fetchall(),
            conn.execute("select dn, object_classes, attrs from entry order by id").fetchall())


def load_directory(conn):
    return make_directory(*fetch_directory_rows(conn))
