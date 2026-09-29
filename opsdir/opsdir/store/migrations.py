"""Versioned changes to the Postgres store, so an upgrade keeps its data and history.

Migrations (sql/migrations/NNNN_name.sql) create and change what holds data: tables, the rule functions and their
triggers. Each is applied once, in version order, and recorded with its checksum in opsdir.schema_migration. An
applied migration is never edited; a change is a new migration.

Definitions hold no data: views and report/graph functions (sql/definitions/, and every domain's and connector's
SQL). They are re-applied on every upgrade after all views are dropped, so they are simply edited in place.

The LDAP schema registry, the reference schemes and the vocabulary (values of `vocab` attributes the domains and
adapters define) are synced on every upgrade from the registered schema fragments, domains and adapters. A definition
no installed part defines any more (an uninstalled adapter's) is removed, unless entries still use it. The schema is
composed inside the upgrade's transaction (the caller's `schema(conn)`: it may read definitions the record holds),
and every stored entry is checked against the result, so no upgrade leaves an entry the schema no longer accepts. `upgrade` brings a database up to date in place; `init` drops the opsdir schema and upgrades from nothing.
"""
import hashlib
import re
from pathlib import Path
from typing import NamedTuple

from psycopg.types.json import Jsonb

from ..core.naming import SUFFIX
from .postgres import revalidate, schema_rows

MIGRATIONS = Path(__file__).resolve().parent / "sql" / "migrations"
DEFINITIONS = Path(__file__).resolve().parent / "sql" / "definitions"

Migration = NamedTuple("Migration", [("version", int), ("name", str), ("sql", str), ("checksum", str)])

_FILE_NAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")
_ATTRIBUTE_COLUMNS = ("name", "oid", "syntax_oid", "equality", "value_type", "portability", "single_value",
                      "description", "origin", "rules")
_CLASS_COLUMNS = ("name", "oid", "sup", "kind", "must", "may", "description", "origin")

STATE_SQL = ("select to_regnamespace('opsdir') is not null, to_regclass('opsdir.schema_migration') is not null")
BOOKKEEPING_SQL = ("create schema if not exists opsdir;"
                   " create table if not exists opsdir.schema_migration ("
                   " version int primary key, name text not null, checksum text not null,"
                   " applied_at timestamptz not null default now())")
APPLIED_SQL = "select version, name, checksum from opsdir.schema_migration order by version"
RECORD_SQL = "insert into opsdir.schema_migration (version, name, checksum) values (%s, %s, %s)"
DROP_VIEWS_SQL = ("do $$ declare v record; begin"
                  " for v in select viewname from pg_views where schemaname = 'opsdir' loop"
                  " execute format('drop view if exists opsdir.%I cascade', v.viewname); end loop; end $$")
VOCABULARY_IN_USE_SQL = (
    "select e.dn, j.k, v from opsdir.entry e, jsonb_each(e.attrs) j(k, vals), jsonb_array_elements_text(j.vals) v"
    " where j.k in (select name from opsdir.attribute_type where value_type = 'vocab')"
    " and not exists (select 1 from opsdir.vocabulary w where w.attr = j.k and w.value = v) order by 1, 2 limit 20")
REGISTERED_SQL = "select (select array_agg(name) from opsdir.attribute_type), (select array_agg(name) from opsdir.object_class)"
ATTRIBUTES_IN_USE_SQL = ("select distinct k from opsdir.entry, jsonb_object_keys(attrs) k where k = any(%s) order by 1")
CLASSES_IN_USE_SQL = ("select distinct c from opsdir.entry, unnest(object_classes) c where c = any(%s) order by 1")


# ------------------------------------------------------------------ pure
def migration(file_name, sql):
    """A Migration from its file name (NNNN_name.sql) and text; the checksum is the text's SHA-256."""
    m = _FILE_NAME.match(file_name)
    if not m:
        raise SystemExit(f"migration file name must look like 0001_name.sql: {file_name}")
    return Migration(int(m.group(1)), m.group(2), sql, hashlib.sha256(sql.encode()).hexdigest())


def label(m):
    return f"{m.version:04d}_{m.name}"


def in_sequence(migrations):
    """The migrations in version order; versions must run 1, 2, 3, ... with no gap or repeat."""
    ordered = tuple(sorted(migrations, key=lambda m: m.version))
    if [m.version for m in ordered] != list(range(1, len(ordered) + 1)):
        raise SystemExit(f"migration versions must run 1, 2, 3, ...: {[label(m) for m in ordered]}")
    return ordered


def pending(applied, migrations):
    """Migrations still to apply, in order. applied: ((version, name, checksum), ...) from the database.
    Refuses a database whose applied migrations this code doesn't have or has with different text."""
    known = {m.version: m for m in migrations}
    unknown = [f"{v:04d}_{n}" for v, n, _ in applied if v not in known]
    if unknown:
        raise SystemExit(f"the database has migrations this code doesn't know: {', '.join(unknown)}")
    edited = [f"{v:04d}_{n}" for v, n, checksum in applied if known[v].checksum != checksum]
    if edited:
        raise SystemExit(f"applied migrations were edited: {', '.join(edited)}. Revert them and add a new migration.")
    done = {v for v, _, _ in applied}
    todo = tuple(m for m in in_sequence(migrations) if m.version not in done)
    if todo and done and todo[0].version < max(done):
        raise SystemExit(f"migration {label(todo[0])} is older than the database's latest ({max(done):04d})")
    return todo


def removed_definitions(registered_attributes, registered_classes, ats, ocs):
    """Registered attribute types and object classes the composed schema no longer defines."""
    attrs, classes = {a["name"] for a in ats}, {o["name"] for o in ocs}
    return (tuple(sorted(n for n in registered_attributes if n not in attrs)),
            tuple(sorted(n for n in registered_classes if n not in classes)))


def misdeclared_vocabulary(vocabulary, ats):
    """(attribute, owner) pairs that declare values for an attribute that is not of value type `vocab`."""
    vocab = {a["name"] for a in ats if a["value_type"] == "vocab"}
    return tuple(dict.fromkeys((attr, owner) for attr, _, owner in vocabulary if attr not in vocab))


def _upsert(table, columns):
    names = ", ".join(columns)
    params = ", ".join(f"%({c})s" for c in columns)
    updates = ", ".join(f"{c} = excluded.{c}" for c in columns if c != "name")
    return f"insert into opsdir.{table} ({names}) values ({params}) on conflict (name) do update set {updates}"


UPSERT_ATTRIBUTE_TYPE = _upsert("attribute_type", _ATTRIBUTE_COLUMNS)
UPSERT_OBJECT_CLASS = _upsert("object_class", _CLASS_COLUMNS)


# ------------------------------------------------------------------ effects
def read_migrations(directory=MIGRATIONS):
    """Effect: every migration file, in version order."""
    return in_sequence(migration(p.name, p.read_text()) for p in directory.glob("*.sql"))


def _apply_definitions(conn, definition_files):
    conn.execute(DROP_VIEWS_SQL)
    for f in definition_files:
        conn.execute(Path(f).read_text())


def _in_use(conn, sql, names):
    return tuple(r[0] for r in conn.execute(sql, (list(names),)).fetchall()) if names else ()


def sync_registry(conn, schema_text):
    """Upsert every definition; remove those no installed part defines, refusing when entries still use them."""
    ats, ocs = schema_rows(schema_text)
    registered = conn.execute(REGISTERED_SQL).fetchone()
    gone_attrs, gone_classes = removed_definitions(registered[0] or (), registered[1] or (), ats, ocs)
    used = _in_use(conn, ATTRIBUTES_IN_USE_SQL, gone_attrs) + _in_use(conn, CLASSES_IN_USE_SQL, gone_classes)
    if used:
        raise SystemExit("schema: entries use definitions that no installed part defines any more (is a package "
                         f"missing?): {', '.join(used)}")
    for a in ats:
        conn.execute(UPSERT_ATTRIBUTE_TYPE, {**a, "rules": Jsonb(a["rules"])})
    for o in ocs:                               # superclasses first (schema_rows)
        conn.execute(UPSERT_OBJECT_CLASS, o)
    conn.execute("delete from opsdir.vocabulary where attr = any(%s)", (list(gone_attrs),))
    conn.execute("delete from opsdir.object_class where name = any(%s)", (list(gone_classes),))
    conn.execute("delete from opsdir.attribute_type where name = any(%s)", (list(gone_attrs),))


def _sync_vocabulary(conn, schema_text, vocabulary):
    wrong = misdeclared_vocabulary(vocabulary, schema_rows(schema_text)[0])
    if wrong:
        raise SystemExit("vocabulary declared for attributes that are not of value type vocab: "
                         + ", ".join(f"{attr} ({owner})" for attr, owner in wrong))
    conn.execute("delete from opsdir.vocabulary")
    for row in vocabulary:
        conn.execute("insert into opsdir.vocabulary (attr, value, owner) values (%s, %s, %s)", row)
    unregistered = conn.execute(VOCABULARY_IN_USE_SQL).fetchall()
    if unregistered:
        raise SystemExit("entries use values no installed domain or adapter defines (is an adapter missing?): "
                         + "; ".join(f"{dn}: {attr}={value}" for dn, attr, value in unregistered))


def _sync_names(conn, ref_schemes):
    conn.execute("insert into opsdir.suffix values (%s) on conflict do nothing", (SUFFIX,))
    for scheme in ref_schemes:
        conn.execute("insert into opsdir.ref_scheme values (%s) on conflict do nothing", (scheme,))


def _sync_secret_patterns(conn, patterns):
    conn.execute("delete from opsdir.secret_pattern")
    for row in patterns:
        conn.execute("insert into opsdir.secret_pattern (name, pattern, owner, description) values (%s, %s, %s, %s)",
                     row)


def upgrade(conn, migrations, definition_files, schema, ref_schemes, vocabulary, secret_patterns):
    """Effect: bring the opsdir schema up to date in one transaction (one migrator at a time): pending migrations,
    then definitions, the LDAP schema registry (schema(conn) composes its text), the reference schemes, the
    vocabulary and the secret patterns ((name, pattern, owner, description), ...). Returns the migrations applied.
    Refuses a database created before versioned migrations, one whose entries use values or definitions no longer
    defined, and one whose entries the new schema doesn't accept (including a value a new secret pattern matches)."""
    with conn.transaction():
        conn.execute("select pg_advisory_xact_lock(hashtext('opsdir.upgrade'))")
        exists, versioned = conn.execute(STATE_SQL).fetchone()
        if exists and not versioned:
            raise SystemExit("this opsdir schema was created before versioned migrations; "
                             "`opsdir init` rebuilds it (its data is dropped)")
        conn.execute(BOOKKEEPING_SQL)
        todo = pending(conn.execute(APPLIED_SQL).fetchall(), migrations)
        for m in todo:
            conn.execute(m.sql)
            conn.execute(RECORD_SQL, (m.version, m.name, m.checksum))
        conn.execute("set search_path = opsdir")
        _apply_definitions(conn, definition_files)
        schema_text = schema(conn)
        sync_registry(conn, schema_text)
        _sync_names(conn, ref_schemes)
        _sync_vocabulary(conn, schema_text, vocabulary)
        _sync_secret_patterns(conn, secret_patterns)
        revalidate(conn)
    return todo


def init(conn, migrations, definition_files, schema, ref_schemes, vocabulary, secret_patterns):
    """Effect: drop the opsdir schema (all data) and upgrade from nothing, atomically."""
    with conn.transaction():
        conn.execute("drop schema if exists opsdir cascade")
        return upgrade(conn, migrations, definition_files, schema, ref_schemes, vocabulary, secret_patterns)


def current_version(conn):
    """Effect: the latest applied migration version (0 when none)."""
    return conn.execute("select coalesce(max(version), 0) from opsdir.schema_migration").fetchone()[0]
