"""The workspace marker in the store: which live snapshot a migration workspace was copied from (effects)."""
from typing import NamedTuple

Base = NamedTuple("Base", [("source", str), ("created_at", object), ("fingerprint", str), ("ldif", str)])

HAS_SCHEMA_SQL = "select to_regclass('opsdir.entry') is not null"
READ_SQL = "select source, created_at, fingerprint, base_ldif from opsdir.workspace_base where id = 1"
WRITE_SQL = ("insert into opsdir.workspace_base (id, source, fingerprint, base_ldif) values (1, %s, %s, %s)"
             " on conflict (id) do update set source = excluded.source, created_at = now(),"
             " fingerprint = excluded.fingerprint, base_ldif = excluded.base_ldif")


def has_schema(conn):
    """Effect: whether the database already holds an opsdir store."""
    return conn.execute(HAS_SCHEMA_SQL).fetchone()[0]


def read_base(conn):
    """Effect: the workspace's Base, or None when the database is not a workspace."""
    row = conn.execute(READ_SQL).fetchone() if has_schema(conn) else None
    return Base(*row) if row else None


def record_base(conn, source, fingerprint, ldif_text):
    """Effect: mark the database as a workspace copied from `source` with this base snapshot."""
    conn.execute(WRITE_SQL, (source, fingerprint, ldif_text))
