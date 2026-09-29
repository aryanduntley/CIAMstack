"""The store's schema: the code-owned fragments (the core's, the domains', the installed adapters') composed with
the custom fields and record types the record itself defines. A connector: it joins the custom domain's composition
with what the store holds."""
from functools import partial

from ..core.directory import make_entry
from ..core.standard import registry_ldif
from ..domains.custom.definitions import FIELD, RECORD_TYPE, compose, problems
from ..domains.custom.naming import CUSTOM_SCHEMA
from ..store.migrations import sync_registry
from ..store.postgres import SchemaSync, rows_of_classes


def composed_schema(fragments, definitions):
    """The schema text: the fragments composed with the custom definitions (entries); refused when they don't
    compose."""
    wrong = problems(fragments, definitions)
    if wrong:
        raise SystemExit("custom definitions don't compose: " + "; ".join(wrong))
    return registry_ldif(compose(fragments, definitions))


def store_schema(conn, fragments):
    """Effect (reads the custom definitions the record holds): the store's schema text."""
    return composed_schema(fragments, tuple(make_entry(*row) for row in rows_of_classes(conn, (FIELD, RECORD_TYPE))))


def _resync(conn, fragments):
    sync_registry(conn, store_schema(conn, fragments))


def schema_sync(fragments):
    """How a write that changes custom definitions re-syncs the store's schema (store.postgres.SchemaSync)."""
    return SchemaSync(CUSTOM_SCHEMA, partial(_resync, fragments=fragments))
