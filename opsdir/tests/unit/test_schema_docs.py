"""The schema reference (documentation/SCHEMA.md, documentation/schema/) is what the schema fragments generate, its
storage layer names every table and column the migrations create, and every link in it lands on an anchor."""
import pathlib
import re

from opsdir.connectors.registry import vocabulary
from opsdir.connectors.schema_docs import PAGES, STORAGE_TABLES, documented_parts, schema_pages
from opsdir.store.migrations import BOOKKEEPING_SQL, MIGRATIONS

DOCUMENTATION = pathlib.Path(__file__).resolve().parents[3] / "documentation"
CONSTRAINTS = ("primary", "unique", "foreign", "check", "constraint")


def _generated():
    return schema_pages(documented_parts(), vocabulary())


def test_the_committed_reference_is_what_the_schema_fragments_generate():
    pages = _generated()
    committed = {f"{PAGES}/{p.name}": p.read_text(encoding="utf-8") for p in (DOCUMENTATION / PAGES).glob("*.md")}
    committed["SCHEMA.md"] = (DOCUMENTATION / "SCHEMA.md").read_text(encoding="utf-8")
    stale = sorted(p for p in set(pages) | set(committed) if pages.get(p) != committed.get(p))
    assert stale == [], f"run opsdir/scripts/gen-schema-docs.py and commit: {stale}"


def _created_tables(sql):
    """{table: {column, ...}} of the tables an SQL text creates, with the columns later ALTER TABLE ... ADD COLUMN
    statements add."""
    plain = re.sub(r"--[^\n]*", "", sql)
    blocks = re.findall(r"create table (?:if not exists )?(?:opsdir\.)?(\w+)\s*\((.*?)\);", plain, re.S | re.I)
    first = tuple((name, (line.split() or [""])[0]) for name, body in blocks for line in body.splitlines())
    tables = {name: {word for n, word in first if n == name and word.lower() not in CONSTRAINTS
                     and re.match(r"^[a-z_]+$", word)} for name, _ in blocks}
    added = re.findall(r"alter table (\w+) add column (\w+)", sql, re.I)
    return {name: cols | {c for t, c in added if t == name} for name, cols in tables.items()}


def test_the_storage_layer_names_every_table_and_column_the_migrations_create():
    bookkeeping = BOOKKEEPING_SQL.replace(",", ",\n") + ";"        # one line, one column per comma
    sql = "\n".join((bookkeeping, *(p.read_text(encoding="utf-8") for p in sorted(MIGRATIONS.glob("*.sql")))))
    created = _created_tables(sql)
    described = {name: {c for c, _, _ in columns} for name, _, columns in STORAGE_TABLES}
    assert described == created


def test_every_link_in_the_reference_lands_on_an_anchor():
    pages = _generated()
    anchors = {path: set(re.findall(r'<a id="([^"]+)"></a>', text)) for path, text in pages.items()}

    def target(path, link):
        file, _, anchor = link.partition("#")
        base = pathlib.PurePosixPath(path).parent
        resolved = str(pathlib.PurePosixPath(base, file)) if file else path
        return resolved.replace("schema/../", ""), anchor
    broken = sorted({(path, link) for path, text in pages.items()
                     for link in re.findall(r"\]\(([^)#]*#[^)]+)\)", text)
                     for resolved, anchor in (target(path, link),)
                     if anchor not in anchors.get(resolved, set())})
    assert broken == []
