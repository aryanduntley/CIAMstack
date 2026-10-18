#!/usr/bin/env python3
"""Generate the schema reference: documentation/SCHEMA.md and documentation/schema/<part>.md.

The pages are built from the schema fragments of the core, its domains and the installed adapter packages
(opsdir.connectors.schema_docs); this script only writes them, removing pages of parts no longer installed. Commit
the result: tests/unit/test_schema_docs.py fails when it differs from what the fragments generate. Run it after any
schema change (with every package installed: scripts/dev-install.sh).
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from opsdir.connectors.registry import vocabulary  # noqa: E402
from opsdir.connectors.schema_docs import PAGES, documented_parts, schema_pages  # noqa: E402

DOCUMENTATION = ROOT.parent / "documentation"


def main():
    pages = schema_pages(documented_parts(), vocabulary())
    stale = [p for p in (DOCUMENTATION / PAGES).glob("*.md") if f"{PAGES}/{p.name}" not in pages]
    for p in stale:
        p.unlink()
    for rel, text in pages.items():
        (DOCUMENTATION / rel).parent.mkdir(parents=True, exist_ok=True)
        (DOCUMENTATION / rel).write_text(text, encoding="utf-8", newline="\n")
    print(f"{len(pages)} page(s) written under {DOCUMENTATION}" + (f", {len(stale)} removed" if stale else ""))


if __name__ == "__main__":
    main()
