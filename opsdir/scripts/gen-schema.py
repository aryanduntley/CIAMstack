#!/usr/bin/env python3
"""Generate schema/ciam-ops.schema.ldif — the opsdir standard as RFC 4512 LDAP schema.

The definitions live with the part of the stack that owns them (core/standard.py and each domain's
schema.py); this script only composes and writes them. Commit the LDIF: it is the published artifact
(loaded by opsdir, and by an LDAP server that ignores the X- extensions).
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from opsdir.connectors.registry import core_fragments  # noqa: E402
from opsdir.core.paths import SCHEMA_FILE  # noqa: E402
from opsdir.core.standard import fragment_counts, schema_ldif  # noqa: E402


def main():
    fragments = core_fragments()
    SCHEMA_FILE.write_text(schema_ldif(fragments))
    print(*fragment_counts(fragments)[:1], "attrs", fragment_counts(fragments)[1], "classes")


if __name__ == "__main__":
    main()
