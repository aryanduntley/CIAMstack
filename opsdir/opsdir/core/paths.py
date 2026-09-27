"""Where the working tree keeps its inputs and outputs (schema, sql, data, changes, out)."""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_FILE = ROOT / "schema" / "ciam-ops.schema.ldif"     # the published LDAP schema (scripts/gen-schema.py)
