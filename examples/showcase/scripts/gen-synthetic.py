#!/usr/bin/env python3
"""Generate the synthetic Example Aero estate as LDIF files in data/, and the directory servers' configuration
exports in exports/ds-config/ and access logs in exports/ds-access-logs/ (a showcase and test fixture).

The estate is built by fixtures/example_estate, one module per part of the stack; this script only writes
it. Everything is fictional. The estate is seeded with realistic problems for the tools to find:
  - ds-2 is missing the `mail` index (unrecorded change → incident INC-2231; its archived configuration from
    before the change is in its export); ds-3 has an extra, unrecorded `description` substring index and a
    different lockout threshold (both in the servers' config.ldif, which the demo imports)
  - a legacy consumer binds with a person account, reads every attribute, has no owner
  - the target (Azure) environment is missing firewall rules and a backup target, and its
    LDAPS service name breaks the stable-name contract
  - partner and consumer allowlists pin our old IP addresses
  - certificates expire before the planned cutover; one work instruction is stale
The planted problems are listed in data/expected-findings.json.
"""
import gzip
import pathlib
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from example_estate.build import build, exports  # noqa: E402

OUT = ROOT / "data"
EXPORTS = ROOT / "exports"


def write_export(rel, text):
    """Effect: one export file; a .gz one compressed as the product keeps it (no timestamp: reproducible)."""
    path = EXPORTS / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if rel.endswith(".gz"):
        path.write_bytes(gzip.compress(text.encode(), mtime=0))
    else:
        path.write_text(text)


def main():
    n, files = build()
    OUT.mkdir(exist_ok=True)
    for old in OUT.glob("*.ldif"):
        old.unlink()
    for rel, text in files.items():
        (OUT / rel).write_text(text)
    for generated in ("ds-config", "ds-access-logs"):
        shutil.rmtree(EXPORTS / generated, ignore_errors=True)
    for rel, text in exports().items():
        write_export(rel, text)
    print(f"wrote {n} entries in {sum(1 for p in files if p.endswith('.ldif'))} files to {OUT.relative_to(ROOT)}/")


if __name__ == "__main__":
    main()
