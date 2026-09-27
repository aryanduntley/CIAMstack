#!/usr/bin/env python3
"""Generate the synthetic Example Aero estate as LDIF files in data/ (a showcase and test fixture).

The estate is built by fixtures/example_estate, one module per part of the stack; this script only writes
it. Everything is fictional. The estate is seeded with realistic problems for the tools to find:
  - ds-2 is missing the `mail` index (unrecorded change → incident INC-2231); ds-3 has an extra,
    unrecorded `description` substring index and a different lockout threshold
  - a legacy consumer binds with a person account, reads every attribute, has no owner
  - the target (Azure) environment is missing firewall rules and a backup target, and its
    LDAPS service name breaks the stable-name contract
  - partner and consumer allowlists pin our old IP addresses
  - certificates expire before the planned cutover; one work instruction is stale
The planted problems are listed in data/expected-findings.json.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from fixtures.example_estate.build import build  # noqa: E402

OUT = ROOT / "data"


def main():
    n, files = build()
    OUT.mkdir(exist_ok=True)
    for old in OUT.glob("*.ldif"):
        old.unlink()
    for rel, text in files.items():
        (OUT / rel).write_text(text)
    print(f"wrote {n} entries in {sum(1 for p in files if p.endswith('.ldif'))} files to {OUT}")


if __name__ == "__main__":
    main()
