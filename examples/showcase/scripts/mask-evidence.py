#!/usr/bin/env python3
"""Mask what an evidence package holds of the wall clock, so snapshots taken anywhere compare equal:

  mask-evidence.py PACKAGE EXPORT

The change history's times (when each change was applied, the store's clock) in the outputs of the package's history
queries become <TIMESTAMP>, and their SHA-256 <SHA256> in the manifest. In the recorded run (ciamEvidenceOutput in
EXPORT, an `opsdir export` LDIF) every hash becomes <SHA256>, refolded as opsdir folds it: the package's files are in
the snapshot themselves, and the in-memory estate the tests build records the run with the same files but not the
store's history (tests/showcase_support.py).
"""
import json
import pathlib
import re
import sys

from opsdir.core.interchange.ldif import fold

TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
OUTPUT = "ciamEvidenceOutput: "
WIDTH = 78                                       # opsdir export's folding width


def history_files(doc):
    """The package paths of its history queries' outputs."""
    return {p for c in doc["controls"] for q in c["queries"] if q["source"] == "history" for p in q["files"]}


def masked_manifest(doc, paths):
    return {**doc, "controls": [{**c, "queries": [{**q, "files": {p: "<SHA256>" if p in paths else h
                                                                  for p, h in q["files"].items()}}
                                                  for q in c["queries"]]} for c in doc["controls"]]}


def logical_lines(text):
    """LDIF's logical lines, each as its physical lines (a line, then its continuations)."""
    return re.split(r"\n(?! )", text)


def masked_export(text):
    """The export with every ciamEvidenceOutput's hash masked; every other line as it is."""
    def line(physical):
        logical = re.sub(r"\n ", "", physical)
        if not logical.startswith(OUTPUT):
            return physical
        path, _ = logical[len(OUTPUT):].rsplit(" ", 1)
        return "\n".join(fold(f"{OUTPUT}{path} <SHA256>", WIDTH))
    return "\n".join(line(physical) for physical in logical_lines(text))


def main(package, export):
    root, ldif = pathlib.Path(package), pathlib.Path(export)
    doc = json.loads((root / "MANIFEST.json").read_text())
    paths = history_files(doc)
    for p in sorted(paths):
        (root / p).write_text(TIMESTAMP.sub("<TIMESTAMP>", (root / p).read_text()))
    (root / "MANIFEST.json").write_text(json.dumps(masked_manifest(doc, paths), indent=2, ensure_ascii=False) + "\n")
    ldif.write_text(masked_export(ldif.read_text()))
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
