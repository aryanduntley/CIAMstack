#!/usr/bin/env python3
"""Check the migration planner against the problems planted in the synthetic data.

  check-findings.py before   every planted blocker and action must be reported, and nothing else
  check-findings.py after    same, except findings cleared by an applied change must be gone

Exit status 0 = the planner found exactly what was planted.
"""
import datetime as dt
import json
import pathlib
import sys
from typing import NamedTuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from opsdir.connectors import plan  # noqa: E402
from opsdir.store import postgres as db  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
AS_OF = dt.date(2026, 9, 23)

Result = NamedTuple("Result", [("kind", str), ("rows", list), ("should", list), ("missed", list),
                               ("unexpected", list), ("cleared", list), ("still", list)])


def applied_changes(conn):
    return {r[0] for r in conn.execute("select distinct change_id from entry_history where change_id <> 'BOOTSTRAP'")}


def _matches(row, finding):
    area, text = finding
    return area == row["area"] and row["match"] in text


def compare(kind, rows, found, applied):
    """How the planner's findings of one kind compare with the planted ones."""
    should = [r for r in rows if not (r["cleared_by"] and r["cleared_by"] in applied)]
    cleared = [r for r in rows if r not in should]
    missed = [r for r in should if not any(_matches(r, f) for f in found)]
    unexpected = [f for f in found if not any(_matches(r, f) for r in should)]
    still = [r for r in cleared if any(_matches(r, f) for f in found)]
    return Result(kind, rows, should, missed, unexpected, cleared, still)


def check(expected, p, applied):
    """Blocker and action Results of a plan against the expected-findings document, given the applied changes."""
    found = {"blockers": [(a, t) for a, t, _ in p.blockers], "actions": [(a, t) for a, t, _, _ in p.actions]}
    return [compare(kind, expected[kind], found[kind], applied) for kind in ("blockers", "actions")]


def result_lines(r):
    return (f"  {r.kind:8} planted {len(r.rows):2}   expected now {len(r.should):2}   "
            f"detected {len(r.should) - len(r.missed):2}   missed {len(r.missed)}   unexpected {len(r.unexpected)}",
            *(f"           {c['id']:4} cleared by {c['cleared_by']}: {c['planted']} → "
              f"{'STILL REPORTED' if c in r.still else 'gone'}" for c in r.cleared),
            *(f"           MISSED {m['id']}: {m['planted']}" for m in r.missed),
            *(f"           UNEXPECTED [{a}] {t[:100]}" for a, t in r.unexpected))


def passed(r):
    return not r.missed and not r.unexpected and not r.still


def main(phase):
    exp = json.loads((ROOT / "data" / "expected-findings.json").read_text())
    conn = db.connect()
    p = plan.plan(db.load_directory(conn), "aws-current/prod", "rtx-next/prod", AS_OF)
    results = check(exp, p, applied_changes(conn) if phase == "after" else set())
    ok = all(passed(r) for r in results)
    print("\n".join((f"Expected findings check ({phase} changes)", *(line for r in results for line in result_lines(r)),
                     "  RESULT: PASS. The planner found every planted problem and nothing else. 'NOT READY' is the "
                     "correct verdict\n          for this deliberately broken environment." if ok else "  RESULT: FAIL")))
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("before", "after"):
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
