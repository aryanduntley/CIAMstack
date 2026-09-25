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

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from opsdir import db, plan  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
AS_OF = dt.date(2026, 9, 23)


def applied_changes(conn):
    return {r[0] for r in conn.execute("select distinct change_id from entry_history where change_id <> 'BOOTSTRAP'")}


def main(phase):
    exp = json.loads((ROOT / "data" / "expected-findings.json").read_text())
    conn = db.connect()
    p = plan.plan(db.Directory(conn), "aws-current/prod", "rtx-next/prod", AS_OF)
    applied = applied_changes(conn) if phase == "after" else set()
    found = {"blockers": [(a, t) for a, t, _ in p["blockers"]], "actions": [(a, t) for a, t, _, _ in p["actions"]]}
    ok = True
    print(f"Expected findings check ({phase} changes)")
    for kind in ("blockers", "actions"):
        rows = exp[kind]
        should = [r for r in rows if not (r["cleared_by"] and r["cleared_by"] in applied)]
        cleared = [r for r in rows if r not in should]
        matched = set()
        missed = []
        for r in should:
            hit = [i for i, (a, t) in enumerate(found[kind]) if a == r["area"] and r["match"] in t]
            if hit:
                matched.update(hit)
            else:
                missed.append(r)
        still = [r for r in cleared if any(a == r["area"] and r["match"] in t for a, t in found[kind])]
        unexpected = [found[kind][i] for i in range(len(found[kind])) if i not in matched]
        print(f"  {kind:8} planted {len(rows):2}   expected now {len(should):2}   detected {len(should) - len(missed):2}"
              f"   missed {len(missed)}   unexpected {len(unexpected)}")
        for r in cleared:
            state = "STILL REPORTED" if r in still else "gone"
            print(f"           {r['id']:4} cleared by {r['cleared_by']}: {r['planted']} → {state}")
        for r in missed:
            print(f"           MISSED {r['id']}: {r['planted']}")
        for a, t in unexpected:
            print(f"           UNEXPECTED [{a}] {t[:100]}")
        ok &= not missed and not unexpected and not still
    print("  RESULT: PASS. The planner found every planted problem and nothing else. 'NOT READY' is the correct"
          " verdict\n          for this deliberately broken environment." if ok else "  RESULT: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("before", "after"):
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
