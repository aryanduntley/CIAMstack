"""The migration runner: move an environment's platform by rendering the target from the same intent.

A run checks both environments' declared stacks against the installed adapters (and stops there on any problem,
since a missing adapter can't render), plans the move (every cross-domain, adapter and domain check) and keeps what
the target renders to. It is ready only when neither the stacks nor the plan have problems or blockers. Directions
are symmetric: any installed provider can be the source or the target. A connector; pure.
"""
from typing import NamedTuple, Optional

from ..core.environment import env_model
from .plan import Plan, plan, request_drafts, to_markdown
from .stack import stack_rows

MigrationRun = NamedTuple("MigrationRun", [("src", str), ("dst", str),
                                           ("stack_rows", tuple), ("stack_problems", int),
                                           ("plan", Optional[Plan]),     # None when the stacks stopped the run
                                           ("ready", bool)])


def run(d, src, dst, as_of, adapters, versions):
    """Check both stacks, then plan the move and render the target."""
    checked = [stack_rows(env_model(d, spec), adapters, versions) for spec in (src, dst)]
    rows, problems = tuple(r for rs, _ in checked for r in rs), sum(n for _, n in checked)
    if problems:
        return MigrationRun(src, dst, rows, problems, None, False)
    p = plan(d, src, dst, as_of, adapters)
    return MigrationRun(src, dst, rows, 0, p, not p.blockers)


def output_files(r):
    """{relative path: text}: the rendered target under target/, PLAN.md and the request drafts."""
    if r.plan is None:
        return {}
    return {**{f"target/{path}": text for path, text in r.plan.target_files.items()},
            "PLAN.md": to_markdown(r.plan), **request_drafts(r.plan)}


def summary(r, out):
    """What the run found and where its outputs are."""
    if r.plan is None:
        return f"stopped: {r.stack_problems} stack problem(s); nothing rendered"
    verdict = "READY" if r.ready else "NOT READY"
    return (f"{r.src} → {r.dst}: {verdict} ({len(r.plan.blockers)} blockers, {len(r.plan.actions)} actions); "
            f"{len(r.plan.target_files)} target files, PLAN.md and {len(r.plan.requests)} request draft(s) in {out}")
