"""The unknowns register: questions the record can't answer yet (ciamUnknown under ou=unknowns), each owned by the
party who must answer it, and the planner's view of them. Pure.

A question concerns the environments (or entries inside them) its ciamConcerns names; one naming none, or naming an
entry outside every environment (intent the environments share), concerns the whole estate. A plan counts the
questions that concern its source or its target, each once: an open blocking question is a blocker (the plan can't be
READY until it is answered), an open one that doesn't block is an action for its owner, dated by when the answer is
needed (else the planned cutover), and an answered one is listed as in place. An answer is a person's: no fix is
offered. An approved risk exception accepts these findings like any other (estate.poam).
"""
import datetime as dt

from ...core.directory import children, date_of, one, rdn_value, values, within
from ...core.findings import findings, responsible
from ...core.naming import branch, env_label
from .naming import UNKNOWNS

AREA = "Unknowns"
UNKNOWN_HEADERS = ("unknown", "question", "owner", "blocking", "concerns", "raised", "needed by", "status", "answer",
                   "answered")
_ENVIRONMENTS = branch("environments")
_ESTATE = "the estate"


def unknowns(d):
    """Every question in the register, by name."""
    return sorted(children(d, UNKNOWNS, "ciamUnknown"), key=rdn_value)


def answered(u):
    """Whether a question has its answer."""
    return bool(one(u, "ciamAnswer"))


def blocking(u):
    """Whether a move waits for a question's answer."""
    return one(u, "ciamBlocking") == "TRUE"


def concerns(u, env_dn):
    """Whether a question concerns an environment: it names none (the estate), the environment or an entry inside it,
    or an entry outside every environment (intent the environments share)."""
    named = values(u, "ciamConcerns")
    return not named or any(within(c, env_dn) or not within(c, _ENVIRONMENTS) for c in named)


def _rdn(dn):
    return dn.split(",", 1)[0].split("=", 1)[1]


def _where(c):
    """How a concerned entry is named: an environment by its label, an entry inside one by its name there, any other
    (a cloud, an entry the environments share) by its name."""
    at = c.find("env=") if within(c, _ENVIRONMENTS) else -1
    if at < 0:
        return _rdn(c)
    return f"`{_rdn(c)}` in {env_label(c[at:])}" if at else env_label(c)


def concerned(u):
    """What a question concerns, in words: its entries, else the estate."""
    return ", ".join(_where(c) for c in values(u, "ciamConcerns")) or _ESTATE


def _open_text(d, u, ask):
    return (f"Open question `{rdn_value(u)}` ({concerned(u)}): {one(u, 'ciamQuestion')} {responsible(d, u)} "
            f"{ask}")


def _on(u):
    day = date_of(u, "ciamAnsweredAt")
    return f" answered {day}" if day else " answered"


def _action(ctx, u):
    """An open question that doesn't block: an action for its owner, dated by when the answer is needed (else the
    planned cutover), already late when that day is past."""
    by = date_of(u, "ciamNeededBy") or ctx.cutover
    late = " (**already late**)" if by is not None and by < ctx.as_of else ""
    when = f" by **{by}**{late}" if by is not None else ""
    return (AREA, _open_text(ctx.d, u, f"to answer it (ciamAnswer, ciamAnsweredAt){when}."), responsible(ctx.d, u),
            by)


def check_unknowns(ctx):
    """Blockers for the open blocking questions that concern the source or the target, actions (dated) for the other
    open ones, and the answered ones as in place."""
    found = tuple(u for u in unknowns(ctx.d) if concerns(u, ctx.src.dn) or concerns(u, ctx.dst.dn))
    is_open = tuple(u for u in found if not answered(u))
    blockers = [(AREA, _open_text(ctx.d, u, "must answer it (ciamAnswer, ciamAnsweredAt) before the move: the plan "
                                            "can't be READY until then."), responsible(ctx.d, u))
                for u in is_open if blocking(u)]
    ok = [f"Question `{rdn_value(u)}`{_on(u)} by {responsible(ctx.d, u)}: {one(u, 'ciamAnswer')}"
          for u in found if answered(u)]
    return findings(blockers=blockers, actions=[_action(ctx, u) for u in is_open if not blocking(u)], ok=ok)


def _date(u, attr):
    day = date_of(u, attr)
    return str(day) if day else ""


def _status(u, day):
    if answered(u):
        return "answered"
    needed = date_of(u, "ciamNeededBy")
    return "overdue" if needed is not None and needed < day else "open"


def unknown_rows(d, dn=None, as_of=None):
    """One row per question: the question, its owner, whether it blocks, what it concerns, when raised and needed,
    its status as of the day (open, overdue past its needed-by date, answered), the answer and when it was given."""
    day = as_of or dt.date.today()
    return [(rdn_value(u), one(u, "ciamQuestion"), responsible(d, u), "yes" if blocking(u) else "no", concerned(u),
             _date(u, "ciamRaisedAt"), _date(u, "ciamNeededBy"), _status(u, day), one(u, "ciamAnswer", ""),
             _date(u, "ciamAnsweredAt")) for u in unknowns(d)]
