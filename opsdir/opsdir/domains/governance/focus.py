"""'My area': what a person's teams own or keep, for focus (reports, plans, open items). Never a security boundary:
reading stays open to every recorded person (permissions are governance.grants'). A report is narrowed by its owner,
owners or keeper column; one without such a column comes back whole, and says so. Fixes and the application view
are narrowed by the teams of the entries they touch, as the store reckons an area's teams for grants. Pure."""
import re

from ...core.directory import get, norm_dn, one, rdn_value, values
from .changes import APPLIED, PROPOSED, REJECTED
from .naming import CHANGES
from .people import team_dn
from .unknowns import answered, unknowns

OWNER_COLUMNS = ("owner", "owners", "keeper", "kept by")
NO_COLUMN = "this report has no owner or keeper column: every row is shown"
KEEPS = ("ciamOwner", "ciamManagedBy")
_ENVIRONMENT = re.compile(r"(?:^|,)(env=[^,]+,cloud=[^,]+,ou=environments,.*)$")


def _names(cell):
    return {n.strip().lower() for n in str(cell or "").split(",") if n.strip()}


def focus_rows(headers, rows, teams):
    """(the rows whose owner, owners or keeper column names one of the teams, a note or None): every row with a note
    when the report has no such column."""
    columns = [i for i, h in enumerate(headers) if str(h).lower() in OWNER_COLUMNS]
    if not columns:
        return tuple(rows), NO_COLUMN
    mine = {t.lower() for t in teams}
    return tuple(r for r in rows if any(_names(r[i]) & mine for i in columns)), None


def entry_teams(d, dn, attrs=None):
    """The teams (normalized DNs) an entry belongs to, as the store reckons them for grants (migration 0011): its own
    owners and keeper (attrs, an add record's, when given; else the record's entry), else its environment's."""
    e = get(d, dn)
    own = attrs if attrs is not None else (e.attrs if e is not None else {})
    kept = frozenset(norm_dn(v) for a in KEEPS for v in own.get(a, ()))
    env = _ENVIRONMENT.search(norm_dn(dn))
    held = get(d, env.group(1)) if env and not kept else None
    return kept or frozenset(norm_dn(v) for a in KEEPS for v in (values(held, a) if held is not None else ()))


def kept_by(d, dn, teams, attrs=None):
    """Whether the entry at dn belongs to one of the teams (names), by entry_teams."""
    return bool(entry_teams(d, dn, attrs) & {norm_dn(team_dn(t)) for t in teams})


def focus_fixes(d, fixes, teams):
    """The fixes (core.findings.Fix) any of whose records, or any of whose options' records, change an entry that
    belongs to one of the teams (an add record by the owners it gives, else where it goes)."""
    def touched(f):
        return (*f.records, *(r for o in f.options for r in o.records))
    return tuple(f for f in fixes
                 if any(kept_by(d, r.dn, teams, r.attrs if r.changetype == "add" else None) for r in touched(f)))


def focus_findings(items, teams):
    """The plan blockers or actions ((area, text, owner, ...), ...) whose owner names one of the teams."""
    mine = {t.lower() for t in teams}
    return tuple(i for i in items if _names(i[2]) & mine)


def open_items(d, login, teams):
    """A person's open items as (section, lines): changes waiting for someone else's approval (proposed, not
    theirs), their own changes not yet applied, and their teams' open unknowns."""
    changes = sorted((c for c in d.entries.values()
                      if "ciamChange" in c.classes and c.norm.endswith("," + CHANGES.lower())), key=rdn_value)
    def line(c):                                                                # noqa: E306
        return f"{rdn_value(c)}  {one(c, 'ciamChangeStatus')}  {one(c, 'ciamTitle')}"
    to_review = [line(c) for c in changes if one(c, "ciamChangeStatus") == PROPOSED
                 and (one(c, "ciamAuthor") or "").lower() != login.lower()]
    mine = [line(c) for c in changes if (one(c, "ciamAuthor") or "").lower() == login.lower()
            and one(c, "ciamChangeStatus") not in (APPLIED, REJECTED)]
    team_dns = {team_dn(t).lower() for t in teams}
    questions = [f"{rdn_value(u)}  {one(u, 'ciamQuestion')}" for u in unknowns(d)
                 if not answered(u) and {o.lower() for o in values(u, "ciamOwner")} & team_dns]
    return (("changes waiting for someone else's approval", tuple(to_review)),
            ("your changes not yet applied", tuple(mine)),
            (f"open unknowns of {', '.join(teams) or 'your teams'}", tuple(questions)))
