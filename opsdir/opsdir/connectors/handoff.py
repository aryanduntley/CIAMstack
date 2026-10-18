"""Findings handed to their owning teams through ITSM (milestone 7.7, decision 3409): for each team a plan's blockers
and actions name as owner, a work-ticket draft in each installed ITSM add-on's own create-request form, as files the
team or an admin files (a person posts them with their own credentials). opsdir stays read-only towards ITSM and holds
no ITSM credential. A filed ticket is linked back on the change that does the work (ciamTicketRef <adapter>:<number>)
and read like any linked ticket (domains.governance.tickets: a work ticket, without an approval to compare).

What an add-on needs to draft for a team (its table or project, the team's queue) is its own estate settings; a team it
can't draft for is a problem the README says how to solve. Findings with no owner reach nobody's ticket: the README
lists them for the operator. Pure."""
from ..core.contract import TicketRequest
from ..core.directory import children, rdn_value
from ..domains.governance.naming import OWNERS
from ..domains.governance.people import team_dn

FOLDER = "tickets"
NO_OWNER = "**NO OWNER**"


def _owners(cell):
    return tuple(n.strip() for n in str(cell or "").split(",") if n.strip() and n.strip() != NO_OWNER)


def _items(p):
    """The plan's findings as (kind, area, text, owner, do_by)."""
    return (*(("blocker", b[0], b[1], b[2], None) for b in p.blockers),
            *(("action", a[0], a[1], a[2], a[3]) for a in p.actions))


def ticket_requests(d, p, teams=None):
    """(the TicketRequests of plan p, one per team its findings name as owner, by team name; the findings no team
    owns, (kind, area, text, do_by)); teams: only these teams' (names, any case). A finding several teams own is in
    each one's request. A team is its ciamParty under ou=owners (by name, any case: its own name and DN), else named
    as the first finding names it, where its entry would be."""
    items = _items(p)
    wanted = {t.lower() for t in teams} if teams is not None else None
    parties = {rdn_value(e).lower(): e for e in children(d, OWNERS, "ciamParty")}
    named = {}
    for o in (o for i in items for o in _owners(i[3]) if wanted is None or o.lower() in wanted):
        named.setdefault(o.lower(), rdn_value(parties[o.lower()]) if o.lower() in parties else o)

    def request(team):
        mine = tuple((k, a, t, by) for k, a, t, o, by in items if team.lower() in {x.lower() for x in _owners(o)})
        dates = [by for *_, by in mine if by is not None]
        party = parties.get(team.lower())
        return TicketRequest(team, party.dn if party is not None else team_dn(team),
                             f"CIAM: {len(mine)} finding{'s' if len(mine) != 1 else ''} for {team} "
                             f"({p.src.label} to {p.dst.label})",
                             mine, min(dates) if dates else None, p.src.label, p.dst.label, p.as_of)
    unowned = tuple((k, a, t, by) for k, a, t, o, by in items if not _owners(o)) if wanted is None else ()
    return tuple(request(t) for t in sorted(named.values(), key=str.lower)), unowned


def request_lines(r):
    """A TicketRequest as plain-text lines (what a draft's description may say): where it comes from, then each
    finding with its area and do-by date, the earliest first, those without one last."""
    ordered = sorted(r.items, key=lambda i: (i[3] is None, i[3] or r.as_of, i[0] != "blocker", i[1]))
    return (f"Findings of the CIAMstack plan from {r.source} to {r.target} (as of {r.as_of.isoformat()}) that "
            f"{r.team} owns.", "",
            *(f"- [{kind}] {area}: {text}" + (f" (do by {by.isoformat()})" if by else "")
              for kind, area, text, by in ordered),
            "", "Link this ticket on the opsdir change that does the work (ciamTicketRef), so its state is read back.")


def _file_name(team):
    return "".join(c if c.isalnum() or c in "-_." else "-" for c in team)


def handoff_files(d, p, installed, teams=None):
    """{path: text}: under tickets/, each installed ITSM add-on's draft for each team plan p's findings name
    (tickets/<adapter>/<team>.<extension>) and a README saying how to file each, what kept a draft from being written
    (with the setting to give) and the findings no team owns; teams: only these teams' drafts."""
    requests, unowned = ticket_requests(d, p, teams)
    adapters = tuple(a for a in installed if a.kind == "itsm" and a.ticket_draft is not None)
    drafts = tuple((a, r, a.ticket_draft(d, r)) for a in adapters for r in requests)
    files = {f"{FOLDER}/{a.name}/{_file_name(r.team)}.{t.extension}": t.body for a, r, t in drafts
             if t.body is not None}
    return {**files, f"{FOLDER}/README.md": _readme(p, adapters, requests, drafts, unowned)}


def _readme(p, adapters, requests, drafts, unowned):
    head = (f"# Work-ticket drafts: {p.src.label} to {p.dst.label}", "",
            f"One draft per owning team and ITSM add-on, of the plan's findings as of {p.as_of.isoformat()}. opsdir "
            "files nothing and holds no ITSM credential: the team (or an admin) posts each draft with their own "
            "credentials, then links the ticket on the opsdir change that does the work "
            "(`ciamTicketRef <adapter>:<number>`), so the next ITSM import reads its state back.", "")
    if not adapters:
        return "\n".join((*head, "No installed ITSM add-on drafts work tickets: nothing was drafted.",
                          *_unowned(unowned))) + "\n"
    if not requests:
        return "\n".join((*head, "No finding names an owning team: nothing was drafted.", *_unowned(unowned))) + "\n"
    sections = tuple(line for a in adapters for line in _adapter_lines(a, [x for x in drafts if x[0] is a]))
    return "\n".join((*head, *sections, *_unowned(unowned))) + "\n"


def _adapter_lines(adapter, drafts):
    """An add-on's README section: its drafts, what kept each from being complete (a problem every team's draft has,
    a setting the whole site lacks, said once), how to file one."""
    how = next((t.how for _, _, t in drafts if t.how), ())
    shared = tuple(p for p in drafts[0][2].problems if all(p in t.problems for _, _, t in drafts[1:])) \
        if len(drafts) > 1 else ()
    return (f"## {adapter.name}", "",
            *(f"- `{adapter.name}/{_file_name(r.team)}.{t.extension}`: {r.team}, {len(r.items)} finding"
              f"{'s' if len(r.items) != 1 else ''}" + (f", earliest do-by {r.do_by.isoformat()}" if r.do_by else "")
              for _, r, t in drafts if t.body is not None),
            *(f"- **not complete for any team**: {problem}" for problem in shared),
            *(f"- **not complete for {r.team}**: {problem}" for _, r, t in drafts for problem in t.problems
              if problem not in shared),
            *(("", "To file a draft:", "", *(f"    {line}" for line in how)) if how else ()), "")


def _unowned(unowned):
    if not unowned:
        return ()
    return ("## Findings no team owns", "",
            "These reach no ticket: give the entries they are about an owner (`ciamOwner`), or hand them over by "
            "hand.", "",
            *(f"- [{kind}] {area}: {text}" + (f" (do by {by.isoformat()})" if by else "")
              for kind, area, text, by in unowned), "")
