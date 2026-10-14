"""Render notes: what a render could not do, or leaves to a person, as data for the team that owns it (flow 43).
Pure.

A renderer that leaves something out or to someone says so in the files it writes (a `# NOTE: ...` comment beside
what it concerns) and, once converted, as a RenderNote its adapter returns (Adapter.notes): the comment is written
from the note (note_comment), so the two never disagree. The render collects every note (collected): where its
comment is in the rendered files (path and line), whose it is (the owners of the entry it is about, else the
environment's), plus every other NOTE comment of the rendered files, not yet a note, as one to review; and writes them
beside the MANIFEST as NOTES.md (people) and NOTES.json (filtering by owner). A note says what (its subject and text),
where (the files and lines, and the scope it concerns outside them), who (its owners) and how to handle it (its
steps), at a severity: blocker (something the environment relies on won't exist or work), action (someone must do
something by hand), note (worth knowing); None for a NOTE comment no renderer has classified yet.
"""
import json
import re
from typing import NamedTuple, Optional

from .directory import get, rdn_value, values
from .findings import findings
from .formats import MARKDOWN
from .manifest import header

SEVERITIES = ("blocker", "action", "note")
# how a note's record-change step ends, in every area: the change is governed, and the render picks it up
RECORD = "under an approved change, and re-render"
_TITLES = {"blocker": "Blockers", "action": "Actions", "note": "Notes", None: "To review"}
_COMMENT = re.compile(r"^\s*(?:#|//)\s*NOTE:\s?(.*?)\s*$")


# One note of a render. area: what it is about, in a word (Monitoring, Network, ...), or None (unclassified); severity:
# one of SEVERITIES, or None (unclassified); subject: the thing it concerns (`canary portal-sso`); text: what is the
# matter with it; how: the steps that handle it (by hand, or the record change that makes it renderable); entry: the
# DN of the record entry it is about, or None; scope: where it applies outside the files (a project, a subscription, a
# network), or None; owners: the names of whoever owns it (filled by collected); places: ((path, line), ...) of its
# comment in the rendered files (filled by collected).
RenderNote = NamedTuple("RenderNote", [("area", Optional[str]), ("severity", Optional[str]), ("subject", str),
                                       ("text", str), ("how", tuple), ("entry", Optional[str]),
                                       ("scope", Optional[str]), ("owners", tuple), ("places", tuple)])


def note(area, severity, subject, text, how=(), entry=None, scope=None):
    """A RenderNote a renderer returns (owners and places are the render's to fill); ValueError for a severity not
    in SEVERITIES."""
    if severity not in SEVERITIES:
        raise ValueError(f"a render note's severity is one of {', '.join(SEVERITIES)}, not {severity!r}")
    return RenderNote(area, severity, subject, text, tuple(how), entry, scope, (), ())


def note_comment(n):
    """The comment text a renderer writes for a note (`NOTE: <subject>: <text>`), in the file's comment syntax."""
    return f"NOTE: {n.subject}: {n.text}"


def _comments(files):
    """((path, line number, comment text after `NOTE:`), ...) of every NOTE comment line (# or //) in the files, in
    path then line order."""
    return tuple((path, i, match.group(1)) for path in sorted(files) for i, line in
                 enumerate(files[path].splitlines(), 1) for match in (_COMMENT.match(line),) if match)


def located(notes, files):
    """The notes with places: every rendered file and line holding a note's comment (a note none holds keeps none:
    its renderer wrote it nowhere)."""
    found = _comments(files)
    return tuple(n._replace(places=tuple((p, i) for p, i, text in found if f"NOTE: {text}" == note_comment(n)))
                 for n in notes)


def scanned(files, notes):
    """The NOTE comments in the files that no note's comment is, each as an unclassified note (severity None) at its
    place, to review: what a renderer not yet converted to notes wrote."""
    known = {note_comment(n) for n in notes}
    return tuple(RenderNote(None, None, "", text, (), None, None, (), ((p, i),))
                 for p, i, text in _comments(files) if f"NOTE: {text}" not in known)


def _owners(d, e):
    return tuple(rdn_value(get(d, o)) for o in values(e, "ciamOwner")) if e is not None else ()


def with_owners(d, env, notes):
    """The notes with owners: their entry's owners (ciamOwner), else the environment's (env); none when neither has
    any."""
    return tuple(n._replace(owners=_owners(d, get(d, n.entry) if n.entry else None) or _owners(d, env))
                 for n in notes)


def _order(n):
    rank = SEVERITIES.index(n.severity) if n.severity in SEVERITIES else len(SEVERITIES)
    return rank, n.owners, n.area or "", n.subject, n.places, n.text


def collected(m, notes, files):
    """Every note of environment m's render: the adapters' notes located in the files, then the files' other NOTE
    comments to review, each with its owners, in severity, owner, area, subject order. A render of one slice (m.scope a
    keeper, class or bindings) keeps the adapters' notes it wrote: the others are other slices'."""
    sliced = m.scope is not None and m.scope.kind != "environment"
    found = tuple(n for n in located(notes, files) if n.places or not sliced)
    return ordered(with_owners(m.d, m.env, (*found, *scanned(files, found))))


def ordered(notes):
    """The notes in severity (blockers first, to review last), owner, area, subject order."""
    return tuple(sorted(notes, key=_order))


def counts(notes):
    """{severity: how many notes} for every severity, None (to review) included."""
    return {s: sum(n.severity == s for n in notes) for s in (*SEVERITIES, None)}


def summary(notes):
    """The counts in words (`2 blockers, 1 action, 0 notes, 14 to review`), or that nothing needs handling."""
    c = counts(notes)
    if not notes:
        return "nothing to handle"
    words = (f"{c['blocker']} blocker{'s' * (c['blocker'] != 1)}", f"{c['action']} action{'s' * (c['action'] != 1)}",
             f"{c['note']} note{'s' * (c['note'] != 1)}", f"{c[None]} to review")
    return ", ".join(words)


def _where(n):
    return ", ".join(f"{p}:{i}" for p, i in n.places) or "not written in any file"


def _who(n):
    return ", ".join(n.owners) or "**NO OWNER**"


def _section(severity, notes):
    if severity is None:
        return ("| Where | Note | Owner |", "|---|---|---|",
                *(f"| {_where(n)} | {n.text.replace('|', '/')} | {_who(n)} |" for n in notes))
    return tuple(line for n in notes for line in (
        f"### {n.subject}" + (f" ({n.area})" if n.area else ""), "",
        f"- **What:** {n.text}",
        f"- **Where:** {_where(n)}" + (f"; {n.scope}" if n.scope else ""),
        f"- **Who:** {_who(n)}",
        *_how(n.how), ""))


def _how(steps):
    if len(steps) < 2:
        return tuple(f"- **How:** {s}" for s in steps)
    return ("- **How:**", *(f"  {i}. {s}" for i, s in enumerate(steps, 1)))


def notes_markdown(m, notes):
    """NOTES.md: the do-not-edit header, the counts, then a section per severity (blockers, actions, notes: what,
    where, who, how each; to review: the unclassified NOTE comments as a table of where, note and owner)."""
    sections = tuple(line for s in (*SEVERITIES, None) for group in ([n for n in notes if n.severity == s],)
                     if group for line in (f"## {_TITLES[s]}", "", *_section(s, group),
                                           *(("",) if s is None else ())))
    return (header(m, f"What the render of {m.label} could not do, or leaves to a person", MARKDOWN)
            + "\n".join((f"# Render notes: {m.label}", "", f"**{summary(notes)}**", "", *sections)).rstrip() + "\n")


def _finding(n, label):
    where = ", ".join(f"{p}:{i}" for p, i in n.places) or f"in no file of {label}'s render"
    how = " ".join(f"{i}) {s}" for i, s in enumerate(n.how, 1)) if len(n.how) > 1 else "".join(n.how)
    return (f"{label}: {n.subject}: {n.text} (render: {where}" + (f"; {n.scope}" if n.scope else "") + ")."
            + (f" How: {how}" if how else ""))


def notes_findings(m, notes, env_owner):
    """Findings of environment m's render notes, for a plan: each blocker a blocker and each action an action (area,
    what, where, how, its owners, else **NO OWNER**), and one action for the NOTE comments still to review; plain notes
    stay in NOTES.md. env_owner: who answers for the environment (the to-review action's owner)."""
    owner = lambda n: ", ".join(n.owners) or "**NO OWNER**"        # noqa: E731
    review = sum(n.severity is None for n in notes)
    return findings(
        blockers=[(n.area or "Render", _finding(n, m.label), owner(n)) for n in notes if n.severity == "blocker"],
        actions=[*((n.area or "Render", _finding(n, m.label), owner(n), None) for n in notes
                   if n.severity == "action"),
                 *((("Render", f"{m.label}'s render holds {review} NOTE comment{'s' * (review != 1)} not yet "
                    "classified: review them (its NOTES.md, To review).", env_owner, None),) if review else ())])


def parsed(text):
    """The RenderNotes of a NOTES.json text (what notes_json wrote), for a reader of a render's files (the CLI, a
    planner check on the target's render)."""
    return tuple(RenderNote(n["area"], n["severity"], n["subject"], n["text"], tuple(n["how"]), n["entry"],
                            n["scope"], tuple(n["owners"]), tuple((p["path"], p["line"]) for p in n["places"]))
                 for n in json.loads(text)["notes"])


def notes_json(m, notes):
    """NOTES.json: the environment, the counts and every note (area, severity, subject, text, how, entry, scope,
    owners, places as {path, line}), for filtering by owner or severity."""
    c = counts(notes)
    return json.dumps({
        "environment": m.dn, "counts": {**{s: c[s] for s in SEVERITIES}, "to_review": c[None]},
        "notes": [{"area": n.area, "severity": n.severity, "subject": n.subject, "text": n.text, "how": list(n.how),
                   "entry": n.entry, "scope": n.scope, "owners": list(n.owners),
                   "places": [{"path": p, "line": i} for p, i in n.places]} for n in notes]}, indent=2) + "\n"
