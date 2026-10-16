"""Source objects: what a product a migration retires holds that the standard model has no equivalent for
(ciamSourceObject under ou=source-objects, one branch per importer that records them), and the planner's view of them.
Pure.

A source object is data, not a comment: what it is (the product's own type and its facts), where (the server role
that holds it, the entries it concerns), who (its owners) and how it is handled (rebuilt, its secrets re-provisioned,
its hosts re-registered, replaced, retired or reviewed, with the steps in words). A plan whose source runs the role
and whose target doesn't makes each an action for its owner by the planned cutover, or a blocker when a move waits for
its handling (ciamBlocking); a target that still runs the role keeps it as it is (in place). An importer records them;
its owners and handling are the record's to change like any other entry.
"""
from ...core.directory import one, rdn_value, subtree, values
from ...core.findings import findings, merge_findings, responsible
from ..compute.workloads import runs_here
from .naming import SOURCE_OBJECTS

AREA = "Source objects"
SOURCE_OBJECT_HEADERS = ("object", "class", "held by", "handling", "blocking", "owner", "how", "facts")


def source_objects(d):
    """Every source object, in DN order (the importers' branches, then names)."""
    return tuple(subtree(d, SOURCE_OBJECTS, "ciamSourceObject"))


def _what(o):
    facts = values(o, "ciamSourceFact")
    return f"`{rdn_value(o)}` ({one(o, 'ciamSourceClass')}{': ' + '; '.join(facts) if facts else ''})"


def _how(o):
    how = one(o, "ciamHow")
    return f"{one(o, 'ciamHandling')}{': ' + how if how else ''}"


def _object(ctx, o):
    role = one(o, "ciamTargetRole")
    if not runs_here(ctx.src, role):
        return findings()
    if runs_here(ctx.dst, role):
        return findings(ok=[f"Source object {_what(o)} stays with `{role}`, which {ctx.dst.label} still runs."])
    text = f"Source object {_what(o)} is held by `{role}`, which {ctx.dst.label} doesn't run: {_how(o)}."
    owner = responsible(ctx.d, o)
    if one(o, "ciamBlocking") == "TRUE":
        return findings(blockers=[(AREA, text + " The move waits for it (ciamBlocking).", owner)])
    return findings(actions=[(AREA, text, owner, ctx.cutover)])


def check_source_objects(ctx):
    """For every source object a role of the source holds: in place when the target still runs the role; otherwise an
    action for its owner by the cutover, or a blocker when the move waits for its handling."""
    return merge_findings([_object(ctx, o) for o in source_objects(ctx.d)])


def source_object_rows(d, dn=None):
    """One row per source object: its name, the product's type, the role holding it, its handling, whether a move
    waits for it, its owner, the steps and its facts."""
    return [(rdn_value(o), one(o, "ciamSourceClass"), one(o, "ciamTargetRole"), one(o, "ciamHandling"),
             "yes" if one(o, "ciamBlocking") == "TRUE" else "no", responsible(d, o), one(o, "ciamHow", ""),
             "; ".join(values(o, "ciamSourceFact"))) for o in source_objects(d)]
