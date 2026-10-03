"""Least privilege and permissions kept across a move: each environment's identities' grants read through its cloud's
permission table (the provider adapter's AccessModel), against what the principals acting as them may do. A connector:
it needs the installed adapters of both environments, which the planner gives it. Pure.

For each identity that records its grants: a grant matching the cloud's escalation patterns that no permission
explains, or a wildcard grant, is an action; so is a grant no permission of its principals explains. Each permission
is judged allowed, denied or unknown (opsdir.domains.access.grants.effective): one the identity isn't granted, or is
denied (with what denies it), is a blocker in the target (after the move the workload can't do what it does today)
and an action in the source; one that can't be told (a condition, an eligible role, a conditional deny) is an action
to verify. An environment whose identities record no grants (rendered from the record, not yet read back) has nothing
to compare.
"""
from ..core.directory import one, rdn_value, values
from ..core.environment import of_class
from ..core.findings import findings, merge_findings, responsible
from ..domains.access.grants import DENIED, NOT_GRANTED, UNKNOWN, effective, escalating, grant_of, wildcard
from ..domains.access.principals import permits, principals


def access_model(adapters):
    """The AccessModel of an environment's provider adapter, or None."""
    return next((a.access for a in adapters if a.kind == "provider" and a.access is not None), None)


def _verdicts(ctx, m, name, x, verdict, who, target):
    """(blockers, actions) for one permit's verdict: in the target what it would lose blocks the move and what can't
    be told is to verify; in the source each is an action."""
    if verdict.state == NOT_GRANTED:
        text = (f"{m.label}: identity `{name}` isn't granted `{x}`, which {who} may do"
                + (f" in {ctx.src.label}: grant it before the move." if target
                   else ": grant it, or drop the permission."))
    elif verdict.state == DENIED:
        text = (f"{m.label}: identity `{name}` may not `{x}`, which {who} may do"
                + (f" in {ctx.src.label}" if target else "") + f": {verdict.why}."
                + (" Lift the deny before the move." if target else ""))
    elif verdict.state == UNKNOWN:
        return (), (f"{m.label}: whether identity `{name}` may `{x}` can't be told: {verdict.why}. Verify it"
                    + (" before the move" if target else "") + " (or record a cloud evaluator's verdict).",)
    else:
        return (), ()
    return ((text,), ()) if target else ((), (text,))


def _identity(ctx, m, model, b, acting, target):
    gs = tuple(grant_of(t) for t in values(b, "ciamGrant"))
    name, owner = rdn_value(b), responsible(ctx.d, *acting, m.env)
    allowed = sorted({x for p in acting for x in permits(ctx.d, p)})
    results = {x: effective(model, m, x, b, of_class(m, "ciamGuardrail")) for x in allowed}
    used = {g for v in results.values() for g in v.serving}
    raising = [g for g in escalating(model, gs) if g not in used]
    flagged = {*raising, *wildcard(gs)}
    who = ", ".join(f"`{rdn_value(p)}`" for p in acting)
    actions = [
        *(("Access", f"{m.label}: identity `{name}` is granted `{g.text}`, which lets it raise its own access: grant "
           "only what its permissions need.", owner, None) for g in raising),
        *(("Access", f"{m.label}: identity `{name}` is granted `{g.text}`, wider than any permission: scope it to the "
           "resources its permissions name.", owner, None) for g in wildcard(gs) if g not in raising),
        *(("Access", f"{m.label}: identity `{name}` is granted `{g.text}`, which no permission of {who} explains: "
           "record the permission, or remove the grant.", owner, None)
          for g in gs if acting and g not in used and g not in flagged)]
    said = [_verdicts(ctx, m, name, x, v, who, target) for x, v in results.items()]
    return findings(blockers=[("Access", t, owner) for blockers, _ in said for t in blockers],
                    actions=[*actions, *(("Access", t, owner, None) for _, notes in said for t in notes)])


def access_check(src_adapters, dst_adapters):
    """The planner check for least privilege in both environments and the permissions the target's identities would
    lose, given each environment's installed adapters."""
    def check_access(ctx):
        everyone, parts = principals(ctx.d), []
        for m, adapters, target in ((ctx.src, src_adapters, False), (ctx.dst, dst_adapters, True)):
            model = access_model(adapters)
            for b in of_class(m, "ciamIdentityBinding") if model is not None else ():
                if values(b, "ciamGrant") or values(b, "ciamEvaluated"):
                    acting = [p for p in everyone if one(p, "ciamIdentityRole") == one(b, "ciamBindingRole")]
                    parts.append(_identity(ctx, m, model, b, acting, target))
        return merge_findings(parts)
    return check_access
