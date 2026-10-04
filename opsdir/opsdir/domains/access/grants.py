"""What a cloud's grants mean as the record's permissions: an identity's grants, denials and boundaries (ciamGrant,
ciamDenial, ciamBoundary, in the cloud's own terms) and those of the guardrails over it, read through the cloud's
permission table (an AccessModel from its adapter). Pure.

A permit (`read-secret pf-admin-password`) needs, for the role's binding in the environment, every requirement of a
table row for the verb and the binding's class: an action or role among the requirement's alternatives (a pattern
such as `secretsmanager:*` counts) on a resource that covers the binding's (the cloud decides: equal, a parent scope,
a pattern), and the row's related requirements on a linked binding (the key that encrypts a secret).

Whether it is effective follows the clouds' documented evaluation order, three ways:
  denied     an unconditional explicit deny matches (the identity's own, a resource's, a deny assignment or policy, a
             guardrail's), or a boundary source (a permissions boundary, a control policy's allows) doesn't allow it;
  allowed    an unconditional allow matches and nothing denies it;
  unknown    the allow is conditional (' (if ...)') or only eligible (' (eligible)': not active), or a conditional
             deny matches: what decides it wasn't imported.
A cloud evaluator's recorded verdict (ciamEvaluated) is preferred. Without any allow the permit isn't granted. A grant
no permit's requirement uses is unexplained; one matching the cloud's escalation patterns lets an identity raise its
own access (a finding unless a permit explains it, as manage-key explains a key policy change); a whole service's
actions, or anything on every resource, is wider than any permit.
"""
import re
from fnmatch import fnmatchcase
from typing import NamedTuple

from ...core.directory import is_kind, one, rdn_value, values
from ...core.environment import one_role

ALLOWED, DENIED, UNKNOWN, NOT_GRANTED = "allowed", "denied", "unknown", "not granted"
RESOURCE_POLICY = " (resource policy)"
_SUFFIX = re.compile(r" \((resource policy|eligible|if [^()]+)\)$")

Grant = NamedTuple("Grant", [("text", str), ("action", str), ("resource", str), ("resource_policy", bool),
                             ("condition", object), ("eligible", bool)])
# A permit's effective state in an environment: one of ALLOWED, DENIED, UNKNOWN, NOT_GRANTED, or None when it can't be
# told (the role unbound there, no table row); why, in words; the grants that serve it.
Verdict = NamedTuple("Verdict", [("state", object), ("why", str), ("serving", tuple)])


def grant_of(text):
    """A ciamGrant, ciamDenial or ciamBoundary value read: '<action or role> on <resource>', then any of
    ' (resource policy)', ' (if <condition>)', ' (eligible)'."""
    body, tags = text, []
    while (m := _SUFFIX.search(body)) is not None:
        tags.append(m.group(1))
        body = body[:m.start()]
    action, _, resource = body.partition(" on ")
    condition = next((t[3:] for t in tags if t.startswith("if ")), None)
    return Grant(text, action.strip(), resource.strip(), "resource policy" in tags, condition, "eligible" in tags)


def _action(alternative, granted):
    """Whether a granted action or role (or pattern: iam:*; 'p!a|b': what p matches but those, '!a|b': every action
    but those) gives the alternative; actions ignore case."""
    included, _, excluded = granted.lower().partition("!")
    alt = alternative.lower()
    return fnmatchcase(alt, included or "*") and not any(fnmatchcase(alt, p) for p in excluded.split("|") if p)


def condition_text(text):
    """A condition as a grant's ' (if ...)' suffix holds it: on one line, without parentheses (they end the suffix)."""
    return " ".join(str(text).replace("(", "[").replace(")", "]").split()) or None


def grant_text(action, resource, condition=None, resource_policy=False, eligible=False):
    """A ciamGrant, ciamDenial or ciamBoundary value: '<action> on <resource>', then ' (resource policy)',
    ' (if <condition>)' and ' (eligible)' as they apply (grant_of reads it back)."""
    cond = condition_text(condition) if condition else None
    return (f"{action} on {resource}" + (RESOURCE_POLICY if resource_policy else "") +
            (f" (if {cond})" if cond else "") + (" (eligible)" if eligible else ""))


def excluding(action, excluded):
    """An action pattern with exclusions ('p!a|b'), or the action itself when nothing is excluded."""
    return f"{action}!{'|'.join(excluded)}" if excluded else action


def rows_for(d, model, binding, verb):
    """The table rows for a verb on a binding of its class or a superclass (and its stream kind)."""
    kind = one(binding, "ciamStreamKind")
    return tuple(r for r in model.permissions
                 if r.verb == verb and is_kind(d, binding, r.binding_class) and r.kind in (None, kind))


def _matching(model, binding, alts, grants):
    return [g for g in grants if any(_action(alt, g.action) for alt in alts) and model.covers(g.resource, binding)]


def _serving(model, binding, row, grants):
    """(whether every requirement of a row is met, the grants meeting them)."""
    met = [_matching(model, binding, alts, grants) for alts in row.needs]
    return all(met), tuple(g for found in met for g in found)


def granted(model, m, permit, grants):
    """(True, grants serving it) when a permit's requirements are met by allows in environment m, (False, ()) when
    they aren't, (None, ()) when it can't be told: the role isn't bound there, or the cloud's table has no row for
    it."""
    verb, _, role = permit.partition(" ")
    binding = one_role(m, role)
    rows = rows_for(m.d, model, binding, verb) if binding is not None else ()
    if not rows:
        return None, ()
    served = [_serving(model, binding, r, grants) for r in rows]
    return (True, next(gs for ok, gs in served if ok)) if any(ok for ok, _ in served) else (False, ())


# ------------------------------------------------------------------ effective access
Limits = NamedTuple("Limits", [("allows", tuple), ("denials", tuple), ("boundaries", tuple)])
# allows: Grants; denials: ((Grant, where), ...); boundaries: ((where, (Grant, ...)), ...) one per source that limits


def limits_of(identity, guardrails):
    """What decides an identity's access: its grants, the explicit denies over it (its own, then each guardrail's),
    and each boundary source (its permissions boundary, each guardrail's allows)."""
    def read(e, attr):
        return tuple(grant_of(v) for v in values(e, attr))
    sources = (("its own policies", identity), *((f"guardrail `{rdn_value(g)}`", g) for g in guardrails))
    return Limits(read(identity, "ciamGrant"),
                  tuple((d, where) for where, e in sources for d in read(e, "ciamDenial")),
                  tuple((where if e is not identity else "its permissions boundary", read(e, "ciamBoundary"))
                        for where, e in sources if values(e, "ciamBoundary")))


_ORDER = (DENIED, NOT_GRANTED, UNKNOWN, ALLOWED)          # the worst requirement decides a row


def _requirement(model, binding, alts, limits):
    """(state, why, serving) of one requirement on one binding."""
    allows = _matching(model, binding, alts, limits.allows)
    hard = [(g, w) for g, w in limits.denials
            if g.condition is None and _matching(model, binding, alts, (g,))]
    soft = [(g, w) for g, w in limits.denials if g.condition is not None and _matching(model, binding, alts, (g,))]
    outside = [where for where, ceiling in limits.boundaries if not _matching(model, binding, alts, ceiling)]
    if hard:
        g, where = hard[0]
        return DENIED, f"explicitly denied by `{g.text}` ({where})", ()
    if outside:
        return DENIED, f"not allowed by {outside[0]}", ()
    plain = [g for g in allows if g.condition is None and not g.eligible]
    if not allows:
        return NOT_GRANTED, "no applicable allow in the imported data", ()
    if not plain:
        g = allows[0]
        why = "eligible, not active" if g.eligible else f"allowed only if {g.condition}"
        return UNKNOWN, f"{why} (`{g.text}`): what decides it wasn't imported", tuple(allows)
    if soft:
        g, where = soft[0]
        return UNKNOWN, f"a conditional deny may apply: `{g.text}` ({where})", tuple(plain)
    return ALLOWED, "", tuple(plain)


def _row(model, m, binding, row, limits):
    """(state, why, serving) of a table row: its requirements, then its related ones on the linked binding."""
    parts = [_requirement(model, binding, alts, limits) for alts in row.needs]
    for attr, needs in row.related:
        linked_role = one(binding, attr)
        linked = one_role(m, linked_role) if linked_role else None
        if linked_role and linked is None:
            parts.append((UNKNOWN, f"the key `{linked_role}` that encrypts it isn't bound in this environment", ()))
        elif linked is not None:
            parts.extend((s, f"{why} on `{linked_role}`" if why else "", serving)
                         for s, why, serving in (_requirement(model, linked, alts, limits) for alts in needs))
    worst = min(parts, key=lambda p: _ORDER.index(p[0]))
    return worst[0], worst[1], tuple(g for _, _, serving in parts for g in serving)


def effective(model, m, permit, identity, guardrails=()):
    """A permit's Verdict for an identity in environment m: a cloud evaluator's recorded verdict when there is one,
    else its grants, denials and boundaries (and the guardrails') through the table's best row."""
    evidence = next((v for v in values(identity, "ciamEvaluated") if v.startswith(f"{permit}: ")), None)
    if evidence:
        state, _, source = evidence[len(permit) + 2:].partition(" ")
        return Verdict(state, f"by {source.strip('()')}", ())
    verb, _, role = permit.partition(" ")
    binding = one_role(m, role)
    rows = rows_for(m.d, model, binding, verb) if binding is not None else ()
    if not rows:
        return Verdict(None, "", ())
    limits = limits_of(identity, guardrails)
    return Verdict(*max((_row(model, m, binding, r, limits) for r in rows), key=lambda p: _ORDER.index(p[0])))


def escalating(model, grants):
    """Grants matching the cloud's escalation patterns (an action or role that lets an identity raise its access)."""
    return tuple(g for g in grants if any(_action(e, g.action) or _action(g.action, e) for e in model.escalations))


def wildcard(grants):
    """Grants of every action (*) or a whole service's (s3:*), or of anything on every resource (*). An action family
    (kms:GenerateDataKey*) is not one."""
    return tuple(g for g in grants if g.action == "*" or g.action.endswith(":*") or g.resource == "*")


def covered(granted_resource, resources):
    """Whether a granted resource covers any of a binding's resources as a cloud names them: equal, a pattern either
    way (arn:...:secret:ciam/* covers a secret; a secret's arn-* pattern matches its suffixed ARN), or a parent scope
    (projects/p, a vault, a resource group)."""
    granted_resource = granted_resource.lower()
    return any(fnmatchcase(r.lower(), granted_resource) or fnmatchcase(granted_resource, r.lower())
               or r.lower().startswith(granted_resource.rstrip("/") + "/") for r in resources if r)
