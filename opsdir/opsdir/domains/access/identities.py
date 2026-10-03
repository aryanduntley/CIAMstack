"""What each environment gives the principals and the platform: the cloud identities principals act as (with the
grants the cloud gives them, in its own terms), the organization guardrails over it, and the paths operators come in
by. The reports and the planner's checks. Pure.

An identity the source runs that no principal names is access nobody described: after a move it is lost, or copied
without anyone knowing what it is for. A guardrail the source has whose prevention the target lacks, and a way in the
source has that the target doesn't, are actions for whoever keeps the target's landing zone.
"""
from ...core.directory import one, rdn_value, subtree, values
from ...core.environment import environment_of, of_class
from ...core.findings import findings, responsible
from ...core.naming import branch, env_label
from .principals import principals
from .workloads import landing_zone_owner, landing_zone_party

IDENTITY_HEADERS = ("environment", "identity", "role", "kind", "principals", "trusted by", "grants", "provider ref")
GUARDRAIL_HEADERS = ("environment", "guardrail", "kind", "denies", "provider ref")
ACCESS_PATH_HEADERS = ("environment", "path", "kind", "trusted by", "grants", "provider ref")


def _held(d, oc):
    """Every environment's bindings of a class, by environment then name."""
    return sorted(subtree(d, branch("environments"), oc), key=lambda e: (env_label(environment_of(e)), rdn_value(e)))


def _acting(d):
    """{identity binding role: names of the principals acting as it}."""
    named = {}
    for p in principals(d):
        named.setdefault(one(p, "ciamIdentityRole"), []).append(rdn_value(p))
    return named


def identity_rows(d, dn=None):
    """One row per cloud identity in every environment: the principals acting as it, who may, what it is granted."""
    acting = _acting(d)
    return [(env_label(environment_of(e)), rdn_value(e), one(e, "ciamBindingRole"), one(e, "ciamIdentityKind") or "",
             ", ".join(acting.get(one(e, "ciamBindingRole"), ())), ", ".join(values(e, "ciamTrustedBy")),
             "; ".join(values(e, "ciamGrant")), one(e, "ciamProviderRef"))
            for e in _held(d, "ciamIdentityBinding")]


def guardrail_rows(d, dn=None):
    """One row per organization guardrail over an environment and what it prevents."""
    return [(env_label(environment_of(e)), rdn_value(e), one(e, "ciamGuardrailKind"),
             ", ".join(values(e, "ciamDenies")), one(e, "ciamProviderRef") or "") for e in _held(d, "ciamGuardrail")]


def access_path_rows(d, dn=None):
    """One row per way operators come into an environment."""
    return [(env_label(environment_of(e)), rdn_value(e), one(e, "ciamAccessKind"),
             ", ".join(values(e, "ciamTrustedBy")), "; ".join(values(e, "ciamGrant")), one(e, "ciamProviderRef") or "")
            for e in _held(d, "ciamAccessPath")]


def _denials(m):
    """{what environment m's guardrails prevent: the guardrail preventing it}."""
    return {x: g for g in of_class(m, "ciamGuardrail") for x in values(g, "ciamDenies")}


def check_identities(ctx):
    """The source's identities no principal acts as, and the preventions and ways in the source has that the target
    lacks, are actions."""
    owner, acting = responsible(ctx.d, ctx.src.env), _acting(ctx.d)
    target_owner = landing_zone_owner(ctx.dst)
    kept, paths = _denials(ctx.dst), {one(a, "ciamAccessKind") for a in of_class(ctx.dst, "ciamAccessPath")}
    missing = [*((f"A guardrail preventing `{x}` (as {ctx.src.label}'s `{rdn_value(g)}` does).", x)
                 for x, g in sorted(_denials(ctx.src).items()) if x not in kept),
               *((f"A way for operators to come in by {kind} (as {ctx.src.label}'s `{rdn_value(a)}`).", kind)
                 for a in of_class(ctx.src, "ciamAccessPath") for kind in (one(a, "ciamAccessKind"),)
                 if kind not in paths)]
    party = landing_zone_party(ctx.dst)
    actions = [
        *(("Access", f"{ctx.src.label} runs identity `{rdn_value(b)}` ({one(b, 'ciamProviderRef')}), which no "
           f"principal acts as (role `{one(b, 'ciamBindingRole')}`): record who uses it and what it may do, or "
           "retire it.", owner, None)
          for b in of_class(ctx.src, "ciamIdentityBinding") if one(b, "ciamBindingRole") not in acting),
        *(("Guardrail", f"{ctx.src.label}'s guardrail `{rdn_value(g)}` prevents `{x}`; nothing in {ctx.dst.label} "
           "does: ask its landing zone's owners for the same guardrail.", target_owner, None)
          for x, g in sorted(_denials(ctx.src).items()) if x not in kept),
        *(("Access", f"Operators come into {ctx.src.label} by {kind} (`{rdn_value(a)}`); {ctx.dst.label} records no "
           "such way in: record it, or how operators reach it instead.", target_owner, None)
          for a in of_class(ctx.src, "ciamAccessPath") for kind in (one(a, "ciamAccessKind"),) if kind not in paths)]
    return findings(actions=actions,
                    requests=[(party, None, text, None, ctx.cutover) for text, _ in missing] if party else [])
