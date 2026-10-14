"""Regulated data: what an environment's data is by regime (ciamRegulatedData: ITAR and EAR export-controlled technical
data, criminal justice information, protected health information, federal tax information), recorded on the
environment and on the reporting obligations it is held to (an obligation may bring it, as it brings a required
authorization level). It is neither an authorization level, a framework nor a classification: each provider says where
its data of a regime may be held, so the cloud adapters' checks give their verdicts (placement_findings); the planner's
own check (authorizations.check_regulated_data) carries it from source to target. Pure."""
from ...core.directory import one, rdn_value, subtree, values
from ...core.environment import env_model
from ...core.findings import findings, responsible
from ...core.naming import branch
from .incidents import obligations_of
from .naming import REGULATED_DATA

AREA = "Regulated data"
REGULATED_HEADERS = ("environment", "regulated data", "from", "cloud environment", "region")


def regulated_data(m):
    """The regulated data environment m holds: its own and its reporting obligations', each once."""
    held = {*values(m.env, "ciamRegulatedData"),
            *(v for o in obligations_of(m) for v in values(o, "ciamRegulatedData"))}
    return tuple(r for r in REGULATED_DATA if r in held)


def regulated_sources(m, regime):
    """What says environment m holds a regime's data: the environment, and each obligation bringing it."""
    return (*(("environment",) if regime in values(m.env, "ciamRegulatedData") else ()),
            *(rdn_value(o) for o in obligations_of(m) if regime in values(o, "ciamRegulatedData")))


def placement_findings(ctx, verdicts):
    """Findings of a cloud adapter's verdicts on where the target may hold its regulated data: ((regime, 'blocker' or
    'action', text), ...)."""
    owner = responsible(ctx.d, ctx.dst.env)
    said = [(f"{ctx.dst.label} holds {regime} data: {text}", kind) for regime, kind, text in verdicts]
    return findings(blockers=[(AREA, t, owner) for t, kind in said if kind == "blocker"],
                    actions=[(AREA, t, owner, ctx.cutover) for t, kind in said if kind == "action"])


def regulated_rows(d, dn=None):
    """One row per environment and the regulated data it holds: where that is said, and where the environment runs."""
    models = [env_model(d, e.dn) for e in subtree(d, branch("environments"), "ciamEnvironment")]
    return [(m.label, r, ", ".join(regulated_sources(m, r)), one(m.cloud, "ciamCloudEnvironment", ""),
             one(m.cloud, "ciamRegion", "")) for m in models for r in regulated_data(m)]
