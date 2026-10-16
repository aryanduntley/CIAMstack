"""Federation planner check: the integrations an identity service serves keep being served when a move leaves that
service behind (its servers' role isn't run by the target: a product the move retires). Pure."""
from ...core.directory import one, rdn_value
from ...core.findings import findings, merge_findings, responsible
from ..compute.workloads import runs_here
from .services import identity_services, integrations, serves


def _listed(services):
    return ", ".join(f"`{rdn_value(s)}`" for s in services) or "none"


def _left_behind(ctx, service, running):
    role = one(service, "ciamTargetRole")
    served = tuple(i for i in integrations(ctx.d) if one(i, "ciamServedBy") is not None and serves(service, i))
    return findings(blockers=[(
        "Federation",
        f"Integration `{rdn_value(i)}` ({one(i, 'ciamProtocolType')}) is served by identity service "
        f"`{rdn_value(service)}`, whose `{role}` servers {ctx.dst.label} doesn't run: its users and partners lose "
        "sign-on. Re-home it to an identity service the target runs (ciamServedBy; there: "
        f"{_listed(running)}): it keeps its entity ID or client ID, and the partner takes the new service's metadata "
        "or issuer.", responsible(ctx.d, i, service)) for i in served])


def check_served_integrations(ctx):
    """A blocker for every integration registered with an identity service whose server role the source runs and the
    target doesn't; nothing when every service it relies on still runs (the identity-service check covers their
    addresses)."""
    services = tuple(s for s in identity_services(ctx.d) if one(s, "ciamTargetRole") is not None)
    running = tuple(s for s in services if runs_here(ctx.dst, one(s, "ciamTargetRole")))
    return merge_findings([_left_behind(ctx, s, running) for s in services
                           if runs_here(ctx.src, one(s, "ciamTargetRole"))
                           and not runs_here(ctx.dst, one(s, "ciamTargetRole"))])
