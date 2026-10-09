"""Whether a service name's load balancer is internal or internet-facing, the one answer every cloud renderer and the
planner read. Its recorded frontend address decides (private-use address space: internal); a name with no address
records its exposure (ciamExposure) and the provider assigns the address, as for an internet-facing AWS ALB, which has
no fixed one. Pure.

A name with neither can't be rendered: the cloud renderers write a comment in place of its load balancer and DNS record
(never a guess that could expose it). In the target that is a blocker, in the source an action. An address and an
exposure that disagree are an action: the address wins.
"""
from ...core.directory import one, rdn_value
from ...core.environment import UNBOUND, of_class
from ...core.findings import findings, responsible
from ...core.network import is_private
from ..infrastructure.naming import EXPOSURES

INTERNAL, INTERNET = EXPOSURES


def _by_address(svc):
    ip = one(svc, "ciamFrontendIp")
    return (INTERNAL if is_private(ip) else INTERNET) if ip else None


def service_exposure(svc):
    """'internal' or 'internet' for service name svc: from its frontend address, else its recorded exposure; None
    when it records neither."""
    return _by_address(svc) or one(svc, "ciamExposure")


def is_internal(svc):
    """Whether service name svc's load balancer is internal."""
    return service_exposure(svc) == INTERNAL


def exposure_unknown(svc):
    """The comment a cloud renderer writes in place of service name svc's load balancer and DNS record when its
    exposure is unknown."""
    return (f"# {UNBOUND}{one(svc, 'ciamBindingRole')}-exposure: service name `{rdn_value(svc)}` "
            f"({one(svc, 'ciamFqdn')}) records no frontend address (ciamFrontendIp) or exposure (ciamExposure), so "
            "whether its load balancer is internal or internet-facing is unknown: not rendered")


def _unknown(m):
    return tuple(svc for svc in of_class(m, "ciamServiceName") if service_exposure(svc) is None)


def _text(m, svc):
    return (f"`{one(svc, 'ciamFqdn')}` (`{one(svc, 'ciamBindingRole')}`) in {m.label} records no frontend address "
            "(ciamFrontendIp) or exposure (ciamExposure: internal or internet), so its load balancer and DNS record "
            "aren't rendered")


def _contradicted(m):
    return tuple(svc for svc in of_class(m, "ciamServiceName")
                 if _by_address(svc) and one(svc, "ciamExposure") and _by_address(svc) != one(svc, "ciamExposure"))


def check_exposure(ctx):
    """Blockers for the target's service names whose exposure is unknown (not rendered), actions for the source's;
    actions for an address that contradicts the recorded exposure (the address wins)."""
    blockers = [("Edge", f"{_text(ctx.dst, svc)}. Record one of them.", responsible(ctx.d, svc, ctx.dst.env))
                for svc in _unknown(ctx.dst)]
    actions = [("Edge", f"{_text(ctx.src, svc)}. Record one of them.", responsible(ctx.d, svc, ctx.src.env), None)
               for svc in _unknown(ctx.src)]
    actions += [("Edge", f"`{one(svc, 'ciamFqdn')}` in {m.label} records exposure `{one(svc, 'ciamExposure')}` but "
                 f"its frontend address {one(svc, 'ciamFrontendIp')} is {_by_address(svc)}: the address decides. "
                 "Correct or remove ciamExposure.", responsible(ctx.d, svc, m.env), None)
                for m in (ctx.src, ctx.dst) for svc in _contradicted(m)]
    return findings(blockers=blockers, actions=actions)
