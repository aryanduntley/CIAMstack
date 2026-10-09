"""Service names whose role an environment runs only on Kubernetes: the cloud renderers write a note in place of their
edge (the load balancer or application gateway, the policies' traffic handling and firewall, the TLS certificate it
presents, the DNS record), since the cluster's ingress serves the role there. What fronts that ingress isn't recorded
yet, so none of it is deployed for them. The planner's check. Pure.

In the target that is a blocker: the name would neither resolve nor be protected as the record states. In the source
it is an action: what fronts the cluster's ingress runs, unrecorded.
"""
from ...core.directory import one, rdn_of, rdn_value
from ...core.environment import of_class
from ...core.findings import findings, responsible
from ..compute.workloads import only_on_kubernetes
from .policies import policy_for


def unrendered_edges(m):
    """((service name, traffic policy or None, protection policy or None), ...): environment m's service names whose
    role it runs only on Kubernetes, with the policies that apply to them, in the record's order."""
    return tuple((svc, policy_for(m.d, "ciamTrafficPolicy", one(svc, "ciamBindingRole")),
                  policy_for(m.d, "ciamProtectionPolicy", one(svc, "ciamBindingRole")))
                 for svc in of_class(m, "ciamServiceName") if only_on_kubernetes(m, one(svc, "ciamTargetRole")))


def _lost(svc, t, p):
    cert = one(svc, "ciamTlsCertificate")
    return ", ".join(("load balancer", *((f"traffic policy `{rdn_value(t)}`",) if t is not None else ()),
                      *((f"protection policy `{rdn_value(p)}`",) if p is not None else ()),
                      *((f"TLS certificate `{rdn_of(cert)}`",) if cert else ()), "DNS record"))


def _text(m, svc, t, p):
    return (f"`{one(svc, 'ciamFqdn')}` (`{one(svc, 'ciamBindingRole')}`) reaches `{one(svc, 'ciamTargetRole')}`, "
            f"which {m.label} runs only on Kubernetes: its cloud render writes no edge for it ({_lost(svc, t, p)}), "
            "and the record doesn't say what fronts the cluster's ingress")


def check_unrendered(ctx):
    """Blockers for the target's service names whose edge isn't rendered (their role only on Kubernetes); actions for
    the source's, whose edge in front of the cluster isn't recorded."""
    blockers = [("Edge", f"{_text(ctx.dst, *e)}. Record what fronts it, or run the role on servers there.",
                 responsible(ctx.d, ctx.dst.env)) for e in unrendered_edges(ctx.dst)]
    actions = [("Edge", f"{_text(ctx.src, *e)}. Record what fronts it.", responsible(ctx.d, ctx.src.env), None)
               for e in unrendered_edges(ctx.src)]
    return findings(blockers=blockers, actions=actions)
