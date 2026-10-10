"""The Prometheus add-on's planner check: a target declaring it whose rules would land nowhere (no server of role
monitoring, no role on Kubernetes) is an action: the rules are rendered, nothing evaluates them. Pure."""
from opsdir.core.environment import servers_with_role
from opsdir.core.findings import findings, responsible
from opsdir.domains.compute.workloads import kubernetes_roles
from .render import HOSTS


def declares(m):
    """Whether environment m's stack declares the Prometheus add-on."""
    return any(c.adapter == "prometheus" for c in m.stack)


def check_placed(ctx):
    """A target declaring Prometheus with neither monitoring servers nor roles on Kubernetes is an action."""
    m = ctx.dst
    if not declares(m) or servers_with_role(m, HOSTS) or kubernetes_roles(m):
        return findings()
    return findings(actions=[("Monitoring", f"{m.label} declares Prometheus but records no server of role `{HOSTS}` "
                              "and runs no role on Kubernetes: its alerting rules are rendered and nothing "
                              f"evaluates them. Record the servers Prometheus runs on (role `{HOSTS}`).",
                              responsible(ctx.d, m.env), None)])
