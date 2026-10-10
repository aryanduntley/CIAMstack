"""A load balancer's own traffic (ciamApplianceSource: its source NAT pool and self addresses) must be admitted by the
servers' firewall rules on every service name's ports: the planner names each port no rule admits it on."""
from types import SimpleNamespace

from opsdir.domains.infrastructure.appliances import check_appliance_sources, unadmitted
from network_fixtures import ALPHA, entry, model, rule

LB = entry(ALPHA, "lb-1", "ciamAppliance", ciamBindingRole="lb-1", ciamStackRole="load-balancer",
           ciamManagementAddress="lb-1.mgmt.example.test", ciamApplianceSource=("10.1.5.0/28", "fd00:5::/64"))


def _alpha(*extra):
    _, alpha, _ = model(alpha=(LB, *extra))
    return alpha


def test_each_unadmitted_source_and_port_is_named():
    alpha = _alpha(rule(ALPHA, "fw-lb-v4", ("10.1.5.0/24",), "443", "web"))      # the IPv6 range isn't admitted
    assert [(src, role, port) for _, src, _, role, port in unadmitted(alpha)] == [("fd00:5::/64", "web", "443")]
    (action,) = check_appliance_sources(SimpleNamespace(d=alpha.d, dst=alpha)).actions
    assert action[1].startswith("alpha/prod: no firewall rule admits load balancer `lb-1`'s traffic from fd00:5::/64 "
                                "to role `web` on port 443")


def test_a_rule_covering_every_source_raises_nothing():
    alpha = _alpha(rule(ALPHA, "fw-lb", ("10.1.5.0/24", "fd00:5::/48"), "443", "web"))
    assert unadmitted(alpha) == () and not check_appliance_sources(SimpleNamespace(d=alpha.d, dst=alpha)).actions
    assert unadmitted(_alpha(rule(ALPHA, "fw-other", ("10.1.5.0/24",), "443", "ds")))       # another role: no
