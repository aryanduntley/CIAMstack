"""Palo Alto Networks network-firewall add-on (decision 2230): the firewall rules an environment records, pushed by
Ansible as PAN-OS objects and security rules to the Panorama or firewalls it records (ciamAppliance, stack role
network-firewall). It renders when the environment's stack declares it, beside opsdir-adapter-ansible."""
from opsdir.core.contract import Adapter
from opsdir.core.findings import findings, responsible
from opsdir.domains.infrastructure.appliances import appliances
from .render import STACK_ROLE, render


def check_appliances(ctx):
    """A blocker when the target declares Palo Alto and records no network-firewall appliance."""
    m = ctx.dst
    if not any(c.adapter == "panos" for c in m.stack) or appliances(m, STACK_ROLE):
        return findings()
    return findings(blockers=[("Firewall", f"{m.label} declares Palo Alto Networks (stack role network-firewall) but "
                               "records no Panorama or firewall for it (ciamAppliance, ciamStackRole "
                               "network-firewall): its firewall rules would be pushed nowhere. Record them.",
                               responsible(ctx.d, m.env))])


ADAPTER = Adapter(name="panos", kind="platform", applies=None, required_roles=(),
                  render_neutral=None, render_env=render, checks=(check_appliances,), ref_schemes=(),
                  secret_schemes={}, renders="the play pushing its firewall rules to Palo Alto Networks",
                  neutral_label=None, vocabulary={}, schema=None, formats=(("ansible/*", "yaml"),), products=(),
                  secret_patterns=(), importers=(), profile_terms=None, access=None)
