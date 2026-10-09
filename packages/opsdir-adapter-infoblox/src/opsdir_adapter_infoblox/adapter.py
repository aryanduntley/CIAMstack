"""Infoblox DNS add-on (the option beside Windows DNS; decision 2230): the records an environment publishes, written
by Ansible through the Infoblox grid masters it records (ciamAppliance, stack role dns). It renders when the
environment's stack declares it, beside opsdir-adapter-ansible."""
from opsdir.core.contract import Adapter
from opsdir.domains.infrastructure.appliances import appliances
from opsdir.core.findings import findings, responsible
from .render import STACK_ROLE, render


def check_appliances(ctx):
    """A blocker when the target declares Infoblox and records no dns appliance."""
    m = ctx.dst
    if not any(c.adapter == "infoblox" for c in m.stack) or appliances(m, STACK_ROLE):
        return findings()
    return findings(blockers=[("DNS", f"{m.label} declares Infoblox (stack role dns) but records no Infoblox grid "
                               "master for it (ciamAppliance, ciamStackRole dns): its records would be published "
                               "nowhere. "
                               "Record the grid master(s).", responsible(ctx.d, m.env))])


ADAPTER = Adapter(name="infoblox", kind="platform", applies=None, required_roles=(),
                  render_neutral=None, render_env=render, checks=(check_appliances,), ref_schemes=(),
                  secret_schemes={}, renders="the play writing its DNS records on Infoblox",
                  neutral_label=None, vocabulary={}, schema=None, formats=(("ansible/*", "yaml"),), products=(),
                  secret_patterns=(), importers=(), profile_terms=None, access=None)
