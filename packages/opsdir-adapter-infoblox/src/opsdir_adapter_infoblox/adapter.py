"""Infoblox DNS add-on (the option beside Windows DNS; decision 2230): the records an environment publishes, written
by Ansible through the Infoblox grid masters it records (ciamAppliance, stack role dns). It renders when the
environment's stack declares it, beside opsdir-adapter-ansible."""
from functools import partial

from opsdir.core.contract import Adapter
from opsdir.domains.infrastructure.appliances import check_appliance
from .render import STACK_ROLE, render

check_appliances = partial(check_appliance, adapter="infoblox", product="Infoblox", stack_role=STACK_ROLE, area="DNS",
                           consequence="its records would be published nowhere", record="the grid master(s)")


ADAPTER = Adapter(name="infoblox", kind="platform", applies=None, required_roles=(),
                  render_neutral=None, render_env=render, checks=(check_appliances,), ref_schemes=(),
                  secret_schemes={}, renders="the play writing its DNS records on Infoblox",
                  neutral_label=None, vocabulary={}, schema=None, formats=(("ansible/*.yml", "yaml"),), products=(),
                  secret_patterns=(), importers=(), profile_terms=None, access=None)
