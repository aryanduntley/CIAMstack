"""Palo Alto Networks network-firewall add-on (decision 2230): the firewall rules an environment records, pushed by
Ansible as PAN-OS objects and security rules to the Panorama or firewalls it records (ciamAppliance, stack role
network-firewall). It renders when the environment's stack declares it, beside opsdir-adapter-ansible."""
from functools import partial

from opsdir.core.contract import Adapter
from opsdir.domains.infrastructure.appliances import check_appliance
from .render import STACK_ROLE, render

check_appliances = partial(check_appliance, adapter="panos", product="Palo Alto Networks", stack_role=STACK_ROLE,
                           area="Firewall", consequence="its firewall rules would be pushed nowhere",
                           record="the Panorama or firewalls")


ADAPTER = Adapter(name="panos", kind="platform", applies=None, required_roles=(),
                  render_neutral=None, render_env=render, checks=(check_appliances,), ref_schemes=(),
                  secret_schemes={}, renders="the play pushing its firewall rules to Palo Alto Networks",
                  neutral_label=None, vocabulary={}, schema=None, formats=(("ansible/*.yml", "yaml"),), products=(),
                  secret_patterns=(), importers=(), profile_terms=None, access=None)
