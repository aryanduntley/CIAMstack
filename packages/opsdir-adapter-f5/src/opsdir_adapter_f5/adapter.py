"""F5 BIG-IP load-balancer add-on (the default on-prem load balancer; decision 2230): an environment's service names
as an AS3 declaration deployed by Ansible to the BIG-IPs it records (ciamAppliance, stack role load-balancer). It
renders when the environment's stack declares it, beside opsdir-adapter-ansible."""
from opsdir.core.contract import Adapter
from .checks import check_appliances
from .render import render

ADAPTER = Adapter(name="f5-bigip", kind="platform", applies=None, required_roles=(),
                  render_neutral=None, render_env=render, checks=(check_appliances,), ref_schemes=(),
                  secret_schemes={}, renders="the AS3 declaration of its BIG-IPs, and the play deploying it",
                  neutral_label=None, vocabulary={}, schema=None,
                  formats=(("ansible/f5/*", "json"), ("ansible/*", "yaml")), products=(), secret_patterns=(),
                  importers=(), profile_terms=None, access=None)
