"""F5 BIG-IP load-balancer add-on (the default on-prem load balancer; decision 2230): an environment's service names
as an AS3 declaration deployed by Ansible to the BIG-IPs it records (ciamAppliance, stack role load-balancer). It
renders when the environment's stack declares it, beside opsdir-adapter-ansible. It applies only where a stack
declares it (never inferred from data): applying is what lets the product adapters read how its virtual servers
forward a verified client certificate (cert_forwarding, through Services)."""
from functools import partial

from opsdir.core.contract import Adapter
from .checks import check_appliances
from .client_certificates import cert_forwarding, client_certificate_notes
from .play import STACK_ROLE
from .render import render

NAME = "f5-bigip"


def applies(m):
    """Whether environment m's stack declares F5 BIG-IP."""
    return any(c.adapter == NAME for c in m.stack)


ADAPTER = Adapter(name=NAME, kind="platform", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(check_appliances,), ref_schemes=(),
                  secret_schemes={}, renders="the AS3 declaration of its BIG-IPs, and the play deploying it",
                  neutral_label=None, vocabulary={}, schema=None,
                  formats=(("ansible/f5/*", "json"), ("ansible/*.yml", "yaml")), products=(), secret_patterns=(),
                  importers=(), profile_terms=None, access=None, notes=client_certificate_notes,
                  cert_forwarding=partial(cert_forwarding, stack_role=STACK_ROLE))
