"""HAProxy load-balancer add-on: an environment's service names fronted by HAProxy on its load-balancer servers,
configured by Ansible (the open-source option beside F5 BIG-IP; decision 2230). It renders when the environment's
stack declares it (stack role load-balancer), beside opsdir-adapter-ansible, whose inventory its play uses. It
applies only where a stack declares it (never inferred from data): applying is what lets the product adapters read
how its frontends forward a verified client certificate (cert_forwarding, through Services)."""
from functools import partial

from opsdir.core.contract import Adapter
from .checks import check_binds, check_hosts
from .client_certificates import cert_forwarding, client_certificate_notes
from .playbook import HOSTS
from .render import render

NAME = "haproxy"


def applies(m):
    """Whether environment m's stack declares HAProxy."""
    return any(c.adapter == NAME for c in m.stack)


ADAPTER = Adapter(name=NAME, kind="platform", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(check_hosts, check_binds), ref_schemes=(),
                  secret_schemes={},
                  renders="the HAProxy configuration of its load balancers, and the play applying it",
                  neutral_label=None, vocabulary={}, schema=None,
                  formats=(("ansible/files/haproxy.cfg", "haproxy-cfg"), ("ansible/files/trust/*.pem", "pem"),
                           ("ansible/*.yml", "yaml")), products=(),
                  secret_patterns=(), importers=(), profile_terms=None, access=None,
                  notes=client_certificate_notes, cert_forwarding=partial(cert_forwarding, hosts=HOSTS))
