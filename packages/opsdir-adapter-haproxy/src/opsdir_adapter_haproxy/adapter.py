"""HAProxy load-balancer add-on: an environment's service names fronted by HAProxy on its load-balancer servers,
configured by Ansible (the open-source option beside F5 BIG-IP; decision 2230). It renders when the environment's
stack declares it (stack role load-balancer), beside opsdir-adapter-ansible, whose inventory its play uses."""
from opsdir.core.contract import Adapter
from .checks import check_hosts
from .render import render

ADAPTER = Adapter(name="haproxy", kind="platform", applies=None, required_roles=(),
                  render_neutral=None, render_env=render, checks=(check_hosts,), ref_schemes=(), secret_schemes={},
                  renders="the HAProxy configuration of its load balancers, and the play applying it",
                  neutral_label=None, vocabulary={}, schema=None,
                  formats=(("ansible/files/haproxy.cfg", "haproxy-cfg"), ("ansible/haproxy.yml", "yaml")), products=(),
                  secret_patterns=(), importers=(), profile_terms=None, access=None)
