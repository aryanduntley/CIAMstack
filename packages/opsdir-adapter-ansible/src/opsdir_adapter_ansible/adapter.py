"""Ansible adapter: configuration management for an environment's servers, on any cloud or on-prem. It renders when
the environment's stack declares it (stack role configuration-management): the servers as an Ansible inventory with
their variables, and the host configuration the record holds for them; secrets are read at run time through the
lookups the secret stores' adapters own."""
from opsdir.core.contract import Adapter
from .baseline import HARDENING_PROFILES
from .render import render

ADAPTER = Adapter(name="ansible", kind="platform", applies=None, required_roles=(),
                  render_neutral=None, render_env=render, checks=(), ref_schemes=(), secret_schemes={},
                  renders="the Ansible inventory and host configuration of its servers", neutral_label=None,
                  vocabulary={"ciamHardeningProfile": HARDENING_PROFILES}, schema=None,
                  formats=(("ansible/templates/*", "text"), ("ansible/*.yml", "yaml")), products=(), secret_patterns=(),
                  importers=(), profile_terms=None, access=None)
