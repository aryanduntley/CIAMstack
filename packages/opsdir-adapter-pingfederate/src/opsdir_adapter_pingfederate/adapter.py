"""PingFederate adapter: applies to environments whose servers run PingFederate."""
from opsdir.core.contract import Adapter
from opsdir.core.directory import one
from .render import render_neutral

PRODUCT = "PingFederate"
SERVER_ROLES = ("pf-engine", "pf-admin")      # ciamServerRole / ciamTargetRole values this adapter defines
REQUIRED_ROLES = ("subnet-pf", "pf-sso-service", "pf-egress", "sso-tls-keystore", "pf-signing-key", "pf-admin-password")


def applies(m):
    return any(one(s, "ciamProductVersion", "").startswith(PRODUCT) for s in m.servers)


ADAPTER = Adapter(name="pingfederate", kind="product", applies=applies, required_roles=REQUIRED_ROLES,
                  render_neutral=render_neutral, render_env=None, checks=(), ref_schemes=(), secret_schemes={},
                  renders=None, neutral_label="PingFederate",
                  vocabulary={"ciamServerRole": SERVER_ROLES, "ciamTargetRole": SERVER_ROLES})
