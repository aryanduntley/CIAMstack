"""Prometheus monitoring add-on: the record's alert rules as Prometheus alerting rules, evaluated on the signals the
environment's products expose as Prometheus metrics (design 2297). It renders when the environment's stack declares
it (stack role monitoring), on the environment's monitoring servers through opsdir-adapter-ansible's inventory, and
as a PrometheusRule where roles run on Kubernetes. It registers the server role monitoring (the servers Prometheus
runs on)."""
from opsdir.core.contract import Adapter
from .checks import check_placed
from .render import HOSTS, render
from .settings import SETTINGS

ADAPTER = Adapter(name="prometheus", kind="platform", applies=None, required_roles=(),
                  render_neutral=None, render_env=render, checks=(check_placed,), ref_schemes=(),
                  secret_schemes={},
                  renders="Prometheus alerting rules from the record's alert rules, and the play placing them",
                  neutral_label=None, vocabulary={"ciamServerRole": (HOSTS,), "ciamTargetRole": (HOSTS,)}, schema=None,
                  formats=(("prometheus/rules/*.yml", "yaml"), ("ansible/*.yml", "yaml"),
                           ("kubernetes/prometheus/*.yaml", "yaml")),
                  products=(), secret_patterns=(), importers=(), profile_terms=None, access=None,
                  settings=SETTINGS)
