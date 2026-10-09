"""Kubernetes adapter: what every workload an environment runs on Kubernetes needs around it (namespaces, service
accounts with their cloud identities, network policies, secret delivery), Kubernetes secrets as a secret store any
environment can reference, and the workloads clusters run, read from their manifests (kubernetes/workloads)."""
from opsdir.core.contract import Adapter
from .render import TARGETS, applies, render
from .secrets import secret_command
from .workloads import WORKLOADS_IMPORTER

ADAPTER = Adapter(name="kubernetes", kind="platform", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(), ref_schemes=("k8s-secret",),
                  secret_schemes={"k8s-secret": secret_command},
                  renders="Kubernetes namespaces, service accounts, network policies and secret delivery",
                  neutral_label=None, vocabulary={}, schema=None, formats=(("kubernetes/*", "yaml"),),
                  products=(),
                  secret_patterns=(), importers=(WORKLOADS_IMPORTER,), profile_terms=None, access=None,
                  render_targets=TARGETS)
