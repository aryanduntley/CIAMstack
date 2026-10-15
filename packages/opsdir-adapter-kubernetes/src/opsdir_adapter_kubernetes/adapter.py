"""Kubernetes adapter: what every workload an environment runs on Kubernetes needs around it (namespaces, service
accounts with their cloud identities, network policies, secret delivery), Kubernetes secrets as a secret store any
environment can reference, and the workloads clusters run, read from their manifests (kubernetes/workloads)."""
from opsdir.core.contract import Adapter, ReadBack
from .gateway import SETTING, VOCABULARY
from .names import NAME
from .render import TARGETS, applies, notes, render
from .secrets import secret_command, secret_lookup
from .workloads import WORKLOADS_IMPORTER

ADAPTER = Adapter(name=NAME, kind="platform", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(), ref_schemes=("k8s-secret",),
                  secret_schemes={"k8s-secret": secret_command},
                  renders="Kubernetes namespaces, service accounts, network policies and secret delivery",
                  neutral_label=None, vocabulary=dict(VOCABULARY), schema=None,
                  formats=(("kubernetes/*", "yaml"),),
                  products=(),
                  secret_patterns=(), importers=(WORKLOADS_IMPORTER,), profile_terms=None, access=None,
                  render_targets=TARGETS, settings=(SETTING,), ansible_lookup={"k8s-secret": secret_lookup},
                  reads_back=(ReadBack("workloads", "kubernetes/*", "kubernetes/", "{environment}/"),),
                  notes=notes)
