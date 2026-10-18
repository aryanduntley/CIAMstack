"""The `sigma` adapter: declaration-only (it renders only where a stack declares it, stack role detections). Its
environment-specific render writes the record's adopted detections as Sigma 2.1.0 rules (sigma/<alert rule>.yml), in
the field names of the product versions the environment runs, from the declarations of the adapters rendering it
(Services.detections); its notes name the rules it leaves out and what a converter needs. Pure."""
from opsdir.core.contract import Adapter
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import dump
from opsdir.core.manifest import header

from .sigma import FOLDER, SPEC, sigma_files, sigma_notes

FILES = ((f"{FOLDER}/*.yml", "yaml"),)


def render_sigma(m, services):
    """The render: environment m's Sigma rules, each file headed by the do-not-edit comment."""
    top = header(m, f"Sigma {SPEC} rules: an alert rule adopting a product's declared detection", YAML)
    return sigma_files(m, services.detections(m), dump, top)


def render_notes(m, services):
    """The render's notes (sigma.sigma_notes)."""
    return sigma_notes(m, services.detections(m))


ADAPTER = Adapter(name="sigma", kind="platform", applies=None, required_roles=(), render_neutral=None,
                  render_env=render_sigma, checks=(), ref_schemes=(), secret_schemes={},
                  renders="Sigma rules of the adopted detections", neutral_label=None, vocabulary={}, schema=None,
                  formats=FILES, products=(), secret_patterns=(), importers=(), profile_terms=None, access=None,
                  notes=render_notes)
