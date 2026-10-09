"""The Ansible render of an environment: its inventory and variables (inventory.py), the host-config playbook
(playbooks.py), what a run needs from Galaxy (requirements.py), each with its do-not-edit header, and the templates of
the product files the servers receive (files.py; no header: they are the products' files). Pure."""
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import dump
from opsdir.core.manifest import header
from .baseline import baseline_vars
from .files import config_templates
from .inventory import inventory_files, roles
from .names import ROOT
from .playbooks import host_config
from .requirements import requirements


def render(m, services):
    """{path: text} of environment m's Ansible files."""
    templates, config_files = config_templates(m, services)
    files = {**inventory_files(m, config_files),
             f"{ROOT}/host-config.yml": ("Applies each server role's host baseline (tags baseline, stig, verify)",
                                         host_config())}
    texts = {path: header(m, what, YAML) + dump(value, indent_sequences=True) for path, (what, value) in files.items()}
    stig = any(baseline_vars(m.d, r).get("ciam_hardening_profile") == "disa-stig" for r in roles(m))
    needs = requirements((*texts.values(), *templates.values()), stig)
    what = "Galaxy collections and roles a run needs, pinned (ansible-galaxy install -r requirements.yml)"
    return {**texts, **templates,
            f"{ROOT}/requirements.yml": header(m, what, YAML) + dump(needs, indent_sequences=True)}
