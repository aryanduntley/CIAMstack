"""The Ansible render of an environment: its inventory and variables (inventory.py), the host-config playbook
(playbooks.py) and what a run needs from Galaxy (requirements.py), each with its do-not-edit header (output.py), and
the templates of the product files the servers receive (files.py; no header: they are the products' files). Pure."""
from .baseline import baseline_vars
from .files import config_templates
from .inventory import inventory_files, roles
from .names import ROOT
from .output import requirements_file, yaml_files
from .playbooks import host_config


def render(m, services):
    """{path: text} of environment m's Ansible files."""
    templates, config_files, not_deployed = config_templates(m, services)
    texts = yaml_files(m, {**inventory_files(m, config_files, not_deployed),
                           f"{ROOT}/host-config.yml": ("Applies each server role's host configuration (tags baseline, "
                                                       "stig, jobs, firewall, files, verify)", host_config())})
    stig = any(baseline_vars(m, r).get("ciam_hardening_profile") == "disa-stig" for r in roles(m))
    return {**texts, **templates,
            f"{ROOT}/requirements.yml": requirements_file(
                m, "Galaxy collections and roles a run needs, pinned (ansible-galaxy install -r requirements.yml)",
                (*texts.values(), *templates.values()), stig)}
