"""The Ansible render of an environment: its inventory and variables (inventory.py), the host-config playbook
(playbooks.py) and what a run needs from Galaxy (requirements.py), each with its do-not-edit header (output.py), and
the templates of the product files the servers receive and of the files other adapters render for them (files.py; no
header: they are the products' and agents' files). Pure."""
from .baseline import baseline_vars
from .files import config_templates, host_file_templates
from .inventory import inventory_files, roles
from .names import ROOT
from .output import requirements_file, yaml_files
from .playbooks import host_config


def render(m, services):
    """{path: text} of environment m's Ansible files."""
    product_templates, config_files, not_deployed = config_templates(m, services)
    host_templates, host_files, hosts_not_deployed = host_file_templates(m, services)
    templates = {**product_templates, **host_templates}
    texts = yaml_files(m, {**inventory_files(m, config_files, (*not_deployed, *hosts_not_deployed), host_files),
                           f"{ROOT}/host-config.yml": ("Applies each server role's host configuration (tags baseline, "
                                                       "stig, jobs, time, firewall, files, host-files, verify)",
                                                       host_config())})
    stig = any(baseline_vars(m, r).get("ciam_hardening_profile") == "disa-stig" for r in roles(m))
    return {**texts, **templates,
            f"{ROOT}/requirements.yml": requirements_file(
                m, "Galaxy collections and roles a run needs, pinned (ansible-galaxy install -r requirements.yml)",
                (*texts.values(), *templates.values()), stig)}
