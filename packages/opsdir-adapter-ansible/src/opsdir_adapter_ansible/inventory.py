"""An environment's servers as an Ansible inventory (YAML): one group per server role, each server by its host name
(ansible_host its private address when the record holds one); variables the playbooks read, by scope: group_vars/all
(the environment, its provider and region or site), group_vars/<role> (the role, its host baseline: baseline.py, jobs:
jobs.py, host firewall: firewall.py, and the product files it receives: files.py),
host_vars/<host> (what the record
holds for that server). Nothing secret: a playbook reads a secret at run time through a lookup
(Services.ansible_lookup). Pure."""
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import subnet_of
from .baseline import baseline_vars
from .firewall import firewall_vars
from .jobs import job_vars
from .names import INVENTORY, ansible_name


def roles(m):
    """Environment m's server roles, in the order its servers are recorded."""
    return tuple(dict.fromkeys(one(s, "ciamServerRole") for s in m.servers))


def hosts(m):
    """The inventory: all -> children -> one group per server role -> its servers."""
    return {"all": {"children": {
        ansible_name(role): {"hosts": {one(s, "ciamHostname"): ({"ansible_host": one(s, "ciamPrivateIp")}
                                                               if one(s, "ciamPrivateIp") else None)
                                       for s in m.servers if one(s, "ciamServerRole") == role}}
        for role in roles(m)}}}


def all_vars(m):
    """Variables every host reads: the environment, its provider and region (an on-prem site)."""
    return {"ciam_environment": m.label, "ciam_provider": m.provider, "ciam_region": one(m.cloud, "ciamRegion")}


def role_vars(m, role, config_files=()):
    """Variables a role's hosts read: the role, its host baseline's, its jobs', its host firewall's, and the product
    files it receives (config_files: [{src, dest}])."""
    return {"ciam_role": role, **baseline_vars(m.d, role), **job_vars(m.d, role), **firewall_vars(m, role),
            **({"ciam_config_files": list(config_files)} if config_files else {})}


def host_vars(m, s):
    """Variables one server reads: its name in the record, zone, subnet and product version (those recorded)."""
    subnet = subnet_of(m, s)
    found = {"ciam_server": rdn_value(s), "ciam_zone": one(s, "ciamZone"),
             "ciam_subnet": one(subnet, "ciamCidr") if subnet is not None else None,
             "ciam_product_version": one(s, "ciamProductVersion")}
    return {k: v for k, v in found.items() if v is not None}


def inventory_files(m, config_files=None):
    """{path: (what, value)}: the inventory and its variable files; config_files: {role: [{src, dest}]} of the product
    files each role receives."""
    config_files = config_files or {}
    return {f"{INVENTORY}/hosts.yml": ("The environment's servers, one group per server role", hosts(m)),
            f"{INVENTORY}/group_vars/all.yml": ("Variables every host reads", all_vars(m)),
            **{f"{INVENTORY}/group_vars/{ansible_name(r)}.yml": (f"Variables role {r}'s hosts read",
                                                                     role_vars(m, r, config_files.get(r, ())))
               for r in roles(m)},
            **{f"{INVENTORY}/host_vars/{one(s, 'ciamHostname')}.yml": (f"Variables server {rdn_value(s)} reads",
                                                                       host_vars(m, s))
               for s in m.servers}}
