"""An environment's servers as an Ansible inventory (YAML): one group per server role, all of them in group
ciam_servers (appliance add-ons put their appliances in groups of their own), each server by its host name
(ansible_host its private address when the record holds one); variables the playbooks read, by scope: group_vars/all
(the environment, its provider and region or site, the product files not deployed), group_vars/<role> (the role, its
host baseline: baseline.py, jobs: jobs.py, host firewall: firewall.py, and the product files it receives: files.py),
host_vars/<host> (what the record holds for that server). Every value is the record's text, those Ansible would
evaluate as a template tagged !unsafe (output.unsafe). Nothing secret: a playbook reads a secret at run time through
a lookup (output.secret_lookup). Pure."""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import of_class, subnet_of
from .baseline import baseline_vars
from .firewall import firewall_vars
from .jobs import job_vars
from .names import INVENTORY, SERVERS, ansible_name
from .output import unsafe


def roles(m):
    """Environment m's server roles, in the order its servers are recorded."""
    return tuple(dict.fromkeys(one(s, "ciamServerRole") for s in m.servers))


def hosts(m):
    """The inventory: all -> ciam_servers -> one group per server role -> its servers."""
    return {"all": {"children": {SERVERS: {"children": {
        ansible_name(role): {"hosts": {one(s, "ciamHostname"): ({"ansible_host": unsafe(one(s, "ciamPrivateIp"))}
                                                               if one(s, "ciamPrivateIp") else None)
                                       for s in m.servers if one(s, "ciamServerRole") == role}}
        for role in roles(m)}}}}}


def time_sources(m):
    """The time servers environment m's servers get their time from (its ciamTimeSource bindings), in record order."""
    return tuple(dict.fromkeys(v for b in of_class(m, "ciamTimeSource") for v in values(b, "ciamTimeServer")))


def all_vars(m, not_deployed=()):
    """Variables every host reads: the environment, its provider and region (an on-prem site), its time servers, and
    the product files that aren't deployed, with why (not_deployed)."""
    return {"ciam_environment": m.label, "ciam_provider": m.provider, "ciam_region": one(m.cloud, "ciamRegion"),
            **({"ciam_time_sources": list(time_sources(m))} if time_sources(m) else {}),
            **({"ciam_config_files_not_deployed": list(not_deployed)} if not_deployed else {})}


def role_vars(m, role, config_files=(), host_files=()):
    """Variables a role's hosts read: the role, its host baseline's, its jobs', its host firewall's, the product
    files it receives (config_files: [{src, dest}]) and the other adapters' files for it (host_files: [{src, dest,
    mode[, reload]}])."""
    return {"ciam_role": role, **baseline_vars(m, role), **job_vars(m, role), **firewall_vars(m, role),
            **({"ciam_config_files": list(config_files)} if config_files else {}),
            **({"ciam_host_files": list(host_files)} if host_files else {})}


def host_vars(m, s):
    """Variables one server reads: its name in the record, zone, subnet and product version (those recorded)."""
    subnet = subnet_of(m, s)
    found = {"ciam_server": rdn_value(s), "ciam_zone": one(s, "ciamZone"),
             "ciam_subnet": one(subnet, "ciamCidr") if subnet is not None else None,
             "ciam_product_version": one(s, "ciamProductVersion")}
    return {k: v for k, v in found.items() if v is not None}


def inventory_files(m, config_files=None, not_deployed=(), host_files=None):
    """{path: (what, value)}: the inventory and its variable files (values tagged unsafe); config_files: {role:
    [{src, dest}]} of the product files each role receives; host_files: {role: [...]} of the other adapters' files;
    not_deployed: the files that aren't deployed, with why."""
    config_files, host_files = config_files or {}, host_files or {}
    return {f"{INVENTORY}/hosts.yml": ("The environment's servers, one group per server role", hosts(m)),
            f"{INVENTORY}/group_vars/all.yml": ("Variables every host reads", unsafe(all_vars(m, not_deployed))),
            **{f"{INVENTORY}/group_vars/{ansible_name(r)}.yml": (f"Variables role {r}'s hosts read",
                                                                     unsafe(role_vars(m, r, config_files.get(r, ()),
                                                                                      host_files.get(r, ()))))
               for r in roles(m)},
            **{f"{INVENTORY}/host_vars/{one(s, 'ciamHostname')}.yml": (f"Variables server {rdn_value(s)} reads",
                                                                       unsafe(host_vars(m, s)))
               for s in m.servers}}
