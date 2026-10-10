"""How Ansible reaches an environment's BIG-IPs and what it pushes: each appliance filling the load-balancer stack role
as a host in its own inventory file (the httpapi connection to its management address, its login name, its password
read at run time from the secret its ciamLoginSecretRole binds: never written), in group f5_bigip and in the group of
its tenant (f5_<tenant>: BIG-IPs sharing a scope are one device cluster, an HA pair syncing its configuration), and a
play per tenant deploying the environment's AS3 declaration (f5networks.f5_bigip.bigip_as3_deploy) to the first
BIG-IP of its group only, so a cluster gets one request. --tags dry-run asks AS3 to check the declaration without
deploying it. An environment with no service names deploys nothing: AS3 would empty the tenant. Pure."""
from opsdir.core.directory import one, rdn_value
from opsdir.domains.infrastructure.appliances import appliances
from opsdir_adapter_ansible.names import ansible_name
from opsdir_adapter_ansible.output import login, unsafe
from .as3 import tenant

STACK_ROLE = "load-balancer"
GROUP = "f5_bigip"


def declaration_path(tenant_name):
    """Where a tenant's declaration is written, beside the playbook (under ansible/)."""
    return f"f5/as3-{tenant_name}.json"


def tenants(m):
    """{tenant: (appliance, ...)} of environment m's BIG-IPs, by scope in record order."""
    found = appliances(m, STACK_ROLE)
    return {t: tuple(a for a in found if tenant(m, a) == t) for t in dict.fromkeys(tenant(m, a) for a in found)}


def _host(m, services, a):
    user, password = login(m, services, a)
    return {"ansible_host": unsafe(one(a, "ciamManagementAddress")), "ansible_connection": "ansible.netcommon.httpapi",
            "ansible_network_os": "f5networks.f5_bigip.bigip", "ansible_httpapi_use_ssl": True,
            "ansible_httpapi_validate_certs": True, "ansible_httpapi_port": 443,
            "ansible_user": user, "ansible_httpapi_password": password}


def inventory(m, services):
    """The inventory file of environment m's BIG-IPs: group f5_bigip, a child group per tenant."""
    return {"all": {"children": {GROUP: {"children": {
        ansible_name(f"f5_{t}"): {"hosts": {rdn_value(a): _host(m, services, a) for a in found}}
        for t, found in tenants(m).items()}}}}}


def _deploy(tenant_name, dry_run):
    return {"name": "Check the AS3 declaration (not deployed)" if dry_run else "Deploy the AS3 declaration",
            "f5networks.f5_bigip.bigip_as3_deploy":
            {"content": f"{{{{ lookup('ansible.builtin.file', '{declaration_path(tenant_name)}') }}}}",
             "tenant": tenant_name, "state": "present", "timeout": 300,
             **({"controls": {"dry_run": True}} if dry_run else {})},
            "tags": ["dry-run", "never"] if dry_run else ["deploy"]}


def play(tenant_name, has_applications):
    """The play deploying a tenant's AS3 declaration to the first BIG-IP of its group, or, when the environment has
    no service names, saying why nothing is deployed."""
    group = f"{ansible_name(f'f5_{tenant_name}')}[0]"
    tasks = [_deploy(tenant_name, True), _deploy(tenant_name, False)] if has_applications else [
        {"name": "Nothing to deploy", "ansible.builtin.debug":
         {"msg": f"The environment has no service names: tenant {tenant_name} isn't deployed (an empty AS3 "
                 "declaration would remove everything in it). Remove the tenant on purpose if that's what's meant."}}]
    return {"name": f"Service names on the BIG-IPs, tenant {tenant_name}, as one AS3 declaration (opsdir)",
            "hosts": group, "gather_facts": False, "tasks": tasks}
