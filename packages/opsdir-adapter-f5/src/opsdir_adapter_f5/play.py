"""How Ansible reaches an environment's BIG-IPs and what it pushes: each appliance filling the load-balancer stack role
as a host of group f5_bigip in its own inventory file (the httpapi connection to its management address, its login
name, its password read at run time from the secret its ciamLoginSecretRole binds: never written), and the play
deploying the environment's AS3 declaration to them (f5networks.f5_bigip.bigip_as3_deploy). Pure."""
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import UNBOUND
from opsdir.core.interchange import jinja
from opsdir.domains.infrastructure.appliances import appliances, login_secret

STACK_ROLE = "load-balancer"
GROUP = "f5_bigip"
DECLARATION = "f5/as3.json"


def _host(m, services, a):
    secret = login_secret(m, a)
    password = jinja.expression(services.ansible_lookup(m, secret)) if secret else \
        f"{UNBOUND}{one(a, 'ciamLoginSecretRole') or rdn_value(a) + '-login-secret'}"
    return {"ansible_host": one(a, "ciamManagementAddress"), "ansible_connection": "ansible.netcommon.httpapi",
            "ansible_network_os": "f5networks.f5_bigip.bigip", "ansible_httpapi_use_ssl": True,
            "ansible_httpapi_validate_certs": True, "ansible_httpapi_port": 443,
            "ansible_user": one(a, "ciamLoginName") or f"{UNBOUND}{rdn_value(a)}-login",
            "ansible_httpapi_password": password}


def inventory(m, services):
    """The inventory file of environment m's BIG-IPs (group f5_bigip)."""
    return {"all": {"children": {GROUP: {"hosts": {rdn_value(a): _host(m, services, a)
                                                   for a in appliances(m, STACK_ROLE)}}}}}


def play(tenant):
    """The play deploying the AS3 declaration (DECLARATION, beside the playbook) for one tenant."""
    return [{"name": "Service names on the BIG-IPs, as one AS3 declaration (opsdir)", "hosts": GROUP,
             "gather_facts": False,
             "tasks": [{"name": "Deploy the AS3 declaration", "f5networks.f5_bigip.bigip_as3_deploy":
                        {"content": f"{{{{ lookup('ansible.builtin.file', '{DECLARATION}') }}}}", "tenant": tenant,
                         "state": "present", "timeout": 300}}]}]
