"""The Palo Alto add-on's render: each appliance filling the network-firewall stack role (a Panorama, or a firewall)
as a host of group panos in its own inventory file (the play runs on the controller, connection local; its provider
is its management address, its login name and its password read at run time from the secret its
ciamLoginSecretRole binds; ciamApplianceScope 'vsys<n>' targets a firewall's vsys, anything else a Panorama device
group, default opsdir-<cloud>-<env>), the play pushing the objects and security rules (rules.py), and what it needs
from Galaxy. Committing is the network team's change: the commit tasks run only with --tags commit. Pure."""
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import UNBOUND
from opsdir.core.formats import YAML
from opsdir.core.interchange import jinja
from opsdir.core.interchange.yaml_text import dump
from opsdir.core.manifest import header
from opsdir.domains.infrastructure.appliances import appliances, login_secret
from opsdir_adapter_ansible.requirements import requirements
from .rules import objects

STACK_ROLE = "network-firewall"
GROUP = "panos"
PANOS = "paloaltonetworks.panos"
TARGET = {"device_group": "{{ ciam_panos_device_group | default(omit) }}",
          "vsys": "{{ ciam_panos_vsys | default(omit) }}", "provider": "{{ ciam_panos_provider }}"}


def _host(m, services, a):
    secret = login_secret(m, a)
    scope = one(a, "ciamApplianceScope") or f"opsdir-{rdn_value(m.cloud)}-{rdn_value(m.env)}"
    return {"ansible_connection": "local",
            **({"ciam_panos_vsys": scope} if scope.startswith("vsys") else {"ciam_panos_device_group": scope}),
            "ciam_panos_provider": {
                "ip_address": one(a, "ciamManagementAddress"),
                "username": one(a, "ciamLoginName") or f"{UNBOUND}{rdn_value(a)}-login",
                "password": jinja.expression(services.ansible_lookup(m, secret)) if secret else
                f"{UNBOUND}{one(a, 'ciamLoginSecretRole') or rdn_value(a) + '-login-secret'}"}}


def _task(name, module, args, loop, label, tags=("rules",), **extra):
    return {"name": name, f"{PANOS}.{module}": args, "loop": loop, "loop_control": {"label": label},
            **extra, "tags": list(tags)}


def _play(found):
    panorama = "ciam_panos_device_group is defined"
    return [{"name": "The record's firewall rules on Palo Alto Networks (opsdir)", "hosts": GROUP,
             "gather_facts": False, "vars": {"ciam_panos": found},
             "tasks": [
                 _task("Address objects", "panos_address_object",
                       {**TARGET, "name": "{{ item.name }}", "value": "{{ item.value }}",
                        "address_type": "{{ item.address_type }}"}, "{{ ciam_panos.addresses }}", "{{ item.name }}"),
                 _task("Service objects", "panos_service_object",
                       {**TARGET, "name": "{{ item.name }}", "protocol": "{{ item.protocol }}",
                        "destination_port": "{{ item.destination_port }}"}, "{{ ciam_panos.services }}",
                       "{{ item.name }}"),
                 _task("Security rules", "panos_security_rule",
                       {**TARGET, "rulebase": f"{{{{ 'pre-rulebase' if {panorama} else omit }}}}",
                        "rule_name": "{{ item.rule_name }}", "description": "{{ item.description }}",
                        "source_zone": ["any"], "destination_zone": ["any"], "source_ip": "{{ item.source_ip }}",
                        "destination_ip": "{{ item.destination_ip }}", "application": ["any"],
                        "service": "{{ item.service }}", "action": "allow", "log_end": True},
                       "{{ ciam_panos.rules }}", "{{ item.rule_name }}"),
                 {"name": "Commit on Panorama", f"{PANOS}.panos_commit_panorama":
                  {"provider": "{{ ciam_panos_provider }}"}, "when": panorama, "tags": ["commit", "never"]},
                 {"name": "Push to the device group", f"{PANOS}.panos_commit_push":
                  {"provider": "{{ ciam_panos_provider }}", "style": "device group",
                   "name": "{{ ciam_panos_device_group }}"}, "when": panorama, "tags": ["commit", "never"]},
                 {"name": "Commit on the firewall", f"{PANOS}.panos_commit_firewall":
                  {"provider": "{{ ciam_panos_provider }}"}, "when": f"not ({panorama})",
                  "tags": ["commit", "never"]}]}]


def render(m, services):
    """{path: text} of environment m's Palo Alto files."""
    yamls = {"ansible/panos.yml": ("Pushes the record's firewall rules to Palo Alto Networks (commit: --tags commit)",
                                   _play(objects(m))),
             "ansible/inventory/panos.yml": ("The Panorama or firewalls (network-firewall appliances)",
                                             {"all": {"children": {GROUP: {"hosts": {
                                                 rdn_value(a): _host(m, services, a)
                                                 for a in appliances(m, STACK_ROLE)}}}}})}
    texts = {p: header(m, what, YAML) + dump(v, indent_sequences=True) for p, (what, v) in yamls.items()}
    return {**texts, "ansible/requirements-panos.yml": header(m, "Galaxy collections the play needs, pinned (and the "
                                                                 "pan-os-python Python package on the controller)",
                                                              YAML)
            + dump(requirements(texts.values(), False), indent_sequences=True)}
