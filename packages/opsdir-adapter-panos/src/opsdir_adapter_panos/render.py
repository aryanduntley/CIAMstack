"""The Palo Alto add-on's render: each appliance filling the network-firewall stack role (a Panorama, or a firewall)
as a host of group panos in its own inventory file (the play runs on the controller, connection local, with the
controller's Python, where pan-os-python is installed; its provider is its management address, its login name and
its password read once per run, at run time, from the secret its ciamLoginSecretRole binds). ciamApplianceScope
'vsys<n>', or none, makes it a firewall (vsys1 when none); any other scope is a Panorama device group. Then the play
pushing the objects and security rules (rules.py), and what it needs from Galaxy.

The record owns a rule's sources, destinations, services, action and logging, and its description, which marks the
rules this environment wrote. The network team owns the rest (zones, application, profiles, tags, schedule, where the
rule sits): a run reads the environment's rules first and keeps those as the firewall has them; a new rule gets
zones and application any and is placed at the top, after the environment's rule before it (ciamRulePriority order).
A rule the environment wrote before and the record no longer holds is removed. Committing is the network team's
change: the commit tasks run only with --tags commit, and commit only the opsdir login's own changes (on Panorama, to
the environment's device group). Pure."""
from opsdir.core.directory import one
from opsdir_adapter_ansible.output import LOCAL, appliance_inventory, login, requirements_file, unsafe, yaml_files
from .rules import marker, objects

STACK_ROLE = "network-firewall"
GROUP = "panos"
PANOS = "paloaltonetworks.panos"
LOGIN = "{{ ciam_panos_login }}"
TARGET = {"device_group": "{{ ciam_panos_device_group | default(omit) }}",
          "vsys": "{{ ciam_panos_vsys | default(omit) }}", "provider": LOGIN}
PANORAMA = "ciam_panos_device_group is defined"
# what the network team owns on a rule opsdir writes: kept as the firewall has it (a new rule: zones, application any)
KEPT = ("source_user", "category", "hip_profiles", "tag_name", "group_tag", "log_setting", "log_start", "schedule",
        "rule_type", "group_profile", "antivirus", "spyware", "vulnerability", "url_filtering", "file_blocking",
        "wildfire_analysis", "data_filtering", "disabled", "negate_source", "negate_destination", "icmp_unreachable",
        "disable_server_response_inspection")
ANY = ("source_zone", "destination_zone", "application")
NOW = ("{{ ciam_panos_rules_now.gathered | default([]) | selectattr('rule_name', 'equalto', item.rule_name) | first "
       "| default({}) }}")


def _host(m, services, a):
    user, password = login(m, services, a)
    scope = one(a, "ciamApplianceScope") or "vsys1"
    return {**LOCAL,
            **({"ciam_panos_vsys": unsafe(scope)} if scope.startswith("vsys")
               else {"ciam_panos_device_group": unsafe(scope)}),
            "ciam_panos_provider": {"ip_address": unsafe(one(a, "ciamManagementAddress")), "username": user,
                                    "password": password}}


def _task(name, module, args, loop, label, tags=("rules",), **extra):
    return {"name": name, f"{PANOS}.{module}": args, "loop": loop, "loop_control": {"label": label},
            **extra, "tags": list(tags)}


def _rule_args():
    return {**TARGET, "rulebase": f"{{{{ 'pre-rulebase' if {PANORAMA} else omit }}}}",
            "rule_name": "{{ item.rule_name }}", "description": "{{ item.description }}",
            "source_ip": "{{ item.source_ip }}", "destination_ip": "{{ item.destination_ip }}",
            "service": "{{ item.service }}", "action": "allow", "log_end": True,
            **{k: f"{{{{ ciam_rule_now.{k} | default(['any'], true) }}}}" for k in ANY},
            **{k: f"{{{{ ciam_rule_now.{k} | default(omit, true) }}}}" for k in KEPT},
            "location": "{{ omit if ciam_rule_now else ('after' if item.after else 'top') }}",
            "existing_rule": "{{ omit if (ciam_rule_now or not item.after) else item.after }}",
            "state": "present"}


def _commits():
    admins = ["{{ ciam_panos_login.username }}"]
    tags = ["commit", "never"]
    return [{"name": "Commit on Panorama (the opsdir login's changes, the device group)",
             f"{PANOS}.panos_commit_panorama": {"provider": LOGIN, "admins": admins,
                                                "device_groups": ["{{ ciam_panos_device_group }}"]},
             "when": PANORAMA, "tags": tags},
            {"name": "Push to the device group (the opsdir login's changes)",
             f"{PANOS}.panos_commit_push": {"provider": LOGIN, "style": "device group", "admins": admins,
                                            "name": "{{ ciam_panos_device_group }}"},
             "when": PANORAMA, "tags": tags},
            {"name": "Commit on the firewall (the opsdir login's changes)",
             f"{PANOS}.panos_commit_firewall": {"provider": LOGIN, "admins": admins},
             "when": f"not ({PANORAMA})", "tags": tags}]


def _play(m, found):
    return [{"name": "The record's firewall rules on Palo Alto Networks (opsdir)", "hosts": GROUP,
             "gather_facts": False, "vars": {"ciam_panos": unsafe(found), "ciam_panos_marker": marker(m)},
             "tasks": [
                 {"name": "The login, read once", "ansible.builtin.set_fact": {"ciam_panos_login":
                                                                              "{{ ciam_panos_provider }}"},
                  "no_log": True, "tags": ["always"]},
                 _task("Address objects", "panos_address_object",
                       {**TARGET, "name": "{{ item.name }}", "value": "{{ item.value }}",
                        "address_type": "{{ item.address_type }}"}, "{{ ciam_panos.addresses }}", "{{ item.name }}"),
                 _task("Service objects", "panos_service_object",
                       {**TARGET, "name": "{{ item.name }}", "protocol": "{{ item.protocol }}",
                        "destination_port": "{{ item.destination_port }}"}, "{{ ciam_panos.services }}",
                       "{{ item.name }}"),
                 {"name": "The rules this environment wrote, as the firewall has them", f"{PANOS}.panos_security_rule":
                  {**TARGET, "rulebase": f"{{{{ 'pre-rulebase' if {PANORAMA} else omit }}}}",
                   "rule_name": "{{ ciam_panos_marker }}", "state": "gathered",
                   "gathered_filter": "description starts-with '{{ ciam_panos_marker }}'"},
                  "register": "ciam_panos_rules_now", "tags": ["rules"]},
                 _task("Security rules", "panos_security_rule", _rule_args(), "{{ ciam_panos.rules }}",
                       "{{ item.rule_name }}", vars={"ciam_rule_now": NOW}),
                 _task("Rules this environment wrote before and the record no longer holds, removed",
                       "panos_security_rule",
                       {**TARGET, "rulebase": f"{{{{ 'pre-rulebase' if {PANORAMA} else omit }}}}",
                        "rule_name": "{{ item.rule_name }}", "state": "absent"},
                       "{{ ciam_panos_rules_now.gathered | default([]) | rejectattr('rule_name', 'in', "
                       "ciam_panos.rules | map(attribute='rule_name') | list) | list }}", "{{ item.rule_name }}"),
                 *_commits()]}]


def render(m, services):
    """{path: text} of environment m's Palo Alto files."""
    texts = yaml_files(m, {
        "ansible/panos.yml": ("Pushes the record's firewall rules to Palo Alto Networks (commit: --tags commit)",
                              _play(m, objects(m))),
        "ansible/inventory/panos.yml": ("The Panorama or firewalls (network-firewall appliances)",
                                        appliance_inventory(m, STACK_ROLE, GROUP, lambda a: _host(m, services, a)))})
    return {**texts, "ansible/requirements-panos.yml": requirements_file(
        m, "Galaxy collections the play needs, pinned (and the pan-os-python Python package on the controller)",
        texts.values())}
