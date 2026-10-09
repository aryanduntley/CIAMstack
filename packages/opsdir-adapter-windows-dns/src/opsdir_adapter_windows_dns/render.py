"""The records an environment publishes (the core edge domain's published records: its service names' A records and
its other records, in zones the platform runs) on its Windows DNS servers: each appliance filling the dns stack role as
a host of group ad_dns in its own inventory file (PowerShell Remoting over HTTPS to its management address, its login
name, its password read at run time from the secret its ciamLoginSecretRole binds; ciamApplianceScope, when recorded,
the DNS server the record is written on), and the play writing each record with ansible.windows.win_dns_record. Types
the module doesn't take are named, not written. Pure."""
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import UNBOUND
from opsdir.core.formats import YAML
from opsdir.core.interchange import jinja
from opsdir.core.interchange.yaml_text import dump
from opsdir.core.manifest import header
from opsdir.domains.edge.records import published
from opsdir.domains.infrastructure.appliances import appliances, login_secret
from opsdir_adapter_ansible.requirements import requirements

STACK_ROLE = "dns"
GROUP = "ad_dns"
TYPES = ("A", "AAAA", "CNAME", "TXT", "PTR")     # what ansible.windows.win_dns_record writes here


def _host(m, services, a):
    secret = login_secret(m, a)
    return {"ansible_host": one(a, "ciamManagementAddress"), "ansible_connection": "ansible.builtin.psrp",
            "ansible_port": 5986, "ansible_psrp_protocol": "https", "ansible_psrp_auth": "negotiate",
            "ansible_psrp_cert_validation": "validate",
            "ansible_user": one(a, "ciamLoginName") or f"{UNBOUND}{rdn_value(a)}-login",
            "ansible_password": jinja.expression(services.ansible_lookup(m, secret)) if secret else
            f"{UNBOUND}{one(a, 'ciamLoginSecretRole') or rdn_value(a) + '-login-secret'}",
            **({"ciam_dns_server": one(a, "ciamApplianceScope")} if one(a, "ciamApplianceScope") else {})}


def _records(m):
    found = published(m)
    return ([{"zone": p.zone, "name": p.name, "type": p.type, "values": list(p.values), "ttl": p.ttl}
             for p in found if p.type in TYPES],
            [f"{p.type} {p.fqdn}" for p in found if p.type not in TYPES])


def _play(records, skipped):
    return [{"name": "The environment's DNS records on its Windows DNS servers (opsdir)", "hosts": GROUP,
             "gather_facts": False, "vars": {"ciam_dns_records": records, "ciam_dns_not_written": skipped},
             "tasks": [
                 {"name": "DNS records", "ansible.windows.win_dns_record":
                  {"computer_name": "{{ ciam_dns_server | default(omit) }}", "zone": "{{ item.zone }}",
                   "name": "{{ item.name }}", "type": "{{ item.type }}", "value": "{{ item.values }}",
                   "ttl": "{{ item.ttl }}", "state": "present"},
                  "loop": "{{ ciam_dns_records }}", "loop_control": {"label": "{{ item.type }} {{ item.name }}"}},
                 {"name": "Records of types this module doesn't write", "ansible.builtin.debug":
                  {"msg": "Not written: {{ ciam_dns_not_written | join(', ') }}"},
                  "when": "ciam_dns_not_written | length > 0"}]}]


def render(m, services):
    """{path: text} of environment m's Windows DNS files."""
    records, skipped = _records(m)
    yamls = {"ansible/ad-dns.yml": ("Writes the environment's DNS records on its Windows DNS servers",
                                    _play(records, skipped)),
             "ansible/inventory/ad-dns.yml": ("The Windows DNS servers (dns appliances)", {"all": {"children": {
                 GROUP: {"hosts": {rdn_value(a): _host(m, services, a) for a in appliances(m, STACK_ROLE)}}}}})}
    texts = {p: header(m, what, YAML) + dump(v, indent_sequences=True) for p, (what, v) in yamls.items()}
    return {**texts, "ansible/requirements-ad-dns.yml": header(m, "Galaxy collections the play needs, pinned", YAML)
            + dump(requirements(texts.values(), False), indent_sequences=True)}
