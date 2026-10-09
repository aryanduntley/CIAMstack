"""The records an environment publishes (the core edge domain's published records) on Infoblox NIOS, through its grid
master's WAPI: each appliance filling the dns stack role as a host of group infoblox in its own inventory file (the
play runs on the controller, connection local; the provider is its management address, its login name and its
password read at run time from the secret its ciamLoginSecretRole binds; ciamApplianceScope the DNS view, else
default), and the play writing one Infoblox record per value with infoblox.nios_modules. Types the play doesn't write
are named. Pure."""
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
GROUP = "infoblox"
WAPI_VERSION = "2.12.3"          # the collection's minimum
# record type -> (module, the module's value parameter)
MODULES = {"A": ("nios_a_record", "ipv4"), "AAAA": ("nios_aaaa_record", "ipv6"),
           "CNAME": ("nios_cname_record", "canonical"), "TXT": ("nios_txt_record", "text")}


def _host(m, services, a):
    secret = login_secret(m, a)
    return {"ansible_connection": "local", "ciam_nios_view": one(a, "ciamApplianceScope") or "default",
            "ciam_nios_provider": {
                "host": one(a, "ciamManagementAddress"), "wapi_version": WAPI_VERSION,
                "username": one(a, "ciamLoginName") or f"{UNBOUND}{rdn_value(a)}-login",
                "password": jinja.expression(services.ansible_lookup(m, secret)) if secret else
                f"{UNBOUND}{one(a, 'ciamLoginSecretRole') or rdn_value(a) + '-login-secret'}"}}


def _task(rtype, records):
    module, param = MODULES[rtype]
    return {"name": f"{rtype} records", f"infoblox.nios_modules.{module}":
            {"name": "{{ item.fqdn }}", param: "{{ item.value }}", "view": "{{ ciam_nios_view }}",
             "ttl": "{{ item.ttl }}", "state": "present", "provider": "{{ ciam_nios_provider }}"},
            "loop": f"{{{{ ciam_dns_records['{rtype}'] }}}}", "loop_control": {"label": "{{ item.fqdn }}"}}


def _play(m):
    found = published(m)
    records = {t: [{"fqdn": p.fqdn, "value": v, "ttl": p.ttl} for p in found if p.type == t for v in p.values]
               for t in MODULES}
    skipped = [f"{p.type} {p.fqdn}" for p in found if p.type not in MODULES]
    return [{"name": "The environment's DNS records on Infoblox (opsdir)", "hosts": GROUP, "gather_facts": False,
             "vars": {"ciam_dns_records": records, "ciam_dns_not_written": skipped},
             "tasks": [*(_task(t, r) for t, r in records.items() if r),
                       {"name": "Records of types this play doesn't write", "ansible.builtin.debug":
                        {"msg": "Not written: {{ ciam_dns_not_written | join(', ') }}"},
                        "when": "ciam_dns_not_written | length > 0"}]}]


def render(m, services):
    """{path: text} of environment m's Infoblox files."""
    yamls = {"ansible/infoblox.yml": ("Writes the environment's DNS records on Infoblox", _play(m)),
             "ansible/inventory/infoblox.yml": ("The Infoblox grid masters (dns appliances)", {"all": {"children": {
                 GROUP: {"hosts": {rdn_value(a): _host(m, services, a) for a in appliances(m, STACK_ROLE)}}}}})}
    texts = {p: header(m, what, YAML) + dump(v, indent_sequences=True) for p, (what, v) in yamls.items()}
    return {**texts, "ansible/requirements-infoblox.yml": header(m, "Galaxy collections the play needs, pinned "
                                                                    "(and the infoblox-client Python package on the "
                                                                    "controller)", YAML)
            + dump(requirements(texts.values(), False), indent_sequences=True)}
