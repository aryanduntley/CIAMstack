"""The records an environment publishes (the core edge domain's published records) on Infoblox NIOS, through its grid
master's WAPI: each appliance filling the dns stack role as a host of group infoblox in its own inventory file (the
play runs on the controller, connection local, with the controller's Python, where infoblox-client is installed; the
provider is its management address over verified TLS, its login name and its password read once per run, at run time,
from the secret its ciamLoginSecretRole binds; ciamApplianceScope the DNS view, else default), and the play writing one
Infoblox record per value with infoblox.nios_modules: A, AAAA, CNAME, TXT, MX, SRV and PTR. Types the play doesn't
write (CAA, ...) are named.

Every record the play writes carries the comment "opsdir <cloud>/<env>". What it wrote before and the record no
longer holds is removed: a run looks up the records carrying its comment in the view and removes those the record
doesn't want; records without it (other teams', other environments') are never touched. Pure."""
from opsdir.core.directory import one
from opsdir.domains.edge.records import parts, published
from opsdir_adapter_ansible.output import LOCAL, appliance_inventory, login, requirements_file, unsafe, yaml_files

STACK_ROLE = "dns"
GROUP = "infoblox"
WAPI_VERSION = "2.12.3"          # the collection's minimum
# record type -> (module, WAPI object, the module's fields after name, in the order a value's parts give them)
MODULES = {"A": ("nios_a_record", "record:a", ("ipv4addr",)),
           "AAAA": ("nios_aaaa_record", "record:aaaa", ("ipv6addr",)),
           "CNAME": ("nios_cname_record", "record:cname", ("canonical",)),
           "TXT": ("nios_txt_record", "record:txt", ("text",)),
           "MX": ("nios_mx_record", "record:mx", ("preference", "mail_exchanger")),
           "SRV": ("nios_srv_record", "record:srv", ("priority", "weight", "port", "target")),
           "PTR": ("nios_ptr_record", "record:ptr", ("ptrdname",))}
NIOS = "infoblox.nios_modules"
PROVIDER = "{{ ciam_nios }}"


def comment(m):
    """The comment marking the records environment m's play wrote."""
    return f"opsdir {m.label}"


def _key(name, fields, record):
    """A record's identity as text: its name and its fields' values (what the clean-up compares)."""
    return " ".join((name, *(str(record[f]) for f in fields)))


def _host(m, services, a):
    user, password = login(m, services, a)
    return {**LOCAL, "ciam_nios_view": unsafe(one(a, "ciamApplianceScope") or "default"),
            "ciam_nios_provider": {"host": unsafe(one(a, "ciamManagementAddress")), "wapi_version": WAPI_VERSION,
                                   "validate_certs": True, "username": user, "password": password}}


def _write(rtype):
    module, _, fields = MODULES[rtype]
    return {"name": f"{rtype} records", f"{NIOS}.{module}":
            {"name": "{{ item.name }}", **{f: f"{{{{ item.{f} }}}}" for f in fields}, "view": "{{ ciam_nios_view }}",
             "ttl": "{{ item.ttl }}", "comment": "{{ ciam_dns_comment }}", "state": "present", "provider": PROVIDER},
            "loop": f"{{{{ ciam_dns_records['{rtype}'] }}}}", "loop_control": {"label": "{{ item.name }}"}}


def _tidy(rtype):
    module, wapi, fields = MODULES[rtype]
    found = (f"{{{{ query('{NIOS}.nios_lookup', '{wapi}', filter={{'comment': ciam_dns_comment, 'view': "
             f"ciam_nios_view}}, return_fields={['name', *fields]}, provider=ciam_nios) }}}}")
    key = " ~ ' ' ~ ".join(("item.name", *(f"item.{f} | string" for f in fields)))
    return {"name": f"{rtype} records this environment wrote before and the record no longer holds, removed",
            f"{NIOS}.{module}": {"name": "{{ item.name }}", **{f: f"{{{{ item.{f} }}}}" for f in fields},
                                 "view": "{{ ciam_nios_view }}", "state": "absent", "provider": PROVIDER},
            "loop": found, "loop_control": {"label": "{{ item.name }}"},
            "when": f"({key}) not in ciam_dns_wanted['{rtype}']"}


def _records(found):
    """({type: [record]}, {type: [key]}) of the published records Infoblox takes, one record per value."""
    records = {t: [{"name": p.fqdn, **dict(zip(MODULES[t][2], parts(t, v))), "ttl": p.ttl}
                   for p in found if p.type == t for v in p.values] for t in MODULES}
    return records, {t: [_key(r["name"], MODULES[t][2], r) for r in rs] for t, rs in records.items()}


def _play(m):
    found = published(m)
    records, wanted = _records(found)
    skipped = [f"{p.type} {p.fqdn}" for p in found if p.type not in MODULES]
    return [{"name": "The environment's DNS records on Infoblox (opsdir)", "hosts": GROUP, "gather_facts": False,
             "vars": {"ciam_dns_records": unsafe(records), "ciam_dns_wanted": unsafe(wanted),
                      "ciam_dns_not_written": unsafe(skipped), "ciam_dns_comment": comment(m)},
             "tasks": [
                 {"name": "The grid master's login, read once", "ansible.builtin.set_fact":
                  {"ciam_nios": "{{ ciam_nios_provider }}"}, "no_log": True},
                 *(_write(t) for t, r in records.items() if r),
                 *(_tidy(t) for t in MODULES),
                 {"name": "Records of types this play doesn't write", "ansible.builtin.debug":
                  {"msg": "Not written: {{ ciam_dns_not_written | join(', ') }}"},
                  "when": "ciam_dns_not_written | length > 0"}]}]


def render(m, services):
    """{path: text} of environment m's Infoblox files."""
    texts = yaml_files(m, {
        "ansible/infoblox.yml": ("Writes the environment's DNS records on Infoblox", _play(m)),
        "ansible/inventory/infoblox.yml": ("The Infoblox grid masters (dns appliances)",
                                           appliance_inventory(m, STACK_ROLE, GROUP, lambda a: _host(m, services, a)))})
    return {**texts, "ansible/requirements-infoblox.yml": requirements_file(
        m, "Galaxy collections the play needs, pinned (and the infoblox-client Python package on the controller)",
        texts.values())}
