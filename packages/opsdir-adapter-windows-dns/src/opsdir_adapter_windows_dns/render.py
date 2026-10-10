"""The records an environment publishes (the core edge domain's published records: its service names' A or AAAA
records and its other records, in zones the platform runs) on its Windows DNS servers: each appliance filling the dns
stack role as a host of group ad_dns in its own inventory file (PowerShell Remoting over HTTPS to its management
address, its login name, its password read at run time from the secret its ciamLoginSecretRole binds;
ciamApplianceScope, when recorded, the DNS server the record is written on), and the play writing each record with
ansible.windows.win_dns_record: A, AAAA, CNAME, TXT, PTR and NS with all their values, SRV when its values share
priority, weight and port (the module takes one set per name). Types the module doesn't write (MX, CAA, ...) and SRV
sets it can't are named, not written.

What the play wrote before and the record no longer holds is removed: in each zone the platform runs, a ledger (TXT
records _opsdir-<cloud>-<env>, one per record written: "<type> <name>") lists what this environment wrote; a run
removes the records its ledger lists and the record no longer wants, then rewrites the ledger. Records the ledger
doesn't list (other teams', other environments') are never touched. Pure."""
from opsdir.core.directory import one, rdn_value
from opsdir.domains.edge.records import parts, platform_zones, published
from opsdir_adapter_ansible.output import appliance_inventory, login, requirements_file, unsafe, yaml_files

STACK_ROLE = "dns"
GROUP = "ad_dns"
TYPES = ("A", "AAAA", "CNAME", "TXT", "PTR", "NS")     # what ansible.windows.win_dns_record writes with every value
SERVER = "{{ ciam_dns_server | default(omit) }}"
TIDY = """[CmdletBinding(SupportsShouldProcess)]
param([string]$Zone, [string]$Ledger, [string[]]$Managed, [string]$Server)
$where = @{ ZoneName = $Zone }
if ($Server) { $where.ComputerName = $Server }
$old = @(Get-DnsServerResourceRecord @where -Name $Ledger -RRType Txt -ErrorAction SilentlyContinue |
    ForEach-Object { $_.RecordData.DescriptiveText })
$stale = @($old | Where-Object { $_ -and $Managed -notcontains $_ })
foreach ($entry in $stale) {
    $type, $name = $entry -split ' ', 2
    if ($PSCmdlet.ShouldProcess("$type $name in $Zone", 'Remove')) {
        Get-DnsServerResourceRecord @where -Name $name -RRType $type -ErrorAction SilentlyContinue |
            Remove-DnsServerResourceRecord @where -Force
    }
    $Ansible.Changed = $true
}
$Ansible.Result = @{ removed = $stale }
"""


def ledger(m):
    """The name of environment m's ledger records in each zone."""
    return f"_opsdir-{rdn_value(m.cloud)}-{rdn_value(m.env)}"


def _host(m, services, a):
    user, password = login(m, services, a)
    return {"ansible_host": unsafe(one(a, "ciamManagementAddress")), "ansible_connection": "ansible.builtin.psrp",
            "ansible_port": 5986, "ansible_psrp_protocol": "https", "ansible_psrp_auth": "negotiate",
            "ansible_psrp_cert_validation": "validate", "ansible_user": user, "ansible_password": password,
            **({"ciam_dns_server": unsafe(one(a, "ciamApplianceScope"))} if one(a, "ciamApplianceScope") else {})}


def _srv(p):
    """An SRV record's {target..., priority, weight, port}, or None when its values differ in those."""
    taken = [parts("SRV", v) for v in p.values]
    shared = {t[:3] for t in taken}
    if len(shared) != 1:
        return None
    (priority, weight, port), = shared
    return {"zone": p.zone, "name": p.name, "targets": [t[3] for t in taken], "priority": priority, "weight": weight,
            "port": port, "ttl": p.ttl}


def _records(m):
    """(records, SRV records, not written, {zone: ledger entries}) of environment m's published records."""
    found = published(m)
    records = [{"zone": p.zone, "name": p.name, "type": p.type, "values": list(p.values), "ttl": p.ttl}
               for p in found if p.type in TYPES]
    srv = [(p, _srv(p)) for p in found if p.type == "SRV"]
    skipped = [*(f"{p.type} {p.fqdn}" for p in found if p.type not in (*TYPES, "SRV")),
               *(f"SRV {p.fqdn} (its values differ in priority, weight or port)" for p, s in srv if s is None)]
    written = [p for p in found if p.type in TYPES or (p.type == "SRV" and _srv(p) is not None)]
    return (records, [s for _, s in srv if s], skipped,
            {z: [f"{p.type} {p.name}" for p in written if p.zone == z] for z in platform_zones(m)})


def _play(m, records, srv, skipped, zones):
    return [{"name": "The environment's DNS records on its Windows DNS servers (opsdir)", "hosts": GROUP,
             "gather_facts": False,
             "vars": {"ciam_dns_records": unsafe(records), "ciam_dns_srv": unsafe(srv),
                      "ciam_dns_not_written": unsafe(skipped), "ciam_dns_ledger": ledger(m),
                      "ciam_dns_zones": [{"zone": z, "managed": unsafe(e)} for z, e in zones.items()]},
             "tasks": [
                 {"name": "DNS records", "ansible.windows.win_dns_record":
                  {"computer_name": SERVER, "zone": "{{ item.zone }}", "name": "{{ item.name }}",
                   "type": "{{ item.type }}", "value": "{{ item.values }}", "ttl": "{{ item.ttl }}",
                   "state": "present"},
                  "loop": "{{ ciam_dns_records }}", "loop_control": {"label": "{{ item.type }} {{ item.name }}"}},
                 {"name": "SRV records", "ansible.windows.win_dns_record":
                  {"computer_name": SERVER, "zone": "{{ item.zone }}", "name": "{{ item.name }}", "type": "SRV",
                   "value": "{{ item.targets }}", "priority": "{{ item.priority }}", "weight": "{{ item.weight }}",
                   "port": "{{ item.port }}", "ttl": "{{ item.ttl }}", "state": "present"},
                  "loop": "{{ ciam_dns_srv }}", "loop_control": {"label": "SRV {{ item.name }}"}},
                 {"name": "Records this environment wrote before and the record no longer holds, removed",
                  "ansible.windows.win_powershell":
                  {"script": TIDY, "parameters": {"Zone": "{{ item.zone }}", "Ledger": "{{ ciam_dns_ledger }}",
                                                  "Managed": "{{ item.managed }}",
                                                  "Server": "{{ ciam_dns_server | default('') }}"}},
                  "loop": "{{ ciam_dns_zones }}", "loop_control": {"label": "{{ item.zone }}"}},
                 {"name": "The ledger of what this environment wrote", "ansible.windows.win_dns_record":
                  {"computer_name": SERVER, "zone": "{{ item.zone }}", "name": "{{ ciam_dns_ledger }}", "type": "TXT",
                   "value": "{{ item.managed }}",
                   "state": "{{ 'present' if item.managed | length > 0 else 'absent' }}"},
                  "loop": "{{ ciam_dns_zones }}", "loop_control": {"label": "{{ item.zone }}"}},
                 {"name": "Records this play doesn't write", "ansible.builtin.debug":
                  {"msg": "Not written: {{ ciam_dns_not_written | join(', ') }}"},
                  "when": "ciam_dns_not_written | length > 0"}]}]


def render(m, services):
    """{path: text} of environment m's Windows DNS files."""
    records, srv, skipped, zones = _records(m)
    texts = yaml_files(m, {
        "ansible/ad-dns.yml": ("Writes the environment's DNS records on its Windows DNS servers",
                               _play(m, records, srv, skipped, zones)),
        "ansible/inventory/ad-dns.yml": ("The Windows DNS servers (dns appliances)",
                                         appliance_inventory(m, STACK_ROLE, GROUP, lambda a: _host(m, services, a)))})
    return {**texts, "ansible/requirements-ad-dns.yml": requirements_file(
        m, "Galaxy collections the play needs, pinned", texts.values())}
