# opsdir-adapter-windows-dns

opsdir DNS add-on: the records an environment publishes, written by Ansible on its Microsoft Windows (Active Directory) DNS servers. It is the default on-prem DNS (milestone 5.3, decision 2230); Infoblox (`opsdir-adapter-infoblox`) is the option.

**Applies to** environments whose stack declares it (`ciamStackRole: dns`, `ciamAdapter: ad-dns`), beside `opsdir-adapter-ansible`. With it declared, the on-prem provider's planner check no longer asks the site's team for the records it writes. **Depends on** `opsdir` (the edge domain's published records, the infrastructure domain's appliances) and `opsdir-adapter-ansible`.

## The DNS servers in the record

A `ciamAppliance` with `ciamStackRole: dns`: `ciamManagementAddress` the host Ansible connects to (the DNS server, or a management host with the DNS Server tools), `ciamApplianceScope` the DNS server the records are written on when that isn't the host itself, `ciamLoginName` and `ciamLoginSecretRole` (the binding of the secret holding the login's password, read when the play runs).

## What it renders

| File | Content |
|---|---|
| `ansible/inventory/ad-dns.yml` | Each DNS server in group `ad_dns`: PowerShell Remoting (`ansible.builtin.psrp`) over HTTPS on 5986, certificate validated, Negotiate authentication; `ciam_dns_server` its scope |
| `ansible/ad-dns.yml` | The play writing each record with `ansible.windows.win_dns_record` (zone, name relative to the zone, type, values, TTL): A, AAAA, CNAME, TXT, PTR and NS with all their values, SRV when its values share priority, weight and port (the module takes one set per name); then, per zone the platform runs, removing what this environment wrote before and no longer wants, and rewriting its ledger (below); what it doesn't write is named |
| `ansible/requirements-ad-dns.yml` | `ansible.windows` 3.8.0 (`community.windows.win_dns_record` is a deprecated redirect to it) |

The records are the core edge domain's published records (`edge.records.published`): each service name's A or AAAA record (by its `ciamFrontendIp`'s version; `UNBOUND:<role>-frontend-ip` when none is recorded) and the environment's other records (`ciamDnsRecord`), in the zone bindings their names fall in. A name that routes between environments is written once, by the environment that renders its routing: a failover pair's primary address only (a DNS server doesn't fail over by itself: switching is a change to the record), a weighted set's addresses as round robin (DNS servers can't weight). Names in a zone another party runs (`ciamManagedBy`), kept by another party (the binding's `ciamManagedBy`), or in no bound zone aren't written: the on-prem provider's planner check still asks their keepers for them (`edge.records.unpublished`).

**What it wrote before.** In each zone the platform runs, the environment keeps a ledger: TXT records named `_opsdir-<cloud>-<env>`, one per record it wrote (`<type> <name>`). A run removes the records its ledger lists and the record no longer wants (`ansible.windows.win_powershell`: `Get-DnsServerResourceRecord` / `Remove-DnsServerResourceRecord`, nothing removed under `--check`), then rewrites the ledger (removed when the zone holds nothing of it any more). Records the ledger doesn't list, other teams' and other environments', are never touched; a ledger deleted by hand only means nothing is tidied on the next run.

## Planner check

`check_appliances`: a target that declares Windows DNS but records no DNS server is a blocker.

## Known limits

- MX, CAA and other types `win_dns_record` doesn't take are named, not written; so is an SRV name whose values differ in priority, weight or port.
- Failover between environments isn't automatic on a DNS server: the primary's address is written; moving it is a change to the record.
- The controller needs the `pypsrp` Python package (Ansible's PSRP connection).

## Tests

`tests/test_windows_dns.py`: the servers' inventory with the password read at run time, the records written (SRV, NS) and the types not written, the ledger, the planner check, the play through the real Ansible tools (marker `ansible`).
