# opsdir-adapter-windows-dns

opsdir DNS add-on: the records an environment publishes, written by Ansible on its Microsoft Windows (Active Directory) DNS servers. It is the default on-prem DNS (milestone 5.3, decision 2230); Infoblox (`opsdir-adapter-infoblox`) is the option.

**Applies to** environments whose stack declares it (`ciamStackRole: dns`, `ciamAdapter: ad-dns`), beside `opsdir-adapter-ansible`. With it declared, the on-prem provider's planner check no longer asks the site's team for these records. **Depends on** `opsdir` (the edge domain's published records, the infrastructure domain's appliances) and `opsdir-adapter-ansible`.

## The DNS servers in the record

A `ciamAppliance` with `ciamStackRole: dns`: `ciamManagementAddress` the host Ansible connects to (the DNS server, or a management host with the DNS Server tools), `ciamApplianceScope` the DNS server the records are written on when that isn't the host itself, `ciamLoginName` and `ciamLoginSecretRole` (the binding of the secret holding the login's password, read when the play runs).

## What it renders

| File | Content |
|---|---|
| `ansible/inventory/ad-dns.yml` | Each DNS server in group `ad_dns`: PowerShell Remoting (`ansible.builtin.psrp`) over HTTPS on 5986, certificate validated, Negotiate authentication; `ciam_dns_server` its scope |
| `ansible/ad-dns.yml` | The play writing each record with `ansible.windows.win_dns_record` (zone, name relative to the zone, type, values, TTL); records of types it doesn't write are named |
| `ansible/requirements-ad-dns.yml` | `ansible.windows` 3.8.0 (`community.windows.win_dns_record` is a deprecated redirect to it) |

The records are the core edge domain's published records (`edge.records.published`): each service name's A record (its `ciamFrontendIp`; `UNBOUND:<role>-frontend-ip` when none is recorded) and the environment's other records (`ciamDnsRecord`), in the zone bindings their names fall in. Zones another party runs (`ciamManagedBy`) are left out, as are names in no bound zone. Types written: A, AAAA, CNAME, TXT, PTR.

## Planner check

`check_appliances`: a target that declares Windows DNS but records no DNS server is a blocker.

## Known limits

- MX, SRV and other types are named, not written.
- A name that routes between environments (failover, weighted) is written with this environment's answer only.
- The controller needs the `pypsrp` Python package (Ansible's PSRP connection).

## Tests

`tests/test_windows_dns.py`: the servers' inventory with the password read at run time, the records written and the types not written, the planner check, the play through the real Ansible tools (marker `ansible`).
