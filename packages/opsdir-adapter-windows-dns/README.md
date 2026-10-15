# opsdir-adapter-windows-dns

opsdir DNS add-on: the records an environment publishes, written by Ansible on its Microsoft Windows (Active Directory) DNS servers. It is the default on-prem DNS (milestone 5.3, decision 2230); Infoblox (`opsdir-adapter-infoblox`) is the option.

**Applies to** environments whose stack declares it (`ciamStackRole: dns`, `ciamAdapter: ad-dns`), beside `opsdir-adapter-ansible`. With it declared, the on-prem provider's planner check (`opsdir-adapter-onprem`, `keepers.py`) asks the zones' keepers only for the names this add-on can't write.

**Depends on** `opsdir` (the edge domain's published records and platform zones, `opsdir.domains.edge.records`; the infrastructure domain's appliances) and `opsdir-adapter-ansible` (the appliance inventory, the login and its run-time secret lookup, the YAML writer, the pinned Galaxy requirements). At run time: the `ansible.windows` collection, and the `pypsrp` Python package on the controller (Ansible's PSRP connection); the DNS Server PowerShell module on the host Ansible connects to.

## The DNS servers in the record

A `ciamAppliance` with `ciamStackRole: dns` (the core's class): `ciamManagementAddress` the host Ansible connects to (the DNS server, or a management host with the DNS Server tools), `ciamApplianceScope` the DNS server the records are written on when that isn't the host itself, `ciamLoginName` and `ciamLoginSecretRole` (the binding of the secret holding the login's password, read when the play runs).

## What it renders

Per environment, nothing environment-neutral:

| File | Content |
|---|---|
| `ansible/inventory/ad-dns.yml` | Each DNS server a host of group `ad_dns` by its record name: PowerShell Remoting (`ansible.builtin.psrp`) over HTTPS on 5986, certificate validated, Negotiate authentication, `ansible_user` its `ciamLoginName`, `ansible_password` a run-time lookup of its login secret (an unrecorded login name or unbound secret role is `UNBOUND:<appliance>-login` / `UNBOUND:<secret role>`); `ciam_dns_server` its scope, when recorded |
| `ansible/ad-dns.yml` | One play on group `ad_dns`: each record with `ansible.windows.win_dns_record` (`computer_name` the scope when recorded, the zone, the name relative to the zone, type, values, TTL); SRV records the same with their targets, priority, weight and port; per zone the platform runs, removing what this environment wrote before and no longer wants, then rewriting its ledger (below); a `debug` task naming what it doesn't write |
| `ansible/requirements-ad-dns.yml` | The Galaxy collections the play names, pinned by `opsdir-adapter-ansible`: `ansible.windows` 3.8.0 (`community.windows.win_dns_record` is a deprecated redirect to it) |

| From the record | win_dns_record |
|---|---|
| A, AAAA, CNAME, TXT, PTR, NS | One record set per name and type with all its values |
| SRV `<priority> <weight> <port> <target>` | When the name's values share priority, weight and port: one set, `value` the targets (the module takes one priority/weight/port per name). Otherwise named, not written |
| MX, CAA, other types | Named, not written |
| `ciamTtlSeconds` (default 300) | `ttl` |

The records are the core edge domain's published records (`edge.records.published`): each service name's A and/or AAAA record (by its `ciamFrontendIp`'s address versions; `UNBOUND:<binding role>-frontend-ip`, an A record, when none is recorded) and the environment's other records (`ciamDnsRecord`: `ciamRecordName`, `ciamRecordType`, `ciamRecordValue`), in the zone bindings (`ciamDnsZoneBinding`) their names fall in. A name that routes between environments (`ciamRoutingPolicy` `failover-primary`, `failover-secondary`, `weighted`) is written once, by the environment holding the primary (for a weighted set, the first by label): a failover pair's primary address only (a DNS server doesn't fail over by itself: switching is a change to the record), a weighted set's addresses as round robin (`ciamRoutingWeight` isn't kept: DNS servers can't weight). Names in a zone another party runs (the zone binding's `ciamManagedBy`), kept by another party (the binding's `ciamManagedBy`), or in no bound zone aren't written: the on-prem provider's planner check still asks their keepers for them (`edge.records.unpublished`).

**What it wrote before.** In each zone the platform runs (`edge.records.platform_zones`: the environment's zone bindings without `ciamManagedBy`), the environment keeps a ledger: TXT records named `_opsdir-<cloud>-<env>`, one value per record set it wrote (`<type> <name>`). A run removes the record sets its ledger lists and the record no longer wants (`ansible.windows.win_powershell`: `Get-DnsServerResourceRecord` / `Remove-DnsServerResourceRecord`, on the scope's server when recorded; the script declares `SupportsShouldProcess`, so nothing is removed under `--check`), then rewrites the ledger (removed when the zone holds nothing of it any more). Records the ledger doesn't list, other teams' and other environments', are never touched; a ledger deleted by hand only means nothing is tidied on the next run.

## Planner checks

`check_appliances` (the core's `check_appliance`): a target that declares Windows DNS but records no DNS server (`ciamAppliance`, `ciamStackRole: dns`) is a blocker (area "DNS"): its records would be published nowhere.

It adds no required roles, importers, reference schemes, vocabulary, schema or secret patterns of its own; the login secret's binding is the core's appliance role (`ciamLoginSecretRole`). Its format: `ansible/*.yml` YAML.

## Known limits

- **Not yet run against a live DNS server.** The play passes ansible-core's syntax check and ansible-lint (marker `ansible`); running it is part of the testing plan (milestone 7.2).
- MX, CAA and other types `win_dns_record` doesn't take are named, not written; so is an SRV name whose values differ in priority, weight or port.
- A stale ledger entry removes every record of its type at its name in the zone, whoever wrote them: the ledger records a name and type, not values.
- Failover between environments isn't automatic on a DNS server: the primary's address is written; moving it is a change to the record. Weights of a weighted set aren't kept.

## Tests

`tests/test_windows_dns.py`: the servers' inventory with the password read at run time, the records written (SRV, NS) and the types not written, the ledger of what was written, the planner check without a DNS server, and (marker `ansible`, skipped without `tools/ansible`) the play through ansible-core and ansible-lint.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-windows-dns/tests` (unit), and with `-m ansible` for the tool checks (`opsdir/scripts/fetch-tools.sh` first).

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `ad-dns`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
