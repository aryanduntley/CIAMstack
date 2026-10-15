# opsdir-adapter-infoblox

opsdir DNS add-on: the records an environment publishes, written by Ansible through Infoblox NIOS's WAPI. It is the option beside Windows DNS (`opsdir-adapter-windows-dns`, the default; milestone 5.3, decision 2230).

**Applies to** environments whose stack declares it (`ciamStackRole: dns`, `ciamAdapter: infoblox`), beside `opsdir-adapter-ansible`. With it declared, the on-prem provider's planner check (`opsdir-adapter-onprem`, `keepers.py`) asks the zones' keepers only for the names this add-on can't write. WAPI version 2.12.3 (the collection's minimum).

**Depends on** `opsdir` (the edge domain's published records, `opsdir.domains.edge.records`; the infrastructure domain's appliances) and `opsdir-adapter-ansible` (the appliance inventory, the login and its run-time secret lookup, the YAML writer, the pinned Galaxy requirements). At run time: the `infoblox.nios_modules` collection and the `infoblox-client` Python package on the controller.

## The grid master in the record

A `ciamAppliance` with `ciamStackRole: dns` (the core's class): `ciamManagementAddress` the grid master's WAPI address, `ciamApplianceScope` the DNS view (else `default`), `ciamLoginName` and `ciamLoginSecretRole` (the binding of the secret holding the password, read when the play runs).

## What it renders

Per environment, nothing environment-neutral:

| File | Content |
|---|---|
| `ansible/inventory/infoblox.yml` | Each grid master a host of group `infoblox` by its record name (connection `local`: the play runs on the controller, with the controller's own Python, `ansible_playbook_python`, where `infoblox-client` is installed): `ciam_nios_view` its view and `ciam_nios_provider` (`host` its management address, `wapi_version` 2.12.3, `validate_certs: true`: the collection's default is off, `username` its `ciamLoginName`, `password` a run-time lookup of its login secret). An unrecorded login name or unbound secret role is `UNBOUND:<appliance>-login` / `UNBOUND:<secret role>` |
| `ansible/infoblox.yml` | One play on group `infoblox`: the login read once (`set_fact`, `no_log`: not once per record); one task per record type present, one Infoblox record per value (`state: present`, the view, `ttl`, the comment `opsdir <cloud>/<env>`); then, for every type it writes, removing the records carrying the comment in the view that the record no longer wants (found with `nios_lookup`, compared by name and fields); a `debug` task naming the records of types it doesn't write |
| `ansible/requirements-infoblox.yml` | The Galaxy collections the play names, pinned by `opsdir-adapter-ansible` (`infoblox.nios_modules` 1.10.0); its header names the `infoblox-client` package the controller also needs |

| From the record | Infoblox module (fields) |
|---|---|
| A | `nios_a_record` (`ipv4addr`) |
| AAAA | `nios_aaaa_record` (`ipv6addr`) |
| CNAME | `nios_cname_record` (`canonical`) |
| TXT | `nios_txt_record` (`text`) |
| MX `<preference> <exchange>` | `nios_mx_record` (`preference`, `mail_exchanger`) |
| SRV `<priority> <weight> <port> <target>` | `nios_srv_record` (`priority`, `weight`, `port`, `target`) |
| PTR | `nios_ptr_record` (`ptrdname`) |
| `ciamTtlSeconds` (default 300) | `ttl` |

The records are the core edge domain's published records (`edge.records.published`): each service name's A and/or AAAA record (by its `ciamFrontendIp`'s address versions; `UNBOUND:<binding role>-frontend-ip`, an A record, when none is recorded) and the environment's other records (`ciamDnsRecord`: `ciamRecordName`, `ciamRecordType`, `ciamRecordValue`), in the zone bindings (`ciamDnsZoneBinding`) their names fall in. A name that routes between environments (`ciamRoutingPolicy` `failover-primary`, `failover-secondary`, `weighted`) is written once, by the environment holding the primary (for a weighted set, the first by label): a failover pair's primary address only (a DNS server doesn't fail over by itself: switching is a change to the record), a weighted set's addresses as round robin (`ciamRoutingWeight` isn't kept: DNS servers can't weight). Names in a zone another party runs (the zone binding's `ciamManagedBy`), kept by another party (the binding's `ciamManagedBy`), or in no bound zone aren't written: the on-prem provider's planner check still asks their keepers for them (`edge.records.unpublished`). Records without this environment's comment (other teams', other environments') are never touched.

## Planner checks

`check_appliances` (the core's `check_appliance`): a target that declares Infoblox but records no grid master (`ciamAppliance`, `ciamStackRole: dns`) is a blocker (area "DNS"): its records would be published nowhere.

It adds no required roles, importers, reference schemes, vocabulary, schema or secret patterns of its own; the login secret's binding is the core's appliance role (`ciamLoginSecretRole`). Its format: `ansible/*.yml` YAML.

## Known limits

- **Not yet run against a live grid.** The play passes ansible-core's syntax check and ansible-lint (marker `ansible`); running it is part of the testing plan (milestone 7.2).
- CAA and other types the collection has no module for are named by the play, not written.
- Failover between environments isn't automatic on a DNS server (Infoblox DTC isn't used): the primary's address is written; moving it is a change to the record. Weights of a weighted set aren't kept.
- The play runs against every grid master recorded (group `infoblox`), each writing the same records in its own view.

## Tests

`tests/test_infoblox.py`: the grid master as provider (verified TLS, the password read once at run time), records by type with the environment's comment, the clean-up of what it wrote before, the planner check without a grid master, and (marker `ansible`, skipped without `tools/ansible`) the play through ansible-core and ansible-lint.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-infoblox/tests` (unit), and with `-m ansible` for the tool checks (`opsdir/scripts/fetch-tools.sh` first).

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `infoblox`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
