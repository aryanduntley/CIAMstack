# opsdir-adapter-infoblox

opsdir DNS add-on: the records an environment publishes, written by Ansible through Infoblox NIOS's WAPI. It is the option beside Windows DNS (milestone 5.3, decision 2230).

**Applies to** environments whose stack declares it (`ciamStackRole: dns`, `ciamAdapter: infoblox`), beside `opsdir-adapter-ansible`. **Depends on** `opsdir` (the edge domain's published records, the infrastructure domain's appliances) and `opsdir-adapter-ansible`.

## The grid master in the record

A `ciamAppliance` with `ciamStackRole: dns`: `ciamManagementAddress` the grid master's WAPI address, `ciamApplianceScope` the DNS view (else `default`), `ciamLoginName` and `ciamLoginSecretRole` (the binding of the secret holding the password, read when the play runs).

## What it renders

| File | Content |
|---|---|
| `ansible/inventory/infoblox.yml` | Each grid master in group `infoblox` (connection `local`: the play runs on the controller, with the controller's own Python, `ansible_playbook_python`, where `infoblox-client` is installed), its provider (`host`, `username`, `password` as a lookup, `wapi_version` 2.12.3, `validate_certs: true`: the collection's default is off) and view |
| `ansible/infoblox.yml` | The login read once (`set_fact`, `no_log`: not once per record), then one task per record type present, one Infoblox record per value, each with the comment `opsdir <cloud>/<env>`: `nios_a_record` (`ipv4addr`), `nios_aaaa_record` (`ipv6addr`), `nios_cname_record` (`canonical`), `nios_txt_record` (`text`), `nios_mx_record` (`preference`, `mail_exchanger`), `nios_srv_record` (`priority`, `weight`, `port`, `target`), `nios_ptr_record` (`ptrdname`); then, per type, removing the records carrying the comment in the view that the record no longer wants (found with `nios_lookup`); other types are named |
| `ansible/requirements-infoblox.yml` | `infoblox.nios_modules` 1.10.0 (the controller also needs the `infoblox-client` Python package) |

The records are the core edge domain's published records (`edge.records.published`): each service name's A or AAAA record (by its `ciamFrontendIp`'s version; `UNBOUND:<role>-frontend-ip` when none is recorded) and the environment's other records (`ciamDnsRecord`), in the zone bindings their names fall in. A name that routes between environments is written once, by the environment that renders its routing: a failover pair's primary address only (a DNS server doesn't fail over by itself: switching is a change to the record), a weighted set's addresses as round robin (DNS servers can't weight). Names in a zone another party runs (`ciamManagedBy`), kept by another party (the binding's `ciamManagedBy`), or in no bound zone aren't written: the on-prem provider's planner check still asks their keepers for them (`edge.records.unpublished`). Records without this environment's comment (other teams', other environments') are never touched.

## Planner check

`check_appliances`: a target that declares Infoblox but records no grid master is a blocker.

## Known limits

- CAA and other types the collection has no module for are named, not written.
- Failover between environments isn't automatic on a DNS server (Infoblox DTC isn't used): the primary's address is written; moving it is a change to the record.

## Tests

`tests/test_infoblox.py`: the grid master as provider (verified TLS, password read once at run time), records by type with the environment's comment, the clean-up of what it wrote before, the planner check, the play through the real Ansible tools (marker `ansible`).
