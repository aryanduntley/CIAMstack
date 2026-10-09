# opsdir-adapter-infoblox

opsdir DNS add-on: the records an environment publishes, written by Ansible through Infoblox NIOS's WAPI. It is the option beside Windows DNS (milestone 5.3, decision 2230).

**Applies to** environments whose stack declares it (`ciamStackRole: dns`, `ciamAdapter: infoblox`), beside `opsdir-adapter-ansible`. **Depends on** `opsdir` (the edge domain's published records, the infrastructure domain's appliances) and `opsdir-adapter-ansible`.

## The grid master in the record

A `ciamAppliance` with `ciamStackRole: dns`: `ciamManagementAddress` the grid master's WAPI address, `ciamApplianceScope` the DNS view (else `default`), `ciamLoginName` and `ciamLoginSecretRole` (the binding of the secret holding the password, read when the play runs).

## What it renders

| File | Content |
|---|---|
| `ansible/inventory/infoblox.yml` | Each grid master in group `infoblox` (connection `local`: the play runs on the controller), its provider (`host`, `username`, `password` as a lookup, `wapi_version` 2.12.3) and view |
| `ansible/infoblox.yml` | One task per record type present, one Infoblox record per value: `nios_a_record` (`ipv4`), `nios_aaaa_record` (`ipv6`), `nios_cname_record` (`canonical`), `nios_txt_record` (`text`); other types are named |
| `ansible/requirements-infoblox.yml` | `infoblox.nios_modules` 1.10.0 (the controller also needs the `infoblox-client` Python package) |

The records are the core edge domain's published records, as for the Windows DNS add-on: service names' A records and the environment's other records in zones the platform runs.

## Planner check

`check_appliances`: a target that declares Infoblox but records no grid master is a blocker.

## Known limits

- MX, SRV, PTR and other types are named, not written.
- A name that routes between environments is written with this environment's answer only.

## Tests

`tests/test_infoblox.py`: the grid master as provider (password read at run time), records by type, types not written, the planner check, the play through the real Ansible tools (marker `ansible`).
