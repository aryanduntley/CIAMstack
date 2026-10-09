# opsdir-adapter-panos

opsdir network-firewall add-on: the firewall rules an environment records, pushed by Ansible as Palo Alto Networks objects and security rules to its Panorama or PAN-OS firewalls (milestone 5.3, decision 2230: Palo Alto is what RTX's public job postings name).

**Applies to** environments whose stack declares it (`ciamStackRole: network-firewall`, `ciamAdapter: panos`), beside `opsdir-adapter-ansible`. With it declared, the on-prem provider's planner check no longer asks the site's team for these rules. **Depends on** `opsdir` (the infrastructure domain's firewall rules and appliances) and `opsdir-adapter-ansible`.

## The firewalls in the record

A `ciamAppliance` with `ciamStackRole: network-firewall`: `ciamManagementAddress` the Panorama's or firewall's address, `ciamApplianceScope` `vsys<n>` for a firewall's virtual system, anything else a Panorama device group (default `opsdir-<cloud>-<env>`), `ciamLoginName` and `ciamLoginSecretRole` (the binding of the secret holding the password, read when the play runs).

## What it renders

| File | Content |
|---|---|
| `ansible/inventory/panos.yml` | Each Panorama or firewall in group `panos` (connection `local`: the play runs on the controller), its `provider` (`ip_address`, `username`, `password` as a lookup) and its device group or vsys |
| `ansible/panos.yml` | `panos_address_object` per source range and per server of each rule's target role (its `ciamPrivateIp`), `panos_service_object` per protocol and port, `panos_security_rule` per firewall rule (`opsdir-<rule>`, zones and application `any`, action allow, logged at session end; Panorama's `pre-rulebase`); the commit tasks only with `--tags commit` (`panos_commit_panorama` then `panos_commit_push` to the device group, or `panos_commit_firewall`) |
| `ansible/requirements-panos.yml` | `paloaltonetworks.panos` 3.4.2 (the controller also needs the `pan-os-python` Python package) |

Committing is the network team's change: by default the play stages the configuration, and `ansible-playbook -i ansible/inventory ansible/panos.yml --tags commit` commits it.

## Planner check

`check_appliances`: a target that declares Palo Alto but records no Panorama or firewall is a blocker.

## Known limits

- The record names no zones or applications: rules use `any` for both; an organization's zone model is added on the firewall.
- A server with no `ciamPrivateIp` gives an `UNBOUND` address object, which PAN-OS refuses, naming it.
- Rules the record no longer holds aren't removed (objects and rules are only created or updated).

## Tests

`tests/test_panos.py`: objects and a rule per firewall rule (IPv4 and IPv6 sources, the target role's servers), Panorama device group or firewall vsys, commits only when asked, the default device group, the planner check, the play through the real Ansible tools (marker `ansible`; ansible-lint checks the modules' arguments against the installed collection).
