# opsdir-adapter-panos

opsdir network-firewall add-on: the firewall rules an environment records, pushed by Ansible as Palo Alto Networks objects and security rules to its Panorama or PAN-OS firewalls (milestone 5.3, decision 2230: Palo Alto is what RTX's public job postings name).

**Applies to** environments whose stack declares it (`ciamStackRole: network-firewall`, `ciamAdapter: panos`), beside `opsdir-adapter-ansible`. With it declared, the on-prem provider's planner check no longer asks the site's team for these rules. **Depends on** `opsdir` (the infrastructure domain's firewall rules and appliances) and `opsdir-adapter-ansible`.

## The firewalls in the record

A `ciamAppliance` with `ciamStackRole: network-firewall`: `ciamManagementAddress` the Panorama's or firewall's address, `ciamApplianceScope` `vsys<n>` for a firewall's virtual system (none: a standalone firewall, `vsys1`), anything else a Panorama device group, `ciamLoginName` and `ciamLoginSecretRole` (the binding of the secret holding the password, read when the play runs).

## What it renders

| File | Content |
|---|---|
| `ansible/inventory/panos.yml` | Each Panorama or firewall in group `panos` (connection `local`: the play runs on the controller, with the controller's own Python, `ansible_playbook_python`, where `pan-os-python` is installed), its `provider` (`ip_address`, `username`, `password` as a lookup) and its device group or vsys |
| `ansible/panos.yml` | The login read once (`set_fact`, `no_log`, every tag); `panos_address_object` per source range (`opsdir-<range>`, shared by environments) and per server of each rule's target role (`opsdir-<cloud>-<env>-<server>`, its `ciamPrivateIp`); `panos_service_object` per protocol and port; the environment's rules as the firewall has them (`panos_security_rule` `state: gathered`, by their description `opsdir <cloud>/<env>: ...`); `panos_security_rule` per firewall rule (below; Panorama's `pre-rulebase`); the rules the environment wrote before and the record no longer holds, removed; the commit tasks only with `--tags commit` |
| `ansible/requirements-panos.yml` | `paloaltonetworks.panos` 3.4.2 (the controller also needs the `pan-os-python` Python package) |

**A security rule** is `opsdir-<cloud>-<env>-<rule>` (names longer than PAN-OS's 63 characters are cut and given a digest of the whole, so two never meet). The record owns its sources, destinations, services, action (allow), logging at session end and description; the network team owns the rest. A run keeps what the firewall has for zones, application, profiles (or profile group), tags, log forwarding, schedule, rule type, user, category, HIP profiles, negation, disabled and where the rule sits; a new rule gets zones and application `any` and is placed at the top, after the environment's rule before it in `ciamRulePriority` order (unpinned rules last, by name). Since the record's lists replace the firewall's, a source the record drops stops being allowed.

**Committing** is the network team's change: by default the play stages the configuration, and `ansible-playbook -i ansible/inventory ansible/panos.yml --tags commit` commits it, only the opsdir login's own changes (`admins`): `panos_commit_panorama` to the environment's device group then `panos_commit_push` to it, or `panos_commit_firewall`. Other administrators' pending changes stay theirs.

## Planner check

`check_appliances`: a target that declares Palo Alto but records no Panorama or firewall is a blocker.

## Known limits

- A server with no `ciamPrivateIp` gives an `UNBOUND` address object, which PAN-OS refuses, naming it.
- Address and service objects the record no longer uses aren't removed (another rule may still use them; PAN-OS refuses deleting a used object): unused ones are harmless and named nowhere.

## Tests

`tests/test_panos.py`: objects and a rule per firewall rule (IPv4 and IPv6 sources, the target role's servers), names per environment and their digest, priority order, Panorama device group or firewall vsys (no scope: vsys1), the team's settings kept and placement only on create, stale rules removed, every commit task tagged `commit` and `never` with the login as its only admin, the planner check, the play through the real Ansible tools (marker `ansible`; ansible-lint checks the modules' arguments against the installed collection).
