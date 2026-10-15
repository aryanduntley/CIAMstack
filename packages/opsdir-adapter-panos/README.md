# opsdir-adapter-panos

opsdir network-firewall add-on: the firewall rules an environment records, pushed by Ansible as Palo Alto Networks objects and security rules to its Panorama or PAN-OS firewalls (milestone 5.3, decision 2230: Palo Alto is what RTX's public job postings name).

**Applies to** environments whose stack declares it (`ciamStackRole: network-firewall`, `ciamAdapter: panos`), beside `opsdir-adapter-ansible`. With it declared, the on-prem provider's planner check (`opsdir-adapter-onprem`, `keepers.py`) no longer asks the site's team for these rules.

**Depends on** `opsdir` (the infrastructure domain's firewall rules and appliances) and `opsdir-adapter-ansible` (the appliance inventory, the login and its run-time secret lookup, the YAML writer, the pinned Galaxy requirements). At run time: the `paloaltonetworks.panos` collection and the `pan-os-python` Python package on the controller.

## The firewalls in the record

A `ciamAppliance` with `ciamStackRole: network-firewall` (the core's class): `ciamManagementAddress` the Panorama's or firewall's address; `ciamApplianceScope` `vsys<n>` for a firewall's virtual system (none: a standalone firewall, `vsys1`), anything else a Panorama device group; `ciamLoginName` and `ciamLoginSecretRole` (the binding of the secret holding the password, read when the play runs).

## What it renders

Per environment, nothing environment-neutral:

| File | Content |
|---|---|
| `ansible/inventory/panos.yml` | Each Panorama or firewall a host of group `panos` by its record name (connection `local`: the play runs on the controller, with the controller's own Python, `ansible_playbook_python`, where `pan-os-python` is installed): `ciam_panos_provider` (`ip_address` its management address, `username` its `ciamLoginName`, `password` a run-time lookup of its login secret) and `ciam_panos_device_group` or `ciam_panos_vsys`. An unrecorded login name or unbound secret role is `UNBOUND:<appliance>-login` / `UNBOUND:<secret role>` |
| `ansible/panos.yml` | One play on group `panos`, each task on the host's device group or vsys (Panorama rules in its `pre-rulebase`): the login read once (`set_fact`, `no_log`, tag `always`); address objects; service objects; the environment's rules as the firewall has them (`panos_security_rule` `state: gathered`, filtered on their description starting `opsdir <cloud>/<env>:`); a security rule per firewall rule; the rules the environment wrote before and the record no longer holds, removed (`state: absent`); the commit tasks (tags `commit`, `never`). Every object and rule task has tag `rules` |
| `ansible/requirements-panos.yml` | The Galaxy collections the play names, pinned by `opsdir-adapter-ansible` (`paloaltonetworks.panos` 3.4.2); its header names the `pan-os-python` package the controller also needs |

| From the record (`ciamFirewallRule`) | PAN-OS |
|---|---|
| Each `ciamSourceCidr` | `panos_address_object` `opsdir-<range, / as _>` (`ip-netmask`): named by the range, the same object in every environment |
| Each server of `ciamTargetRole` | `panos_address_object` `opsdir-<cloud>-<env>-<server>`, its `ciamPrivateIp` (else `UNBOUND:<server>-address`): environments sharing a firewall don't overwrite each other's |
| `ciamProtocol` (default `tcp`), each `ciamPort` | `panos_service_object` `opsdir-<protocol>-<port>` (`destination_port`), shared by environments |
| The rule | `panos_security_rule` `opsdir-<cloud>-<env>-<rule>`: those sources, destinations (the role's servers; `UNBOUND:<role>-servers` when it has none) and services, `action: allow`, `log_end: true`, description `opsdir <cloud>/<env>: <rule> -> role <role>` |
| `ciamRulePriority` | Where a new rule is placed: at the top, or after the environment's rule before it in priority order (unpinned rules last, by name) |

Names are `opsdir-<…>` in PAN-OS's characters (letters, digits, `.`, `_`, `-`; others become `-`); a name longer than PAN-OS's 63 characters is cut and given an 8-character SHA-256 digest of the whole, so two never meet.

**Who owns what on a rule.** The record owns its sources, destinations, services, action (allow), logging at session end and description; the network team owns the rest. A run keeps what the firewall has for zones and application (a new rule: `any`), user, category, HIP profiles, tags and group tag, log forwarding and log at session start, schedule, rule type, the profile group or each security profile, disabled, negation, ICMP unreachable, server response inspection, and where the rule sits (`location` and `existing_rule` only on create). Since the record's lists replace the firewall's, a source the record drops stops being allowed.

**Committing** is the network team's change: by default the play stages the configuration; `ansible-playbook -i ansible/inventory ansible/panos.yml --tags commit` runs only the login and the commit tasks, which commit only the opsdir login's own changes (`admins`): `panos_commit_panorama` of the environment's device group, then `panos_commit_push` to it (`style: device group`), or `panos_commit_firewall`. Other administrators' pending changes stay theirs.

## Planner checks

`check_appliances` (the core's `check_appliance`): a target that declares Palo Alto but records no Panorama or firewall (`ciamAppliance`, `ciamStackRole: network-firewall`) is a blocker (area "Firewall"): its firewall rules would be pushed nowhere.

It adds no required roles, importers, reference schemes, vocabulary, schema or secret patterns of its own; the login secret's binding is the core's appliance role (`ciamLoginSecretRole`). Its format: `ansible/*.yml` YAML.

## Known limits

- **Not yet run against a live Panorama or firewall.** The play passes ansible-core's syntax check and ansible-lint, which checks the modules' arguments against the installed collection (marker `ansible`); running it is part of the testing plan (milestone 7.2).
- A server with no `ciamPrivateIp`, or a target role with no servers, gives an `UNBOUND` address object or destination, which PAN-OS refuses, naming it.
- Address and service objects the record no longer uses aren't removed (another rule may still use them; PAN-OS refuses deleting a used object): unused ones are harmless and named nowhere.
- Only allow rules on the pre-rulebase (Panorama) or the firewall's rulebase: the record's rules are inbound allows; denies, NAT and decryption policy stay the network team's.

## Tests

`tests/test_panos.py`: objects and a rule per firewall rule (IPv4 and IPv6 sources, the target role's servers), names per environment and their digest, priority order, Panorama device group or firewall vsys (no scope: vsys1), the team's settings kept and placement only on create, stale rules removed, every commit task tagged `commit` and `never` with the login as its only admin, the planner check without a firewall, and (marker `ansible`, skipped without `tools/ansible`) the play through ansible-core and ansible-lint.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-panos/tests` (unit), and with `-m ansible` for the tool checks (`opsdir/scripts/fetch-tools.sh` first).

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `panos`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
