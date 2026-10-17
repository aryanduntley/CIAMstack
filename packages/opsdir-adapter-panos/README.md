# opsdir-adapter-panos

opsdir network-firewall add-on: the firewall rules an environment records, pushed by Ansible as Palo Alto Networks objects and security rules to its Panorama or PAN-OS firewalls (milestone 5.3, decision 2230: Palo Alto is what RTX's public job postings name), and read back, read-only, from their running configuration (milestone 6.2c): rules changed out of band, rules the record doesn't hold, rules missing, and the external allowlists that live on them.

**Applies to** environments whose stack declares it (`ciamStackRole: network-firewall`, `ciamAdapter: panos`), beside `opsdir-adapter-ansible`. With it declared, the on-prem provider's planner check (`opsdir-adapter-onprem`, `keepers.py`) no longer asks the site's team for these rules.

**Depends on** `opsdir` (the infrastructure domain's firewall rules and appliances) and `opsdir-adapter-ansible` (the appliance inventory, the login and its run-time secret lookup, the YAML writer, the pinned Galaxy requirements), and PyYAML (the round trip reads the rendered play back). At run time: the `paloaltonetworks.panos` collection and the `pan-os-python` Python package on the controller.

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

## Reading the rules back (importer `panos/running-config`)

What runs, not what is staged: the **running** configuration. Two forms, one folder per environment and appliance, `<cloud>/<env>/<appliance>/` (the appliance's record name):

| File | What it is |
|---|---|
| `running-config.xml` | An explicit running-configuration snapshot (a `<config>` document): a saved or exported **running** configuration. A candidate one, a named snapshot of the candidate, or a CLI capture is not running evidence, and a file name proves nothing: export it as the running configuration. Its `version` is named in the notices |
| `api/<scope>/<family>.xml` | What `opsdir collect` saves: the XML API's answer (`<response status="success"><result>…`) to `type=config&action=show` (the running configuration; `action=get` would be the candidate) for one family of one scope: `shared`, `device-group/<name>` (Panorama) or `vsys/<name>` (a firewall); families `pre-rulebase`, `post-rulebase`, `rulebase`, `address`, `address-group`, `service`, `service-group`. An answer that isn't `status="success"` makes the whole read incomplete, and nothing is read from that appliance (an incomplete read must never say a rule is missing) |

On a Panorama the API answers can also hold (milestone 106, decision 3293):

| File | What it is |
|---|---|
| `api/op/dg-hierarchy.xml` | `show dg-hierarchy`: each device group's parent |
| `api/op/devices.xml` | `show devices all`: each managed firewall's serial, host name, connection, software version, high availability and shared policy status |
| `api/device-group/<name>/devices.xml` | The device group's firewalls (`type=config&action=show` of its `devices`): serials and their virtual systems |
| `api/firewall/<serial>/<vsys>/pre-rulebase.xml`, `post-rulebase.xml` | The policy Panorama pushed to that firewall (`/config/panorama/vsys/entry[@name='<vsys>']/<rulebase>/security/rules`, `action=show`, read through Panorama with `target=<serial>`) |
| `api/firewall/<serial>/<vsys>/hit-count.xml` | `show rule-hit-count vsys vsys-name <vsys> rule-base security rules all`, through Panorama with `target=<serial>` |

A snapshot's device-group parents are read from its `readonly` section when it holds them.

A document with a DOCTYPE or entity declaration is refused. Where the rules are read: on a Panorama (a scope other than `vsys<n>`), in enforcement order: shared's pre-rulebase, the ancestors' pre-rulebases (highest first), the device group's pre- and post-rulebase, the ancestors' post-rulebases (nearest first), shared's post-rulebase. On a firewall, its vsys's rulebase (no scope: `vsys1`). Objects resolve in the rule's scope, then the device group's ancestors (nearest first), then shared. Ancestors are known only when the hierarchy was read (`api/op/dg-hierarchy.xml`, or a snapshot's `readonly` section); an older export without it reads as before, and an object only an ancestor holds is named as not in the export. **API answers lacking a part the read expects** (any family of the appliance's scope, its ancestors' or shared's) make the read incomplete, so nothing is read and nothing is said missing. A device group's `devices` part is optional, because older exports lack it.

**Each firewall behind the Panorama.** When the policy pushed to the device group's firewalls was read, each firewall is recorded under the Panorama's appliance (core `ciamManagedFirewall`, cn its serial: name, virtual systems, device group, connected, software version, `active, peer <serial>`, shared policy status as Panorama words it). Each of the environment's rules gets a `ciamRuleObservation` per firewall and virtual system (cn `<rule>/<vsys>`): deployed, disabled or missing in the pushed policy (matched by marker, else by the add-on's name), with its hit count, first and last hit, and when counting began (the later of the counters' last reset and the rule's creation, from PAN-OS's epoch timestamps; 0 means never). The rule's `ciamRunningState` becomes the rollup: deployed when every firewall runs it, `partial` when not, disabled or missing when they all agree. A firewall whose pushed policy wasn't read is named in a notice and given no observation. A copy of a rule on another of the environment's appliances belongs to that appliance and is never counted as an unrecorded duplicate.

**Matching.** A running rule is the record's rule its description's marker names (`opsdir <cloud>/<env>: <rule> -> role <role>`), else the one whose name the add-on writes (`opsdir-<cloud>-<env>-<rule>`, then its edited description is a fact). The rule's UUID is only evidence (it is regenerated when a firewall moves under Panorama). Another environment's marked rules are left to that environment's read.

| What the read finds | What the record gets |
|---|---|
| The rule's sources, ports, protocol, target role | Read into the rule (core.inventory, infrastructure import kind `firewall`): a difference is the import's **conflict** (`--take`: the record follows the firewall; `--keep`: the next push restores the record). A source or service that doesn't resolve leaves the record's values as they are |
| Where it runs | `ciamRunningState`: `committed` (on a Panorama: the manager's intent, **its delivery to the firewalls isn't confirmed by this read**), `deployed` (on a firewall), `disabled`, `missing` (the record holds it, no rule runs for it) |
| What the record owns that it runs otherwise | `ciamRunningFact`: `action <x>`, `log-end no`, `destination <addresses>` (not the target role's servers), `description <text>`, `source <member (why)>` and `service <member (why)>` for what doesn't resolve (address ranges, wildcards, FQDNs, dynamic groups, `application-default`, port ranges, predefined services: named, never guessed) |
| The network team's settings that limit what it admits | `ciamRunningFact`: `negate-source yes`, `negate-destination yes`, `schedule <name>`, `rulebase <where>` (not the pre-rulebase or rulebase the add-on writes to). The team's other settings (zones, application, profiles, tags, log forwarding) are theirs, never reported |
| A rule with the environment's marker the record lacks, a repeat of a matched rule, an unmarked allow to the environment's servers (their addresses or the add-on's server objects) | `ciamUnrecordedRule` on the appliance: `<scope> <rulebase> <rule>: <sources> -> <destinations> <services>` |
| An external allowlist whose `ciamAllowlistRef` is `panos:<management host>/<scope>/<address\|address-group\|rule>/<name>` and whose object the files hold | Its `ciamRecordedCidr`: the addresses the object holds (a rule's sources for `partner-ingress`, else its destinations); what doesn't resolve is named, not recorded. Its request status stays a person's: PAN-OS has no request workflow (a ticket manager's adapter would read one) |

Every observed value is replaced by the next read; values that look like secret material are withheld. `opsdir report firewall-running` lists the rules read back and the unrecorded ones; the core's planner check `check_firewall_running` makes each an action (for the source and the target of a plan).

**The round trip.** The render reads back through the same importer (`reads_back`, an intent read-back): its play and inventory become the running configuration a push leaves (`readback.py`), and reading that back changes nothing but the observed state.

## Collecting (`opsdir collect --env CLOUD/ENV --adapter panos`)

The environment's collection source for `panos/running-config` (`ciamCollectionSource`): `ciamSourceRef` the Panorama's or firewall's `https://<management address>` (one of the environment's network-firewall appliances), `ciamCredentialScheme: api-key` with `ciamCredentialRole` the binding of the API key's secret reference (sent in the `X-PAN-KEY` header, never in the URL), and `ciamCaRole` the binding of the certificate the management interface is trusted by. One `GET /api/?type=config&action=show&xpath=…` per family of the appliance's scope, of shared, and of the scopes the external allowlists on that appliance name. On a Panorama, also:
- the two operational commands of `running.OP_COMMANDS` (`show dg-hierarchy`, `show devices all`);
- the device group's `devices`, and its ancestors' families once the hierarchy is in;
- for each firewall and virtual system of the device group, through Panorama (`target=<serial>`), the pushed pre- and post-rulebase and `show rule-hit-count`.

Those op commands are the only ones the read sends, and each only shows. Names in xpaths are XPath literals (`running.literal`: `'…'`, `"…"` or `concat()`), so no name can change the path. Nothing is ever set, edited or committed.

**Acceptance items before the first live read:**
- **The xpaths are reconstructed** from Palo Alto's documented examples (`running.SCOPE_XPATHS`, `FAMILY_XPATHS`: `/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='<DG>']/pre-rulebase/security/rules`, `/config/shared/address`, …), not tried against an appliance: confirm each in the appliance's `/api/` browser.
- **The least-privilege XML API role is release-specific.** Mint the key with `type=keygen` (an HTTPS POST, never a URL) for a read-only administrator (Superuser (read-only), Device or Virtual system administrator (read-only)), short-lived. Current help describes the XML API permission as enable/disable, and a Panorama role's configuration permission as retrieving or modifying: verify on the release that the account can read and not change, and that a Panorama access domain limits what the XML API reads.
- **The `api-key` credential scheme** is the core's (milestone 6.2b, task 528): this collector builds its requests against it.

## Planner checks

`check_appliances` (the core's `check_appliance`): a target that declares Palo Alto but records no Panorama or firewall (`ciamAppliance`, `ciamStackRole: network-firewall`) is a blocker (area "Firewall"): its firewall rules would be pushed nowhere.

It adds no required roles, reference schemes, vocabulary, schema or secret patterns of its own (the read-back's observed attributes are the core's); the login secret's binding is the core's appliance role (`ciamLoginSecretRole`). Its format: `ansible/*.yml` YAML.

## Known limits

- **Not yet run against a live Panorama or firewall.** The play passes ansible-core's syntax check and ansible-lint, which checks the modules' arguments against the installed collection (marker `ansible`); running it is part of the testing plan (milestone 7.2). The read-back and its collector were built from Palo Alto's documentation only (the acceptance items above).
- Without the firewalls' pushed policy (an older export, or a firewall that couldn't be read), a Panorama's read is the manager's intent: `committed`, its delivery unconfirmed. With several network firewalls in one environment, a rule is missing only when none of them runs it.
- **Reconstructed from documentation, to confirm live (milestone 7.2):** the answer shapes of `show devices all` (the 11.x/12.x schema isn't fully published; a field it lacks is unknown, never guessed), `show dg-hierarchy` (nested `<dg name>`), `show rule-hit-count`, the pushed-policy xpath, and the device group's `devices` path. HA state comes from `show devices all` only, not `show high-availability state` per firewall. The firewalls' own local rules (between the pushed pre- and post-rulebase) aren't read.
- Panorama templates (zones, interfaces) aren't read: the record doesn't model them, and they are the network team's (decision 3293). Address ranges, wildcards, FQDNs, dynamic groups, `application-default`, port ranges and predefined services are named, never resolved; a rule using one keeps the record's sources or ports.
- Only allow rules are the record's: a matched rule whose action isn't allow is drift (`action <x>`), an unmarked deny is the team's.
- A server with no `ciamPrivateIp`, or a target role with no servers, gives an `UNBOUND` address object or destination, which PAN-OS refuses, naming it.
- Address and service objects the record no longer uses aren't removed (another rule may still use them; PAN-OS refuses deleting a used object): unused ones are harmless and named nowhere.
- Only allow rules on the pre-rulebase (Panorama) or the firewall's rulebase: the record's rules are inbound allows; denies, NAT and decryption policy stay the network team's.

## Tests

`tests/test_running.py`: a snapshot and the API answers read alike, what isn't running evidence refused, addresses and services resolved or named, a push's running configuration read back as committed and nothing else, drift read into the rule (a conflict), observed (state, facts) and named on the appliance (unrecorded), a firewall's vsys deployed, an external allowlist's addresses, the collector's read-only requests and why it can't read, the render's round trip.

`tests/test_delivery.py`: a device-group hierarchy resolving an ancestor's objects; each firewall's pushed policy and hit counts read into managed firewalls and rule observations, and the rollup (deployed, partial, disabled); the core's actions for a partial rule, a disconnected firewall and an unused rule (and none for a used or young one); the report rows; answers lacking an expected part read nothing; older exports without the hierarchy still read; names in xpaths as literals; the collector's later steps (ancestors, each firewall through `target`), with no write ever.

`tests/test_panos.py`: objects and a rule per firewall rule (IPv4 and IPv6 sources, the target role's servers), names per environment and their digest, priority order, Panorama device group or firewall vsys (no scope: vsys1), the team's settings kept and placement only on create, stale rules removed, every commit task tagged `commit` and `never` with the login as its only admin, the planner check without a firewall, and (marker `ansible`, skipped without `tools/ansible`) the play through ansible-core and ansible-lint.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-panos/tests` (unit), and with `-m ansible` for the tool checks (`opsdir/scripts/fetch-tools.sh` first).

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `panos`); nothing in the opsdir core changes (the observed attributes, check and report it fills are the core's infrastructure domain's). In this repository: `opsdir/scripts/dev-install.sh`.
