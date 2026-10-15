# opsdir-adapter-onprem

opsdir provider adapter for environments on the operators' own hardware: data centers and server rooms the organization runs (`ciamCloudProvider: onprem`). Its region is the site the environment runs in, read from the organization's own list of sites into the region catalog; it renders nothing itself; its planner check asks the site's teams for what fronts and connects the servers, unless an add-on in the stack renders it.

**Applies to** environments whose cloud's `ciamCloudProvider` is `onprem` (kind `provider`): an environment that declares a stack uses it only when the stack names it (`onprem`); one that declares none, by its cloud's provider. **Depends on** `opsdir` (the estate's region catalog, the edge, access and infrastructure domains).

## What it renders

Nothing. An on-prem environment's servers are configured by the configuration-management adapter (`opsdir-adapter-ansible`) and its products by the product adapters, as on any cloud. What fronts and connects the servers (load balancers, DNS, network firewalls) is rendered by an appliance add-on when the environment's stack declares one for that part (stack roles `load-balancer`, `dns`, `network-firewall`: opsdir-adapter-f5, -haproxy, -infoblox, -windows-dns, -panos), else asked of whoever keeps it (below).

## What it reads back: sites, the region catalog

An on-prem environment's cloud names its site as its region:

```ldif
dn: cloud=plant,ou=environments,dc=ciam-ops
objectClass: ciamCloud
cloud: plant
ciamCloudProvider: onprem
ciamCloudEnvironment: on-premises
ciamRegion: hq-dc1
```

No provider publishes the list of sites: the operators keep it, a JSON list, and import it like a cloud's region list (importer `onprem/sites`; prerequisite `onprem-sites`, `opsdir prerequisites`):

```json
[{"code": "hq-dc1", "name": "Headquarters data center 1", "geography": "United States", "status": "available"}]
```

```bash
opsdir import --dry-run onprem/sites sites.json
opsdir import --change CHG-… onprem/sites sites.json
```

`code` is required (what `ciamRegion` names); `name` and `geography` as the organization calls them; `status` `available` (default, also for any other value) or `not-listed` (a site retired). Each site is a region of the `onprem` provider in the `on-premises` partition (`cn=<site>,cn=onprem,ou=regions,dc=ciam-ops`, core `estate.regions`). A refresh keeps what the file doesn't give; a site the record holds that the file lacks stays, marked not-listed. A file that isn't a JSON list is named, not read. So residencies allow sites as they allow cloud regions (`ciamAllowedRegion` naming the site's entry), and the planner's region check names a site the catalog doesn't list. The adapter renders nothing, so it has no read-back (`reads_back`); its guarantee is that importing the same list again changes nothing.

## Planner check: the site's keepers

`check_keepers` (area `On-prem`), for an on-prem target: each of these is a request to whoever keeps it (drafted under `requests/<party>.md`, at the move's cutover), unless the stack declares an add-on for its part:

| From the record | Asked for | Stack role that renders it instead |
|---|---|---|
| each service name (`ciamServiceName`) | a load balancer for its `ciamFqdn` (address `ciamFrontendIp` when recorded, its ports, `ciamExposure`, in front of the target role's servers by host name) | `load-balancer` |
| each service name; each `ciamDnsRecord` | the service name's DNS record answering its load balancer's address; every other DNS record (type, name, values) | `dns` |
| with a DNS add-on: the names it can't write (core `edge.records.unpublished`: in a zone another party runs, in no bound zone, or kept by another party) | their DNS records, still asked for | |
| each firewall rule (`ciamFirewallRule`) | the rule on the network's firewalls (source ranges, target role, ports); the host firewall is the configuration-management adapter's | `network-firewall` |

Who keeps it: the binding's `ciamManagedBy` (service names and firewall rules may record one), for DNS the party running the zone the name falls in, else the site's owner (the owners of the environment's guardrails, its cloud, or the environment, as for a landing zone). An item no one is recorded to keep is an action, owned by the binding's responsible team. A cloud target isn't asked.

## References, vocabulary and prerequisites it owns

Vocabulary: `ciamCloudProvider`, `ciamOnProvider` (`onprem`) and `ciamCloudEnvironment` (`on-premises`). Prerequisite `onprem-sites` (the region catalog holds the onprem provider's regions). No reference schemes, schema, secret patterns or required roles.

## Known limits

- **Nothing rendered for what fronts the servers** without an add-on: the requests are the hand-off.
- No on-prem Kubernetes specifics yet (a cluster on the operators' hardware is recorded as any cluster; no workload identity provider, so the kubernetes adapter writes no cloud identity for its service accounts).
- Appliance add-ons (load balancers, DNS, firewalls) are separate packages, chosen per environment.
- Not run against a live site: the requests and the sites import are tested offline.

## Tests

`tests/test_onprem.py`: sites read into the catalog as the onprem regions; the same list imported again changes nothing; actions for a target with no keeper; requests to the site's owner unless an add-on renders its part; a DNS add-on still leaving the names it can't write to their keepers; a cloud target isn't asked.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-onprem/tests`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `onprem`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
