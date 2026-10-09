# opsdir-adapter-onprem

opsdir provider adapter for environments on the operators' own hardware: data centers and server rooms the organization runs (`ciamCloudProvider: onprem`). Its region is the site the environment runs in; it renders nothing itself; its planner check asks the site's teams for what fronts and connects the servers.

**Applies to** environments whose cloud's `ciamCloudProvider` is `onprem` (and whose stack declares it as the provider). **Depends on** `opsdir` (the estate's region catalog, the edge and access domains).

## What it renders

Nothing. An on-prem environment's servers are configured by the configuration-management adapter (`opsdir-adapter-ansible`, milestone 5.3) and its products by the product adapters, as on any cloud. What fronts and connects the servers (load balancers, DNS, network firewalls) is rendered by an appliance add-on when the environment's stack declares one for that part (stack roles `load-balancer`, `dns`, `network-firewall`), else asked of whoever keeps it (below).

## Sites: the region catalog

An on-prem environment's cloud names its site as its region:

```ldif
dn: cloud=plant,ou=environments,dc=ciam-ops
objectClass: ciamCloud
cloud: plant
ciamCloudProvider: onprem
ciamCloudEnvironment: on-premises
ciamRegion: hq-dc1
```

No provider publishes the list of sites: the operators keep it, a JSON list, and import it like a cloud's region list (prerequisite `onprem-sites`, `opsdir prerequisites`):

```json
[{"code": "hq-dc1", "name": "Headquarters data center 1", "geography": "United States", "status": "available"}]
```

```bash
opsdir import --dry-run onprem/sites sites.json
opsdir import --change CHG-… onprem/sites sites.json
```

`code` is required (what `ciamRegion` names); `name` and `geography` as the organization calls them; `status` `available` (default) or `not-listed` (a site retired). A refresh keeps what the file doesn't give; a site the record holds that the file lacks stays, marked not-listed. So residencies allow sites as they allow cloud regions (`ciamAllowedRegion` naming `cn=<site>,cn=onprem,ou=regions,dc=ciam-ops`), and the planner's region check names a site the catalog doesn't list.

## Planner check: the site's keepers

For an on-prem target, each of these is a request to whoever keeps it (drafted under `requests/<party>.md`), unless the stack declares an add-on for its part:

| Item | Stack role that renders it instead |
|---|---|
| Each service name's load balancer (its name, ports, exposure, address when recorded, the target role's servers) | `load-balancer` |
| Each service name's DNS record, and every other DNS record | `dns` |
| Each firewall rule, on the network's firewalls (the host firewall is the configuration-management adapter's) | `network-firewall` |

Who keeps it: the binding's `ciamManagedBy` (service names and firewall rules may record one), for DNS the party running the zone the name falls in, else the site's owner (the owners of the environment's guardrails, its cloud, or the environment, as for a landing zone). An item no one is recorded to keep is an action.

## Known limits

- No on-prem Kubernetes specifics yet (a cluster on the operators' hardware is recorded as any cluster; no workload identity provider).
- Appliance add-ons (load balancers, DNS) are separate packages, chosen per environment.

## Tests

`tests/test_onprem.py`: sites read into the catalog; requests to the site's owner; actions with no keeper; an add-on in the stack removes its part; a cloud target isn't asked.
