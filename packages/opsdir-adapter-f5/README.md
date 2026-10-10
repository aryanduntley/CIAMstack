# opsdir-adapter-f5

opsdir load-balancer add-on: an environment's service names on F5 BIG-IP, as an AS3 declaration per tenant deployed by Ansible (`f5networks.f5_bigip.bigip_as3_deploy`). It is the default on-prem load balancer (milestone 5.3, decision 2230: the DoD/defense norm, with a DISA STIG); HAProxy (`opsdir-adapter-haproxy`) is the open-source option.

**Applies to** environments whose stack declares it (`ciamStackRole: load-balancer`, `ciamAdapter: f5-bigip`), beside `opsdir-adapter-ansible`. With it declared, the on-prem provider's planner check no longer asks the site's team for these load balancers. **Depends on** `opsdir` (the edge domain's policies, the infrastructure domain's appliances) and `opsdir-adapter-ansible`.

## The BIG-IPs in the record

```ldif
dn: cn=bigip-1,ou=bindings,env=prod,cloud=plant,ou=environments,dc=ciam-ops
objectClass: ciamAppliance
cn: bigip-1
ciamBindingRole: lb-bigip-1
ciamStackRole: load-balancer
ciamManagementAddress: bigip-1.mgmt.example.test
ciamApplianceScope: CIAM_Prod
ciamLoginName: opsdir-as3
ciamLoginSecretRole: bigip-login
ciamApplianceSource: 10.80.9.0/28
```

`ciamApplianceScope` is the AS3 tenant (else `opsdir_<cloud>_<env>`). AS3 replaces a tenant whole, so the tenant must be this environment's alone: another team's applications in it would be removed by the next deployment. BIG-IPs with the same scope are one device cluster (an HA pair syncing its configuration): the play deploys to the first of them only. `ciamLoginSecretRole` names the binding (a secret reference) holding the login's password, read when the play runs. `ciamApplianceSource` (any number) is where the BIG-IP's own traffic to the servers comes from: its source NAT pool and self addresses, health monitors included.

## What it renders

| File | Content |
|---|---|
| `ansible/f5/as3-<tenant>.json` | Per tenant, the AS3 request (`class AS3`, `action deploy`, `persist`), declaration schema 3.54.0 (the AS3 LTS): the tenant, an application per service name. None when the environment has no service names: an empty declaration would remove everything in the tenant |
| `ansible/f5-bigip.yml` | A play per tenant on the first BIG-IP of its group (`f5_<tenant>[0]`): `bigip_as3_deploy` of its declaration (tag `deploy`), and the same with `controls.dry_run` (tags `dry-run`, `never`: `--tags dry-run` asks AS3 to check it without deploying). With no service names, a message saying nothing is deployed |
| `ansible/inventory/f5-bigip.yml` | Each BIG-IP (`ciamAppliance` with stack role `load-balancer`) in group `f5_bigip` and its tenant's group `f5_<tenant>`: `ansible.netcommon.httpapi` to its `ciamManagementAddress` (HTTPS, certificate validated), `ansible_user` its `ciamLoginName`, `ansible_httpapi_password` a lookup of its login secret |
| `ansible/requirements-f5-bigip.yml` | `f5networks.f5_bigip` 3.14.0, `ansible.netcommon` 8.7.1 |

Per service name and port, from its policies (the core edge domain's `EdgeSpec`, as every cloud's front):

| Policy | AS3 |
|---|---|
| none, or `ciamTlsMode: passthrough` | `Service_TCP` over a pool of the target role's servers (`ciamPrivateIp` on the same port), monitor `tcp` |
| `terminate` | `Service_HTTPS` (`redirect80` off), `serverTLS` a `TLS_Server` presenting the service name's certificate as the BIG-IP holds it (`Certificate` `{bigip: /Common/<certificate>.crt}` and `.key`: the key never enters a declaration), the TLS versions under `ciamTlsMinVersion` off; an `http`/`https` `Monitor` sending the health path with the service name as `Host` |
| `reencrypt` | as `terminate`, and `clientTLS` a `TLS_Client` (`validateCertificate` unless `ciamBackendValidation: none`) |
| `ciamStickiness: cookie` | `persistenceMethods: [cookie]` |
| request inspection (WAF mode, categories, rate limits, address or country rules) | `policyWAF` `{bigip: /Common/<protection policy>}`: the BIG-IP's WAF policy named after the protection policy |

A value the record can't give is `UNBOUND:<what>` (a server or frontend address): AS3 refuses the declaration, naming it.

## Planner check

`check_appliances`: a target that declares F5 BIG-IP but records no load-balancer appliance is a blocker. The infrastructure domain's `check_appliance_sources` (any load balancer) names each service name's port that no firewall rule admits the BIG-IP's `ciamApplianceSource` ranges on, to the role behind it: without such a rule the servers' host firewall (and a network firewall the record drives) drops the BIG-IP's connections and health monitors.

## Validation

`opsdir/scripts/validate-ansible.sh` checks `ansible/f5/*.json` against AS3's JSON schema 3.54.0 (`fetch-tools.sh` fetches it, SHA-256 pinned) besides the play's syntax and lint (pytest marker `ansible`). Before deploying, `--tags dry-run` asks the BIG-IP itself (`controls.dry_run`).

## Known limits

- The service names' certificates and keys must already be on the BIG-IPs under their certificate names (`/Common/<name>.crt`, `.key`); the WAF policies under their protection policies' names. Neither is uploaded by the play.
- `TLS_Client` doesn't name a CA bundle: the BIG-IP's default trust applies when it validates the servers.
- Rate limits, address and country rules are the WAF policy's (not rendered as iRules).

## Tests

`tests/test_f5.py`: an HTTPS virtual server for a terminating service name, a TCP one without a policy, the BIG-IPs' inventory with the password read at run time, a play per tenant on its first BIG-IP with the dry run, no declaration for an environment without service names, the requirements, the planner check, and the declaration against the AS3 schema with the real Ansible tools (marker `ansible`).
