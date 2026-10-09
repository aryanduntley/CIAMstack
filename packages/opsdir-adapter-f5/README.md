# opsdir-adapter-f5

opsdir load-balancer add-on: an environment's service names on F5 BIG-IP, as one AS3 declaration deployed by Ansible (`f5networks.f5_bigip.bigip_as3_deploy`). It is the default on-prem load balancer (milestone 5.3, decision 2230: the DoD/defense norm, with a DISA STIG); HAProxy (`opsdir-adapter-haproxy`) is the open-source option.

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
```

`ciamApplianceScope` is the AS3 tenant (else `opsdir_<cloud>_<env>`); `ciamLoginSecretRole` names the binding (a secret reference) holding the login's password, read when the play runs.

## What it renders

| File | Content |
|---|---|
| `ansible/f5/as3.json` | The AS3 request (`class AS3`, `action deploy`, `persist`), declaration schema 3.54.0 (the AS3 LTS): the tenant, an application per service name |
| `ansible/f5-bigip.yml` | The play on group `f5_bigip`: `bigip_as3_deploy` of the declaration for the tenant |
| `ansible/inventory/f5-bigip.yml` | Each BIG-IP (`ciamAppliance` with stack role `load-balancer`) in group `f5_bigip`: `ansible.netcommon.httpapi` to its `ciamManagementAddress` (HTTPS, certificate validated), `ansible_user` its `ciamLoginName`, `ansible_httpapi_password` a lookup of its login secret |
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

`check_appliances`: a target that declares F5 BIG-IP but records no load-balancer appliance is a blocker.

## Validation

`opsdir/scripts/validate-ansible.sh` checks `ansible/f5/*.json` against AS3's JSON schema 3.54.0 (`fetch-tools.sh` fetches it, SHA-256 pinned) besides the play's syntax and lint (pytest marker `ansible`). Before a first deployment, `bigip_as3_deploy`'s `controls.dry_run` asks the BIG-IP itself.

## Known limits

- The service names' certificates and keys must already be on the BIG-IPs under their certificate names (`/Common/<name>.crt`, `.key`); the WAF policies under their protection policies' names. Neither is uploaded by the play.
- `TLS_Client` doesn't name a CA bundle: the BIG-IP's default trust applies when it validates the servers.
- Rate limits, address and country rules are the WAF policy's (not rendered as iRules).

## Tests

`tests/test_f5.py`: an HTTPS virtual server for a terminating service name, a TCP one without a policy, the BIG-IPs' inventory with the password read at run time, the play and requirements, the planner check, and the declaration against the AS3 schema with the real Ansible tools (marker `ansible`).
