# opsdir-adapter-f5

opsdir load-balancer add-on: an environment's service names on F5 BIG-IP, as an AS3 declaration per tenant deployed by Ansible (`f5networks.f5_bigip.bigip_as3_deploy`). It is the default on-prem load balancer (milestone 5.3, decision 2230: the DoD/defense norm, with a DISA STIG); HAProxy (`opsdir-adapter-haproxy`) is the open-source option.

**Applies to** environments whose stack declares it (`ciamStackRole: load-balancer`, `ciamAdapter: f5-bigip`), beside `opsdir-adapter-ansible`. With it declared, the on-prem provider's planner check (`opsdir-adapter-onprem`, `keepers.py`) no longer asks the site's team for these load balancers. AS3 declaration schema 3.54.0 (the AS3 LTS).

**Depends on** `opsdir` (the edge domain's policies, `opsdir.domains.edge.resolve`; the infrastructure domain's appliances, `opsdir.domains.infrastructure.appliances`) and `opsdir-adapter-ansible` (Ansible names, the YAML file writer, the login and secret lookups, the pinned Galaxy requirements). At run time: the `f5networks.f5_bigip` and `ansible.netcommon` collections.

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

Every `ciamAppliance` with `ciamStackRole: load-balancer` is a BIG-IP (the class and its attributes are the core's). `ciamApplianceScope` is the AS3 tenant (else `opsdir_<cloud>_<env>`; either made an AS3 name: letters, digits and underscores, starting with a letter). AS3 replaces a tenant whole, so the tenant must be this environment's alone: another team's applications in it would be removed by the next deployment. BIG-IPs with the same scope are one device cluster (an HA pair syncing its configuration): the play deploys to the first of them only. `ciamLoginSecretRole` names the binding (a secret reference) holding the login's password, read when the play runs. `ciamApplianceSource` (any number) is where the BIG-IP's own traffic to the servers comes from: its source NAT pool and self addresses, health monitors included.

## What it renders

Per environment, nothing environment-neutral:

| File | Content |
|---|---|
| `ansible/f5/as3-<tenant>.json` | Per tenant, the AS3 request (`class AS3`, `action deploy`, `persist`), its ADC declaration (`schemaVersion` 3.54.0, `id` `opsdir-<tenant>`): the tenant, an application per service name. None when the environment has no service names: an empty declaration would remove everything in the tenant. No header: the JSON has none, its MANIFEST entry records it |
| `ansible/f5-bigip.yml` | A play per tenant on the first BIG-IP of its group (`f5_<tenant>[0]`, `gather_facts: false`): `bigip_as3_deploy` of its declaration (read with the `file` lookup; `state: present`, `timeout: 300`, tag `deploy`), and the same with `controls.dry_run` (tags `dry-run`, `never`: `--tags dry-run` asks AS3 to check it without deploying). With no service names, a `debug` task saying nothing is deployed and why |
| `ansible/inventory/f5-bigip.yml` | Group `f5_bigip`, a child group `f5_<tenant>` per tenant, each BIG-IP a host by its record name: `ansible.netcommon.httpapi` to its `ciamManagementAddress` (`ansible_network_os` `f5networks.f5_bigip.bigip`, HTTPS on 443, certificate validated), `ansible_user` its `ciamLoginName`, `ansible_httpapi_password` a run-time lookup of its login secret (never its value) |
| `ansible/requirements-f5-bigip.yml` | The Galaxy collections the play uses, pinned by `opsdir-adapter-ansible` (`requirements.py`): `f5networks.f5_bigip` 3.14.0, `ansible.netcommon` 8.7.1 |

Each application (`template: generic`, `label` the service name's `ciamFqdn`) has, per `ciamPort`, a virtual server `vs_<port>` on the service name's `ciamFrontendIp` and a pool `pool_<port>` of the target role's (`ciamTargetRole`) servers by `ciamPrivateIp` on the same port. Its shape comes from the service name's traffic and protection policies (the core edge domain's `EdgeSpec`, as every cloud's front):

| From the record | AS3 |
|---|---|
| No policy, or `ciamTlsMode: passthrough` (the default) | `Service_TCP`, pool monitor `tcp` |
| `ciamTlsMode: terminate` | `Service_HTTPS` (`redirect80` off), `serverTLS` a `TLS_Server` presenting the service name's certificate (`ciamTlsCertificate`, by its entry name) as the BIG-IP holds it: `Certificate` `{bigip: /Common/<certificate>.crt}` and `.key` (the key never enters a declaration) |
| `ciamTlsMode: reencrypt` | as `terminate`, and `clientTLS` a `TLS_Client`; `validateCertificate` is true unless `ciamBackendValidation` is `none`, which is the default when the policy doesn't set it |
| `ciamTlsMinVersion` (default 1.2) | On `TLS_Server` and `TLS_Client`, `tls1_0Enabled` … off for each version under it |
| Health check: `ciamHealthProtocol`, `ciamHealthPath`, `ciamHealthIntervalSeconds`, else the product's declared health endpoint (over `http` when terminating, `https` when re-encrypting) | On a layer-7 service, a `Monitor` (`monitorType` the protocol) sending `GET <path>` with the service name's `ciamFqdn` as `Host`, expecting `HTTP/1.1 2xx/3xx`, `interval` when the policy sets one. A `tcp` health check (no path anywhere) is the built-in `tcp` monitor |
| `ciamStickiness: cookie` | `persistenceMethods: [cookie]` on the virtual server |
| Request inspection on the protection policy (`ciamWafMode`, `ciamWafCategory`, `ciamRateLimit`, `ciamIpRule`, `ciamGeoRule`) | On a layer-7 service, `policyWAF` `{bigip: /Common/<protection policy>}`: the BIG-IP's WAF policy named after the protection policy entry |

A value the record can't give is `UNBOUND:<what>`: `<binding role>-frontend-ip`, `<binding role>-certificate`, `<server>-address`, `<role>-servers` (no server has the target role), and in the inventory `<appliance>-login` (no `ciamLoginName`) and the login secret role (no binding for it, else `<appliance>-login-secret`). AS3 refuses such a declaration, naming it; an unbound login fails the play's sign-in.

Not rendered: the certificates, keys and WAF policies themselves (they must already be on the BIG-IPs), the policies' stickiness duration, idle timeout, draining and health thresholds, and a health port other than the service's.

## Planner checks

`check_appliances`: a target whose stack declares F5 BIG-IP but records no load-balancer appliance is a blocker (area "Load balancer", to the environment's responsible party): its service names would have no load balancer.

The infrastructure domain's `check_appliance_sources` (any load balancer, not this package's) makes an action of each service name's port that no firewall rule admits a BIG-IP's `ciamApplianceSource` ranges on, to the role behind it: without such a rule the servers' host firewall (and a network firewall the record drives) drops the BIG-IP's connections and health monitors.

It adds no required roles, importers, reference schemes, vocabulary, schema or secret patterns of its own; the login secret's binding is the core's appliance role (`ciamLoginSecretRole`). Its formats: `ansible/f5/*` JSON, `ansible/*.yml` YAML.

## Validation

`opsdir/scripts/validate-ansible.sh` checks `ansible/f5/*.json` against AS3's JSON schema 3.54.0 (`opsdir/scripts/fetch-tools.sh` fetches `as3-schema-3.54.0-6.json`, SHA-256 pinned) besides the play's syntax and lint. Before deploying, `--tags dry-run` asks the BIG-IP itself (`controls.dry_run`).

## Known limits

- **Not yet run against a live BIG-IP.** The declaration is checked offline against the AS3 schema and the play by ansible-core and ansible-lint; deploying it is part of the testing plan (milestone 7.2).
- The service names' certificates and keys must already be on the BIG-IPs under their certificate names (`/Common/<name>.crt`, `.key`); the WAF policies under their protection policies' names. Neither is uploaded by the play.
- `TLS_Client` doesn't name a CA bundle: the BIG-IP's default trust applies when it validates the servers.
- Rate limits, address and country rules are the WAF policy's (not rendered as iRules); a passthrough service can't have one (`policyWAF` is on `Service_HTTPS` only).
- The monitor checks the pool member's port: a product health endpoint declared on another port isn't followed.
- One declaration per tenant from the first BIG-IP of each scope group; a cluster that doesn't sync its configuration would need each member deployed.

## Tests

`tests/test_f5.py`: an HTTPS virtual server for a terminating service name, a TCP one without a policy, the BIG-IPs' inventory with the password read at run time, a play per tenant on its first BIG-IP with the dry run, no declaration for an environment without service names, the requirements, the planner check, and (marker `ansible`, skipped without `tools/ansible`) the play and declaration through `validate-ansible.sh`, the declaration against the AS3 schema.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-f5/tests` (unit), and with `-m ansible` for the tool checks (`opsdir/scripts/fetch-tools.sh` first).

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `f5-bigip`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
