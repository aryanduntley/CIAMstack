# opsdir-adapter-azure

opsdir adapter for Microsoft Azure: Terraform for Azure environments; Azure Terraform state, Azure CLI output and ARM/Bicep deployments read back into the record; `azkv://` secret references.

**Applies to** environments whose cloud has `ciamCloudProvider: azure`, in the commercial (`ciamCloudEnvironment: public`) or government (`usgovernment`) partition. A provider adapter: it renders and reads an environment's infrastructure bindings; products (PingDS, PingFederate, …) are other adapters.

**Depends on** `opsdir` and `opsdir-format-terraform` (HCL formatting, the Terraform state reader).

## What it renders

Per environment, `terraform/providers.tf` (`hashicorp/azurerm ~> 4.0`; `subscription_id` and `admin_ssh_public_key` as variables; `environment = "usgovernment"` for the government partition) and `terraform/main.tf`:

| From the record | Rendered as |
|---|---|
| The `network` binding: `ciamResourceGroup`, `ciamProviderRef` (the virtual network's name) | `data` resource group (its location places everything) and virtual network: the landing zone owns them |
| Subnet bindings: `ciamProviderRef` = `<vnet>/<subnet>` | `data azurerm_subnet` |
| One network security group per server role | `azurerm_network_security_group` `nsg-ciam-<env>-<role>` |
| Firewall rules | `azurerm_network_security_rule`, inbound allow; priority from `ciamRulePriority`. An unpinned rule takes the next free slot (100, 110, …) with a `# NOTE` asking for it to be pinned, so adding a rule never renumbers others |
| Servers | NIC (static private address in the server's subnet), NSG association, `azurerm_linux_virtual_machine` (size, zone, `source_image_id`, SSH key only; OS disk `Premium_LRS` encrypted with the `disk-encryption` binding's disk encryption set, `ciamProviderRef`, else an `UNBOUND` comment; tags `Role`, `Hostname`, `Product`, `ManagedBy`) |
| Service names | Standard load balancer: an internal frontend (static `ciamFrontendIp` in the first target's subnet, zones 1–3) or the public IP named by the service's `ciamProviderRef`; a backend pool of the servers with the target role; a TCP probe and rule per `ciamPort`; an A record in `ciamDnsZone` (private DNS for an internal address) |
| Secret references (`azkv://<vault>/<name>`) | Per vault: `data` Key Vault and its secret names (`azurerm_key_vault_secrets`), with a postcondition per secret, so a missing secret fails the plan with its role. Names only: `azurerm_key_vault_secret` would copy each value into Terraform state, so it is never rendered |
| Workload principals (core `access` domain: kind `workload`, `ciamTargetRole` a server role here) | Per principal: `azurerm_user_assigned_identity` (named by its identity binding's provider ref, else `ciam-<env>-<server role>`) set on the role's VMs (`identity { type = "UserAssigned" }`), and one `azurerm_role_assignment` per permission from the access table below at the narrowest scope: the secret or key in its vault (`${data.azurerm_key_vault.<v>.id}/secrets/<name>`, Key Vault's RBAC model), the storage container, the resource a stream's or log destination's provider ref names; `data` vaults and storage accounts the scopes need; a permission that can't be granted is a `# NOTE` |
| Interconnects; required roles without a binding | Comments: the landing zone provides interconnects; `# UNBOUND: required role …` |

Not rendered: egress (NAT gateways), backup targets (`azblob://`), Key Vault keys and disk encryption sets (referenced by ID, not created), Windows VMs.

## Reading an environment back from Terraform state

```bash
terraform -chdir=… state pull > export/target/prod/terraform.tfstate     # one folder per <cloud>/<env>
opsdir import --dry-run azure/terraform-state export/                      # what the live environment differs in
opsdir import --change CHG-… azure/terraform-state export/                 # record it
```

The importer `azure/terraform-state` reads Terraform state (format version 4, `hashicorp/azurerm`; managed resources and data sources) into the environment's servers and bindings. Environments are chosen by the folder layout, `<cloud>/<env>/`; an environment whose cloud isn't Azure, and a state outside the layout, are named, not imported.

| Azure resource | Record entry | Matched by |
|---|---|---|
| `azurerm_virtual_network` | network: first address space, resource group | its name (`ciamProviderRef`) |
| `azurerm_subnet` | subnet binding | `<vnet>/<subnet>` (`ciamProviderRef`) |
| `azurerm_linux_virtual_machine`, `azurerm_windows_virtual_machine`, `azurerm_virtual_machine` | server: size, zone, image (ID or `publisher:offer:sku:version`), the private address and subnet of its primary NIC; name, role, hostname and product from tags `Name`, `Role`, `Hostname`, `Product` (hostname else the computer name, only when fully qualified) | name, hostname or private address |
| `azurerm_lb` + rules, backend pools and their NIC associations, `azurerm_public_ip`, `azurerm_dns_a_record` / `azurerm_private_dns_a_record` | service name: DNS name and zone of the A record holding the frontend address (else tag `Service`), rule ports, the role of the VMs in its pools, private address or public IP (name and address) | DNS name |
| `azurerm_network_security_rule` and inline `security_rule` of `azurerm_network_security_group` | firewall rule (inbound allow only): sources (`*`/`Internet` → `0.0.0.0/0`, a bare address → `/32`), ports, protocol, priority; target role from the VMs whose NICs or subnets the group guards, else the group's tag `Role`, else its name's last part | rule name |
| `azurerm_key_vault_secret` | secret reference `azkv://<vault>/<name>` | reference URI |
| `azurerm_key_vault_key` (+ `azurerm_disk_encryption_set`) | key reference `azkv-key://<vault>/keys/<name>`: `hsm` for `*-HSM` key types else `software`; automatic rotation when the state has a rotation policy; the disk encryption set using the key (`ciamProviderRef`) | reference URI |
| `azurerm_storage_container` | backup target `azblob://<account>/<container>` | storage reference |
| `azurerm_nat_gateway` + public IP and prefix associations | egress: its public addresses | its name (`ciamProviderRef`) |
| `azurerm_linux_function_app`, `azurerm_windows_function_app` (+ `azurerm_function_app_function`) | job binding (`ciamJobBinding`, the core automation domain): the function app's ID, its runtime (`python 3.11`, from the application stack or `linuxFxVersion`), and the NCRONTAB schedules of its timer-triggered functions; the job itself (`ou=jobs`) names the binding role (`ciamJobRole`) | its ID (`ciamProviderRef`) |
| `azurerm_linux_virtual_machine_scale_set`, `azurerm_windows_virtual_machine_scale_set`, `azurerm_orchestrated_virtual_machine_scale_set` (+ the `azurerm_monitor_autoscale_setting` targeting it) | compute group (`ciamComputeGroup`, the core compute domain): the server role it runs (`ciamTargetRole`, its tag `Role`), SKU, instances, zones, image, min/max from the autoscale setting's capacity. Its binding role is its tag `BindingRole`, else `compute-<role>` | its ID (`ciamProviderRef`) |
| `azurerm_kubernetes_cluster` (+ `azurerm_kubernetes_cluster_node_pool`) | cluster (`ciamCluster`): Kubernetes version, the add-ons it enables (Azure Policy, monitoring agent, Key Vault secrets provider, Application Gateway ingress, workload identity, OIDC issuer, HTTP application routing, Open Service Mesh, Defender), node pools (`name: VM size, min-max`), zones. Its binding role is its tag `BindingRole` or `Role`, else `cluster` | its ID (`ciamProviderRef`) |
| `azurerm_email_communication_service_domain` (customer-managed; + `azurerm_dns_cname_record`, `azurerm_dns_txt_record`) | sending identity (`ciamSendingIdentity`, the core messaging domain) for a domain: DKIM verified when every selector its verification records name is a CNAME in Azure DNS, SPF authorizing Communication Services (`include:spf.protection.outlook.com`), the DMARC policy | its ID (`ciamProviderRef`) |
| `azurerm_servicebus_queue`, `azurerm_servicebus_topic`, `azurerm_eventhub`, `azurerm_eventgrid_topic` | stream carrier (`ciamStreamBinding`); Service Bus queues and topics carry no tags, so their roles come from `roles.json` | its ID (`ciamProviderRef`) |
| `azurerm_monitor_action_group` | alert channel (`ciamAlertChannel`, the core observability domain): `action-group`; an alert rule's `ciamAlertRole` names it | its ID (`ciamProviderRef`) |
| `azurerm_log_analytics_workspace` | log destination (`ciamLogDestination`): `workspace`, its retention in days; a log route's `ciamLogDestinationRole` names it | its ID (`ciamProviderRef`) |
| `azurerm_monitor_metric_alert`, `azurerm_monitor_scheduled_query_rules_alert_v2` | alarm the cloud runs (`ciamAlarmBinding`): what it evaluates (`ciamMetric`: metric namespace and name, or `log query`), the action groups it notifies (`ciamNotifies`), the alert rule it realizes (tag `Realizes`). Its binding role is its tag `Role` or `BindingRole`, else `alarm-<Realizes>`; untagged alerts are named, not recorded | its ID (`ciamProviderRef`) |
| `azurerm_application_insights_standard_web_test` | synthetic check the cloud runs (`ciamCanaryBinding`): its frequency as an interval (`5m`), the canary it realizes (tag `Realizes`); binding role else `canary-<Realizes>` | its ID (`ciamProviderRef`) |
| `azurerm_user_assigned_identity` (+ `azurerm_federated_identity_credential`) | identity binding (kind `managed-identity`, `federated` when a federated credential trusts it: `<issuer URL> <subject>`); role from its tag `Role` | its ID, else its name |
| `azurerm_role_assignment`, `azurerm_pim_active_role_assignment`, `azurerm_pim_eligible_role_assignment` | the principal's grants: `<role> on <scope>`, ` (if <condition>)` for an ABAC condition, ` (eligible)` for a PIM eligible assignment; a custom role (`azurerm_role_definition`) as its actions and data actions with its notActions excluded (`a!b`); a role known only by its definition ID takes its name from a `data azurerm_role_definition` in the state, else the ID is kept (named). A principal that isn't a managed identity here is an identity of its own (kind `group`, `user` or `other` by `principal_type`; its object id as provider ref, as the landing zone names an operator's group) | (on the identity) / object id |
| `azurerm_key_vault` `access_policy`, `azurerm_key_vault_access_policy` | grants on the vault (` (resource policy)`), each permission as the data action Key Vault's RBAC names for it (`Get` secret: `Microsoft.KeyVault/vaults/secrets/getSecret/action`, `UnwrapKey`: `…/keys/unwrap/action`, …) | (on the identity, by object id) |
| `azurerm_subscription_policy_assignment`, `_resource_group_`, `_management_group_`, `azurerm_policy_assignment` | a guardrail per scope (kind `policy-assignment`; role `guardrail-policy-<scope name>`): what its assignments prevent (`ciamDenies`), by the built-in definitions the renderer assigns | `<scope>/providers/Microsoft.Authorization/policyAssignments` |
| `azurerm_bastion_host` | access path `bastion` (tag `Role`, else `access-bastion`) | its ID |

**What changes.** What the state says replaces the record's values for what it covers; everything else on the entry (owner, rotation dates, consumers, …) is kept. An entry of a kind the state reports but that the state lacks is named ("in the record but not in what the cloud reports"); kinds the state doesn't report at all are left alone. An overlay environment leaves the bindings it inherits to its base.

**Roles of new resources.** A resource the record doesn't have is added only when a role is known, because every binding needs one (`ciamBindingRole`, which migrations, required-role checks and renderers match on) and a role can't be guessed. The role comes from, in order:

1. the resource's tag `Role` (or `BindingRole`);
2. for a storage container, which carries metadata rather than ARM tags, its metadata key `role` (or `bindingrole`, any case);
3. the environment's role map, `roles.json` beside the state: a JSON object of provider references or names to roles. This is the route for what Azure can't tag at all: subnets and individual security rules.

```json
{"vnet-ciam-prod/snet-admin": "subnet-admin", "fw-admin": "fw-admin"}
```

The importer fills in everything else from the state. Where the source names a role itself, the source's is kept; map entries that disagree with it or match nothing, and a malformed map, are named in the notices. Without a role the resource is named in the notices with what the state says about it ("tag it Role, name it in roles.json, or record it"). A new entry also needs its class's required attributes (a server its hostname and subnet, a service its DNS name, target role and ports, …); one that lacks them is named.

**Named, not recorded:** source service tags (`VirtualNetwork`, `AzureLoadBalancer`, …) since they aren't address ranges; port ranges (`ciamPort` holds single ports); deny and outbound rules; resource types that hold secret values or aren't modeled yet (`random_password`, `tls_private_key`, `azurerm_key_vault_certificate`, database servers), counted by type.

**Identities, guardrails and access paths.** An identity binding is matched by its provider ref, else by the identity's short name (an IAM role's name, a resource ID's last segment, a service account's account id), so a record that names an identity by its short name takes the full reference from the state. Grants, denials and ceilings are written in the cloud's own terms (`ciamGrant`, `ciamDenial`, `ciamBoundary`: `<action or role> on <resource>`, then ` (resource policy)`, ` (if <condition>)`, ` (eligible)`; parentheses in a condition become brackets; `p!a|b` is what `p` matches but `a` and `b`, `!a|b` every action but those), and the planner evaluates them (see Access below). Groups, users and other principals the state names without a role (a role map names them, as for any resource) are counted in one notice, not listed one by one. Deny assignments are created by Azure itself (deployment stacks, managed applications), never by Terraform: the CLI inventory reads them.

**Secrets.** Secret values are never read: a Key Vault secret is recorded from its vault and name alone, and the reader drops whatever the state marks sensitive before anything sees it.

## Reading an environment from the Azure CLI

Where there is no Terraform state (or to check it against what the subscription actually runs), `azure/cli-inventory` reads the JSON the Azure CLI prints. Collect it once per environment, into one folder per `<cloud>/<env>`; file names are free, because every item says what it is (its ARM `type`, or for Key Vault its URL):

```bash
out=export/target/prod; RG=rg-ciam-prod; KV=kv-ciam-prod; SA=stciamprod    # the environment's resource group scopes it
mkdir -p $out
az network vnet list -g $RG -o json                         > $out/vnets.json
az vm list -d -g $RG -o json                                > $out/vms.json          # -d adds private addresses
az network nic list -g $RG -o json                          > $out/nics.json
az network lb list -g $RG -o json                           > $out/lbs.json
az network public-ip list -g $RG -o json                    > $out/public-ips.json
az network public-ip prefix list -g $RG -o json             > $out/public-ip-prefixes.json
az network nsg list -g $RG -o json                          > $out/nsgs.json
az network nat gateway list -g $RG -o json                  > $out/nat-gateways.json
az disk-encryption-set list -g $RG -o json                  > $out/disk-encryption-sets.json
for zone in $(az network dns zone list -g $RG --query '[].name' -o tsv); do
  az network dns record-set a list -g $RG -z "$zone" -o json          > "$out/dns-$zone.json"
done
for zone in $(az network private-dns zone list -g $RG --query '[].name' -o tsv); do
  az network private-dns record-set a list -g $RG -z "$zone" -o json  > "$out/private-dns-$zone.json"
done
az storage container-rm list --storage-account $SA -g $RG -o json     > $out/containers.json   # with metadata
az keyvault secret list --vault-name $KV -o json                      > $out/kv-secrets.json   # names, never values
for key in $(az keyvault key list --vault-name $KV --query '[].name' -o tsv); do
  az keyvault key show --vault-name $KV -n "$key" -o json                  > "$out/kv-key-$key.json"
  az keyvault key rotation-policy show --vault-name $KV -n "$key" -o json  > "$out/kv-rotation-$key.json"
done

az functionapp list -g $RG -o json                                     > $out/functionapps.json
for app in $(az functionapp list -g $RG --query '[].name' -o tsv); do
  az functionapp function list -g $RG -n "$app" -o json                > "$out/functions-$app.json"   # timer schedules
done

# access control: identities, assignments (inherited and through groups), roles, PIM, deny assignments, policies
az identity list                                                        > $out/identities.json
for id in $(az identity list --query '[].[name,resourceGroup]' -o tsv | tr '\t' ':'); do
  az identity federated-credential list --identity-name "${id%%:*}" -g "${id##*:}" > "$out/federated-${id%%:*}.json"
done
az role assignment list --all --include-inherited --include-groups      > $out/role-assignments.json
az role definition list                                                 > $out/role-definitions.json
SUB=$(az account show --query id -o tsv)
az rest --url "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01" > $out/pim-eligible.json
az rest --url "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/denyAssignments?api-version=2022-04-01" > $out/deny-assignments.json
for kv in $(az keyvault list --query '[].name' -o tsv); do az keyvault show -n "$kv" > "$out/vault-$kv.json"; done
az policy assignment list                                               > $out/policy-assignments.json
az network bastion list                                                 > $out/bastions.json

opsdir import --dry-run azure/cli-inventory export/
opsdir import --change CHG-… azure/cli-inventory export/
```

The outputs are read into the same resources as Terraform state (the mapping is shared), so the tables above, what changes, roles and `roles.json` apply unchanged. A key's type comes from `key show` (`RSA-HSM` → `hsm`) and its automatic rotation from its rotation policy (a `Rotate` action); without those outputs the record's values are kept. NSG default rules (`AllowVnetInBound`, …) aren't read. Differences in scope:

- **Network resources:** subnets, interfaces and VMs are read only inside the virtual networks `vnet list` returns; others are counted. Scope the other lists by resource group, as above.
- **Account-wide listings** (Key Vault secrets and keys, storage containers) cover a whole vault or account: the ones the record doesn't have and nothing names a role for are counted with a few examples. Certificate-backed secrets and keys (`managed`) are skipped. Function apps are listed per resource group and counted like the account-wide listings; their app settings are never read.
- `keyvault secret list` never returns values; nothing reads `secret show` output. Items the importer doesn't recognize are counted per file and named.

**Access control** is read as from Terraform state (`opsdir_adapter_azure.cli_iam`), and what Terraform never creates besides: deny assignments (Azure's own, from deployment stacks and managed applications), denials on the principals they name (everyone, `00000000-…`, less the excluded). `az rest` prints `{"value": [...]}`; its items are read. `--include-inherited` adds the assignments at the subscription and above, `--include-groups` those through groups. Built-in role definitions name the roles PIM assignments use by ID; custom ones are expanded. Azure has no evaluator for any principal (its permissions API answers for the caller only), so no `access/evaluate.sh` is rendered.

## Reading an environment from its ARM or Bicep deployments

Where the environment is deployed with ARM templates or Bicep, `azure/arm` reads each deployment: one folder per deployment under `<cloud>/<env>/` (any folder name), holding the template and what Azure knows about the deployment:

```bash
d=export/target/prod/ciam-prod; mkdir -p $d
az bicep build --file main.bicep --stdout                  > $d/template.json     # Bicep; or copy azuredeploy.json,
                                                                                  # or `az deployment group export`
az deployment group show -g rg-ciam-prod -n ciam-prod      > $d/deployment.json   # subscription, group, parameters,
                                                                                  # the resources it produced
cp main.parameters.json $d/                                                       # optional: parameter values
opsdir import --dry-run azure/arm export/
```

Expressions are evaluated where they depend only on what the deployment knows: parameters (the deployment's values, else a parameters file's, else the template's defaults), variables, `concat`, `format`, `resourceId`, `subscription()`, `resourceGroup()`, `equals`, `if`, `toLower`, `toUpper`, `string`, `replace`, `split`, `first`, `last`. Anything else (`reference`, `listKeys`, `uniqueString`, `copyIndex`, `union`, …) is counted per deployment, and the attributes it computes keep the record's values; so do values Azure assigns at deployment (a public IP's address). **Secure parameters are never read**, not even from a parameters file, and a Key Vault secret's `value` is dropped before anything is evaluated.

Each resource the template declares (nested child resources included; `existing` references and resources whose condition is false excluded; when the deployment is given, only those it produced) is given its ARM ID and read like the CLI's output of the same resource, so the tables above, roles and `roles.json` apply unchanged. Without `az deployment group show` the subscription and resource group are unknown: links within the template still resolve, but disk encryption sets aren't read (their ID is what the record keeps for the key). Named in the notices: functions not evaluated, resources that couldn't be named (loops over `copyIndex()`), declared resources the deployment didn't produce, and resource types not read.

## Landing zone

What the platform needs from the organization rather than its own Terraform is rendered per environment into `terraform/landing-zone/` (its own root: `providers.tf`, `main.tf`) for whoever keeps the landing zone: the header names them (the owners of the environment's guardrails, else of its cloud, else of the environment) and the MANIFEST marks the files `landing-zone`. Nothing is rendered when the environment needs nothing from one. When the target lacks a guardrail's prevention or a way in the source has, the planner drafts a request to that owner (`requests/<owner>.md`).

| From the record | Rendered as |
|---|---|
| Deployer principals whose identity binding trusts an OIDC issuer (`ciamTrustedBy`: `<issuer URL> <subject>`) | `azurerm_user_assigned_identity` per deployer with an `azurerm_federated_identity_credential` (that issuer and subject, audience `api://AzureADTokenExchange`) and its role assignments |
| Operator principals whose identity binding names an Entra group (its object id) | `azurerm_role_assignment` per permission to the group at the narrowest scope; eligible instead (`azurerm_pim_eligible_role_assignment`, activated when needed, renewed yearly) when the principal's `ciamCondition` says `jit` |
| Guardrails' denials (`ciamDenies`) | `azurerm_subscription_policy_assignment` of a built-in definition, by ID: `region-escape` Allowed locations (`e56962a6-…`, the cloud's region), `public-storage` Storage account public access should be disallowed (`4fa4b6c0-…`, Deny), `key-deletion` Key vaults should have deletion protection enabled (`0b60c0b2-…`, Deny), `audit-log-disable` Do not allow deletion of resource types on diagnostic settings (`78460a36-…`; it blocks deleting them, not changing them: Azure has no built-in for that). `service-account-keys`, `metadata-v1`, `root-use` don't apply on Azure (`# NOTE`) |

## Access: what permissions mean on Azure

Permissions are recorded neutrally (the core `access` domain: permission sets of `<verb> <binding role>`, held by principals); this table says what each verb on a binding of a class means here. The renderer grants the first alternative of each requirement. The planner (`opsdir plan`) judges each permission of an identity that records what the cloud gives it, following the cloud's evaluation order: **denied** when an unconditional explicit deny matches (`ciamDenial`: the identity's own policies, a resource's policy, a deny assignment or policy, or a guardrail's) or a ceiling doesn't allow it (`ciamBoundary`: a permissions boundary, a control policy's allows); **allowed** when an unconditional grant (`ciamGrant`) matches; **unknown** when the only grant is conditional (`(if …)`) or eligible but not active (`(eligible)`), or a conditional deny matches, since what decides it wasn't imported. A cloud evaluator's verdict recorded on the identity (`ciamEvaluated`) wins. In the target, a permission denied or not granted is a blocker (with what denies it) and an unknown one an action to verify; grants no permission explains, wildcard grants and escalations no permission explains are actions.

| Verb | Binding | Built-in roles (any of) |
|---|---|---|
| `read-secret` / `write-secret` | secret (`azkv://`) | Key Vault Secrets User, Secrets Officer, Administrator / Secrets Officer, Administrator |
| `use-key` / `manage-key` | key (`azkv-key://`) | Key Vault Crypto User, Crypto Service Encryption User, Crypto Officer, Administrator / Crypto Officer, Administrator |
| `read-storage` / `write-storage` | backup target (`azblob://`) | Storage Blob Data Reader, Contributor, Owner / Contributor, Owner |
| `publish-stream` | stream: event hub, queue, topic | Azure Event Hubs Data Sender (Owner); Azure Service Bus Data Sender (Owner); EventGrid Data Sender (an Event Grid topic) |
| `consume-stream` | stream: event hub, queue | Azure Event Hubs Data Receiver (Owner); Azure Service Bus Data Receiver (Owner) |
| `write-logs` / `read-logs` | log destination | Monitoring Metrics Publisher (on the data collection rule: broad) / Log Analytics Reader, Monitoring Reader (broad) |
| `manage` | secret / service name / scale set | Key Vault Secrets Officer, Administrator / Network Contributor on the renderer's `lb-ciam-<env>-<service>` + DNS Zone Contributor or Private DNS Zone Contributor on its zone (broad) / Virtual Machine Contributor (broad) |

A role assigned at a parent scope (the vault, the storage account, a resource group, the subscription) covers what is under it; the record doesn't hold which resource group or subscription a vault is in, so those are taken to cover it. **Escalation** roles and actions: Owner, User Access Administrator, Role Based Access Control Administrator, Key Vault Contributor (on access-policy vaults it can grant itself data access), `Microsoft.Authorization/roleAssignments/write`, `Microsoft.Authorization/*`. Deny assignments (created by Azure, e.g. deployment stacks; listed with the `denyAssignments` REST API) are denials; a role assignment's ABAC `condition` makes it conditional; a PIM role that is only eligible is unknown until activated; a custom role is read through its definition (actions, notActions, dataActions, notDataActions). After the built-in roles, each requirement also names the (data) action those roles carry (`Microsoft.KeyVault/vaults/secrets/getSecret/action` for `read-secret`, `…/blobs/write` for `write-storage`, `Microsoft.Insights/Telemetry/Write` for `write-logs`, …), so a custom role's actions or a vault access policy can meet it and a deny of that action denies it. Azure has no evaluator for any principal (its permissions API answers for the caller only), so Azure is evaluated from the imported assignments. Key Vault secrets need nothing of a key on the reader's side.

## References and vocabulary it owns

| Scheme | Form | Resolved |
|---|---|---|
| `azkv` | `azkv://<vault>/<name>` (Key Vault secret) | at run time: `az keyvault secret show --vault-name <vault> --name <name> --query value -o tsv` |
| `azkv-key` | `azkv-key://<vault>/keys/<name>` (Key Vault key) | never: a key is referenced, its material stays in the vault |
| `azkv-cert` | Key Vault certificate | not resolved |
| `azblob` | `azblob://<account>/<container>` (Blob Storage container) | not resolved |

Values of `ciamCloudProvider` (`azure`) and `ciamCloudEnvironment` (`public`, `usgovernment`) are validated against this adapter. The store refuses Azure credential forms anywhere in the record: storage account keys (`AccountKey=…`) and shared access signatures (`sig=…`).

It adds no required roles, planner checks or schema of its own; the environment's product adapters say which roles it must bind.

## Known limits

- **Not yet run against a live subscription.** The Terraform and the importer follow the `hashicorp/azurerm` 4.x schema; `terraform validate`/`plan` against a real subscription is part of the testing plan (milestone 7.2).
- **Linux only.** Servers render as Linux VMs with SSH keys; the importer reads Windows VMs but the renderer doesn't write them.
- **What the importers can't see:** container metadata other than a role, the identity a disk encryption set uses, role assignments and Key Vault access policies in CLI output and ARM/Bicep deployments (Terraform state only, for now), private endpoints, Application Gateway / Front Door (edge, milestone 4.8), scale sets and AKS clusters, and the monitoring above (action groups, workspaces, alerts, web tests), in CLI output and ARM/Bicep deployments (Terraform state only, for now).

## Tests

`tests/test_azure.py` (registration, vocabulary, secret resolution), `tests/test_azure_state.py` (the state importer: round trip, drift, new resources and role sources, rules, services, secrets never read, layout), `tests/test_azure_cli.py` (the CLI importer: round trip over `az` output shapes, drift from `key show` and rotation policies, network scoping, counted listings, unrecognized items), `tests/test_azure_arm.py` (the ARM importer: round trip over a Bicep-style template and its deployment, drift, `resourceId()` links, secure parameters never read, what the deployment didn't produce, no deployment, the evaluator), `tests/test_azure_messaging.py` (an email domain verified or not by its DNS, SPF and DMARC; queues and topics as stream carriers), `tests/test_azure_observability.py` (action groups as alert channels, workspaces with their retention, metric and log-query alerts and standard web tests with what they realize), `tests/test_azure_compute.py` (a scale set with its autoscale capacity, an AKS cluster with its pools and enabled add-ons), `tests/test_azure_jobs.py` (a function app with its runtime and timer schedules from state, CLI output and an ARM template; app settings never read), `tests/test_azure_state_store.py` (state and CLI against Postgres: imported under an approved change, re-import changes nothing). The rendered Terraform is covered end to end by the showcase's golden outputs (`examples/showcase`, the target environment).

`tests/test_azure_cli_iam.py`: access control from the CLI and `az rest`: a federated identity, conditional and custom-role assignments, PIM named by its own output, an everyone deny assignment with an exclusion, vault access policies, policy assignments, a bastion.

`tests/test_azure_iam.py`: access control from state: a managed identity's federated trust and assignments (an ABAC condition), a custom role's actions with its notActions excluded, a group's PIM eligibility (its role named from the data source, else by ID), Key Vault access policies as data actions, policy assignments with what they prevent, a bastion; the planner's verdicts from what was imported.

`tests/test_azure_landing.py`: the landing zone: a deployer's OIDC trust and permissions, an operator group's access, the guardrails, the owner in the header, nothing rendered without need.

`tests/test_azure_access.py`: the Azure access table: a Key Vault secret by vault, secret or parent scope (not another vault, not Reader), a storage container, roles that assign access. `tests/test_azure_identities.py`: a workload's managed identity and role assignments at the narrowest scope, Event Grid's sender role, the data sources scopes need.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `azure`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
