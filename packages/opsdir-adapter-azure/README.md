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

opsdir import --dry-run azure/cli-inventory export/
opsdir import --change CHG-… azure/cli-inventory export/
```

The outputs are read into the same resources as Terraform state (the mapping is shared), so the tables above, what changes, roles and `roles.json` apply unchanged. A key's type comes from `key show` (`RSA-HSM` → `hsm`) and its automatic rotation from its rotation policy (a `Rotate` action); without those outputs the record's values are kept. NSG default rules (`AllowVnetInBound`, …) aren't read. Differences in scope:

- **Network resources:** subnets, interfaces and VMs are read only inside the virtual networks `vnet list` returns; others are counted. Scope the other lists by resource group, as above.
- **Account-wide listings** (Key Vault secrets and keys, storage containers) cover a whole vault or account: the ones the record doesn't have and nothing names a role for are counted with a few examples. Certificate-backed secrets and keys (`managed`) are skipped.
- `keyvault secret list` never returns values; nothing reads `secret show` output. Items the importer doesn't recognize are counted per file and named.

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
- **What the importers can't see:** container metadata other than a role, the identity a disk encryption set uses, Key Vault access policies and RBAC, private endpoints, Application Gateway / Front Door (edge, milestone 4.8).

## Tests

`tests/test_azure.py` (registration, vocabulary, secret resolution), `tests/test_azure_state.py` (the state importer: round trip, drift, new resources and role sources, rules, services, secrets never read, layout), `tests/test_azure_cli.py` (the CLI importer: round trip over `az` output shapes, drift from `key show` and rotation policies, network scoping, counted listings, unrecognized items), `tests/test_azure_arm.py` (the ARM importer: round trip over a Bicep-style template and its deployment, drift, `resourceId()` links, secure parameters never read, what the deployment didn't produce, no deployment, the evaluator), `tests/test_azure_state_store.py` (state and CLI against Postgres: imported under an approved change, re-import changes nothing). The rendered Terraform is covered end to end by the showcase's golden outputs (`examples/showcase`, the target environment).

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `azure`); nothing in the opsdir core changes. In this repository: `scripts/dev-install.sh`.
