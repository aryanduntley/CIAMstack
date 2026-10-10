# opsdir-adapter-azure

opsdir adapter for Microsoft Azure: Terraform for Azure environments; Azure Terraform state, Azure CLI output and ARM/Bicep deployments read back into the record; `azkv://` secret references.

**Applies to** environments whose cloud has `ciamCloudProvider: azure`, in the commercial (`ciamCloudEnvironment: public`) or government (`usgovernment`) partition. A provider adapter: it renders and reads an environment's infrastructure bindings; products (PingDS, PingFederate, …) are other adapters.

**Depends on** `opsdir` and `opsdir-format-terraform` (HCL formatting, the Terraform state reader).

## What it renders

Per environment, `terraform/providers.tf` (`hashicorp/azurerm ~> 4.0`; `subscription_id` and `admin_ssh_public_key` as variables; `environment = "usgovernment"` for the government partition; when the cloud's `ciamFipsEndpoints` is TRUE, a comment that azurerm has no FIPS endpoint switch: FIPS 140 is met by the services' validated modules or by Azure Government; the landing-zone roots use the same provider block) and `terraform/main.tf`:

| From the record | Rendered as |
|---|---|
| The `network` binding: `ciamResourceGroup`, `ciamProviderRef` (the virtual network's name) | `data` resource group (its location places everything) and virtual network: the landing zone owns them |
| Subnet bindings: `ciamProviderRef` = `<vnet>/<subnet>` | `data azurerm_subnet` |
| One network security group per server role | `azurerm_network_security_group` `nsg-ciam-<env>-<role>` |
| Firewall rules | `azurerm_network_security_rule`, inbound allow; priority from `ciamRulePriority`. An unpinned rule takes the next free slot (100, 110, …) with a `# NOTE` asking for it to be pinned, so adding a rule never renumbers others. The planner check `check_priorities` makes unpinned rules in the target an action, with a fix (`priorities:<environment>`) pinning the slots the render assigns, once an import has read the environment's rules after their last change |
| Servers | NIC (static private address in the server's subnet), NSG association, `azurerm_linux_virtual_machine` (size, zone, `source_image_id`, SSH key only; OS disk `Premium_LRS` encrypted with the `disk-encryption` binding's disk encryption set, `ciamProviderRef`, else an `UNBOUND` comment; tags `Role`, `Hostname`, `Product`, `ManagedBy`) A server without `ciamImageRef` or `ciamInstanceSize` (both optional) gets `UNBOUND:<server>-image` / `-size` there (core `environment.recorded`; the planner's blocker in the target); without `ciamPrivateIp` its NIC takes a dynamic address, without `ciamZone` no zone. |
| Service names | Standard load balancer: an internal frontend (static `ciamFrontendIp` in the first target's subnet, zones 1–3) or the public IP named by the service's `ciamProviderRef`; a backend pool of the servers with the target role; a TCP probe and rule per `ciamPort`; an A record in `ciamDnsZone` (private DNS for an internal address). With no `ciamFrontendIp`, its exposure (`ciamExposure`, core `edge.exposure`) decides: an internal load balancer takes a dynamic private address (the record answers `azurerm_lb.<n>.private_ip_address`), an internal Application Gateway an `UNBOUND` static one, an internet-facing one the public IP (`data.azurerm_public_ip`); with neither, an `UNBOUND:<role>-exposure` comment replaces the load balancer and record (the planner's blocker). The record's zone is `ciamDnsZone`, else the zone binding the name falls in, else an `UNBOUND:<role>-dns-zone` comment. A service whose role a traffic or protection policy names (core `edge` domain) is tuned or replaced by it: see [Edge](#edge-traffic-and-protection-policies) |
| Secret references (`azkv://<vault>/<name>`) | Per vault: `data` Key Vault and its secret names (`azurerm_key_vault_secrets`), with a postcondition per secret, so a missing secret fails the plan with its role. Names only: `azurerm_key_vault_secret` would copy each value into Terraform state, so it is never rendered |
| Workload principals (core `access` domain: kind `workload`, `ciamTargetRole` a server role here) | Per principal: `azurerm_user_assigned_identity` (named by its identity binding's provider ref, else `ciam-<env>-<server role>`) set on the role's VMs (`identity { type = "UserAssigned" }`), and one `azurerm_role_assignment` per permission from the access table below at the narrowest scope: the secret or key in its vault (`${data.azurerm_key_vault.<v>.id}/secrets/<name>`, Key Vault's RBAC model), the storage container, the resource a stream's or log destination's provider ref names; `data` vaults and storage accounts the scopes need; a permission that can't be granted is a `# NOTE` |
| Control-plane audit trails (core `observability`: `ciamAuditTrail`, scope `account`) the platform team keeps | The subscription's Activity Log export: `azurerm_monitor_diagnostic_setting` on `data.azurerm_subscription.current` with the audit categories `Administrative`, `Security` and `Policy`, to what its `ciamLogDestinationRole` names: an object store's storage account (`storage_account_id`: the account the stack renders, the ARM ID from the container's `ciamProviderRef`, else an input; Azure writes into container `insights-activity-logs`, and another container is a `# NOTE`) or a Log Analytics workspace (`log_analytics_workspace_id`: its `ciamProviderRef`, else an input). The Activity Log covers every region. Data reads and writes are a comment (each resource's own diagnostic settings log them); so is `ciamIntegrityValidation` when the container's immutability policy isn't locked (Azure keeps no digest: a locked, `compliance`, container is what protects the records from alteration, and the planner grades it as CloudTrail validation's equal; an unlocked, `governance`, one a privileged user can lift is graded lower). A trail someone else keeps (`ciamManagedBy`) is a comment naming its keeper; an `organization` trail (Azure has none: each subscription has its own setting, usually deployed by the landing zone's policy) and any other destination are a `# NOTE` |
| Security services (core `estate`: `ciamSecurityService`) the platform team keeps | Microsoft Defender for Cloud: one `azurerm_security_center_subscription_pricing` (tier `Standard`) per plan the kept services need, merged: threat detection's areas control-plane `Arm`, compute and network `VirtualMachines` `P2` (agentless scanning; Plan 2 carries DNS threat detection), containers `Containers`, storage `StorageAccounts` `DefenderForStorageV2` (malware scanning on upload), databases `SqlServers`, `SqlServerVirtualMachines`, `OpenSourceRelationalDatabases`, `CosmosDbs`, key-vaults `KeyVaults` `PerKeyVault`, applications `AppServices`, `Api` (identity: a comment, Entra ID Protection watches sign-ins); vulnerability scanning `VirtualMachines` `P2` with `azurerm_security_center_server_vulnerability_assessments_setting` (`MdeTvm`) and `Containers` with registry vulnerability assessment; posture `CloudPosture` (Defender CSPM) and an `azurerm_subscription_policy_assignment` per framework's built-in initiative found by display name (`NIST SP 800-53 Rev. 5`, `NIST SP 800-171 Rev. 2`, `FedRAMP High`/`Moderate`, `CMMC 2.0 Level 2`, `CMMC Level 3`, `DoD Impact Level 4`/`5` in Azure Government, CIS v2.0.0, `PCI DSS v4.0.1`, `ISO 27001:2013`, `SOC 2 Type 2`); the Microsoft cloud security benchmark is Defender's own default assignment (a comment). Findings go by continuous export (`azurerm_security_center_automation`: alerts, sub-assessments, assessments and regulatory compliance) to the Log Analytics workspace of the binding `ciamFindingsRole` names (an Event Hub needs a secret connection string: a `# NOTE`). Findings at or above `ciamIncidentSeverity` (high by default) also go to the incident process (`ciamIncidentRole`): to a Log Analytics workspace by a second continuous export whose sources carry one rule set per Defender severity at or above it (alerts: `Severity` `Equals` `high`/`medium`/`low`, as Microsoft's built-in continuous-export policy filters them; assessments and sub-assessments: `properties.metadata.severity` `High`/`Medium`/`Low`; regulatory compliance has no severity and is left out), or to an action group by an `azurerm_monitor_scheduled_query_rules_alert_v2` on the table of the workspace the service's findings are exported to (threat detection: `SecurityAlert`, `AlertSeverity` at or above it; vulnerability scanning: `SecurityNestedRecommendation`, posture: `SecurityRecommendation`, `RecommendationSeverity` at or above it and `RecommendationState` not `Healthy`; alert severity 0-3 from critical to low); Defender has no critical severity, so critical routes its high findings (a comment). Configuration recording is a comment (Azure keeps resource change history itself, about 14 days). In Azure Government every plan is rendered, and one Microsoft's availability pages list as unavailable there (Containers, Cosmos DB, APIs, App Service, integrated vulnerability assessment; CMMC 2.0 Level 2's initiative) carries a comment naming the page, to confirm with the account team. Organization scope, services someone else keeps and other clouds' baselines are comments |
| Data discovery (core `estate`: `ciamDataDiscovery`) the platform team keeps | Defender for Cloud's sensitive data discovery: the `SensitiveDataDiscovery` extension on the Defender CSPM plan (`CloudPosture`), merged into the one pricing the security services render for it. The rest is Microsoft's, said in comments: it examines every block blob, Azure Files (SMB) and ADLS Gen2 storage account and Azure SQL database in the subscription by sampling (complete cataloguing needs Microsoft Purview scanning, not rendered), and names the other stores the record examines that it doesn't (other database engines); object storage refreshes within eight days of a change, databases weekly (a comment when `ciamRescanDays` asks for more often); own data types (`ciamCustomIdentifier`) are Purview custom sensitive information types imported into its data sensitivity settings (no Terraform); results stay in Defender (a comment for `ciamResultsRole`); findings are Defender recommendations and alerts that reach `ciamFindingsRole` through the security services' continuous export. Azure Government: rendered with a comment (the support matrix lists Defender CSPM's sensitive data scanning GA; the prerequisites page lists only commercial regions for storage accounts; Defender for Storage's sensitive data threat detection is not available there) |
| Suppressions of findings (core `estate`: `ciamSuppression`, carrying out an exception) the platform team keeps | Named after the exception (`exc-<exception>`): an `azurerm_subscription_policy_exemption` per framework of its `azure:policy:<framework>[/<reference id>]` refs, of the subscription's `ciam-<framework>` initiative assignment (the posture renderer's), for the reference ids given (the whole initiative without), category `Mitigated` for a compensating control and `Waiver` otherwise, `expires_on` the exception's expiry, the exception in `metadata`. Defender alert suppression rules (`azure:alerts:<alert type>`) have no azurerm resource: with the cloud's azapi add-on (`ciamProviderAddOn: azapi`) an `azapi_resource` `Microsoft.Security/alertsSuppressionRules@2019-01-01-preview` (reason `FalsePositive` for a false positive, else `Other`; `state` `Enabled`; `expirationDateUtc`), the root pinning `Azure/azapi` `~> 2.0` and an azapi provider (`environment` `usgovernment` in Azure Government); without it a comment naming the rules to create. Other providers' refs and suppressions someone else keeps are comments |
| Interconnects; required roles without a binding | Comments: the landing zone provides interconnects; `# UNBOUND: required role …` |

Not rendered: egress (NAT gateways), backup targets (`azblob://`), Key Vault keys and disk encryption sets (referenced by ID, not created), Windows VMs.


## Kubernetes workloads

For an environment that runs workloads on AKS, the `kubernetes` adapter asks this one how a workload's service account federates with its managed identity and how `azkv://` references reach the cluster (`kubernetes.py`):

- **Workload identity**: annotation `azure.workload.identity/client-id`, the identity binding's `ciamIdentityClientId` (`UNBOUND:<role>-client-id` until the record holds it), and `azure.workload.identity/tenant-id` when the cloud records its tenant (`ciamOrganizationRef`); pods carry the label `azure.workload.identity/use: "true"` (the deployment kit adds it). The importers read a user-assigned identity's client id into `ciamIdentityClientId` (Terraform state `client_id`, `az identity` `clientId`). The platform's Terraform renders the trust: an `azurerm_federated_identity_credential` on the managed identity per service account that assumes it (issuer the AKS cluster's `oidc_issuer_url`, read as a data source from the cluster binding's ARM ID; subject `system:serviceaccount:<namespace>:<name>`; audience `api://AzureADTokenExchange`). A service account whose cluster the environment doesn't bind is a `# NOTE`.
- **External Secrets Operator**: a SecretStore per vault with provider `azurekv` (`vaultUrl` `https://<vault>.vault.azure.net`, or `.vault.usgovcloudapi.net` in Azure Government; `authType: WorkloadIdentity` as the workload's service account; `tenantId`; `environmentType` `PublicCloud` or `USGovernmentCloud`); `remoteRef.key` the secret's name.
- **Secrets Store CSI driver** (Azure Key Vault provider, provider `azure`): `keyvaultName`, `clientID`, `tenantId`, `cloudName` `AzurePublicCloud` or `AzureUSGovernmentCloud`, each secret under its alias.

Azure Government: no Microsoft page found confirming AKS workload identity or the Key Vault CSI add-on there; both are rendered with the government endpoints, as add-ons to confirm.

**Behind a cluster gateway** (`ingress.py`): a service name whose role the environment runs only on AKS, in a cluster with an in-cluster gateway (`ciamClusterGateway`), gets the same Application Gateway v2 (WAF_v2 when inspected, TLS policy, Key Vault certificate, Front Door when a CDN fronts it, DNS record) a service on servers gets. Its backend pool is the gateway's private address (`ciamFrontendIp`): HTTP on 80 when the front terminates TLS, HTTPS on 443 when the policy re-encrypts, the backend settings then trusting the CA the gateway's internal certificate chains to (`trusted_root_certificate` from Key Vault: the gateway binding's `ciamTrustsCertificate`, held as an `azkv-cert://` reference; read by the Application Gateway's identity). The plug (`gateway_plug`) makes the gateway's Service an AKS internal load balancer: `azure-load-balancer-internal`, `azure-load-balancer-internal-subnet` (the subnet the binding's `ciamSubnetRole` names, `<virtual network>/<subnet>`), `azure-load-balancer-ipv4` (the same address). Application Gateway for Containers isn't used: its Azure Government availability wasn't confirmed (5.2c research). No NSG rule is rendered for the Application Gateway -> gateway hop: the AKS node subnet's NSG (AKS's own) admits traffic within the virtual network by its default rule `AllowVnetInBound`; a landing zone that puts its own NSG there must keep that flow open.

## Planner checks

- `check_boundary`: the Azure services the target uses, named as Microsoft's compliance-scope page names them (Virtual Machines, Virtual Network, Load Balancer, Azure Database for PostgreSQL, Storage: Blobs, Storage: Disks, Key Vault, Azure Monitor, Microsoft Defender for Cloud, ...; the page's qualifiers such as `(incl. ...)` match), checked against the in-scope list of the authorization the target relies on (core `estate`: blockers where the target must rely on one). Neither of the page's tables (Azure, Azure Government; 2026-10) names Azure Communication Services or the DNS Private Resolver: a target using them is told so; a forwarder on the environment's own DNS servers (`ciamResolverHost`) counts as Virtual Machines. In Azure Government, Microsoft's GA roadmap (2026-10-07) lists Azure DNS Private Resolver as GA and authorized at FedRAMP High (DoD IL4 and IL5 forecasted: forwarders on virtual machines there), and Communication Services is FedRAMP High as part of the Microsoft 365 GCC High offering (a separate package, FR1824057433) with no SMTP endpoint.

## Edge: traffic and protection policies

A service name whose role an `edge` traffic or protection policy names (`ou=edge-policies`) is rendered from it; one no policy names renders as above. Health paths, rate-limit targets and exclusions come from the endpoints the product adapters declare, unless a policy's `ciamEndpointPath` moves one.

| From the policies | Rendered as |
|---|---|
| TLS mode `passthrough` (or none) | The Standard load balancer above; its probes take the policy's health check (`Tcp`, `Http`, `Https` with `request_path`, interval, failed probes), its rules `ciamIdleTimeoutSeconds` (4–30 minutes) and `SourceIP` distribution for `source-ip` stickiness |
| TLS mode `terminate` / `reencrypt` | An Application Gateway v2 (zones 1–3, autoscaling 2–10) in the subnet bound to role `subnet-edge` (Application Gateway needs its own subnet; without the binding, an `UNBOUND` comment): the public IP named by the service's `ciamProviderRef` or the static private `ciamFrontendIp`; a backend pool of the servers' addresses; per port a listener with the predefined TLS policy for (`ciamTlsMinVersion`, `ciamTlsProfile`) and the certificate the environment keeps in Key Vault (an `azkv-cert://<vault>/<name>` certificate reference, read through the gateway's own user-assigned identity granted `Key Vault Secrets User` on the vault), backend settings over `Http` (terminate) or `Https` (reencrypt, host name the service's) with cookie affinity, request timeout, draining and a probe (the policy's health check, status 200–399) |
| Protection policy with firewall rules, rate limits, address or country rules | SKU `WAF_v2` and an `azurerm_web_application_firewall_policy` (mode `Prevention`, `Detection` for `detect`): custom rules for addresses (`IPMatch`), countries (`GeoMatch`; `allow` negated), rate limits (`RateLimitRule` on the endpoint paths as regular expressions, by client address, one or five minutes with the threshold scaled), the Default Rule Set 2.1 and Bot Manager 1.1 by category, exclusions by request argument, header or cookie name |
| `ciamDdosTier` `network-advanced` / `application-advanced` | A comment: DDoS Network Protection is a plan linked to the virtual network the landing zone keeps (or IP Protection on the public address) |

| TLS terms | Predefined policy |
|---|---|
| 1.2 modern / intermediate / compatible | `AppGwSslPolicy20220101S` / `AppGwSslPolicy20220101` / `AppGwSslPolicy20170401S` (nearest) |
| 1.3, any profile | `AppGwSslPolicy20220101S` (nearest: no predefined policy is TLS 1.3 only) |

| WAF category | Managed rule set |
|---|---|
| `core-rules`, `known-bad-inputs` | `Microsoft_DefaultRuleSet` 2.1 |
| `bot-control`, `ip-reputation` | `Microsoft_BotManagerRuleSet` 1.1 |
| `account-takeover`, `account-creation-fraud` | none (a comment names them) |


### DNS

Nothing is rendered into a zone whose binding names `ciamManagedBy` (someone outside the platform runs it): a comment names them, and the plan drafts the request. A name that routes between environments (`ciamRoutingPolicy` `failover-primary` / `failover-secondary` / `weighted` on the service names of several environments) is answered from the environment holding the primary (a weighted set: the first by label), which renders every environment's answer; the others render a comment.

| From the record | Rendered as |
|---|---|
| A service name | Its A record with `ciamTtlSeconds` (300 when not recorded); routed, an `azurerm_traffic_manager_profile` (`Priority` for a failover pair, `Weighted` for a weighted set; TTL; TCP monitoring on the first port), every environment's address an `azurerm_traffic_manager_external_endpoint` (priority by order, or weight), and a CNAME to the profile (Azure DNS has no failover of its own). Traffic Manager answers public names only: a routed private name keeps one private record (a comment) |
| DNS records | `azurerm_dns_<type>_record` (A, AAAA, CNAME, TXT, MX, SRV, CAA, NS) or `azurerm_private_dns_<type>_record` in a private zone (no CAA or NS there: a comment), relative name (`@` for the apex), TTL; MX, SRV and CAA values taken apart into their record blocks |
| Outbound forwarders | Per domain an `azurerm_private_dns_resolver_forwarding_rule` in `var.dns_forwarding_ruleset_id` (the landing zone's ruleset; declared only when there are forwarders), a target per `ciamForwardTarget`. Inbound forwarders: a comment (the resolver's inbound endpoint). A forwarder on the environment's own DNS servers (`ciamResolverHost`: virtual machines) gets no rule; the ruleset variable is declared only for managed forwarders: a comment says what those servers must forward and that the network's DNS servers point at them |

### CDN

A protection policy with `ciamCdn` puts Front Door in front of the service (`Premium_AzureFrontDoor` when it inspects requests, else Standard): profile, endpoint, an origin group probing the policy's health check, the origin (the Application Gateway when TLS terminates at the edge, else the Standard load balancer, TLS then ending at Front Door; by its public address, with the service name as host header and the origin's certificate name checked), the service name as a custom domain (the certificate the environment keeps in Key Vault as a Front Door secret, else a managed certificate; TLS 1.2 minimum) validated by a `_dnsauth` TXT record, a route sending everything over HTTPS without caching. The protection policy becomes a Front Door firewall policy (custom IP, country and rate-limit rules, the Default Rule Set and Bot Manager, exclusions by post argument, query argument, header or cookie name) attached to the domain by a security policy; the gateway behind it keeps no WAF policy (`Standard_v2`). The service's DNS name is a CNAME to the endpoint. Front Door's service principal needs `Key Vault Secrets User` on the vault and the origins should admit only Front Door (service tag `AzureFrontDoor.Backend`): both the landing zone's. A private origin needs Private Link: a comment.

### Network depth

What the core `network` domain records and the stack keeps itself (no `ciamManagedBy`) renders into the platform's root; what someone else keeps (the hub's firewall, the landing zone's endpoints) is a comment naming them, rendered in their root. Nothing recorded, nothing rendered (`opsdir_adapter_azure.network`).

| Record | Renders as |
|---|---|
| `ciamPrivateEndpoint` (kind `interface`) | An `azurerm_private_endpoint` per resource its `ciamReachesRole` bindings name: a provider ref that is a resource id as is, the Key Vault of an `azkv://` secret or `azkv-key://` key, the storage account of an `azblob://` container (`data` sources named for the endpoint). Subresource by service: `vault` (secrets, keys), `blob` (object storage), `namespace` (messaging), `registry`; in the first subnet its `ciamSubnetRole` names, a static address from `ciamFrontendIp`, a `private_dns_zone_group` on the zone `ciamDnsZoneRef` names when `ciamPrivateDns` (no zone ref: an `UNBOUND` comment naming the `privatelink.*` zone) |
| Other kinds or services | A comment (gateway endpoints and service endpoints aren't Azure private endpoints; a database or logs need the target's resource id and subresource) |
| `ciamEndpointService` | An `azurerm_private_link_service` on the Standard load balancer frontend of the service name `ciamServiceRole` names, its NAT address in the subnet `ciamSubnetRole` names, `visibility_subscription_ids` from `ciamVisibleTo`, `auto_approval_subscription_ids` from `ciamAllowedPrincipal` unless `ciamAcceptanceRequired`. A service on an Application Gateway (its own private link configuration) is a comment |
| `ciamProxy` kind `firewall` the stack keeps | An `azurerm_firewall_policy_rule_collection_group` in the Firewall policy its `ciamProviderRef` names, from the network's range: application rules per web port (`Http` on 80, where certificate status is fetched; `Https` on 443), network rules by FQDN for other ports (they need the policy's DNS proxy) |
| Other proxies | A comment: their allowlist is kept there |

### Managed databases

The core `data` domain's databases (`ciamDatabase`) the stack keeps render into `main.tf`; one naming someone else in `ciamManagedBy` is a comment naming them (`opsdir_adapter_azure.databases`). PostgreSQL and MySQL run on Azure Database Flexible Server; other engines are a comment (SQL Server is Azure SQL, a different offering).

| Record | Renders as |
|---|---|
| `ciamDatabase` (`postgresql`, `mysql`) | `azurerm_postgresql_flexible_server` / `azurerm_mysql_flexible_server`: `version` (PostgreSQL's major version; MySQL `5.7` or `8.0.21`: Azure keeps minor versions current, so a re-import records the major version), `sku_name` from `ciamInstanceSize`, `storage_mb` / `storage.size_gb` from `ciamDbStorageGb`, `zone`, a `ZoneRedundant` standby when `ciamDbHighAvailability` is `zone-redundant`, `backup_retention_days`, `geo_redundant_backup_enabled` when `ciamCopyRegion` is recorded (Azure copies the backups and point-in-time logs to the region's pair: a recorded region that isn't the pair, or a pair not known here (a nonpaired region, or US DoD Central and East: no pair published), is a comment; so is an adopted server, since the setting is chosen when a server is created); tags `Role`, `ManagedBy` |
| `ciamSubnetRole` | `delegated_subnet_id` of the first subnet named, `private_dns_zone_id` an input (`<database>_private_dns_zone_id`, the `privatelink.<engine>.database.azure.com` zone), no public network access |
| Its role, `ciamSourceCidr` | `azurerm_network_security_group` `nsg-ciam-<env>-<role>` on the delegated subnet (`azurerm_subnet_network_security_group_association`), with an inbound rule `<role>-clients` (priority 100) admitting the ranges to the database's port (`ciamPort`, else the engine's) |
| `ciamEncryptedByRole` (an `azkv-key://` key) | `customer_managed_key` with the key (`data azurerm_key_vault_key`) through a user-assigned identity granted `Key Vault Crypto Service Encryption User` on the key |
| `ciamDbCredentialRole` (an `azkv://` secret) | The administrator password read when applied by an `ephemeral azurerm_key_vault_secret` and written write-only (`administrator_password_wo`): no Terraform state holds it, and the record holds only the reference. The login is an input (`<database>_admin_login`) |
| `ciamDbParameter`, `ciamDbTlsRequired` `FALSE` | A `…_flexible_server_configuration` per parameter, and `require_secure_transport` `off` (both engines require TLS by default) |
| `ciamDbDeletionProtection` `TRUE` | An `azurerm_management_lock` `CanNotDelete` on the server |
| `ciamProviderRef` recorded | An `import` block (the ARM ID): the server is adopted, not created |

### Disks

The core `data` domain's volumes (`ciamVolume`, each server role's disks) render into `main.tf` (`opsdir_adapter_azure.volumes`). Classes to types: `standard` Standard_LRS, `ssd` Premium_LRS, `provisioned` PremiumV2_LRS.

| Record | Renders as |
|---|---|
| The role's boot volume | Each VM's `os_disk`: `disk_size_gb`, `storage_account_type` (an OS disk can't be PremiumV2/Ultra: Premium_LRS, said), the disk encryption set of its key role (`ciamEncryptedByRole`, else the `disk-encryption` binding's `ciamProviderRef`); the VM tagged `BootVolume` (what the readers find it by). Without one, `os_disk` is as before |
| Each data volume of the role | Per VM: an `azurerm_managed_disk` (`Empty`) in the VM's zone with its size, type, `disk_iops_read_write` and `disk_mbps_read_write` (PremiumV2/Ultra only), disk encryption set, tags `Volume`, `Role`, `Server`, `SnapshotPolicy`; an `azurerm_virtual_machine_data_disk_attachment` at LUN 0, 1, … in the volumes' order, caching `None`; the VM mounts it at `ciamMountPath` itself (a comment) |
| `ciamVolumeEncrypted` `FALSE`, a key role without a disk encryption set | A comment: Azure encrypts every managed disk at rest, with its own key when no disk encryption set is named |
| `ciamSnapshotPolicy` | A comment: Azure snapshots managed disks on a schedule only with Azure Backup's disk backup; record a backup plan (`ciamBackupPlan`) with the policy's role and a vault, which renders as one (below) |

### Backup vaults and plans

The core `data` domain's backup vaults (`ciamBackupVault`) and plans (`ciamBackupPlan`) render as Azure Backup into `main.tf` (`opsdir_adapter_azure.backups`). A volume's `ciamSnapshotPolicyRole` may name a backup plan: on Azure that is how a disk is snapshotted on a schedule.

| Record | Renders as |
|---|---|
| `ciamBackupVault` the stack keeps | An `azurerm_data_protection_backup_vault` `ciam-<env>-<name>` (`VaultStore`; `GeoRedundant` with `cross_region_restore_enabled` when `ciamCrossRegionRestore`, `LocallyRedundant` otherwise; `immutability` `Unlocked` for a governance lock, `Locked` for compliance, which can't be turned off, `Disabled` without), a system-assigned identity, tags `Name`, `Role`; its key role an `azurerm_data_protection_backup_vault_customer_managed_key` after the identity's Key Vault Crypto Service Encryption User grant on the key. A lock's days are a comment: a locked vault keeps each recovery point as long as its policy says. An `import` block when its provider ref is recorded |
| `ciamBackupPlan` the stack keeps | For the volumes it protects (the roles it lists that are volumes, and the volumes naming it): an `azurerm_data_protection_backup_policy_disk` named as the plan in its vault (`backup_repeating_time_intervals` `R/2024-01-01T<at>:00+00:00/PT<n>H`, `P1D` daily: every 1, 2, 4, 6, 8 or 12 hours or daily, another interval is a comment; `default_retention_duration` `P<days>D`, at most 360), and per disk of those volumes' VMs an `azurerm_data_protection_backup_instance_disk` (snapshots kept in the environment's resource group) after the vault identity's grants: Disk Backup Reader on the disk, Disk Snapshot Contributor on the resource group (once per vault). Copies to another region are a comment (disk backup keeps snapshots in the disk's region), and so is a protected role that isn't a volume, or a vault the stack doesn't keep |
| One someone else keeps (`ciamManagedBy`) | A comment naming them |

### Monitoring: metric alerts, workspaces and availability tests

The core `observability` domain's alerting, log destinations and synthetic checks render into `main.tf` (`opsdir_adapter_azure.observability`, `opsdir_adapter_azure.canaries`), from the core's cloud-neutral view (`domains/observability/alarms`, `canaries`).

| Record | Renders as |
|---|---|
| An alert rule the environment delivers, realized by an alarm binding recording `ciamMetric` `<metric namespace> <metric name>` | `azurerm_monitor_metric_alert` named as the binding, scoped to the virtual machines of the rule's target role (with more than one, `target_resource_type` and `target_resource_location`): the comparison (`ne` isn't a metric alert's: a NOTE), the threshold in the unit written (a comment says which unit the metric must report: a metric alert has none), a rate as the `Total` over the window, the evaluation period as `window_size` raised to one Azure allows (PT1M … P1D), `frequency` PT1M (PT5M past five minutes), `ciamSeverity` `sev0`..`sev4` as `severity`, the channel's action group; tags `Realizes`, `BindingRole` |
| A rule realized by a log query alarm (`ciamMetric` `log query`), with no target role or no virtual machine of it here, or with no alarm here | A NOTE (Prometheus may evaluate it) |
| A log destination of kind `workspace` (its `ciamProviderRef` a workspace ID) | `azurerm_log_analytics_workspace` of that name, `PerGB2018`, `retention_in_days` as recorded within 30..730 (fewer raised to 30; more, or never expire, kept 730 with a comment: a table's total retention keeps logs longer, up to 4383 days) |
| A canary whose checked service is internet-facing, flow `health` or `login-page` | `azurerm_application_insights_standard_web_test` named as its canary binding: a GET of its URL expecting 200, TLS checked, retries on, every 5, 10 or 15 minutes (its interval, raised to the next), from five test locations (Azure Government's when the cloud's region is a US Gov or DoD region); the Application Insights resource is the root's input `application_insights_id` (the record doesn't name it); tags `Realizes`, `BindingRole` |
| Not rendered, as a NOTE | An `oidc-token` canary (a standard test can't read a secret when it runs: its credentials would sit in the test), a service name that isn't internet-facing, a SAML or LDAP flow |
| Kept elsewhere: someone else keeps it (`ciamManagedBy`), or an overlay inherits it from its base | A comment naming the keeper |

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
| `azurerm_storage_container` | object store `azblob://<account>/<container>` | storage reference |
| `azurerm_nat_gateway` + public IP and prefix associations | egress: its public addresses | its name (`ciamProviderRef`) |
| `azurerm_linux_function_app`, `azurerm_windows_function_app` (+ `azurerm_function_app_function`) | job binding (`ciamJobBinding`, the core automation domain): the function app's ID, its runtime (`python 3.11`, from the application stack or `linuxFxVersion`), and the NCRONTAB schedules of its timer-triggered functions; the job itself (`ou=jobs`) names the binding role (`ciamJobRole`) | its ID (`ciamProviderRef`) |
| `azurerm_linux_virtual_machine_scale_set`, `azurerm_windows_virtual_machine_scale_set`, `azurerm_orchestrated_virtual_machine_scale_set` (+ the `azurerm_monitor_autoscale_setting` targeting it) | compute group (`ciamComputeGroup`, the core compute domain): the server role it runs (`ciamTargetRole`, its tag `Role`), SKU, instances, zones, image, min/max from the autoscale setting's capacity. Its binding role is its tag `BindingRole`, else `compute-<role>` | its ID (`ciamProviderRef`) |
| `azurerm_kubernetes_cluster` (+ `azurerm_kubernetes_cluster_node_pool`) | cluster (`ciamCluster`): Kubernetes version, the add-ons it enables (Azure Policy, monitoring agent, Key Vault secrets provider, Application Gateway ingress, workload identity, OIDC issuer, HTTP application routing, Open Service Mesh, Defender), node pools (`name: VM size, min-max`), zones. Its binding role is its tag `BindingRole` or `Role`, else `cluster` | its ID (`ciamProviderRef`) |
| `azurerm_email_communication_service_domain` (customer-managed; + `azurerm_dns_cname_record`, `azurerm_dns_txt_record`) | sending identity (`ciamSendingIdentity`, the core messaging domain) for a domain: DKIM verified when every selector its verification records name is a CNAME in Azure DNS, SPF authorizing Communication Services (`include:spf.protection.outlook.com`), the DMARC policy | its ID (`ciamProviderRef`) |
| `azurerm_servicebus_queue`, `azurerm_servicebus_topic`, `azurerm_eventhub`, `azurerm_eventgrid_topic` | stream carrier (`ciamStreamBinding`); Service Bus queues and topics carry no tags, so their roles come from `roles.json` | its ID (`ciamProviderRef`) |
| `azurerm_monitor_action_group` | alert channel (`ciamAlertChannel`, the core observability domain): `action-group`; an alert rule's `ciamAlertRole` names it | its ID (`ciamProviderRef`) |
| `azurerm_log_analytics_workspace` | log destination (`ciamLogDestination`): `workspace`, its retention in days; a log route's `ciamLogDestinationRole` names it | its ID (`ciamProviderRef`) |
| `azurerm_monitor_diagnostic_setting` whose target is a subscription | audit trail (`ciamAuditTrail`, role `audit-trail`): scope `account`, `control-plane` when `Administrative` is exported (or every log), all regions, and where its records go (`ciamLogDestinationRole`: the role of its workspace, or of the object store that is its storage account's `insights-activity-logs` container). Integrity comes from that container's immutability policy (locked: as protected as CloudTrail validation; unlocked: less). A resource's own diagnostic settings aren't read here | `<subscription>/providers/Microsoft.Insights/diagnosticSettings/<name>` (`ciamProviderRef`) |
| `azurerm_security_center_subscription_pricing` (tier `Standard`), `azurerm_security_center_server_vulnerability_assessments_setting`, `azurerm_subscription_policy_assignment` of a known initiative (by display name), `azurerm_security_center_automation` | security services (`ciamSecurityService`, role its kind): threat detection over the areas its plans watch (`VirtualMachines` `P2`: compute and network), vulnerability scanning (the assessment setting: compute; a `Containers` plan with registry vulnerability assessment: containers), posture (`CloudPosture` and the frameworks of the assigned initiatives; Defender CSPM assesses the Microsoft cloud security benchmark), each `account` scope over every region, findings going to the workspace or Event Hub a continuous export of their source names, and the incident route (`ciamIncidentRole`, `ciamIncidentSeverity`): the workspace an export filtering on severity goes to, or the action group a log alert on its kind's table (`SecurityAlert`, `SecurityNestedRecommendation`, `SecurityRecommendation`) notifies, with the least severity it lets through | `<subscription>/providers/Microsoft.Security/pricings/defender`, the assessment setting's or `CloudPosture`'s ID |
| `azurerm_security_center_subscription_pricing` `CloudPosture` (tier `Standard`) with the `SensitiveDataDiscovery` extension | data discovery (`ciamDataDiscovery`, role `data-discovery`) | the pricing's id + `/SensitiveDataDiscovery` |
| `azurerm_subscription_policy_exemption`, `azapi_resource` of type `Microsoft.Security/alertsSuppressionRules` | suppression (`ciamSuppression`, role `suppression-<exception>`), merged per exception: `azure:policy:<framework>/<reference id>` (the framework from a `ciam-<framework>` assignment) and `azure:alerts:<alert type>`, the exception from the exemption's metadata or the rule's comment (else its `exc-` name) | the exemption's or rule's ID |
| `azurerm_monitor_metric_alert`, `azurerm_monitor_scheduled_query_rules_alert_v2` | alarm the cloud runs (`ciamAlarmBinding`): what it evaluates (`ciamMetric`: metric namespace and name, or `log query`), the action groups it notifies (`ciamNotifies`), the alert rule it realizes (tag `Realizes`); a log alert on a table Defender's findings are exported to (`SecurityAlert`, `SecurityNestedRecommendation`, `SecurityRecommendation`) is a security service's incident route instead. Its binding role is its tag `Role` or `BindingRole`, else `alarm-<Realizes>`; untagged alerts are named, not recorded | its ID (`ciamProviderRef`) |
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

### The edge, read back

What the edge runs comes back in the edge domain's terms (`opsdir_adapter_azure.edge_inventory`; only what someone chose, the TLS mode always kept):

| Azure resource | Record entry |
|---|---|
| `azurerm_lb` (rules, probes) | facts on its service name: `tls-mode passthrough`, an HTTP(S) probe as `health`, `SourceIP` distribution as `stickiness source-ip`, an idle timeout other than 4 minutes |
| `azurerm_application_gateway` | a service name (DNS name from the record answering for its frontend, listener ports, the role of the servers its pools hold) with `tls-mode` terminate/reencrypt, `tls-min` / `tls-profile` from its predefined policy, `health`, `stickiness cookie`, `idle-timeout` (not 30), `drain` |
| the service's DNS answer | an A record holding its address, a CNAME to the Front Door endpoint fronting it, or a CNAME to the Traffic Manager profile routing to it: TTL, and from Traffic Manager the routing (priority: primary/secondary; weight); the profile's other endpoints are named |
| `azurerm_web_application_firewall_policy`, `azurerm_cdn_frontdoor_firewall_policy` | edge services `waf` (`waf-mode`, `waf-category` from the managed rule sets, `rate-limit` from custom rules named `rate<kind>`, `ip-rule`, `geo-rule`; exclusions and others as settings) of the gateway using it or the service the Front Door fronts |
| `azurerm_cdn_frontdoor_profile` (+ origin) | edge service `cdn` of the service whose public address its origin names |
| `azurerm_network_ddos_protection_plan` | edge service `ddos` (`network-advanced`; role from its tags) |
| `azurerm_dns_zone`, `azurerm_private_dns_zone`, other `azurerm_(private_)dns_<type>_record`s, `azurerm_private_dns_resolver_forwarding_rule` | DNS zones, records (MX, SRV, CAA values joined), forwarders |

### The network depth, read back

What the network carries beyond virtual networks, subnets and NSGs comes back in the network domain's terms (`opsdir_adapter_azure.network_inventory`; CLI and ARM items normalize to the same names: `cli_network.py`). Matching is by provider ref (the ARM ID); a new one needs its tag `Role`, or a role in `roles.json` for what Azure can't tag (peerings); an untagged subnet flow log takes `flow-logs-<subnet role>`.

| Azure resource | Record entry |
|---|---|
| `azurerm_route_table` (+ `azurerm_route`, `azurerm_subnet_route_table_association`) | route table: routes `<prefix or service tag> <kind> [<target>]`: `VirtualAppliance` an appliance at its address, or `firewall` when the address is an Azure Firewall's (its policy the target); `VirtualNetworkGateway` vpn, `VnetLocal` local, `Internet`, `None`; the associated subnets |
| `azurerm_private_endpoint` | private endpoint (interface): what its subresource reaches (`vault`: secrets, `blob`, `namespace`, `registry`), its subnet, its static address, the private DNS zone group's zone (private DNS) |
| `azurerm_private_link_service` | endpoint service: the load balancer whose frontend it exposes, its alias, the subscriptions it is visible to and approves automatically (none: acceptance required), its NAT subnet |
| `azurerm_firewall_policy_rule_collection_group` (+ `azurerm_firewall_policy`, `azurerm_firewall`) | egress firewall (proxy kind `firewall`) under its policy: the sites its application rules (HTTP 80, HTTPS) and FQDN network rules allow, with their ports (443 implicit) |
| `azurerm_virtual_network_peering`, `azurerm_virtual_network_gateway_connection` (+ local and virtual network gateways), `azurerm_virtual_hub_connection` | interconnect depth: peering (the CLI's `peeringState`: connected; its other side the environment whose network binding is the remote virtual network, else a tag `PeerEnvironment`), VPN or ExpressRoute with the peer's gateway, BGP numbers and the ranges it routes to, hub |
| `azurerm_network_watcher_flow_log` | flow log: scope (virtual network, subnet, interface), retention, the workspace traffic analytics sends it to; an NSG's flow logs are named (they retire on 2027-09-30) |
| `azurerm_nat_gateway` | its egress binding's `ciamNatAllocation`: `static` (Standard public addresses) |

### Managed databases, read back

`opsdir_adapter_azure.databases` (CLI and ARM items normalize to the same names: `cli_database.py`). Matching is by provider ref (the ARM ID); a new one needs its tag `Role`. `administrator_password` is never read.

| Azure resource | Record entry |
|---|---|
| `azurerm_postgresql_flexible_server`, `azurerm_mysql_flexible_server` (+ their `_configuration`s, an `azurerm_management_lock` on them) | database: engine, version, service `flexible-server`, endpoint (`fqdn`) and the engine's port, SKU, storage, zone, `zone-redundant` with a `ZoneRedundant` standby, TLS from `require_secure_transport` (else on), retention and point-in-time restore (on while backups are kept), geo-redundant backups as `ciamCopyRegion` (the location's pair; the CLI's `backup.geoRedundantBackup`; a location whose pair isn't known: a notice, no copy region), deletion protection from a `CanNotDelete` or `ReadOnly` lock, the other parameters set on it, the ranges the inbound allow rules of the NSG on its delegated subnet admit (`ciamSourceCidr`; that NSG isn't read as firewall rules); its delegated subnet and customer-managed key as roles |

### Disks, read back

`opsdir_adapter_azure.volumes` (CLI and ARM items normalize to the same names: `cli_disk.py`). Volumes are matched by name; a new one needs its tag `Role`.

| Azure resource | Record entry |
|---|---|
| `azurerm_managed_disk` (+ `azurerm_virtual_machine_data_disk_attachment`), grouped by tag `Volume` | data volume of the role its VMs run: the most common size, class, IOPS and MB/s, the key of its disk encryption set as its key role |
| A VM's `os_disk`, the VM tagged `BootVolume` | the role's boot volume, the same way |

A disk an Azure Backup backup instance protects follows that instance's disk backup policy: its volume's snapshot policy role is the backup plan's.

### Backup vaults and plans, read back

`opsdir_adapter_azure.backups` (CLI and ARM items normalize to the same names: `cli_backup.py`; properties nested or flattened).

| Azure resource | Record entry |
|---|---|
| `azurerm_data_protection_backup_vault` (+ its customer-managed key) | backup vault named by its tag `Name` (else its name): `immutability` as its lock (`Unlocked` governance, `Locked` compliance), `cross_region_restore_enabled` as restores in another region, its key as its key role |
| `azurerm_data_protection_backup_policy_disk` (+ the backup instances using it) | backup plan named as the policy: interval as every hours and start time (several intervals, or one it can't read: named), default retention in days, its vault; the roles (tag `Role`) of the disks its backup instances protect, and the plan's role from their tag `SnapshotPolicy` |

A data disk attached to one of the environment's VMs without a `Volume` tag is named. The CLI's `az disk list` gives the data disks (an OS disk is the VM's, from its `storageProfile`), `az vm list` the OS disks and the data disks' LUNs; an ARM template's `Microsoft.Compute/disks` read the same way.

## Collecting from Azure (`opsdir collect`)

`opsdir collect --env CLOUD/ENV --adapter azure` reads what the two importers below read, read-only, under your own
Azure CLI login (`opsdir_adapter_azure.collect`), and imports it like an export you saved:

- First `az account show`: its `id` must be the cloud's `ciamAccountRef` (the subscription) and its `environmentName`
  the cloud's (`AzureCloud`, or `AzureUSGovernment` when `ciamCloudEnvironment` is `usgovernment`: run `az cloud set
  --name AzureUSGovernment` and sign in there first), or nothing is read.
- `azure/cli-inventory`: every call of the script below, as exact calls in rounds, scoped as it is: the environment's
  resource group (its network binding's `ciamResourceGroup`, else the environment's), its virtual network, its region,
  the Key Vaults its `azkv://` references name and the storage accounts its object stores name; then each listed
  item's details. `az rest` reads (PIM eligibility, deny assignments) are `--method get` against the cloud's own
  management endpoint (`management.usgovcloudapi.net` in Azure Government). VPN connections are projected to what the
  importer reads (shared keys are never fetched); Key Vault secrets are listed by name, never shown.
- `azure/terraform-state`: (a) by default the state blob a collection source names, read with `az storage blob download
  --auth-mode login -o none` to standard output (no `terraform init`, no lock):

  ```ldif
  dn: cn=tf-state,ou=bindings,env=prod,cloud=target,ou=environments,dc=ciam-ops
  objectClass: ciamCollectionSource
  ciamBindingRole: collect-tf-state
  ciamImporter: azure/terraform-state
  ciamSourceRef: azblob://stciamtfstate/tfstate/ciam-prod.terraform.tfstate
  ```

  (b) `--terraform-dir DIR`: `terraform state pull` in that initialized working directory.

Least privilege: `Reader` on the subscription (management-plane reads: networks, compute, role assignments and
definitions, policy assignments, PIM eligibility, deny assignments, diagnostic settings), `Key Vault Reader` on each
vault the record names (key and secret metadata, never values), and `Storage Blob Data Reader` on the Terraform state
container only. The tests pin every command the collector may run (`tests/test_azure_collect.py`, OPERATIONS) and
refuse any that returns secret material (secret show, app settings, connection strings, shared keys, storage keys).

## Reading an environment from the Azure CLI

Where there is no Terraform state (or to check it against what the subscription actually runs), `azure/cli-inventory` reads the JSON the Azure CLI prints. Collect it once per environment, into one folder per `<cloud>/<env>`; file names are free, because every item says what it is (its ARM `type`, or for Key Vault its URL):

```bash
out=export/target/prod; RG=rg-ciam-prod; KV=kv-ciam-prod; SA=stciamprod    # the environment's resource group scopes it
VNET=vnet-ciam-prod; LOCATION=eastus2                                         # its virtual network and region
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
  az network dns record-set list -g $RG -z "$zone" -o json            > "$out/dns-$zone.json"     # every type
done
for zone in $(az network private-dns zone list -g $RG --query '[].name' -o tsv); do
  az network private-dns record-set list -g $RG -z "$zone" -o json    > "$out/private-dns-$zone.json"
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

# the edge: gateways, WAF policies, Front Door, DDoS plans, Traffic Manager, DNS zones, forwarding rules
az network application-gateway list -g $RG -o json            > $out/gateways.json
az network application-gateway waf-policy list -g $RG -o json > $out/waf-policies.json
az network ddos-protection list -g $RG -o json                > $out/ddos.json
az network traffic-manager profile list -g $RG -o json        > $out/traffic-manager.json
az network dns zone list -g $RG -o json                       > $out/dns-zones.json
az network private-dns zone list -g $RG -o json               > $out/private-dns-zones.json
az afd profile list -g $RG -o json                            > $out/afd-profiles.json
for p in $(az afd profile list -g $RG --query '[].name' -o tsv); do
  az afd endpoint list -g $RG --profile-name "$p" -o json        > "$out/afd-$p-endpoints.json"
  az afd security-policy list -g $RG --profile-name "$p" -o json > "$out/afd-$p-security-policies.json"
  az afd origin-group list -g $RG --profile-name "$p" -o json    > "$out/afd-$p-origin-groups.json"
  for g in $(az afd origin-group list -g $RG --profile-name "$p" --query '[].name' -o tsv); do
    az afd origin list -g $RG --profile-name "$p" --origin-group-name "$g" -o json > "$out/afd-$p-$g-origins.json"
  done
done
az network front-door waf-policy list -g $RG -o json          > $out/front-door-waf.json
for rs in $(az dns-resolver forwarding-ruleset list -g $RG --query '[].name' -o tsv); do
  az dns-resolver forwarding-rule list -g $RG --ruleset-name "$rs" -o json > "$out/forwarding-rules-$rs.json"
done

# the network depth: route tables, private endpoints and link services, firewalls, links, flow logs
az network route-table list -g $RG -o json                    > $out/route-tables.json
az network private-endpoint list -g $RG -o json               > $out/private-endpoints.json
for pe in $(az network private-endpoint list -g $RG --query '[].name' -o tsv); do
  az network private-endpoint dns-zone-group list -g $RG --endpoint-name "$pe" -o json > "$out/pe-zones-$pe.json"
done
az network private-link-service list -g $RG -o json           > $out/private-link-services.json
az network firewall list -o json                              > $out/firewalls.json
az network firewall policy list -o json                       > $out/firewall-policies.json
for fp in $(az network firewall policy list --query '[].[resourceGroup,name]' -o tsv | tr '\t' ','); do
  az network firewall policy rule-collection-group list -g "${fp%%,*}" --policy-name "${fp##*,}" -o json \
    > "$out/rule-collection-groups-${fp##*,}.json"
done
az network vnet peering list -g $RG --vnet-name "$VNET" -o json > $out/peerings.json
az network vpn-connection list -g $RG -o json                 > $out/vpn-connections.json
az network local-gateway list -g $RG -o json                  > $out/local-gateways.json
az network vnet-gateway list -g $RG -o json                   > $out/vnet-gateways.json
az network watcher flow-log list --location "$LOCATION" -o json > $out/flow-logs.json

# the control-plane audit trail: the subscription's Activity Log export (an ARM template's subscription
# Microsoft.Insights/diagnosticSettings is read the same way)
az monitor diagnostic-settings subscription list -o json     > $out/activity-log.json

# managed databases: the servers, the parameters set on them (only user-set values are read) and their locks
az postgres flexible-server list -g $RG -o json               > $out/postgres-servers.json
for s in $(az postgres flexible-server list -g $RG --query '[].name' -o tsv); do
  az postgres flexible-server parameter list -g $RG --server-name "$s" -o json > "$out/postgres-parameters-$s.json"
done
az disk list -g $RG -o json                                   > $out/disks.json
# Azure Backup: the Data Protection vaults, and each vault's backup policies and backup instances
az dataprotection backup-vault list -g $RG -o json            > $out/backup-vaults.json
for v in $(az dataprotection backup-vault list -g $RG --query '[].name' -o tsv); do
  az dataprotection backup-policy list -g $RG --vault-name "$v" -o json   > "$out/backup-policies-$v.json"
  az dataprotection backup-instance list -g $RG --vault-name "$v" -o json > "$out/backup-instances-$v.json"
done
az mysql flexible-server list -g $RG -o json                  > $out/mysql-servers.json
for s in $(az mysql flexible-server list -g $RG --query '[].name' -o tsv); do
  az mysql flexible-server parameter list -g $RG --server-name "$s" -o json > "$out/mysql-parameters-$s.json"
done
az lock list -g $RG -o json                                   > $out/locks.json

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

## The region list (a provider prerequisite)

The record's region catalog (core `estate` domain: residencies and the planner's region checks) needs Azure's own list of regions. The adapter declares it as the prerequisite `azure-regions` (`opsdir prerequisites` shows whether it is met) and reads it with `azure/regions`: the output of `az account list-locations -o json`, the regions of the cloud you are signed in to (public or US Government), each with its display name and geography.

```sh
opsdir import azure/regions --run --change CHG-…         # runs the Azure CLI under your own login; opsdir never sees the credentials
az account list-locations -o json > regions.json
opsdir import azure/regions regions.json --change CHG-…  # or run it yourself (elsewhere) and import the file
```

Only physical regions are recorded; logical entries (geographies such as `unitedstates`, `global`) are left out and named. A refresh adds new regions, shows changed names as conflicts to take or keep, and keeps a region Azure stops listing, marked `not-listed`. An export listing no region is refused.

## Quota limits (a provider prerequisite)

Environments record what they need of Azure's limits (core `estate`: `ciamQuotaNeed`, by kind or by `ciamProviderRef`: a usage's `name.value`, such as a VM family's `standardDSv5Family`; a VM must fit both the region's total and its family's vCPU quota, so record the family's need too). The kinds: `vcpus` is the compute usage named "Total Regional vCPUs"; `public-ips` `PublicIPAddresses`, `networks` `VirtualNetworks`, `load-balancers` `LoadBalancers` (network usages). `database-instances` and `kubernetes-clusters` have no usage Azure reports (Azure SQL servers and AKS clusters per subscription and region are raised by a support request): the planner names them as limits to confirm. The prerequisite `azure-quotas` is met once every subscription and region whose environments record needs has its limits:

```sh
opsdir import azure/quotas --run --change CHG-…   # az account show, then per region az vm list-usage and
                                                  # az network list-usages (--location <region> -o json)
```

Saved by hand, keep each region's outputs in a folder named after it (`<region>/compute.json`, `<region>/network.json`, next to `account.json`): the compute output doesn't name its region. An increase the operator decided to request has no azurerm resource: the root names it in a comment, to request through the Quota API (`az quota update`, Microsoft.Quota) or a support request; Microsoft's pages don't say whether the Quota API serves Azure Government.

## Budgets

Each budget the platform team keeps (core `estate`: `ciamBudget`) is rendered as `azurerm_consumption_budget_resource_group` on the environment's resource group: its amount, time grain (`Monthly`, `Quarterly`, `Annually`), `time_period` from the input `budget_start_date` (the first of a month; changing it replaces the budget), and a `GreaterThan` notification per `ciamActualThreshold` (`Actual`) and `ciamForecastThreshold` (`Forecasted`) to the action group of the channel its `ciamAlertRole` names (`contact_groups`). Azure needs a notification with a contact on every budget: without thresholds it alerts at 100% spent, without an action group the subscription's Owners (both commented), at most five (the rest named). Budgets count in the billing account's currency (another recorded currency is commented). In Azure Government, Cost Management budgets serve Enterprise Agreement and pay-as-you-go subscriptions, not CSP ones (a comment). Read back from Terraform state (`_resource_group` and `_subscription` budgets).

## Landing zone

What the platform needs from the organization rather than its own Terraform is rendered per environment into `terraform/landing-zone/` (its own root: `providers.tf`, `main.tf`) for whoever keeps the landing zone: the header names them (the owners of the environment's guardrails, else of its cloud, else of the environment) and the MANIFEST marks the files `landing-zone`. Nothing is rendered when the environment needs nothing from one. When the target lacks a guardrail's prevention or a way in the source has, the planner drafts a request to that owner (`requests/<owner>.md`).

| From the record | Rendered as |
|---|---|
| Deployer principals whose identity binding trusts an OIDC issuer (`ciamTrustedBy`: `<issuer URL> <subject>`) | `azurerm_user_assigned_identity` per deployer with an `azurerm_federated_identity_credential` (that issuer and subject, audience `api://AzureADTokenExchange`) and its role assignments |
| Operator principals whose identity binding names an Entra group (its object id) | `azurerm_role_assignment` per permission to the group at the narrowest scope; eligible instead (`azurerm_pim_eligible_role_assignment`, activated when needed, renewed yearly) when the principal's `ciamCondition` says `jit` |
| Guardrails' denials (`ciamDenies`) | `azurerm_subscription_policy_assignment` of a built-in definition, by ID: `region-escape` Allowed locations (`e56962a6-…`: the cloud's region and those the environment's residency allows, core `estate` domain), `public-storage` Storage account public access should be disallowed (`4fa4b6c0-…`, Deny), `key-deletion` Key vaults should have deletion protection enabled (`0b60c0b2-…`, Deny), `audit-log-disable` Do not allow deletion of resource types on diagnostic settings (`78460a36-…`; it blocks deleting them, not changing them: Azure has no built-in for that). `service-account-keys`, `metadata-v1`, `root-use` don't apply on Azure (`# NOTE`) |

### Network plumbing

The network's plumbing is the landing zone's, not the platform's: NAT egress, route tables, interconnects and flow logs always, plus private endpoints and egress firewalls whose binding names someone else in `ciamManagedBy`. It renders into `terraform/landing-zone/network.tf` for the landing zone's owner, or into `terraform/landing-zone/<party>/` (that party's own root, with its own `providers.tf`) when `ciamManagedBy` names another party. What already exists (a provider ref) gets an `import` block with its ARM ID, built from the resource group when the record holds only a name (a NAT gateway). Child resources (peerings, hub connections) are adopted only when the ref is their full ARM ID. What doesn't exist yet is created. Inputs only the keeper knows become variables in that root's `providers.tf`. When the planner finds target plumbing with no provider ref, it drafts a request to its keeper (`requests/<party>.md`).

| From the record | Rendered as |
|---|---|
| NAT egress (`ciamEgress`) | `azurerm_nat_gateway` (Standard). Each /32 gets an `azurerm_nat_gateway_public_ip_association` and each wider range an `azurerm_nat_gateway_public_ip_prefix_association`; the public IP or prefix is an input, because Azure looks these up by name, not address. `azurerm_subnet_nat_gateway_association` on each of the environment's subnets. A private range is named, not rendered (Azure NAT is public only) |
| Route table (`ciamRouteTable`) | `azurerm_route_table` with inline routes and `azurerm_subnet_route_table_association` per subnet role. Next hops: `firewall` and `appliance` map to `VirtualAppliance`, at the proxy's `ciamProxyAddress` or the route's address, else an input; `vpn` and `transit` map to `VirtualNetworkGateway`; `internet` to `Internet`; `local` to `VnetLocal`; `none` to `None`. A destination may be a service tag. `nat`, `peering` and `endpoint` targets aren't next hops in Azure, and routes scoped `for <roles>` apply to the whole subnet: both are named. Azure has no main table, so that is named too |
| Network ACL (`ciamNetworkAcl`) | Named: Azure has no stateless ACLs (the stack's NSGs carry its rules) |
| Interconnect `peering` | `azurerm_virtual_network_peering` (our half) to the other environment's VNet: its ARM ID, a data source by name and resource group, or an input. A peer on another provider is named (record it as `vpn`). Until `ciamPeerAccepted` is TRUE, a note says the other half is theirs |
| Interconnect `vpn` | `azurerm_local_network_gateway` (`ciamPeerGateway`, accepted ranges, `bgp_settings` with `ciamPeerAsn` and the peering address as an input) and `azurerm_virtual_network_gateway_connection` (`IPsec`, the gateway an input, `bgp_enabled` when the peer has an ASN). The shared key is a sensitive input from the secret store, never recorded |
| Interconnect `hub` / `transit` / `dedicated` | `azurerm_virtual_hub_connection` (the hub an input). `transit` and ExpressRoute circuits are named |
| Flow log (`ciamFlowLog`) | VNet flow logs: `azurerm_network_watcher_flow_log` (version 2) on the VNet or each subnet, with the Network Watcher and its resource group as inputs. They go to the storage account the log destination's ref names; a Log Analytics workspace destination adds `traffic_analytics`, and the storage account becomes an input. Retention is `ciamRetentionDays`. NSG flow logs are never rendered (they retire), and interface scopes are named |
| Private endpoint / egress firewall kept by another party | As the stack renders its own (`azurerm_private_endpoint`, `azurerm_firewall_policy_rule_collection_group`), in that party's root |

## Access: what permissions mean on Azure

Permissions are recorded neutrally (the core `access` domain: permission sets of `<verb> <binding role>`, held by principals); this table says what each verb on a binding of a class means here. The renderer grants the first alternative of each requirement. The planner (`opsdir plan`) judges each permission of an identity that records what the cloud gives it, following the cloud's evaluation order: **denied** when an unconditional explicit deny matches (`ciamDenial`: the identity's own policies, a resource's policy, a deny assignment or policy, or a guardrail's) or a ceiling doesn't allow it (`ciamBoundary`: a permissions boundary, a control policy's allows); **allowed** when an unconditional grant (`ciamGrant`) matches; **unknown** when the only grant is conditional (`(if …)`) or eligible but not active (`(eligible)`), or a conditional deny matches, since what decides it wasn't imported. A cloud evaluator's verdict recorded on the identity (`ciamEvaluated`) wins. In the target, a permission denied or not granted is a blocker (with what denies it) and an unknown one an action to verify; grants no permission explains, wildcard grants and escalations no permission explains are actions.

| Verb | Binding | Built-in roles (any of) |
|---|---|---|
| `read-secret` / `write-secret` | secret (`azkv://`) | Key Vault Secrets User, Secrets Officer, Administrator / Secrets Officer, Administrator |
| `use-key` / `manage-key` | key (`azkv-key://`) | Key Vault Crypto User, Crypto Service Encryption User, Crypto Officer, Administrator / Crypto Officer, Administrator |
| `read-storage` / `write-storage` | object store, backup targets included (`azblob://`) | Storage Blob Data Reader, Contributor, Owner / Contributor, Owner |
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

Configuration management (`opsdir-adapter-ansible`) reads `azkv://` references at run time with the `azure.azcollection.azure_keyvault_secret` lookup (`ansible_lookup`), its `vault_url` built from the environment's Key Vault store's `ciamStoreEndpoint` (`https://<vault>.vault.azure.net`, or `.vault.usgovcloudapi.net` in Azure Government), read as the operator's `az login` (`auth_source=cli`, `use_msi=false`: the lookup's managed-identity probe would sign in as the controller VM, only for the public cloud, and wait out a timeout off Azure; in Azure Government the operator runs `az cloud set --name AzureUSGovernment` first, as for the CLI); without a recorded endpoint, through the `az` command above.

Values of `ciamCloudProvider` (`azure`) and `ciamCloudEnvironment` (`public`, `usgovernment`) are validated against this adapter. The store refuses Azure credential forms anywhere in the record: storage account keys (`AccountKey=…`) and shared access signatures (`sig=…`).

It adds no required roles, planner checks or schema of its own; the environment's product adapters say which roles it must bind.

## Known limits

- **Not yet run against a live subscription.** The Terraform and the importer follow the `hashicorp/azurerm` 4.x schema; `terraform validate`/`plan` against a real subscription is part of the testing plan (milestone 7.2).
- **Linux only.** Servers render as Linux VMs with SSH keys; the importer reads Windows VMs but the renderer doesn't write them.
- **Edge.** Application Gateway WAF exclusions apply on every path, not only the endpoint kind a policy names; a rate limit keyed by a header is grouped by client address; Application Gateway v2 validates the servers' certificates (chain and name) whatever `ciamBackendValidation` says; DDoS Network Protection isn't rendered (the landing zone's virtual network).
- **Databases someone else keeps** (`ciamManagedBy`) are named in a comment, not rendered into their keeper's root yet; SQL Server, Oracle and MariaDB have no Flexible Server and aren't rendered.
- **Scale sets' disks:** the adapter doesn't render scale sets yet, so their volumes come from the record only, and a scale set's data disks aren't read into volumes yet.
- **Backups of what isn't a disk:** a backup plan renders Azure Backup's disk backup only; a plan protecting a database or the servers of a role is a comment (Flexible Servers keep their own backups: `ciamDatabase`). Disk backup keeps snapshots in the disk's region, so a plan's copy regions are a comment.
- **What the importers can't see:** container metadata other than a role, the identity a disk encryption set uses, role assignments and Key Vault access policies in CLI output and ARM/Bicep deployments (Terraform state only, for now), private endpoints, Application Gateway / Front Door (read back with milestone 4.8's importers), scale sets and AKS clusters, and the monitoring above (action groups, workspaces, alerts, web tests), in CLI output and ARM/Bicep deployments (Terraform state only, for now).

## Tests

`tests/test_azure_audit.py`: control-plane audit trails: an account trail the platform keeps as the subscription's Activity Log diagnostic setting into a storage account or workspace (data events and integrity without an immutable container noted, another container named), trails kept by someone else, organization trails and other destinations named; read back from state (a resource's own setting skipped; the container's role as where records go), CLI output and an ARM template.

`tests/test_azure_cli_edge.py`: the edge from CLI output: a gateway with its WAF policy, Front Door, a DDoS plan, DNS zones and record sets of several types (a service's CNAME, the apex NS left to the zone), forwarding rules: the same facts and edge services as from state.

`tests/test_azure_edge_state.py`: the edge read back from state: an Application Gateway's facts, a load balancer routed by Traffic Manager, WAF policies, Front Door and a DDoS plan as edge services, zones, records and forwarding rules.

`tests/test_azure.py` (registration, vocabulary, secret resolution), `tests/test_azure_state.py` (the state importer: round trip, drift, new resources and role sources, rules, services, secrets never read, layout), `tests/test_azure_cli.py` (the CLI importer: round trip over `az` output shapes, drift from `key show` and rotation policies, network scoping, counted listings, unrecognized items), `tests/test_azure_arm.py` (the ARM importer: round trip over a Bicep-style template and its deployment, drift, `resourceId()` links, secure parameters never read, what the deployment didn't produce, no deployment, the evaluator), `tests/test_azure_messaging.py` (an email domain verified or not by its DNS, SPF and DMARC; queues and topics as stream carriers), `tests/test_azure_observability.py` (action groups as alert channels, workspaces with their retention, metric and log-query alerts and standard web tests with what they realize), `tests/test_azure_compute.py` (a scale set with its autoscale capacity, an AKS cluster with its pools and enabled add-ons), `tests/test_azure_jobs.py` (a function app with its runtime and timer schedules from state, CLI output and an ARM template; app settings never read), `tests/test_azure_state_store.py` (state and CLI against Postgres: imported under an approved change, re-import changes nothing). The rendered Terraform is covered end to end by the showcase's golden outputs (`examples/showcase`, the target environment).

`tests/test_azure_backups.py`: Azure Backup rendered (vault with redundancy, cross-region restore, immutability, identity and customer-managed key; disk backup policy with its interval and retention; a backup instance per disk after the identity's grants; copies, lock days, roles that aren't volumes, other intervals and vaults kept elsewhere said) and read back from state, the CLI and ARM (a disk's backup instance links its volume to the plan, whatever the case of the ids).

`tests/test_azure_volumes.py`: disks rendered (the boot volume as the os_disk with its disk encryption set and the VM's BootVolume tag, an OS disk that can't be PremiumV2, data volumes as managed disks attached at their LUNs, an unencrypted record and a key without a disk encryption set said, snapshot policies a comment) and read back from state, the CLI (OS disks from the VMs' storageProfile, data disks and LUNs) and an ARM template; untagged disks on the environment's VMs named.

`tests/test_azure_databases.py`: managed databases rendered (a PostgreSQL Flexible Server with its customer-managed key, write-only password from an ephemeral Key Vault read, parameters, lock and import block; its role's NSG on the delegated subnet admitting its ranges; MySQL storage and TLS off; engines it doesn't run and databases others keep named; no credential role or an unbound key said) and read back from state (the rules of the NSG on its delegated subnet as its ranges, not firewall rules), the CLI (user-set parameters only, the lock) and an ARM template (its password parameter never evaluated).

`tests/test_azure_cdn.py`: Front Door over the gateway with its firewall policy and Key Vault certificate, Standard over the load balancer with a managed certificate, a private origin, the gateway behind keeping no WAF.

`tests/test_azure_dns.py`: routing as Traffic Manager from the primary (priority and weighted, CNAME), records by type and zone visibility, outbound forwarders as ruleset rules.

`tests/test_azure_edge.py`: the edge: TLS terms as predefined policies and back, a gateway in the edge subnet with its Key Vault certificate through its identity, probe, affinity, draining and WAF policy, what's unbound without the subnet or certificate, a private frontend, the WAF policy's custom and managed rules and exclusions, what Azure lacks, DDoS asked of the landing zone.

`tests/test_azure_cli_iam.py`: access control from the CLI and `az rest`: a federated identity, conditional and custom-role assignments, PIM named by its own output, an everyone deny assignment with an exclusion, vault access policies, policy assignments, a bastion.

`tests/test_azure_iam.py`: access control from state: a managed identity's federated trust and assignments (an ABAC condition), a custom role's actions with its notActions excluded, a group's PIM eligibility (its role named from the data source, else by ID), Key Vault access policies as data actions, policy assignments with what they prevent, a bastion; the planner's verdicts from what was imported.

`tests/test_azure_landing.py`: the landing zone: a deployer's OIDC trust and permissions, an operator group's access, the guardrails, the owner in the header, nothing rendered without need.

`tests/test_azure_access.py`: the Azure access table: a Key Vault secret by vault, secret or parent scope (not another vault, not Reader), a storage container, roles that assign access. `tests/test_azure_identities.py`: a workload's managed identity and role assignments at the narrowest scope, Event Grid's sender role, the data sources scopes need.

`tests/test_azure_network.py`: the network depth the stack keeps: one private endpoint per vault reached with its DNS zone group, a static address, a storage account and a missing zone, a resource id used as is, what Azure doesn't reach this way, a Private Link Service on the load balancer (visibility, auto-approval or acceptance, NAT subnet; not on an Application Gateway), the egress firewall's application rules per web port and network rules by FQDN for others, nothing rendered without records.

`tests/test_azure_network_state.py`: the network depth read back from state, the CLI and ARM: route tables (an Azure Firewall's address as the firewall), private endpoints (zone, static address), Private Link Services (acceptance from auto-approval), the Firewall policy's sites with their ports, peering state, VPN depth, VNet flow logs (an NSG's named).

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `azure`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

