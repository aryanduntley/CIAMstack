# opsdir-adapter-gcp

opsdir adapter for Google Cloud: Terraform for Google Cloud environments, read back from Terraform state or from Cloud Asset Inventory and `gcloud` output; `gcp-sm://` secret references.

**Applies to** environments whose cloud has `ciamCloudProvider: gcp`, in Google Cloud's public cloud (`ciamCloudEnvironment: public`). Assured Workloads isn't a separate partition (it's a folder-level control boundary), so it isn't an environment value. A provider adapter: it renders and reads an environment's infrastructure bindings; products (PingDS, PingFederate, …) are other adapters.

**Depends on** `opsdir` and `opsdir-format-terraform` (HCL formatting, the Terraform state reader).

## What it renders

Per environment, `terraform/providers.tf` (`hashicorp/google ~> 8.0`; the project as variable `project_id`, the region as variable `region`, defaulting to the cloud's `ciamRegion`; when the cloud's `ciamFipsEndpoints` is TRUE, a comment that the google provider has no FIPS endpoint switch: FIPS 140 is met by Google Cloud's own validated modules or enforced with Assured Workloads; credentials come from the usual Google Cloud environment, never from the record) and `terraform/main.tf`:

| From the record | Rendered as |
|---|---|
| The `network` binding: `ciamProviderRef` (the network's resource name, `projects/<host>/global/networks/<name>`, or its name) | `data google_compute_network` `main`, in the host project the name gives (Shared VPC): the landing zone owns it |
| Subnet bindings: `ciamProviderRef` = `projects/<host>/regions/<region>/subnetworks/<name>` (or a name in the cloud's region) | `data google_compute_subnetwork` |
| Firewall rules | `google_compute_firewall`, ingress allow, VPC-wide, targeting the network tag of the rule's target role (`ciam-<env>-<role>`); network firewall policy rules by secure tag instead under the `policy` firewall model (see [Network depth](#network-depth)); priority from `ciamRulePriority`. An unpinned rule takes the next free slot from 1000 (step 10) with a `# NOTE` asking for it to be pinned, so adding a rule never renumbers others (the same rule as Azure's NSG priorities, `opsdir.domains.infrastructure.firewall`). The planner check `check_priorities` makes unpinned rules in the target an action, with a fix (`priorities:<environment>`) pinning the slots the render assigns, once an import has read the environment's rules after their last change |
| Servers | `google_compute_instance`: machine type, zone, hostname, the role's network tag, a boot disk from `ciamImageRef` encrypted with the `disk-encryption` binding's Cloud KMS key (`kms_key_self_link`, else an `UNBOUND` comment), the server's subnetwork and static address, Shielded VM (secure boot, vTPM, integrity monitoring), OS Login, labels `role`, `product`, `managed_by` |
| Service names | A passthrough network load balancer: an unmanaged instance group per zone of the target role's servers, a regional TCP health check on the first port and a firewall rule admitting Google Cloud's health-check probes to the role's tag on that port (`35.191.0.0/16`; external also `209.85.152.0/22`, `209.85.204.0/22`), a regional backend service over the groups (by `self_link`, `CONNECTION` balancing), a forwarding rule (`INTERNAL` in the first target's subnetwork for a private `ciamFrontendIp`, else `EXTERNAL`; a public address named by the service's `ciamProviderRef` is read as `data google_compute_address`); a Cloud DNS record in the managed zone `ciamDnsZoneRef`. An `EXTERNAL` backend service names its port (`port_name` `ciam`, each group's `named_port`) and sets `capacity_scaler`; `INTERNAL` takes neither. A forwarding rule takes at most five ports: a service with more forwards all ports (`all_ports`, with a comment), and its firewall rules still admit only the service's. A service whose role a traffic or protection policy names (core `edge` domain) is tuned or replaced by it: see [Edge](#edge-traffic-and-protection-policies) |
| Secret references (`gcp-sm://projects/<p>/secrets/<name>`, regional `…/locations/<l>/secrets/<name>`) | `data google_secret_manager_secret` (regional: `google_secret_manager_regional_secret`): metadata only, so a missing secret fails the plan and no value enters Terraform state (secret versions are never rendered) |
| The `backup-target` binding (`gs://<bucket>`) | `data google_storage_bucket` `ds_backups` |
| The `pf-egress` binding | A comment naming the Cloud NAT the landing zone provides (rendered in its root: [Landing zone](#landing-zone)) |
| Workload principals (core `access` domain: kind `workload`, `ciamTargetRole` a server role here) | Per principal: `google_service_account` (account id from its identity binding's provider ref, else `ciam-<env>-<server role>`, at most 30 characters) set on the role's instances with scope `cloud-platform` (IAM alone decides), and one resource-level IAM member per permission from the access table below: `google_secret_manager_secret_iam_member` (regional: `google_secret_manager_regional_secret_iam_member`), `google_kms_crypto_key_iam_member`, `google_storage_bucket_iam_member`, `google_pubsub_topic_iam_member`; log writes as `google_project_iam_member` on the log bucket's project (the narrowest scope Google Cloud allows); a permission that can't be granted is a `# NOTE` |
| Control-plane audit trails (core `observability`: `ciamAuditTrail`) the platform team keeps | A log sink exporting Cloud Audit Logs (`filter = logName:"cloudaudit.googleapis.com"`, unique writer identity): `google_logging_project_sink`, or for scope `organization` `google_logging_organization_sink` with `include_children` on `var.organization_id`; to what its `ciamLogDestinationRole` names: an object store's bucket (`storage.googleapis.com/<bucket>`, with `google_storage_bucket_iam_member` granting the sink's writer identity `roles/storage.objectCreator`) or a log bucket (`logging.googleapis.com/<its ciamProviderRef>`; one in another project needs `roles/logging.bucketWriter`: a comment). `data-read` / `data-write` turn on Data Access logs for every service (`google_project_iam_audit_config` / `google_organization_iam_audit_config`, `allServices`). Admin Activity is always recorded, in every region. Google keeps no digest of audit logs: `ciamIntegrityValidation` without a bucket whose retention policy is locked (`ciamStorageImmutability` `compliance`) is a comment, and the planner grades a locked bucket as CloudTrail validation's equal. A trail someone else keeps (`ciamManagedBy`) is a comment naming its keeper; another destination a `# NOTE` |
| Required roles without a binding | `# UNBOUND: required role …` |

Not rendered here: networks, subnetworks, DNS managed zones (the landing zone creates them); Cloud NAT and Cloud Routers, routes, peerings and VPNs (the landing zone's root renders them); Cloud KMS keys (referenced by resource name); egress firewall rules; instance service accounts and their roles (milestone 4.7); certificate maps (the target proxy names Certificate Manager certificates directly).

PingFederate's cluster discovery on Google Cloud: Ping documents no Cloud Storage protocol, so a Google Cloud environment binds `pf-cluster-discovery` with `pingfedDiscoveryProtocol` `DNS_PING` (GKE) or `TCPPING` (VMs) (see the PingFederate adapter).

## Edge: traffic and protection policies

A service name whose role an `edge` traffic or protection policy names (`ou=edge-policies`) is rendered from it; one no policy names renders as above. Health paths, rate-limit targets and exclusions come from the endpoints the product adapters declare, unless a policy's `ciamEndpointPath` moves one.

| From the policies | Rendered as |
|---|---|
| TLS mode `passthrough` (or none) | The passthrough load balancer above; its health check takes the policy's (`tcp`, `http`, `https` with `request_path`, interval, thresholds), its backend service `CLIENT_IP` affinity for `source-ip` stickiness and `ciamDrainSeconds`; `ciamDdosTier` beyond standard on an external one adds advanced network DDoS protection (`google_compute_region_security_policy` of type `CLOUD_ARMOR_NETWORK` with `ddos_protection` `ADVANCED`, and a `google_compute_network_edge_security_service`; Cloud Armor Enterprise) |
| TLS mode `terminate` / `reencrypt` | A regional Application Load Balancer (`EXTERNAL_MANAGED`, Standard tier, or `INTERNAL_MANAGED` in the first target's subnetwork) beside the proxy-only subnet bound to role `subnet-edge` (without the binding, an `UNBOUND` comment): a regional SSL policy for (`ciamTlsMinVersion`, `ciamTlsProfile`), a target HTTPS proxy with the Certificate Manager certificate the environment holds (a `gcp-cert://` certificate reference), a URL map, a backend service over `HTTP` (terminate) or `HTTPS` (reencrypt) on the instance groups' named port with the policy's health check, `GENERATED_COOKIE` or `CLIENT_IP` affinity, `ciamIdleTimeoutSeconds` as `timeout_sec`, draining; firewall rules admitting the proxy-only subnet and the health checks (`35.191.0.0/16`, `130.211.0.0/22`) to the role's tag |
| Protection policy with firewall rules, rate limits, address or country rules | A regional Cloud Armor policy on the backend service, one rule per address range (`SRC_IPS_V1`), country rule (`origin.region_code`; `allow` negated), rate limit (`throttle` on the endpoint paths as `request.path.matches`, by client address or header, the interval Cloud Armor allows at or above the policy's with the count scaled, `deny(429)` past it) and preconfigured WAF rule set; `detect` marks every rule `preview`. An exclusion is a `preconfigured_waf_config` exclusion on each of its category's rules |

| TLS terms | SSL policy |
|---|---|
| modern / intermediate / compatible | profile `RESTRICTED` / `MODERN` / `COMPATIBLE`, `min_tls_version` `TLS_1_2` or `TLS_1_3` (exact) |

| WAF category | Preconfigured rules |
|---|---|
| `core-rules` | `sqli`, `xss`, `lfi`, `rfi`, `rce`, `methodenforcement`, `scannerdetection`, `protocolattack`, `sessionfixation` (`-v33-stable`) |
| `known-bad-inputs` | `cve-canary`, `java-v33-stable` |
| `ip-reputation`, `bot-control`, `account-takeover`, `account-creation-fraud` | not rendered (a comment: threat intelligence and reCAPTCHA need Cloud Armor Enterprise and keys; no preconfigured rules for the others) |


### DNS

Nothing is rendered into a zone whose binding names `ciamManagedBy` (someone outside the platform runs it): a comment names them, and the plan drafts the request. A name that routes between environments (`ciamRoutingPolicy` `failover-primary` / `failover-secondary` / `weighted` on the service names of several environments) is answered from the environment holding the primary (a weighted set: the first by label), which renders every environment's answer; the others render a comment.

| From the record | Rendered as |
|---|---|
| A service name | Its record set with `ciamTtlSeconds` (300 when not recorded); a weighted set, a `routing_policy` of `wrr` items (each environment's weight and address). A failover pair is a plain record with a comment: Cloud DNS's primary-backup policy over health-checked external endpoints is configured by hand |
| DNS records | `google_dns_record_set` in the zone's managed zone (its `ciamProviderRef`, else a label of its name), type, TTL, values (TXT quoted) |
| Outbound forwarders | Per domain a private `google_dns_managed_zone` on the network with a `forwarding_config` target per `ciamForwardTarget`. Inbound forwarders: a comment (a DNS server policy the landing zone keeps) |

### CDN

Cloud CDN belongs to Google's global external Application Load Balancer, so a protection policy with `ciamCdn` renders the service's load balancer global (whatever its TLS mode; a passthrough service keeps HTTPS to its servers): a global SSL policy, health check, backend service with `enable_cdn` and `cache_mode` `USE_ORIGIN_HEADERS` (the origin's `Cache-Control` decides: sign-in pages and tokens send `no-store`), URL map, target HTTPS proxy, a global forwarding rule on the reserved global address the service's `ciamProviderRef` names (`data google_compute_global_address`), the health-check firewall rule (no proxy-only subnet), and the protection policy as a global Cloud Armor policy, with Adaptive Protection (layer 7 DDoS defense) for `application-advanced`. The DNS record points at the global forwarding rule. A private address can't have a CDN: a comment.

### Network depth

What the core `network` domain records and the stack keeps itself (no `ciamManagedBy`) renders into the platform's root; what someone else keeps is a comment naming them, rendered in their root. Nothing recorded, nothing rendered (`opsdir_adapter_gcp.network`, `opsdir_adapter_gcp.firewall_policy`).

| Record | Renders as |
|---|---|
| `ciamFirewallModel` `policy` on the `network` binding | A network firewall policy instead of VPC firewall rules, in the network's project (a Shared VPC's host project; the deployer needs rights there): `google_compute_network_firewall_policy` and its association with the network (unless the network policy, `ciamFirewallPolicy` scope `network`, is kept by someone else: its `ciamProviderRef` then names it), a tag key with purpose `GCE_FIREWALL` for the network (or the one `ciamTagKeyRef` names) and a value per server role bound to each instance (`google_tags_location_tag_binding`; the deployer needs the Tag User role on the values, an access request). The record's rules become policy rules targeting the role's tag value (priorities pinned as before); rules a hierarchical policy holds (`ciamPolicyRole`) are read, never rendered. The health-check and proxy rules of load balancers follow the model. `ciamPolicyOrder` is the network's `network_firewall_policy_enforcement_order` (the landing zone's): a comment |
| `ciamPrivateEndpoint` kind `all-apis` | Private Service Connect for Google's APIs in the network's project: a global internal address (`PRIVATE_SERVICE_CONNECT`, `ciamFrontendIp`) and a global forwarding rule to `all-apis` (its name 1-20 lowercase letters and digits); with `ciamPrivateDns`, a comment for the landing zone's `googleapis.com` zone |
| `ciamPrivateEndpoint` kind `peered-service` with `ciamCidr` | Private services access (where managed databases' private addresses come from), in its keeper's root like any plumbing: a global internal address with purpose `VPC_PEERING` (`address`, `prefix_length` from the range; named by its provider ref) and the `google_service_networking_connection` reserving it, import blocks for both when it exists. The range is among the private ranges the egress allowlist admits |
| Kinds `subnet-access`, `gateway`, `interface`; `peered-service` without a range | A comment: Private Google Access is the landing zone's subnet setting; Google Cloud has no gateway endpoints; an endpoint to a published service needs its service attachment; private services access needs its allocated range |
| `ciamEndpointService` | A `google_compute_service_attachment` on the internal passthrough forwarding rule of the service name `ciamServiceRole` names, NAT subnets from `ciamSubnetRole` (PSC subnets the landing zone keeps), `ACCEPT_MANUAL` with a consumer accept list per `ciamAllowedPrincipal` (a project, or a network URL) when `ciamAcceptanceRequired`, else `ACCEPT_AUTOMATIC`. A public or application load balancer: a comment |
| `ciamProxy` kind `firewall` the stack keeps | Under the policy model, egress rules for every role's tag value: `dest_fqdns` per port (a wildcard domain can't be an FQDN object: a comment), the ranges the stack reaches privately (its network, its interconnects', its private endpoints' addresses and ranges), then a deny of all other egress at the lowest priority. Under the rules model a comment: FQDN rules exist only in network firewall policies |
| Other proxies | A comment: their allowlist is kept there |

### Managed databases

The core `data` domain's databases (`ciamDatabase`) the stack keeps render into `main.tf`; one naming someone else in `ciamManagedBy` is a comment naming them (`opsdir_adapter_gcp.databases`). PostgreSQL, MySQL and SQL Server run on Cloud SQL; other engines are a comment.

| Record | Renders as |
|---|---|
| `ciamDatabase` | `google_sql_database_instance`: `database_version` from the engine, major version and edition (`POSTGRES_16`, `MYSQL_8_0`, `SQLSERVER_2019_ENTERPRISE`: Cloud SQL keeps minor versions current, so a re-import records the major version), `tier` from `ciamInstanceSize`, `disk_size`, the zone as `location_preference`, `REGIONAL` availability when zone-redundant (else `ZONAL`), labels `role` and `managed_by` |
| `ciamRetentionDays`, `ciamDbPointInTime`, `ciamCopyRegion` | `backup_configuration`: enabled with `retained_backups` (daily backups kept), `point_in_time_recovery_enabled` (MySQL: `binary_log_enabled`), `location` from the first copy region (a region, or a multi-region such as `us`; Cloud SQL keeps backups in one location, so others are a comment) |
| Network, `ciamDbTlsRequired` | A private IP on the environment's network (`private_network`, no public IPv4; private services access is a `peered-service` private endpoint, usually the landing zone's), `ssl_mode` `ENCRYPTED_ONLY` or `ALLOW_UNENCRYPTED_AND_ENCRYPTED` |
| `ciamSourceCidr` | A comment: Cloud SQL's private IP is in Google's service producer network, which the network's firewall rules don't reach; the private services access peering carries the traffic |
| `ciamDbParameter` | A `database_flags` block per parameter |
| `ciamEncryptedByRole` (a `gcp-kms://` key) | `encryption_key_name`; a comment: the Cloud SQL service agent needs `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key |
| `ciamDbDeletionProtection` | `deletion_protection` (Terraform) and `deletion_protection_enabled` (the API) |
| `ciamDbCredentialRole` (a global `gcp-sm://` secret) | The password read when applied by an `ephemeral google_secret_manager_secret_version` and written write-only: a `google_sql_user` with `password_wo` (PostgreSQL, MySQL; the login an input, `<database>_admin_login`), SQL Server's `root_password_wo`. No Terraform state holds it. A regional secret has no ephemeral read: a comment |
| `ciamProviderRef` recorded | An `import` block (`projects/<project>/instances/<name>`) |

### Disks and snapshot schedules

The core `data` domain's volumes (`ciamVolume`, each server role's disks) and snapshot policies (`ciamSnapshotPolicy`) render into `main.tf` (`opsdir_adapter_gcp.volumes`). Classes to types: `standard` pd-standard, `ssd` pd-ssd, `provisioned` hyperdisk-balanced (it needs a machine series that takes Hyperdisk: a comment).

| Record | Renders as |
|---|---|
| The role's boot volume | Each instance's `boot_disk`: `initialize_params` `size`, `type` (a provisioned boot disk is pd-ssd, said) and labels `volume`, `role`; `kms_key_self_link` from its key role (`ciamEncryptedByRole`, else the `disk-encryption` key). Without one, the boot disk is as before |
| Each data volume of the role | Per instance: a `google_compute_disk` in its zone (size, type, `provisioned_iops` and `provisioned_throughput` where the type takes them, `disk_encryption_key`), labelled `volume`, `role`, `server`, `snapshot_policy`, and a `google_compute_attached_disk` with the volume as its device name; the instance mounts it at `ciamMountPath` itself (a comment) |
| `ciamVolumeEncrypted` `FALSE`, an unbound key role | A comment: Google Cloud encrypts every disk at rest, with its own key when none is named |
| `ciamSnapshotPolicy` the stack keeps | A `google_compute_resource_policy` `ciam-<env>-<name>` with a snapshot schedule: `daily_schedule` every 24 hours, `hourly_schedule` every 1 to 23 (more is a comment), from `ciamSnapshotAt` on the hour; `max_retention_days`, snapshots kept when the disk is deleted; `storage_locations` the first `ciamCopyRegion` (one location: more are a comment); `guest_flush` when application-consistent; its snapshots labelled `policy` (the record's name) and `role`; an `import` block when its provider ref is recorded. Attached to each disk that follows it by `google_compute_disk_resource_policy_attachment` (a boot disk by its instance's name). One someone else keeps: a comment |

### Backup vaults and plans

The core `data` domain's backup vaults (`ciamBackupVault`) and plans (`ciamBackupPlan`) render as Backup and DR into `main.tf` (`opsdir_adapter_gcp.backups`).

| Record | Renders as |
|---|---|
| `ciamBackupVault` the stack keeps | A `google_backup_dr_backup_vault` `ciam-<env>-<name>` in the copy region of the plans writing to it (the first; a vault in another region is how Backup and DR copies backups there), else the environment's region; `backup_minimum_enforced_retention_duration` its lock days (a day when nothing is locked: Backup and DR always enforces one); labelled `name`, `role`. A compliance lock's `effective_time` (after which the minimum can't be lowered) and a vault restoring elsewhere without a copy region are comments. An `import` block when its provider ref is recorded |
| `ciamBackupPlan` the stack keeps | A `google_backup_dr_backup_plan` with `backup_plan_id` its name, in the environment's region (where the disks are), for `compute.googleapis.com/Disk`, writing to its vault, with one backup rule: `backup_retention_days` (less than the vault enforces, which Backup and DR refuses: the plan is a comment), a `standard_schedule` `HOURLY` every `ciamBackupEveryHours` (6 to 23: Google's console guide sets six hours as the least) or `DAILY`, `UTC`, its `backup_window` from `ciamBackupAt`'s hour for `ciamBackupWindowHours` (6 when not stated); and a `google_backup_dr_backup_plan_association` per disk of the volumes it protects (its protected roles that are volumes, and the volumes naming it). Another interval, more copy regions than the first, a protected role that isn't a volume, and a vault the stack doesn't keep are comments |
| One someone else keeps (`ciamManagedBy`) | A comment naming them |

## Reading an environment back from Terraform state

```bash
terraform -chdir=… state pull > export/target/prod/terraform.tfstate     # one folder per <cloud>/<env>
opsdir import --dry-run gcp/terraform-state export/                        # what the live environment differs in
opsdir import --change CHG-… gcp/terraform-state export/                   # record it
```

The importer `gcp/terraform-state` reads Terraform state (format version 4, `hashicorp/google`; managed resources and data sources) into the environment's servers and bindings. Environments are chosen by the folder layout, `<cloud>/<env>/`; an environment whose cloud isn't Google Cloud, and a state outside the layout, are named, not imported. Resource names (`projects/<p>/…`) are the provider references; self links are read as the names they end with.

| Google Cloud resource | Record entry | Matched by |
|---|---|---|
| `google_compute_network` | network | its resource name (`ciamProviderRef`) |
| `google_compute_subnetwork` | subnet binding: its range | its resource name |
| `google_compute_instance` | server: address, zone, machine type, boot image, subnetwork; role and product from metadata `ciam-role`, `ciam-product` (exact; the renderer writes them), else labels `role`, `product`; hostname | name, hostname or private address |
| `google_compute_firewall` (ingress allow) | firewall rule: sources, single ports, protocol, priority; named by the rule name its description ends with (`… (fw-name)`, as rendered), else its name; target role from the instances carrying its target tag, else the tag's `ciam-<env>-` suffix. Rules admitting only Google Cloud's health-check probes belong to load balancers and are left out | rule name |
| `google_compute_forwarding_rule` + `google_compute_region_backend_service` (or global), `google_compute_instance_group`, `google_dns_record_set` | service name: DNS name and managed zone of the A record holding its address, its ports (none from a rule forwarding all ports), the role most of its instances have, its address | DNS name |
| `google_compute_router_nat` (+ `google_compute_address`) | egress: its static addresses | its resource name |
| `google_secret_manager_secret`, `google_secret_manager_regional_secret` | secret reference `gcp-sm://projects/<p>/[locations/<l>/]secrets/<name>`; automatic rotation when it has a rotation period (Secret Manager's rotation notifies; something must act on it) | reference URI |
| `google_kms_crypto_key` | key reference `gcp-kms://<name>`: protection level (`SOFTWARE` → `software`, `HSM` → `hsm`, `HSM_SINGLE_TENANT` → `managed-hsm`, `EXTERNAL`/`EXTERNAL_VPC` → `external`), automatic rotation when it has a rotation period | reference URI |
| `google_storage_bucket` | object store `gs://<bucket>` | storage reference |
| `google_storage_transfer_job` (enabled; its replication spec, else a transfer spec from bucket to bucket) | the copied bucket's replica (`ciamStorageReplicaRef`, `gs://<sink>[/<path>]`) | the bucket's |
| `google_cloudfunctions2_function`, `google_cloudfunctions_function`, `google_cloud_run_v2_job`, `google_cloudbuild_trigger` (+ `google_cloud_scheduler_job`) | job binding: runtime, and the schedules of the Cloud Scheduler jobs whose HTTP or Pub/Sub target names it | its resource name |
| `google_compute_region_instance_group_manager`, `google_compute_instance_group_manager` (+ autoscaler, instance template) | compute group: the role its template's labels name, machine type, image, target size, min/max from the autoscaler, zones. Binding role label `bindingrole`, else `compute-<role>` | its resource name |
| `google_container_cluster` (+ `google_container_node_pool`) | cluster: version, the add-ons it enables (from `addons_config`, workload identity, Secret Manager), node pools (`name: machine type, min-max`), node locations. Binding role label `bindingrole` or `role`, else `cluster` | its resource name |
| `google_pubsub_topic` | stream carrier: topic | its resource name |
| `google_monitoring_notification_channel` | alert channel: `pagerduty` → `paging-service`, `email`, `pubsub` → `topic`, `webhook`, else `other` | its resource name |
| `google_logging_project_bucket_config` | log destination: `log-group`, its retention in days | its resource name |
| `google_logging_project_sink`, `google_logging_organization_sink`, `google_logging_folder_sink` (+ `google_project_iam_audit_config`, `_organization_`, `_folder_`, and IAM policies' `auditConfigs`) | audit trail (`ciamAuditTrail`, role `audit-trail`) when its filter exports Cloud Audit Logs (no filter: every log): scope `account` for a project's sink, `organization` for one including its children; `control-plane` when it exports Admin Activity, `data-read` / `data-write` when it exports Data Access and an audit config on its parent turns them on; every region; where its records go (`ciamLogDestinationRole`: its bucket's object store, or its log bucket). Disabled sinks and the built-in `_Required` and `_Default` sinks aren't trails | its resource name (`ciamProviderRef`) |
| `google_monitoring_alert_policy` | alarm the cloud runs: the metric its first condition filters on (`metric.type`), or `log query`; the channels it notifies; the alert rule it realizes (label `realizes`). Binding role label `role` or `bindingrole`, else `alarm-<realizes>` | its resource name |
| `google_monitoring_uptime_check_config` | synthetic check: its period as an interval (`5m`), the canary it realizes; binding role else `canary-<realizes>` | its resource name |
| `google_service_account` | identity binding (kind `service-account`, `federated` when a workload identity pool's subjects may act as it); role from its display name's `(<role>)`, as the renderer writes it | its email, else its account id |
| `google_<target>_iam_member`, `_iam_binding`, `_iam_policy` on a project, folder, organization, secret (global or regional), key, key ring, bucket, topic, subscription, service account, IAP tunnel | each member's grants: `<role> on <resource name>`, ` (if <condition title or expression>)` when conditional; a custom role (`google_project_iam_custom_role`, `google_organization_iam_custom_role`) as its permissions; a role bound on a folder or the organization is inherited and covers the environment's resources. A group or user member is an identity of its own (kind `group` / `user`, its email as provider ref, as the landing zone names an operator's group); `allUsers` / `allAuthenticatedUsers` grants are named, not recorded | (on the identity) / email |
| `roles/iam.workloadIdentityUser` for `principal://…/workloadIdentityPools/<pool>/subject/<subject>` (+ `google_iam_workload_identity_pool_provider`) | the service account's trust (`ciamTrustedBy`): `<issuer URL> <subject>` for each OIDC provider of the pool | (on the identity) |
| `google_iam_deny_policy` | denials (`ciamDenial`) on the identities its rules name (`principalSet://goog/public:all`: every identity in the state, its exception principals left out): each denied permission as IAM names it (`secretmanager.googleapis.com/versions.access`: `secretmanager.versions.access`), exception permissions excluded (`p!e`), on the resource it is attached to, ` (if <condition>)` when conditional | (on the identity) |
| `google_org_policy_policy`, `google_project_organization_policy` | a guardrail per parent (kind `org-constraint`; role `guardrail-org-policy-<parent id>`): what its enforced constraints prevent (`ciamDenies`), by the constraints the renderer sets | `<parent>/policies` |
| `google_iap_tunnel_iam_*`, `google_iap_tunnel_instance_iam_*` | access path `iap` (role `access-iap`): who may tunnel in (`ciamTrustedBy`) and the grants | `projects/<p>/iap_tunnel` |

**What changes**, **roles of new resources** and the role map (`roles.json` beside the state, `{provider ref or name: role}`) work as on AWS and Azure (`opsdir.core.inventory`). Roles come from labels `role` / `bindingrole`; label values are lowercase, as the record's roles are. Firewall rules carry no labels: name new ones in `roles.json`, or record them.

**Named, not recorded:** port ranges and all-ports rules (`ciamPort` holds single ports); network tag and service account sources (not address ranges); deny and egress rules; resource types that hold secret values or aren't modeled yet (`google_secret_manager_secret_version`, `google_secret_manager_regional_secret_version`, `random_password`, `tls_private_key`, `google_service_account_key`, `google_sql_user`), counted by type.

**Identities, guardrails and access paths.** An identity binding is matched by its provider ref, else by the identity's short name (an IAM role's name, a resource ID's last segment, a service account's account id), so a record that names an identity by its short name takes the full reference from the state. Grants, denials and ceilings are written in the cloud's own terms (`ciamGrant`, `ciamDenial`, `ciamBoundary`: `<action or role> on <resource>`, then ` (resource policy)`, ` (if <condition>)`, ` (eligible)`; parentheses in a condition become brackets; `p!a|b` is what `p` matches but `a` and `b`, `!a|b` every action but those), and the planner evaluates them (see Access below). Groups, users and other principals the state names without a role (a role map names them, as for any resource) are counted in one notice, not listed one by one.

**Secrets.** Secret values are never read: a Secret Manager secret is recorded from its project, location and name alone, and the reader drops whatever the state marks sensitive before anything sees it.

### The edge, read back

What the edge runs comes back in the edge domain's terms (`opsdir_adapter_gcp.edge_inventory`; only what someone chose, the TLS mode always kept):

| Google Cloud resource | Record entry |
|---|---|
| forwarding rule (regional or global) and what it leads to | facts on its service name: `tls-mode` (passthrough when it names a backend service; terminate or reencrypt through a target HTTPS proxy and URL map), `tls-min` / `tls-profile` from the SSL policy, `health`, `stickiness`, `idle-timeout` (not 30), `drain` (not 0 or 300) |
| `google_dns_record_set` holding its address | the service name's TTL; in a weighted round robin, `weighted` and its weight (the other answers named) |
| backend service's security policy (+ its rules) | edge service `waf` (Cloud Armor): `waf-mode` (detect when every rule is a preview), `waf-category` from preconfigured rule sets, `rate-limit` from rules described `rate-<kind>`, `ip-rule`, `geo-rule`; Adaptive Protection as edge service `ddos application-advanced` |
| backend service with `enable_cdn` | edge service `cdn` |
| `CLOUD_ARMOR_NETWORK` policy with advanced protection | edge service `ddos network-advanced` (role from its labels) |
| `google_dns_managed_zone` (a forwarding zone: a forwarder), other record sets | DNS zones, records (TXT unquoted), forwarders |

Rules admitting only a proxy-only subnet (role `subnet-edge`), like those admitting only the health checks, belong to load balancers and are left out.

### The network depth, read back

What the network carries beyond networks, subnetworks and VPC firewall rules comes back in the network domain's terms (`opsdir_adapter_gcp.network_inventory`; Cloud Asset Inventory and gcloud items normalize to the same names: `cli_network.py`). Matching is by provider ref (the resource name); a new one needs its label `role`, or a role in `roles.json`. What Google Cloud can't label takes a role by convention, the same in every environment: a network's routes `routes`, a peering `peering-<peer network name>`, a subnetwork's flow logs `flow-logs-<subnet role>`.

| Google Cloud resource | Record entry |
|---|---|
| `google_compute_network_firewall_policy_rule` | firewall rules under the policy model: ingress allow rules by rule name, sources, single ports, priority, the policy they belong to (`ciamPolicyRole`), the role of the instances their target secure tag values are bound to (else the value's short name); probe and proxy-only-subnet rules are the load balancers'; egress allow rules naming sites (`dest_fqdns`) are the policy's egress allowlist |
| `google_compute_network_firewall_policy` (+ association) | firewall policy (scope network); the network's `network_firewall_policy_enforcement_order` as its `ciamPolicyOrder`; the egress allowlist as a proxy kind `firewall` with the policy's name as its provider ref |
| `google_compute_firewall_policy` (+ rules) | firewall policy (scope hierarchical): read, never rendered; its rules counted, not recorded |
| `google_compute_route` | one route table per network (Google Cloud's routes are network-wide): `<destination> <kind> [<target>] [for <roles>]`, the roles those of the instances carrying the route's network tags |
| `google_compute_global_address` (`PRIVATE_SERVICE_CONNECT`) + global forwarding rule to `all-apis` / `vpc-sc` | private endpoint `all-apis` (the forwarding rule its provider ref, the address its frontend, the address's label `role`); not a service name |
| `google_compute_global_address` (`VPC_PEERING`) | private endpoint `peered-service`: private services access, its allocated range (`address`/`prefix_length`) as `ciamCidr`, the address its provider ref, its label `role`; what it serves is the record's |
| `google_compute_service_attachment` | endpoint service: the forwarding rule it exposes, its URI for consumers, the projects and networks accepted, acceptance, its PSC NAT subnets |
| `google_compute_network_peering`, `google_compute_vpn_tunnel` (+ router and router peer), `google_compute_interconnect_attachment` | interconnect depth: peering (`ACTIVE`: accepted; its other side the environment whose network binding is the peer network), VPN (peer address, BGP numbers), dedicated |
| a subnetwork's `log_config` | flow log (scope subnet) |
| `google_compute_router_nat` | its egress binding's `ciamNatAllocation`: `MANUAL_ONLY` static, `AUTO_ONLY` automatic (nothing a partner can allowlist) |

A tag key the platform's own Terraform made (its description says `Managed by opsdir`, or its short name is the render's `ciam-<env>-role`) isn't read into `ciamTagKeyRef` (the render would then stop making it); a firewall tag key someone else made for the environment's network (`purpose_data.network`) is the network policy's `ciamTagKeyRef`, which the render references instead of creating one (several such keys are named: which one is the record's to say). A VPN's other side comes from its label-free tag `PeerEnvironment` only: the record holds no gateways to match `peer_gcp_gateway` against, and a peer's address isn't evidence of an environment.

### Managed databases, read back

`opsdir_adapter_gcp.databases` (Cloud Asset Inventory's `sqladmin.googleapis.com/Instance` and `gcloud sql instances list` normalize to the same names). Matching is by provider ref (`projects/<project>/instances/<name>`); a new one needs its label `role`. `root_password` is never read, and `google_sql_user` (it can hold a password) is counted, not read.

| Google Cloud resource | Record entry |
|---|---|
| `google_sql_database_instance` | database: engine, major version and edition from `database_version`, service `cloud-sql`, endpoint (`dns_name`) and the engine's port, tier, disk, zone, `zone-redundant` when `REGIONAL`, TLS from `ssl_mode` (`ENCRYPTED_ONLY`, `TRUSTED_CLIENT_CERTIFICATE_REQUIRED`, else `require_ssl`), retained backups (7 when enabled without a count) and point-in-time restore (PITR or binary log), a backup `location` other than its region as `ciamCopyRegion`, deletion protection, its flags; its CMEK key as a role |

### Disks and snapshot schedules, read back

`opsdir_adapter_gcp.volumes` (Cloud Asset Inventory's `compute.googleapis.com/Disk` and `ResourcePolicy`, `gcloud compute disks list` and `resource-policies list` normalize to the same names). Volumes and snapshot policies are matched by name; a new one needs its label `role`.

| Google Cloud resource | Record entry |
|---|---|
| `google_compute_disk` (+ `google_compute_attached_disk`), grouped by label `volume` | data volume of the role its instances run (an instance's boot disk: its role's boot volume): the most common size, class, IOPS and throughput, its key and the schedule its resource policies (or a policy attachment) name as roles |
| An instance's `boot_disk` labelled `volume` (Terraform state, where no disk of its own is reported) | the role's boot volume |
| `google_compute_resource_policy` with a snapshot schedule | snapshot policy named by its snapshots' label `policy` (else its own name, `ciam-<env>-<name>` when rendered here): hours (daily is 24), start time, `max_retention_days`, a storage location outside its region as its copy region, consistency from `guest_flush` |

A data disk the environment's instances use without a `volume` label is named.

### Backup vaults and plans, read back

`opsdir_adapter_gcp.backups` (Cloud Asset Inventory's `backupdr.googleapis.com/BackupVault`, `BackupPlan` and `BackupPlanAssociation`, and `gcloud backup-dr … list`, normalize to the same names).

| Google Cloud resource | Record entry |
|---|---|
| `google_backup_dr_backup_vault` | backup vault named by its label `name` (else its id): its minimum enforced retention as its lock (`governance`, `compliance` once it has an effective time; a day: none) and lock days; restoring in another region when a plan in another location writes to it |
| `google_backup_dr_backup_plan` (+ its associations) | backup plan named by its id: its first rule's schedule (every hours, start hour, window unless the default 6), retention, the vault's location as its copy region when it differs, its vault; the roles (label `role`) of the disks its associations name; a new plan's role is its id (plans carry no labels in Terraform). A disk an association names follows the plan (its volume's snapshot policy role). Several rules: the first is read |

A vault, plan or association whose `state` says it is being deleted, deleted or inactive is named, not read.

## Reading an environment from Cloud Asset Inventory and gcloud

Where there is no Terraform state (or to check it against what the project actually runs), `gcp/cli-inventory` reads Cloud Asset Inventory and `gcloud … --format=json` output. Collect it once per environment, into one folder per `<cloud>/<env>`; file names are free (`.json`, or `.jsonl` for an export), because every item says what it is: an asset by its asset type, a compute item by its `kind`, the others by their resource names. The one exception is DNS: `gcloud dns record-sets list` doesn't print the zone, so each zone's record sets go in a file named after the zone (record sets in an asset export name their zone).

```bash
out=export/target/prod; P=ciam-prod; HOST=host-net; R=us-central1      # the environment's project, the Shared VPC host
mkdir -p $out/dns $out/health
# the broad inventory: every asset with its resource data (gcloud asset export --content-type=resource to Cloud
# Storage writes the same assets as JSON lines)
gcloud asset list --project=$P --content-type=resource --format=json       > $out/assets.json
gcloud asset list --project=$HOST --content-type=resource --format=json \
  --asset-types=compute.googleapis.com/Network,compute.googleapis.com/Subnetwork   > $out/host-network.json
gcloud projects describe $P --format=json                                 > $out/project.json   # numbers -> IDs
# what the inventory lacks: instance metadata (exact role and product), backend membership, record sets, schedules
gcloud compute instances list --project=$P --format=json                  > $out/instances.json
gcloud compute backend-services list --project=$P --format='value(name,region.basename())' |
  while read -r name region; do
    gcloud compute backend-services get-health "$name" --region="$region" --project=$P --format=json > "$out/health/$name.json"
  done
for zone in $(gcloud dns managed-zones list --project=$HOST --format='value(name)'); do
  gcloud dns record-sets list --zone="$zone" --project=$HOST --format=json > "$out/dns/$zone.json"
done
gcloud scheduler jobs list --location=$R --project=$P --format=json       > $out/scheduler.json
gcloud beta monitoring channels list --project=$P --format=json           > $out/channels.json
gcloud sql instances list --project=$P --format=json                      > $out/sql-instances.json   # also in assets
gcloud compute disks list --project=$P --format=json                      > $out/disks.json           # also in assets
gcloud compute resource-policies list --project=$P --format=json          > $out/resource-policies.json
gcloud backup-dr backup-vaults list --project=$P --location=- --format=json     > $out/backup-vaults.json      # also in assets
gcloud backup-dr backup-plans list --project=$P --location=- --format=json      > $out/backup-plans.json
gcloud backup-dr backup-plan-associations list --project=$P --location=- --format=json > $out/backup-plan-associations.json

# the edge (also in the asset export): URL maps, HTTPS proxies, SSL and security policies, health checks, zones
for kind in url-maps target-https-proxies ssl-policies health-checks security-policies; do
  gcloud compute $kind list --project=$PROJECT --format=json > "$out/$kind.json"
done
gcloud dns managed-zones list --project=$HOST --format=json > $out/managed-zones.json

# the network depth: network and hierarchical firewall policies, routes, attachments, tunnels, tag values and bindings
gcloud compute network-firewall-policies list --project=$HOST --format='value(name)' | while read -r fp; do
  gcloud compute network-firewall-policies describe "$fp" --global --project=$HOST --format=json > "$out/policy-$fp.json"
done
gcloud compute routes list --project=$HOST --format=json                  > $out/routes.json
gcloud compute service-attachments list --project=$P --format=json        > $out/service-attachments.json
gcloud compute vpn-tunnels list --project=$HOST --format=json             > $out/vpn-tunnels.json
gcloud resource-manager tags values list --parent=tagKeys/KEY --format=json  > $out/tag-values.json
gcloud compute instances list --project=$P --format='value(name,zone.basename(),id)' |
  while read -r name zone id; do
    gcloud resource-manager tags bindings list --location=$zone --format=json \
      --parent=//compute.googleapis.com/projects/$P/zones/$zone/instances/$id > "$out/tag-bindings-$name.json"
  done

# IAM: policies on every resource, the folders and organization above (inherited), accounts, roles, deny and org policies
gcloud asset export --content-type=iam-policy --project=$P --output-path=gs://<bucket>/iam.json   # then copy it here, or:
gcloud asset search-all-iam-policies --scope=organizations/<org id> --format=json > $out/iam-policies.json
gcloud iam service-accounts list --project=$P --format=json            > $out/service-accounts.json
for r in $(gcloud iam roles list --project=$P --format='value(name)'); do
  gcloud iam roles describe "$r" --format=json                         > "$out/role-${r##*/}.json"
done
for pool in $(gcloud iam workload-identity-pools list --location=global --project=$P --format='value(name)'); do
  gcloud iam workload-identity-pools providers list --workload-identity-pool="${pool##*/}" --location=global --project=$P --format=json > "$out/providers-${pool##*/}.json"
done
AP=cloudresourcemanager.googleapis.com/projects/$P
for d in $(gcloud iam policies list --attachment-point=$AP --kind=denypolicies --format='value(name)'); do
  gcloud iam policies get "${d##*/}" --attachment-point=$AP --kind=denypolicies --format=json > "$out/deny-${d##*/}.json"
done
for c in $(gcloud org-policies list --project=$P --format='value(constraint)'); do
  gcloud org-policies describe "$c" --project=$P --effective --format=json > "$out/org-policy-${c##*/}.json"
done

opsdir import --dry-run gcp/cli-inventory export/
opsdir import --change CHG-… gcp/cli-inventory export/
```

Without Cloud Asset Inventory (the API disabled, or no `cloudasset.assets.listResource` permission), the same resources come from the services' own lists: `gcloud compute networks|networks subnets|instances|disks|firewall-rules|forwarding-rules|backend-services|addresses|routers|instance-groups managed|instance-templates|autoscalers list`, `gcloud secrets list`, `gcloud kms keys list --keyring=… --location=…`, `gcloud storage buckets list`, `gcloud functions list --v2`, `gcloud run jobs list`, `gcloud builds triggers list`, `gcloud container clusters list`, `gcloud pubsub topics list`, `gcloud monitoring policies list`, `gcloud monitoring uptime list-configs`, `gcloud logging buckets list`, `gcloud logging sinks list` (saved as `log-sinks/<project>.json`, an organization's as `log-sinks/organizations-<id>.json`: the list doesn't name its parent) (each `--format=json`). Data Access audit configs come from the project's IAM policy (`--content-type=iam-policy`). Both may be mixed; an item listed twice is read once.

The outputs are read into the same resources as Terraform state (the mapping is shared), so the table above, what changes, roles and `roles.json` apply unchanged. Differences:

- **Instance metadata.** Cloud Asset Inventory keeps only a few platform metadata keys (`enable-oslogin`, …), so an instance it reports takes its role from its label `role` and its exact product isn't read; `gcloud compute instances list` carries the metadata (`ciam-role`, `ciam-product`), and only those two keys are kept (never startup scripts).
- **Load balancers.** Instance groups don't list their members; `backend-services get-health` does, so a service's target role needs it.
- **Project numbers.** Some services name resources by project number (`projects/123…/secrets/…`); with `gcloud projects describe` output beside them, numbers are read as project IDs, else each number is named in the notices.
- **Scope.** Subnetworks and instances are read only inside the networks listed; others are counted. Project-wide listings (secrets, keys, buckets, jobs, topics, monitoring) are counted rather than named when the record doesn't have them and nothing names a role.
- **Named, not read:** search results (`gcloud asset search-all-resources` holds no resource data), asset types the mapping doesn't model (counted by type; node pools and 1st-gen `CloudFunction` assets are read from their cluster and `Function` assets), files that aren't JSON and items that aren't recognized (counted per file).
- **Secrets.** Secret values are never read: `secrets list` returns names and settings only, and a notification channel's configuration labels (addresses, partially returned tokens) are dropped.

**IAM** is read as from Terraform state (`opsdir_adapter_gcp.cli_iam`): IAM policies from the inventory (`iamPolicy` of an export, `policy` of a search; search the organization or a folder to see what the project inherits), service accounts, custom roles (`roles describe`: `list` leaves out their permissions), pool providers, deny policies, organization policies (`org-policies describe`, or the inventory's `orgPolicy`). A bucket's inventory name (`//storage.googleapis.com/<bucket>`) is read as IAM names it, project numbers as project IDs.

### What a cloud evaluator says

The renderer writes `access/evaluate.sh` beside the Terraform when an identity the environment binds (by its provider ref) has principals acting as it: for each of their permissions it asks Policy Troubleshooter (`gcloud policy-intelligence troubleshoot-policy iam <full resource name> --principal-email=<account> --permission=<permission>`: allow and deny policies): each requirement's IAM permission on its binding's resource and saves the answer as `evaluations/<identity>/<verb>__<role>[.<n>].json` (n numbers a permission's parts: one per requirement). Run it where the CLI is signed in, into the environment's export folder, then import as above:

```bash
sh out/gcp-prod/access/evaluate.sh export/source/prod
opsdir import --dry-run gcp/cli-inventory export/
```

Each answer is recorded on the identity as `ciamEvaluated` (`<verb> <role>: allowed|denied|unknown (gcp-policy-troubleshooter <date of the import>)`, the worst of a permission's parts), and the planner prefers it over evaluating the recorded policies. States: `CAN_ACCESS` allowed, `CANNOT_ACCESS` denied, `UNKNOWN_INFO` and `UNKNOWN_CONDITIONAL` unknown (the caller can't see everything, or a condition's context wasn't given). It answers for service accounts and users, not groups: a group's permissions are left to the recorded policies. A service name's forwarding rule and zone are named by pattern in the record, so they aren't asked.

## The region list (a provider prerequisite)

The record's region catalog (core `estate` domain: residencies and the planner's region checks) needs Google Cloud's own list of regions. The adapter declares it as the prerequisite `gcp-regions` (`opsdir prerequisites` shows whether it is met) and reads it with `gcp/regions`: the output of `gcloud compute regions list --format=json`, the Compute Engine regions your project can see.

```sh
opsdir import gcp/regions --run --change CHG-…         # runs gcloud under your own login; opsdir never sees the credentials
gcloud compute regions list --format=json > regions.json
opsdir import gcp/regions regions.json --change CHG-…  # or run it yourself (elsewhere) and import the file
```

Every region listed is recorded `available` in the `public` partition (Google Cloud has one). The list gives no display names or geography: add them to the catalog yourself, a refresh keeps them. A refresh adds new regions, shows changed details as conflicts to take or keep, and keeps a region Google Cloud stops listing, marked `not-listed`. An export listing no region is refused.

## Landing zone

What the platform needs from the organization rather than its own Terraform is rendered per environment into `terraform/landing-zone/` (its own root: `providers.tf`, `main.tf`) for whoever keeps the landing zone: the header names them (the owners of the environment's guardrails, else of its cloud, else of the environment) and the MANIFEST marks the files `landing-zone`. Nothing is rendered when the environment needs nothing from one. When the target lacks a guardrail's prevention or a way in the source has, the planner drafts a request to that owner (`requests/<owner>.md`).

| From the record | Rendered as |
|---|---|
| Deployer principals whose identity binding trusts an OIDC issuer (`ciamTrustedBy`: `<issuer URL> <subject>`) | `google_iam_workload_identity_pool` (`ciam-<env>-ci`), a `google_iam_workload_identity_pool_provider` per issuer whose attribute condition accepts only the deployers' subjects, and per deployer a `google_service_account` its subject may act as (`roles/iam.workloadIdentityUser` for `principal://…/subject/<subject>`) with its resource-level IAM members |
| Operator principals whose identity binding names a group (its email) | Resource-level IAM members granted to `group:<email>` |
| Guardrails' denials (`ciamDenies`) | `google_org_policy_policy` on the project, each constraint once: `region-escape` `gcp.resourceLocations` (`in:<region>-locations` for the cloud's region and each region the environment's residency allows, core `estate` domain), `public-storage` `storage.publicAccessPrevention`, `service-account-keys` `iam.disableServiceAccountKeyCreation` and `iam.disableServiceAccountKeyUpload`, `key-deletion` `cloudkms.disableBeforeDestroy`, `audit-log-disable` `iam.disableAuditLoggingExemption` (Admin Activity audit logs can't be disabled at all; this stops new exemptions). `metadata-v1` and `root-use` don't apply (`# NOTE`) |

### The network plumbing

The network's plumbing is the landing zone's (`ciamEgress`, `ciamRouteTable`, `ciamNetworkAcl`, `ciamInterconnect`, `ciamFlowLog`), as are private endpoints and egress firewalls whose `ciamManagedBy` names someone else: rendered into `terraform/landing-zone/network.tf` for the landing zone's owner, or into `terraform/landing-zone/<party>/` (its own root, applied by that team) when `ciamManagedBy` names another party. A binding with a provider ref already exists: its resource carries a Terraform `import` block so the keeper adopts it; one without is created, and the planner asks its keeper for it (`requests/<party>.md`). Everything lives in the network's project (a Shared VPC's host project); the network and subnetworks are read as data. Inputs only the keeper knows are variables in the root's `providers.tf`.

| From the record | Rendered as |
|---|---|
| `ciamEgress` | `google_compute_router` and `google_compute_router_nat` for the environment's subnetworks (`LIST_OF_SUBNETWORKS`; all when none is recorded): `ciamNatAllocation` `static` is `MANUAL_ONLY` with `nat_ips` the reserved addresses of its `ciamCidr`, looked up by IP (`data google_compute_addresses`, `filter = "address:<ip>"`); `automatic` is `AUTO_ONLY`. The provider ref (`<project>/<region>/<router>/<nat>`, as the importers record it) names both and is imported. A private range is Private NAT: a comment |
| `ciamRouteTable` | Google Cloud's routes are network-wide: a `google_compute_route` per `ciamRoute` (`ciam-<env>-<table>-<n>`, priority 1000), `tags` the network tags of the roles after `for`; next hop: `internet` the default internet gateway, `appliance` an address (`next_hop_ip`) or instance, `gateway-lb` an internal load balancer's forwarding rule, `firewall` the load balancer in front of the egress firewall (a variable), `vpn` a tunnel (routes over an HA VPN rendered here are learned by BGP: a comment). `nat`, `peering`, `transit`, `endpoint` aren't next hops: comments. `ciamSubnetRole` can't be associated: a comment. Existing routes keep their own names (not recorded): a comment on importing them |
| `ciamNetworkAcl` | A comment: Google Cloud has no stateless network ACLs |
| `ciamInterconnect` `ciamLinkKind` `peering` | `google_compute_network_peering` (our half) with the other environment's network (`peer_network` its self link; on another provider: a comment to record a VPN), imported as `<project>/<network>/<peering>`; a comment for the other half unless `ciamPeerAccepted` |
| `vpn` | HA VPN with BGP: `google_compute_ha_vpn_gateway`, `google_compute_external_vpn_gateway` (an interface per `ciamPeerGateway`, up to four), a `google_compute_router` with the local ASN (`ciamLocalAsn`; `ciamAdvertisedCidr` as custom advertised ranges), and per peer address a `google_compute_vpn_tunnel`, `google_compute_router_interface` and `google_compute_router_peer` (`ciamPeerAsn`). The pre-shared key (sensitive) and each tunnel's link-local BGP range and peer address are variables, never the record's. Without both ASNs, or a peer gateway: a comment |
| `dedicated`, `hub`, `transit`, or no `ciamLinkKind` | A comment: a Cloud Interconnect attachment, a Network Connectivity Center spoke, no transit gateway on Google Cloud, the kind not recorded |
| `ciamFlowLog` | A comment per subnet (scope `network`: every subnet): flow logs are the subnetwork's `log_config`, set where the subnetwork is defined, and where they go (`ciamLogDestinationRole`, retention) |
| `ciamPrivateEndpoint` kept by someone else | As the stack renders it (Private Service Connect for Google's APIs), the forwarding rule imported from the provider ref |
| `ciamProxy` kind `firewall` kept by someone else | Its allowlist as egress rules in the keeper's network firewall policy (named by the provider ref), for every instance of the network |

## Access: what permissions mean on Google Cloud

Permissions are recorded neutrally (the core `access` domain: permission sets of `<verb> <binding role>`, held by principals); this table says what each verb on a binding of a class means here. The renderer grants the first alternative of each requirement. The planner (`opsdir plan`) judges each permission of an identity that records what the cloud gives it, following the cloud's evaluation order: **denied** when an unconditional explicit deny matches (`ciamDenial`: the identity's own policies, a resource's policy, a deny assignment or policy, or a guardrail's) or a ceiling doesn't allow it (`ciamBoundary`: a permissions boundary, a control policy's allows); **allowed** when an unconditional grant (`ciamGrant`) matches; **unknown** when the only grant is conditional (`(if …)`) or eligible but not active (`(eligible)`), or a conditional deny matches, since what decides it wasn't imported. A cloud evaluator's verdict recorded on the identity (`ciamEvaluated`) wins. In the target, a permission denied or not granted is a blocker (with what denies it) and an unknown one an action to verify; grants no permission explains, wildcard grants and escalations no permission explains are actions.

| Verb | Binding | Predefined roles (any of) |
|---|---|---|
| `read-secret` / `write-secret` | secret (`gcp-sm://`) | `roles/secretmanager.secretAccessor`, `secretmanager.admin` / `secretVersionAdder`, `secretVersionManager`, `admin` |
| `use-key` / `manage-key` | key (`gcp-kms://`) | `roles/cloudkms.cryptoKeyEncrypterDecrypter`, `cryptoOperator` / `roles/cloudkms.admin` |
| `read-storage` / `write-storage` | object store, backup targets included (`gs://`) | `roles/storage.objectViewer`, `objectUser`, `objectAdmin` / `objectCreator`, `objectUser`, `objectAdmin` |
| `publish-stream` / `consume-stream` | stream: topic | `roles/pubsub.publisher`, `pubsub.editor` / `roles/pubsub.subscriber` |
| `write-logs` / `read-logs` | log destination (log bucket) | `roles/logging.logWriter`, `logging.bucketWriter` / `logging.viewer`, `logging.privateLogViewer` (project-level: broad) |
| `manage` | secret / service name / instance group | `roles/secretmanager.admin` / `roles/compute.loadBalancerAdmin` + `roles/dns.admin` (broad) / `roles/compute.instanceAdmin.v1` (broad) |

A role bound on a parent (a key ring, the project) covers what is under it; a bucket's project isn't in the record, so a project-level grant is taken to cover it. A role bound on a folder or the organization covers the environment's resources (inherited: the state was given for this environment). After the predefined roles, each requirement also names the IAM permission those roles carry (`secretmanager.versions.access` for `read-secret`, `storage.objects.create` for `write-storage`, `logging.logEntries.create` for `write-logs`, …), so a custom role's permissions can meet it and a deny policy denying that permission denies it. **Escalation** roles: `roles/owner`, `roles/editor`, `roles/iam.serviceAccountUser`, `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountAdmin`, `roles/iam.securityAdmin`, `roles/resourcemanager.projectIamAdmin`, and the permission `iam.serviceAccounts.actAs`. IAM deny policies (on the organization, a folder or the project; inherited) are denials; an IAM Condition on a binding makes it conditional; bindings inherited from the organization and folders count as the project's (Cloud Asset Inventory `search-all-iam-policies`). Evaluator: Policy Troubleshooter (allow, deny and principal access boundary policies; unknown when a condition's context is missing) may be recorded per permission. A secret under a customer managed key needs nothing of the key on the accessor's side: Secret Manager's service agent uses it.

## References and vocabulary it owns

| Scheme | Form | Resolved |
|---|---|---|
| `gcp-sm` | `gcp-sm://projects/<project>/secrets/<name>` or `gcp-sm://projects/<project>/locations/<location>/secrets/<name>` (Secret Manager) | at run time: `gcloud secrets versions access latest --secret=<name> --project=<project> [--location=<location>]` |
| `gcp-kms` | `gcp-kms://projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>` (Cloud KMS key) | never: a key is referenced, its material stays in Cloud KMS |
| `gcp-cert` | Certificate Manager certificate | not resolved |
| `gs` | `gs://<bucket>` (Cloud Storage bucket) | not resolved |

Values of `ciamCloudProvider` (`gcp`) and `ciamCloudEnvironment` (`public`) are validated against this adapter. The store refuses Google Cloud credential forms anywhere in the record: service account key files (`"private_key_id": "<40 hex>"`; the private key itself is refused by the core's private-key pattern), API keys (`AIza…`) and OAuth client secrets (`GOCSPX-…`). Cloud Storage HMAC secrets have no recognizable form; the core's secret-assignment pattern catches them in configuration syntax.

It adds no required roles, planner checks or schema of its own; the environment's product adapters say which roles it must bind.

## Known limits

- **Not yet run against a live project.** The Terraform follows the `hashicorp/google` 8.x schema; `terraform validate`/`plan` against a real project is part of the testing plan (milestone 7.2).
- **Linux only**, as on AWS and Azure.
- **DNS failover** is a plain record with a comment (Cloud DNS's primary-backup policy is configured by hand).
- **Edge.** Preconfigured WAF exclusions apply on every path; Adaptive Protection (global backend services) isn't rendered for the regional load balancer.
- **Cloud Asset Inventory and `gcloud` shapes** follow Google's API references and the gcloud source (checked 2026-10-02); like the Terraform, the importer hasn't yet read a live project (milestone 7.2).
- **Databases someone else keeps** (`ciamManagedBy`) are named in a comment, not rendered into their keeper's root yet; Oracle and MariaDB have no Cloud SQL and aren't rendered; read replicas aren't modeled yet (DR, milestone 4.10).
- **Managed instance groups' disks:** the adapter doesn't render instance templates yet, so their volumes come from the record only, and an instance template's disks aren't read into volumes yet. A snapshot schedule stores snapshots in one location and a disk follows one schedule; a policy copying to several regions renders the first, and copies to more are a backup plan's (Backup and DR, its vault there).
- **Backup and DR:** plans back up disks only (a plan protecting a database or the servers of a role is a comment: Cloud SQL keeps its own backups, `ciamDatabase`); one copy region per vault (its location).
- **Firewall model.** Classic VPC firewall rules with network tags stay the default; an environment chooses network firewall policies with secure tags (IAM-governed targeting) with `ciamFirewallModel` `policy`. The importers read both (see [The network depth, read back](#the-network-depth-read-back)); hierarchical policies are read, never rendered.

## Tests

`tests/test_gcp_audit.py`: control-plane audit trails: a project sink exporting Cloud Audit Logs to its bucket with the writer identity's grant and an audit config for data events (integrity without a locked bucket noted), an organization sink into a locked bucket, a log bucket destination, trails kept by someone else and other destinations named; the events a sink exports from its filter and its parent's audit configs (resources and IAM policies); sinks read back from state (built-in, disabled and non-audit sinks skipped), gcloud (parent from the file name) and Cloud Asset Inventory.

`tests/test_gcp_backups.py`: Backup and DR rendered (vault in the copy region with its minimum enforced retention, plan for disks with its rule, schedule and window, an association per disk; a day's minimum, compliance, other intervals, short retention, roles that aren't volumes said) and read back from state and Cloud Asset Inventory (lock and days, cross-region restore, schedule, copy region, protected roles; an association links its disk's volume to the plan; the default window isn't recorded).

`tests/test_gcp_volumes.py`: disks rendered (the boot volume on the boot disk with labels and key, data volumes as attached disks with provisioned IOPS and throughput, schedules attached to the data and boot disks) and snapshot schedules (daily and hourly, on the hour, one storage location, guest flush, an interval it can't take named, import block), read back from state and Cloud Asset Inventory / gcloud (boot disks among the disks, keys without their version, schedules linked through the disks' resource policies or attachments, an unlabelled data disk named).

`tests/test_gcp_databases.py`: managed databases rendered (a Cloud SQL instance with its key, write-only password from an ephemeral Secret Manager read, flags, backups and import; MySQL's binary log and TLS allowed; SQL Server's root password; engines Cloud SQL doesn't run and databases others keep named; the ranges it admits a comment) and read back from state (root password and SQL users never read), Cloud Asset Inventory and gcloud (the same resource).

`tests/test_gcp_cli_edge.py`: the edge from gcloud output: a forwarding rule through proxy, URL map and backend service (SSL policy, health check, affinity, timeout, draining), Cloud Armor rules, managed zones and a forwarding zone, weighted routing with the other answer named.

`tests/test_gcp_edge_state.py`: the edge read back from state: regional and global Application Load Balancers' facts with weighted routing, Cloud Armor, Cloud CDN and DDoS as edge services, zones, records and forwarding zones, the load balancers' firewall rules left out.

`tests/test_gcp.py`: registration, vocabulary and reference schemes; secret references resolved with `gcloud` (global and regional); the credential forms the store refuses; the rendered Terraform for a small environment (network from a Shared VPC host project, firewall rules by tag with pinned and assigned priorities, instances with CMEK, Shielded VM and OS Login, an internal passthrough load balancer over two zones with its DNS record, backends by `self_link` and the health-check probe rule, an external one naming its port and forwarding all ports past five, Secret Manager secrets named, never read).

`tests/test_gcp_cdn.py`: a global load balancer with Cloud CDN, global Cloud Armor and Adaptive Protection, a passthrough service keeping HTTPS to its servers, a private one refused, the record on the global forwarding rule.

`tests/test_gcp_dns.py`: weighted round robin from the first answer, failover as a plain record, records in managed zones (TXT quoted), private forwarding zones.

`tests/test_gcp_edge.py`: the edge: TLS terms as SSL policies and back, an Application Load Balancer beside the proxy-only subnet (certificate, scheme, affinity, timeout, firewall rules, Cloud Armor), what's unbound without the subnet or certificate, an internal one, Cloud Armor's rules (one exclusion per rule set, preview in detect mode, rate intervals), advanced network DDoS.

`tests/test_gcp_cli_iam.py`: IAM from the inventory and gcloud: policies on a secret, a bucket (conditional), the IAP tunnel and a folder (a custom role), project numbers as IDs, a deny policy, an organization policy; Policy Troubleshooter's verdicts read back dated; the rendered `access/evaluate.sh` (not asked for a group).

`tests/test_gcp_iam.py`: IAM from state: service accounts (role from display name), members on a secret, a bucket (conditional), a folder (inherited), a custom role's permissions for a group, workload identity trust, a deny policy (public:all, an exception, a condition), organization policies and an IAP tunnel; the planner's verdicts from what was imported.

`tests/test_gcp_landing.py`: the landing zone: a deployer's OIDC trust and permissions, an operator group's access, the guardrails, the owner in the header, nothing rendered without need.

`tests/test_gcp_access.py`: the Google Cloud access table: a secret by name or project (not another project), a bucket by its IAM name or a project, project-level log writes, roles that grant access or impersonate. `tests/test_gcp_identities.py`: a workload's service account and resource-level IAM members (global and regional secrets, a key, a bucket, a topic, log writes on the project), service account ids Google accepts.

`tests/test_gcp_cli.py`: the Cloud Asset Inventory and `gcloud` importer: items recognized by asset type (either key spelling), kind or shape; an export's instance by label and a `gcloud` instance with its exact product; firewall rules (probe rules left out); a service from forwarding rule, backend service, get-health and its zone file, and one from an exported record set and a one-port range; project numbers read as IDs (and named without the project); secrets, keys, egress, storage, jobs (a Knative-shaped Cloud Run job), compute groups, GKE add-ons from `disabled`/`enabled` flags, monitoring; search results, unmodeled asset types, other networks' instances, non-JSON files and unknown items named; no secret value carried; drift imported.

`tests/test_gcp_state.py`: the Terraform state importer: networks, subnetworks, servers with their exact role and product, firewall rules by name (probe rules left out; what can't be recorded named), a forwarding rule as a service named by its DNS record, secrets, keys, storage, jobs, compute groups, clusters, monitoring; drift found and recorded.

`tests/test_gcp_network.py`: the policy firewall model (policy and association in the network's project, tag key and values, instance tag bindings, rules by secure tag, a recorded tag key and a policy someone else keeps, hierarchical rules read only, probe and proxy rules following the model), the rules model unchanged, a PSC endpoint for Google's APIs, what the landing zone keeps, the egress private rule admitting private services access, a service attachment with its accept lists, the egress allowlist ending in a deny, nothing rendered without records.

`tests/test_gcp_network_state.py`: the policy firewall model read back (rules by secure tag as the bound role's, probe rules left out, the egress allowlist, the enforcement order, hierarchical rules counted), routes as a network-wide table, PSC for Google's APIs as a private endpoint and not a service, private services access as a peered private endpoint with its range, service attachments, peering and VPN depth, subnet flow logs, Cloud NAT's allocation; Cloud Asset Inventory and gcloud reading the same.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `gcp`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

