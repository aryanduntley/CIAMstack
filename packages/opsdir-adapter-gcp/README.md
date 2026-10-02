# opsdir-adapter-gcp

opsdir adapter for Google Cloud: Terraform for Google Cloud environments, read back from Terraform state or from Cloud Asset Inventory and `gcloud` output; `gcp-sm://` secret references.

**Applies to** environments whose cloud has `ciamCloudProvider: gcp`, in Google Cloud's public cloud (`ciamCloudEnvironment: public`). Assured Workloads isn't a separate partition (it's a folder-level control boundary), so it isn't an environment value. A provider adapter: it renders and reads an environment's infrastructure bindings; products (PingDS, PingFederate, …) are other adapters.

**Depends on** `opsdir` and `opsdir-format-terraform` (HCL formatting, the Terraform state reader).

## What it renders

Per environment, `terraform/providers.tf` (`hashicorp/google ~> 8.0`; the project as variable `project_id`, the region as variable `region`, defaulting to the cloud's `ciamRegion`; credentials come from the usual Google Cloud environment, never from the record) and `terraform/main.tf`:

| From the record | Rendered as |
|---|---|
| The `network` binding: `ciamProviderRef` (the network's resource name, `projects/<host>/global/networks/<name>`, or its name) | `data google_compute_network` `main`, in the host project the name gives (Shared VPC): the landing zone owns it |
| Subnet bindings: `ciamProviderRef` = `projects/<host>/regions/<region>/subnetworks/<name>` (or a name in the cloud's region) | `data google_compute_subnetwork` |
| Firewall rules | `google_compute_firewall`, ingress allow, VPC-wide, targeting the network tag of the rule's target role (`ciam-<env>-<role>`); priority from `ciamRulePriority`. An unpinned rule takes the next free slot from 1000 (step 10) with a `# NOTE` asking for it to be pinned, so adding a rule never renumbers others (the same rule as Azure's NSG priorities, `opsdir.domains.infrastructure.firewall`) |
| Servers | `google_compute_instance`: machine type, zone, hostname, the role's network tag, a boot disk from `ciamImageRef` encrypted with the `disk-encryption` binding's Cloud KMS key (`kms_key_self_link`, else an `UNBOUND` comment), the server's subnetwork and static address, Shielded VM (secure boot, vTPM, integrity monitoring), OS Login, labels `role`, `product`, `managed_by` |
| Service names | A passthrough network load balancer: an unmanaged instance group per zone of the target role's servers, a regional TCP health check on the first port and a firewall rule admitting Google Cloud's health-check probes to the role's tag on that port (`35.191.0.0/16`; external also `209.85.152.0/22`, `209.85.204.0/22`), a regional backend service over the groups (by `self_link`, `CONNECTION` balancing), a forwarding rule (`INTERNAL` in the first target's subnetwork for a private `ciamFrontendIp`, else `EXTERNAL`; a public address named by the service's `ciamProviderRef` is read as `data google_compute_address`); a Cloud DNS record in the managed zone `ciamDnsZoneRef`. An `EXTERNAL` backend service names its port (`port_name` `ciam`, each group's `named_port`) and sets `capacity_scaler`; `INTERNAL` takes neither. A forwarding rule takes at most five ports: a service with more forwards all ports (`all_ports`, with a comment), and its firewall rules still admit only the service's |
| Secret references (`gcp-sm://projects/<p>/secrets/<name>`, regional `…/locations/<l>/secrets/<name>`) | `data google_secret_manager_secret` (regional: `google_secret_manager_regional_secret`): metadata only, so a missing secret fails the plan and no value enters Terraform state (secret versions are never rendered) |
| The `backup-target` binding (`gs://<bucket>`) | `data google_storage_bucket` `ds_backups` |
| The `pf-egress` binding | A comment naming the Cloud NAT the landing zone provides |
| Required roles without a binding | `# UNBOUND: required role …` |

Not rendered: networks, subnetworks, Cloud NAT and Cloud Routers, DNS managed zones (the landing zone creates them); Cloud KMS keys (referenced by resource name); egress firewall rules; instance service accounts and their roles (milestone 4.7); proxy (application) load balancers, certificate maps and Cloud Armor (milestone 4.8).

PingFederate's cluster discovery on Google Cloud: Ping documents no Cloud Storage protocol, so a Google Cloud environment binds `pf-cluster-discovery` with `pingfedDiscoveryProtocol` `DNS_PING` (GKE) or `TCPPING` (VMs) (see the PingFederate adapter).

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
| `google_storage_bucket` | storage `gs://<bucket>` | storage reference |
| `google_cloudfunctions2_function`, `google_cloudfunctions_function`, `google_cloud_run_v2_job`, `google_cloudbuild_trigger` (+ `google_cloud_scheduler_job`) | job binding: runtime, and the schedules of the Cloud Scheduler jobs whose HTTP or Pub/Sub target names it | its resource name |
| `google_compute_region_instance_group_manager`, `google_compute_instance_group_manager` (+ autoscaler, instance template) | compute group: the role its template's labels name, machine type, image, target size, min/max from the autoscaler, zones. Binding role label `bindingrole`, else `compute-<role>` | its resource name |
| `google_container_cluster` (+ `google_container_node_pool`) | cluster: version, the add-ons it enables (from `addons_config`, workload identity, Secret Manager), node pools (`name: machine type, min-max`), node locations. Binding role label `bindingrole` or `role`, else `cluster` | its resource name |
| `google_pubsub_topic` | stream carrier: topic | its resource name |
| `google_monitoring_notification_channel` | alert channel: `pagerduty` → `paging-service`, `email`, `pubsub` → `topic`, `webhook`, else `other` | its resource name |
| `google_logging_project_bucket_config` | log destination: `log-group`, its retention in days | its resource name |
| `google_monitoring_alert_policy` | alarm the cloud runs: the metric its first condition filters on (`metric.type`), or `log query`; the channels it notifies; the alert rule it realizes (label `realizes`). Binding role label `role` or `bindingrole`, else `alarm-<realizes>` | its resource name |
| `google_monitoring_uptime_check_config` | synthetic check: its period as an interval (`5m`), the canary it realizes; binding role else `canary-<realizes>` | its resource name |

**What changes**, **roles of new resources** and the role map (`roles.json` beside the state, `{provider ref or name: role}`) work as on AWS and Azure (`opsdir.core.inventory`). Roles come from labels `role` / `bindingrole`; label values are lowercase, as the record's roles are. Firewall rules carry no labels: name new ones in `roles.json`, or record them.

**Named, not recorded:** port ranges and all-ports rules (`ciamPort` holds single ports); network tag and service account sources (not address ranges); deny and egress rules; resource types that hold secret values or aren't modeled yet (`google_secret_manager_secret_version`, `google_secret_manager_regional_secret_version`, `random_password`, `tls_private_key`, `google_service_account_key`, `google_sql_database_instance`, `google_sql_user`), counted by type.

**Secrets.** Secret values are never read: a Secret Manager secret is recorded from its project, location and name alone, and the reader drops whatever the state marks sensitive before anything sees it.

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

opsdir import --dry-run gcp/cli-inventory export/
opsdir import --change CHG-… gcp/cli-inventory export/
```

Without Cloud Asset Inventory (the API disabled, or no `cloudasset.assets.listResource` permission), the same resources come from the services' own lists: `gcloud compute networks|networks subnets|instances|disks|firewall-rules|forwarding-rules|backend-services|addresses|routers|instance-groups managed|instance-templates|autoscalers list`, `gcloud secrets list`, `gcloud kms keys list --keyring=… --location=…`, `gcloud storage buckets list`, `gcloud functions list --v2`, `gcloud run jobs list`, `gcloud builds triggers list`, `gcloud container clusters list`, `gcloud pubsub topics list`, `gcloud monitoring policies list`, `gcloud monitoring uptime list-configs`, `gcloud logging buckets list` (each `--format=json`). Both may be mixed; an item listed twice is read once.

The outputs are read into the same resources as Terraform state (the mapping is shared), so the table above, what changes, roles and `roles.json` apply unchanged. Differences:

- **Instance metadata.** Cloud Asset Inventory keeps only a few platform metadata keys (`enable-oslogin`, …), so an instance it reports takes its role from its label `role` and its exact product isn't read; `gcloud compute instances list` carries the metadata (`ciam-role`, `ciam-product`), and only those two keys are kept (never startup scripts).
- **Load balancers.** Instance groups don't list their members; `backend-services get-health` does, so a service's target role needs it.
- **Project numbers.** Some services name resources by project number (`projects/123…/secrets/…`); with `gcloud projects describe` output beside them, numbers are read as project IDs, else each number is named in the notices.
- **Scope.** Subnetworks and instances are read only inside the networks listed; others are counted. Project-wide listings (secrets, keys, buckets, jobs, topics, monitoring) are counted rather than named when the record doesn't have them and nothing names a role.
- **Named, not read:** search results (`gcloud asset search-all-resources` holds no resource data), asset types the mapping doesn't model (counted by type; node pools and 1st-gen `CloudFunction` assets are read from their cluster and `Function` assets), files that aren't JSON and items that aren't recognized (counted per file).
- **Secrets.** Secret values are never read: `secrets list` returns names and settings only, and a notification channel's configuration labels (addresses, partially returned tokens) are dropped.

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
- **Cloud Asset Inventory and `gcloud` shapes** follow Google's API references and the gcloud source (checked 2026-10-02); like the Terraform, the importer hasn't yet read a live project (milestone 7.2).
- **Classic VPC firewall rules with network tags.** Google's direction for governed targeting is Cloud NGFW network firewall policies with secure tags (IAM-governed); network tags remain supported. The firewall model becomes a per-environment choice in milestone 4.9.

## Tests

`tests/test_gcp.py`: registration, vocabulary and reference schemes; secret references resolved with `gcloud` (global and regional); the credential forms the store refuses; the rendered Terraform for a small environment (network from a Shared VPC host project, firewall rules by tag with pinned and assigned priorities, instances with CMEK, Shielded VM and OS Login, an internal passthrough load balancer over two zones with its DNS record, backends by `self_link` and the health-check probe rule, an external one naming its port and forwarding all ports past five, Secret Manager secrets named, never read).

`tests/test_gcp_cli.py`: the Cloud Asset Inventory and `gcloud` importer: items recognized by asset type (either key spelling), kind or shape; an export's instance by label and a `gcloud` instance with its exact product; firewall rules (probe rules left out); a service from forwarding rule, backend service, get-health and its zone file, and one from an exported record set and a one-port range; project numbers read as IDs (and named without the project); secrets, keys, egress, storage, jobs (a Knative-shaped Cloud Run job), compute groups, GKE add-ons from `disabled`/`enabled` flags, monitoring; search results, unmodeled asset types, other networks' instances, non-JSON files and unknown items named; no secret value carried; drift imported.

`tests/test_gcp_state.py`: the Terraform state importer: networks, subnetworks, servers with their exact role and product, firewall rules by name (probe rules left out; what can't be recorded named), a forwarding rule as a service named by its DNS record, secrets, keys, storage, jobs, compute groups, clusters, monitoring; drift found and recorded.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `gcp`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
