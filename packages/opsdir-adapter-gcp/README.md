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
| Workload principals (core `access` domain: kind `workload`, `ciamTargetRole` a server role here) | Per principal: `google_service_account` (account id from its identity binding's provider ref, else `ciam-<env>-<server role>`, at most 30 characters) set on the role's instances with scope `cloud-platform` (IAM alone decides), and one resource-level IAM member per permission from the access table below: `google_secret_manager_secret_iam_member` (regional: `google_secret_manager_regional_secret_iam_member`), `google_kms_crypto_key_iam_member`, `google_storage_bucket_iam_member`, `google_pubsub_topic_iam_member`; log writes as `google_project_iam_member` on the log bucket's project (the narrowest scope Google Cloud allows); a permission that can't be granted is a `# NOTE` |
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
| `google_service_account` | identity binding (kind `service-account`, `federated` when a workload identity pool's subjects may act as it); role from its display name's `(<role>)`, as the renderer writes it | its email, else its account id |
| `google_<target>_iam_member`, `_iam_binding`, `_iam_policy` on a project, folder, organization, secret (global or regional), key, key ring, bucket, topic, subscription, service account, IAP tunnel | each member's grants: `<role> on <resource name>`, ` (if <condition title or expression>)` when conditional; a custom role (`google_project_iam_custom_role`, `google_organization_iam_custom_role`) as its permissions; a role bound on a folder or the organization is inherited and covers the environment's resources. A group or user member is an identity of its own (kind `group` / `user`, its email as provider ref, as the landing zone names an operator's group); `allUsers` / `allAuthenticatedUsers` grants are named, not recorded | (on the identity) / email |
| `roles/iam.workloadIdentityUser` for `principal://…/workloadIdentityPools/<pool>/subject/<subject>` (+ `google_iam_workload_identity_pool_provider`) | the service account's trust (`ciamTrustedBy`): `<issuer URL> <subject>` for each OIDC provider of the pool | (on the identity) |
| `google_iam_deny_policy` | denials (`ciamDenial`) on the identities its rules name (`principalSet://goog/public:all`: every identity in the state, its exception principals left out): each denied permission as IAM names it (`secretmanager.googleapis.com/versions.access`: `secretmanager.versions.access`), exception permissions excluded (`p!e`), on the resource it is attached to, ` (if <condition>)` when conditional | (on the identity) |
| `google_org_policy_policy`, `google_project_organization_policy` | a guardrail per parent (kind `org-constraint`; role `guardrail-org-policy-<parent id>`): what its enforced constraints prevent (`ciamDenies`), by the constraints the renderer sets | `<parent>/policies` |
| `google_iap_tunnel_iam_*`, `google_iap_tunnel_instance_iam_*` | access path `iap` (role `access-iap`): who may tunnel in (`ciamTrustedBy`) and the grants | `projects/<p>/iap_tunnel` |

**What changes**, **roles of new resources** and the role map (`roles.json` beside the state, `{provider ref or name: role}`) work as on AWS and Azure (`opsdir.core.inventory`). Roles come from labels `role` / `bindingrole`; label values are lowercase, as the record's roles are. Firewall rules carry no labels: name new ones in `roles.json`, or record them.

**Named, not recorded:** port ranges and all-ports rules (`ciamPort` holds single ports); network tag and service account sources (not address ranges); deny and egress rules; resource types that hold secret values or aren't modeled yet (`google_secret_manager_secret_version`, `google_secret_manager_regional_secret_version`, `random_password`, `tls_private_key`, `google_service_account_key`, `google_sql_database_instance`, `google_sql_user`), counted by type.

**Identities, guardrails and access paths.** An identity binding is matched by its provider ref, else by the identity's short name (an IAM role's name, a resource ID's last segment, a service account's account id), so a record that names an identity by its short name takes the full reference from the state. Grants, denials and ceilings are written in the cloud's own terms (`ciamGrant`, `ciamDenial`, `ciamBoundary`: `<action or role> on <resource>`, then ` (resource policy)`, ` (if <condition>)`, ` (eligible)`; parentheses in a condition become brackets; `p!a|b` is what `p` matches but `a` and `b`, `!a|b` every action but those), and the planner evaluates them (see Access below). Groups, users and other principals the state names without a role (a role map names them, as for any resource) are counted in one notice, not listed one by one.

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

Without Cloud Asset Inventory (the API disabled, or no `cloudasset.assets.listResource` permission), the same resources come from the services' own lists: `gcloud compute networks|networks subnets|instances|disks|firewall-rules|forwarding-rules|backend-services|addresses|routers|instance-groups managed|instance-templates|autoscalers list`, `gcloud secrets list`, `gcloud kms keys list --keyring=… --location=…`, `gcloud storage buckets list`, `gcloud functions list --v2`, `gcloud run jobs list`, `gcloud builds triggers list`, `gcloud container clusters list`, `gcloud pubsub topics list`, `gcloud monitoring policies list`, `gcloud monitoring uptime list-configs`, `gcloud logging buckets list` (each `--format=json`). Both may be mixed; an item listed twice is read once.

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

## Landing zone

What the platform needs from the organization rather than its own Terraform is rendered per environment into `terraform/landing-zone/` (its own root: `providers.tf`, `main.tf`) for whoever keeps the landing zone: the header names them (the owners of the environment's guardrails, else of its cloud, else of the environment) and the MANIFEST marks the files `landing-zone`. Nothing is rendered when the environment needs nothing from one. When the target lacks a guardrail's prevention or a way in the source has, the planner drafts a request to that owner (`requests/<owner>.md`).

| From the record | Rendered as |
|---|---|
| Deployer principals whose identity binding trusts an OIDC issuer (`ciamTrustedBy`: `<issuer URL> <subject>`) | `google_iam_workload_identity_pool` (`ciam-<env>-ci`), a `google_iam_workload_identity_pool_provider` per issuer whose attribute condition accepts only the deployers' subjects, and per deployer a `google_service_account` its subject may act as (`roles/iam.workloadIdentityUser` for `principal://…/subject/<subject>`) with its resource-level IAM members |
| Operator principals whose identity binding names a group (its email) | Resource-level IAM members granted to `group:<email>` |
| Guardrails' denials (`ciamDenies`) | `google_org_policy_policy` on the project, each constraint once: `region-escape` `gcp.resourceLocations` (`in:<region>-locations`), `public-storage` `storage.publicAccessPrevention`, `service-account-keys` `iam.disableServiceAccountKeyCreation` and `iam.disableServiceAccountKeyUpload`, `key-deletion` `cloudkms.disableBeforeDestroy`, `audit-log-disable` `iam.disableAuditLoggingExemption` (Admin Activity audit logs can't be disabled at all; this stops new exemptions). `metadata-v1` and `root-use` don't apply (`# NOTE`) |

## Access: what permissions mean on Google Cloud

Permissions are recorded neutrally (the core `access` domain: permission sets of `<verb> <binding role>`, held by principals); this table says what each verb on a binding of a class means here. The renderer grants the first alternative of each requirement. The planner (`opsdir plan`) judges each permission of an identity that records what the cloud gives it, following the cloud's evaluation order: **denied** when an unconditional explicit deny matches (`ciamDenial`: the identity's own policies, a resource's policy, a deny assignment or policy, or a guardrail's) or a ceiling doesn't allow it (`ciamBoundary`: a permissions boundary, a control policy's allows); **allowed** when an unconditional grant (`ciamGrant`) matches; **unknown** when the only grant is conditional (`(if …)`) or eligible but not active (`(eligible)`), or a conditional deny matches, since what decides it wasn't imported. A cloud evaluator's verdict recorded on the identity (`ciamEvaluated`) wins. In the target, a permission denied or not granted is a blocker (with what denies it) and an unknown one an action to verify; grants no permission explains, wildcard grants and escalations no permission explains are actions.

| Verb | Binding | Predefined roles (any of) |
|---|---|---|
| `read-secret` / `write-secret` | secret (`gcp-sm://`) | `roles/secretmanager.secretAccessor`, `secretmanager.admin` / `secretVersionAdder`, `secretVersionManager`, `admin` |
| `use-key` / `manage-key` | key (`gcp-kms://`) | `roles/cloudkms.cryptoKeyEncrypterDecrypter`, `cryptoOperator` / `roles/cloudkms.admin` |
| `read-storage` / `write-storage` | backup target (`gs://`) | `roles/storage.objectViewer`, `objectUser`, `objectAdmin` / `objectCreator`, `objectUser`, `objectAdmin` |
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
- **Cloud Asset Inventory and `gcloud` shapes** follow Google's API references and the gcloud source (checked 2026-10-02); like the Terraform, the importer hasn't yet read a live project (milestone 7.2).
- **Classic VPC firewall rules with network tags.** Google's direction for governed targeting is Cloud NGFW network firewall policies with secure tags (IAM-governed); network tags remain supported. The firewall model becomes a per-environment choice in milestone 4.9.

## Tests

`tests/test_gcp.py`: registration, vocabulary and reference schemes; secret references resolved with `gcloud` (global and regional); the credential forms the store refuses; the rendered Terraform for a small environment (network from a Shared VPC host project, firewall rules by tag with pinned and assigned priorities, instances with CMEK, Shielded VM and OS Login, an internal passthrough load balancer over two zones with its DNS record, backends by `self_link` and the health-check probe rule, an external one naming its port and forwarding all ports past five, Secret Manager secrets named, never read).

`tests/test_gcp_cli_iam.py`: IAM from the inventory and gcloud: policies on a secret, a bucket (conditional), the IAP tunnel and a folder (a custom role), project numbers as IDs, a deny policy, an organization policy; Policy Troubleshooter's verdicts read back dated; the rendered `access/evaluate.sh` (not asked for a group).

`tests/test_gcp_iam.py`: IAM from state: service accounts (role from display name), members on a secret, a bucket (conditional), a folder (inherited), a custom role's permissions for a group, workload identity trust, a deny policy (public:all, an exception, a condition), organization policies and an IAP tunnel; the planner's verdicts from what was imported.

`tests/test_gcp_landing.py`: the landing zone: a deployer's OIDC trust and permissions, an operator group's access, the guardrails, the owner in the header, nothing rendered without need.

`tests/test_gcp_access.py`: the Google Cloud access table: a secret by name or project (not another project), a bucket by its IAM name or a project, project-level log writes, roles that grant access or impersonate. `tests/test_gcp_identities.py`: a workload's service account and resource-level IAM members (global and regional secrets, a key, a bucket, a topic, log writes on the project), service account ids Google accepts.

`tests/test_gcp_cli.py`: the Cloud Asset Inventory and `gcloud` importer: items recognized by asset type (either key spelling), kind or shape; an export's instance by label and a `gcloud` instance with its exact product; firewall rules (probe rules left out); a service from forwarding rule, backend service, get-health and its zone file, and one from an exported record set and a one-port range; project numbers read as IDs (and named without the project); secrets, keys, egress, storage, jobs (a Knative-shaped Cloud Run job), compute groups, GKE add-ons from `disabled`/`enabled` flags, monitoring; search results, unmodeled asset types, other networks' instances, non-JSON files and unknown items named; no secret value carried; drift imported.

`tests/test_gcp_state.py`: the Terraform state importer: networks, subnetworks, servers with their exact role and product, firewall rules by name (probe rules left out; what can't be recorded named), a forwarding rule as a service named by its DNS record, secrets, keys, storage, jobs, compute groups, clusters, monitoring; drift found and recorded.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `gcp`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
