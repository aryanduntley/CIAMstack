"""What Cloud Asset Inventory and gcloud report about an environment, read into the record's neutral resources. Pure.

Saved under <cloud>/<env>/ with any file names (JSON, or JSON lines as `gcloud asset export` writes), each item is
recognized on its own and normalized to the attribute names of the matching hashicorp/google resource, so the same
mapping reads them as reads Terraform state (opsdir_adapter_gcp.inventory.pairs_resources):

  gcloud asset list --content-type=resource     every asset by its asset type, from its resource.data (the service's
  gcloud asset export --content-type=resource   own representation, as the gcloud commands below print it, less some
                                                fields: an instance's metadata keeps only a few platform keys, so its
                                                role comes from its label role and its exact product only from
                                                `gcloud compute instances list`); record sets name their zone
  gcloud compute networks|subnets|instances|disks|firewall-rules|forwarding-rules|backend-services|addresses|routers
         |instance-groups managed|instance-templates|autoscalers list        compute resources, by their kind
  gcloud compute backend-services get-health    which instances each backend's instance group holds (the groups
                                                themselves don't list their members)
  gcloud dns record-sets list --zone=<zone>     record sets, saved as <zone>.json: the items don't name their zone
  gcloud scheduler jobs list                    (Cloud Asset Inventory has no Cloud Scheduler asset type)
  gcloud secrets list, gcloud kms keys list, gcloud storage buckets list, gcloud functions list, gcloud run jobs list,
  gcloud scheduler jobs list, gcloud builds triggers list, gcloud container clusters list, gcloud pubsub topics list,
  gcloud monitoring channels|policies|uptime list, gcloud logging buckets list      by their resource names and shapes
  gcloud logging sinks list                     log sinks (logging.googleapis.com/LogSink), the Cloud Audit Logs exports
                                                among them read as audit trails (see audit.py); the list doesn't name
                                                its parent: save it as log-sinks/<project>.json (an organization's:
                                                organizations-<id>.json, a folder's: folders-<id>.json)
  gcloud transfer jobs list                     Storage Transfer Service jobs (transferJobs/...), as their assets
                                                (storagetransfer.googleapis.com/TransferJob): the buckets they copy
  gcloud compute disks list, resource-policies list   disks (compute#disk: size, type, key, labels, the instances
                                                using them, their snapshot schedules) and snapshot schedules
                                                (compute#resourcePolicy), as their assets
  gcloud sql instances list                     Cloud SQL instances (sql#instance), as their assets
                                                (sqladmin.googleapis.com/Instance) are: never a password
  gcloud projects describe <project>            project numbers (in Secret Manager's and others' names) read as IDs
  the network depth: network and hierarchical firewall policies, routes, service attachments, VPN tunnels,
  interconnect attachments, tag values and bindings: see cli_network.py
  IAM: IAM and organization policies (asset export --content-type=iam-policy / org-policy, search-all-iam-policies),
  service accounts, custom roles, pool providers, deny policies, Policy Troubleshooter's verdicts: see cli_iam.py
Subnetworks and instances outside the listed networks are counted, not read. Search results (`gcloud asset
search-all-resources`) carry no resource data and are named, not read; so are asset types the mapping doesn't model
(node pools and 1st-gen CloudFunction assets are read from their cluster's and Function's assets).
Secret values are never read: a secret is recorded from its name; instance metadata keeps only ciam-role and
ciam-product; a notification channel's configuration labels are dropped.
"""
import re
from collections import Counter
from pathlib import PurePosixPath
from types import MappingProxyType

from opsdir.core.contract import Importer
from opsdir.core.inventory import layout_import
from opsdir.core.sources import json_records
from .cli_edge import KINDS as EDGE_KINDS, backend_attributes, edge_pairs, record_routing
from .cli_iam import KINDS as IAM_KINDS, iam_kind, iam_pairs
from .cli_network import KINDS as NETWORK_KINDS, network_pairs, network_shape
from .databases import sql_instance
from .storage import bucket_attributes, transfer_job_attributes
from .audit import sink_attributes, sink_parent
from .backups import BACKUP_ASSETS, BACKUP_COLLECTIONS, backup_attributes
from .volumes import disk_attributes, policy_attributes
from .inventory import PROVIDER, pairs_resources
from .names import name_parts, resource_id

ACCOUNT_WIDE = ("secret", "key", "storage", "job", "stream", "channel", "logs", "alarm", "canary", "identity")
METADATA = ("ciam-role", "ciam-product")         # the instance metadata the mapping reads; never startup scripts
# Cloud Asset Inventory asset types and gcloud's compute kinds -> what an item is
KINDS = MappingProxyType({
    "compute.googleapis.com/Network": "network", "compute#network": "network",
    "compute.googleapis.com/Subnetwork": "subnetwork", "compute#subnetwork": "subnetwork",
    "compute.googleapis.com/Instance": "instance", "compute#instance": "instance",
    "compute.googleapis.com/Disk": "disk", "compute#disk": "disk",
    "compute.googleapis.com/ResourcePolicy": "resource-policy", "compute#resourcePolicy": "resource-policy",
    "compute.googleapis.com/Firewall": "firewall", "compute#firewall": "firewall",
    "compute.googleapis.com/ForwardingRule": "forwarding-rule", "compute#forwardingRule": "forwarding-rule",
    "compute.googleapis.com/BackendService": "backend-service",
    "compute.googleapis.com/RegionBackendService": "backend-service", "compute#backendService": "backend-service",
    "compute.googleapis.com/Address": "address", "compute#address": "address",
    "compute.googleapis.com/Router": "router", "compute#router": "router",
    "compute.googleapis.com/InstanceGroupManager": "group-manager", "compute#instanceGroupManager": "group-manager",
    "compute.googleapis.com/Autoscaler": "autoscaler", "compute#autoscaler": "autoscaler",
    "compute.googleapis.com/InstanceTemplate": "template", "compute#instanceTemplate": "template",
    "dns.googleapis.com/ResourceRecordSet": "record-set", "dns#resourceRecordSet": "record-set",
    "storage.googleapis.com/Bucket": "bucket", "storage#bucket": "bucket",
    **{f"backupdr.googleapis.com/{asset}": kind for kind, asset in BACKUP_ASSETS},
    "storagetransfer.googleapis.com/TransferJob": "transfer-job",
    "secretmanager.googleapis.com/Secret": "secret",                    # regional ones too (a location)
    "cloudkms.googleapis.com/CryptoKey": "key",
    "cloudfunctions.googleapis.com/Function": "function",               # both generations
    "run.googleapis.com/Job": "run-job",
    "cloudbuild.googleapis.com/BuildTrigger": "trigger",
    "container.googleapis.com/Cluster": "cluster",
    "pubsub.googleapis.com/Topic": "topic",
    "monitoring.googleapis.com/NotificationChannel": "channel",
    "monitoring.googleapis.com/AlertPolicy": "alert-policy",
    "monitoring.googleapis.com/UptimeCheckConfig": "uptime-check",
    "logging.googleapis.com/LogBucket": "log-bucket",
    "logging.googleapis.com/LogSink": "log-sink",
    "sqladmin.googleapis.com/Instance": "database", "sql#instance": "database",
    **EDGE_KINDS, **NETWORK_KINDS,
})
# asset types another asset already holds: a cluster its node pools, Function a 1st-gen CloudFunction
COVERED = frozenset(("container.googleapis.com/NodePool", "cloudfunctions.googleapis.com/CloudFunction"))
# gcloud items without a kind, by their resource names
NAMED = (("secret", re.compile(r"^projects/[^/]+/(?:locations/[^/]+/)?secrets/[^/]+$")),
         ("key", re.compile(r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$")),
         ("topic", re.compile(r"^projects/[^/]+/topics/[^/]+$")),
         ("channel", re.compile(r"^projects/[^/]+/notificationChannels/[^/]+$")),
         ("alert-policy", re.compile(r"^projects/[^/]+/alertPolicies/[^/]+$")),
         ("uptime-check", re.compile(r"^projects/[^/]+/uptimeCheckConfigs/[^/]+$")),
         ("log-bucket", re.compile(r"^projects/[^/]+/locations/[^/]+/buckets/[^/]+$")),
         ("function", re.compile(r"^projects/[^/]+/locations/[^/]+/functions/[^/]+$")),
         ("job", re.compile(r"^projects/[^/]+/locations/[^/]+/jobs/[^/]+$")),
         *((kind, re.compile(rf"^projects/[^/]+/locations/[^/]+/{c}/[^/]+$")) for kind, c in BACKUP_COLLECTIONS))
_NUMBERED = re.compile(r"(?<![\w-])projects/(\d+)(?=/|$)")


def _last(v):
    return (v or "").rstrip("/").rsplit("/", 1)[-1] or None


def _snake(name):
    return re.sub(r"([A-Z])", r"_\1", name).lower()


def _shape(item):
    """What a gcloud item without a compute kind is, from its fields and name; None when unrecognized."""
    name = item.get("name") or ""
    found = next((k for k, pattern in NAMED if pattern.match(name)), None)
    if found == "job":
        return "scheduler-job" if "schedule" in item else "run-job"
    if found:
        return found
    if "destination" in item and ("writerIdentity" in item or "filter" in item) and "/" not in name:
        return "log-sink"                               # gcloud logging sinks list: names carry no parent
    if network_shape(item):
        return network_shape(item)
    if "projectId" in item and "projectNumber" in item:
        return "project"
    if "backend" in item and "healthStatus" in (item.get("status") or {}):
        return "health"
    if (item.get("apiVersion") or "").startswith("run.googleapis.com") and item.get("kind") == "Job":
        return "run-job"
    if "currentMasterVersion" in item or ("nodePools" in item and "location" in item):
        return "cluster"
    if "/triggers/" in (item.get("resourceName") or ""):
        return "trigger"
    if (item.get("storage_url") or "").startswith("gs://"):
        return "bucket"
    if (item.get("name") or "").startswith("transferJobs/"):
        return "transfer-job"
    return None


def kind_of(item):
    """(what an item is, its data): a Cloud Asset Inventory asset by its asset type and resource.data ('search' for a
    search result, which holds none; 'covered' for a type another asset holds), a gcloud item by its kind or shape;
    (None, item) when unrecognized and ('asset:<type>', item) for an asset type the mapping doesn't model."""
    if not isinstance(item, dict):
        return None, item
    if iam_kind(item):
        return iam_kind(item), item
    asset_type = item.get("assetType") or item.get("asset_type")
    if asset_type:
        data = (item.get("resource") or {}).get("data")
        if data is None:
            return "search", item
        return ("covered" if asset_type in COVERED
                else KINDS.get(asset_type) or IAM_KINDS.get(asset_type) or f"asset:{asset_type}"), data
    return KINDS.get(item.get("kind")) or _shape(item), item


def _origin(item, path):
    """Where an item came from: its Cloud Asset Inventory name (//<service>/projects/...), else its file's path."""
    return (item.get("name") if isinstance(item, dict) and (item.get("assetType") or item.get("asset_type"))
            else None) or path


def _zone(origin):
    """A record set's managed zone: from its asset name (.../managedZones/<zone>/rrsets/...), else its file name
    (gcloud dns record-sets list prints no zone)."""
    m = re.search(r"/managedZones/([^/]+)/", origin)
    return m.group(1) if m else PurePosixPath(origin).stem


def _once(items):
    """Items listed by both Cloud Asset Inventory and gcloud (or twice) read once: per kind and resource name the
    gcloud item, which holds what the inventory leaves out (instance metadata), else the last one seen."""
    def key(x):
        kind, d, origin = x
        name = resource_id(d.get("selfLink") or d.get("name")) if kind not in ("health", "record-set") else None
        return (kind, name) if name else (kind, id(d))
    best = {}
    for x in items:
        k = key(x)
        if k not in best or not x[2].startswith("//") or best[k][2].startswith("//"):
            best[k] = x
    return list(best.values())


def _items(texts):
    """((kind, data, origin) of every recognized item, each resource once), notices for files and items that
    aren't."""
    docs = {p: json_records(t) for p, t in sorted(texts.items())}
    kinds = {p: [(*kind_of(i), _origin(i, p)) for i in doc] for p, doc in docs.items() if doc is not None}
    found = [x for xs in kinds.values() for x in xs]
    by_type = Counter(k[len("asset:"):] for k, _, _ in found if k and k.startswith("asset:"))
    return (_once([x for x in found if x[0] and x[0] not in ("search", "covered") and not x[0].startswith("asset:")]),
            (*(f"{p}: not JSON; not read" for p, doc in docs.items() if doc is None),
             *(f"{p}: {n} Cloud Asset Inventory search result(s) carry no resource data; not read "
               "(gcloud asset list or export --content-type=resource has it)"
               for p, xs in kinds.items() for n in (sum(1 for k, _, _ in xs if k == "search"),) if n),
             *(f"{p}: {n} item(s) that aren't Cloud Asset Inventory or gcloud output this importer reads; not read"
               for p, xs in kinds.items() for n in (sum(1 for k, _, _ in xs if not k),) if n),
             *(f"{t} ({n}): Cloud Asset Inventory assets of a type not read" for t, n in sorted(by_type.items()))))


def _of(items, kind):
    return [(d, p) for k, d, p in items if k == kind]


def _self(d):
    return resource_id(d.get("selfLink") or d.get("name"))


# ------------------------------------------------------------------ compute
def _networks(items):
    order = "network_firewall_policy_enforcement_order"
    return [*(("google_compute_network", {"id": _self(d), "name": d.get("name"),
                                          order: d.get("networkFirewallPolicyEnforcementOrder")})
              for d, _ in _of(items, "network")),
            *(("google_compute_subnetwork", {"id": _self(d), "name": d.get("name"),
                                             "ip_cidr_range": d.get("ipCidrRange"), "purpose": d.get("purpose"),
                                             "network": resource_id(d.get("network")),
                                             "log_config": [{"enable": True}]
                                             if (d.get("logConfig") or {}).get("enable") else []})
              for d, _ in _of(items, "subnetwork"))]


def _instances(items):
    images = {_self(d): resource_id(d.get("sourceImage")) for d, _ in _of(items, "disk")}

    def instance(d):
        boot = next((x for x in d.get("disks") or () if x.get("boot")), {})
        nic = (d.get("networkInterfaces") or [{}])[0]
        metadata = {i.get("key"): i.get("value") for i in (d.get("metadata") or {}).get("items") or ()
                    if i.get("key") in METADATA}
        return ("google_compute_instance", {
            "id": _self(d), "name": d.get("name"), "zone": _last(d.get("zone")), "instance_id": d.get("id"),
            "machine_type": _last(d.get("machineType")), "hostname": d.get("hostname"),
            "tags": (d.get("tags") or {}).get("items") or [], "labels": d.get("labels") or {}, "metadata": metadata,
            "boot_disk": [{"source": resource_id(boot.get("source")) or None,
                           "initialize_params": [{"image": images.get(resource_id(boot.get("source")))}]}],
            "network_interface": [{"network_ip": nic.get("networkIP"), "network": resource_id(nic.get("network")),
                                   "subnetwork": resource_id(nic.get("subnetwork"))}]})
    return [instance(d) for d, _ in _of(items, "instance")]


def _rules(blocks):
    return [{"protocol": b.get("IPProtocol"), "ports": b.get("ports") or []} for b in blocks or ()]


def _firewalls(items):
    return [("google_compute_firewall", {
        "name": d.get("name"), "description": d.get("description"), "direction": d.get("direction"),
        "priority": d.get("priority"), "source_ranges": d.get("sourceRanges") or [],
        "source_tags": d.get("sourceTags") or [], "source_service_accounts": d.get("sourceServiceAccounts") or [],
        "target_tags": d.get("targetTags") or [], "allow": _rules(d.get("allowed")), "deny": _rules(d.get("denied"))})
        for d, _ in _of(items, "firewall")]


def _groups(items):
    """Instance groups and their members, from backend-services get-health (a group seen by several services once)."""
    members = {}
    for d, _ in _of(items, "health"):
        group = resource_id(d.get("backend"))
        members[group] = sorted({*members.get(group, ()), *(resource_id(h.get("instance"))
                                                           for h in d["status"].get("healthStatus") or ()
                                                           if h.get("instance"))})
    return [("google_compute_instance_group", {"id": g, "instances": m}) for g, m in sorted(members.items())]


def _load_balancing(items):
    return [*(("google_compute_region_backend_service" if d.get("region") else "google_compute_backend_service",
               {"id": _self(d), "name": d.get("name"), **backend_attributes(d),
                "backend": [{"group": resource_id(b.get("group"))} for b in d.get("backends") or ()]})
              for d, _ in _of(items, "backend-service")),
            *(("google_compute_forwarding_rule" if d.get("region") else "google_compute_global_forwarding_rule", {
                "id": _self(d), "name": d.get("name"), "ip_address": d.get("IPAddress"), "ports": d.get("ports") or [],
                "all_ports": d.get("allPorts"), "port_range": d.get("portRange"),
                "load_balancing_scheme": d.get("loadBalancingScheme"),
                "backend_service": resource_id(d.get("backendService")), "target": resource_id(d.get("target")),
                "labels": d.get("labels") or {}})
              for d, _ in _of(items, "forwarding-rule")),
            *_groups(items),
            *(("google_dns_record_set", {"name": d.get("name"), "type": d.get("type"),
                                         "rrdatas": d.get("rrdatas") or [], "managed_zone": _zone(p),
                                         **record_routing(d)})
              for d, p in _of(items, "record-set")),
            *edge_pairs(lambda kind: _of(items, kind))]


def _egress(items):
    def nat(router, n):
        where = name_parts(_self(router))
        return ("google_compute_router_nat", {
            "id": f"{where.get('projects')}/{where.get('regions')}/{router.get('name')}/{n.get('name')}",
            "name": n.get("name"), "nat_ips": [resource_id(a) for a in n.get("natIps") or ()],
            "nat_ip_allocate_option": n.get("natIpAllocateOption")})
    return [*(("google_compute_address", {"id": _self(d), "name": d.get("name"), "address": d.get("address")})
              for d, _ in _of(items, "address")),
            *(nat(d, n) for d, _ in _of(items, "router") for n in d.get("nats") or ())]


def _compute_groups(items):
    def manager(d):
        templates = [resource_id(v["instanceTemplate"]) for v in d.get("versions") or () if v.get("instanceTemplate")]
        return ("google_compute_region_instance_group_manager" if d.get("region") else
                "google_compute_instance_group_manager", {
                    "id": _self(d), "name": d.get("name"), "target_size": d.get("targetSize"),
                    "zone": _last(d.get("zone")),
                    "instance_template": resource_id(d.get("instanceTemplate")),
                    "version": [{"instance_template": t} for t in templates],
                    "distribution_policy_zones": [_last(z.get("zone"))
                                                  for z in (d.get("distributionPolicy") or {}).get("zones") or ()]})

    def template(d):
        props = d.get("properties") or {}
        return ("google_compute_instance_template", {
            "id": _self(d), "name": d.get("name"), "machine_type": props.get("machineType"),
            "labels": props.get("labels") or {},
            "disk": [{"source_image": resource_id((k.get("initializeParams") or {}).get("sourceImage"))}
                     for k in props.get("disks") or ()]})
    return [*(manager(d) for d, _ in _of(items, "group-manager")),
            *(template(d) for d, _ in _of(items, "template")),
            *(("google_compute_autoscaler", {"target": resource_id(d.get("target")), "autoscaling_policy": [{
                "min_replicas": (d.get("autoscalingPolicy") or {}).get("minNumReplicas"),
                "max_replicas": (d.get("autoscalingPolicy") or {}).get("maxNumReplicas")}]})
              for d, _ in _of(items, "autoscaler"))]


# ------------------------------------------------------------------ references, automation, clusters, monitoring
def _references(items):
    def secret(d):
        where = name_parts(d.get("name"))
        regional = "locations" in where
        return ("google_secret_manager_regional_secret" if regional else "google_secret_manager_secret", {
            "id": d.get("name"), "secret_id": where.get("secrets"), "project": where.get("projects"),
            **({"location": where["locations"]} if regional else {}), "labels": d.get("labels") or {},
            "rotation": [{"rotation_period": (d.get("rotation") or {}).get("rotationPeriod")}]})

    def key(d):
        level = ((d.get("versionTemplate") or {}).get("protectionLevel")
                 or (d.get("primary") or {}).get("protectionLevel"))
        return ("google_kms_crypto_key", {"id": d.get("name"), "name": _last(d.get("name")),
                                          "labels": d.get("labels") or {},
                                          "rotation_period": d.get("rotationPeriod"),
                                          "version_template": [{"protection_level": level}]})
    return [*(secret(d) for d, _ in _of(items, "secret")), *(key(d) for d, _ in _of(items, "key")),
            *(("google_storage_bucket", bucket_attributes(d)) for d, _ in _of(items, "bucket")),
            *(("google_storage_transfer_job", transfer_job_attributes(d)) for d, _ in _of(items, "transfer-job"))]


def _automation(items):
    def run_job(d):
        meta = d.get("metadata")
        if meta is None:                                    # the v2 API shape
            return ("google_cloud_run_v2_job", {"id": d.get("name"), "name": _last(d.get("name")),
                                                "labels": d.get("labels") or {}})
        labels = meta.get("labels") or {}
        location = labels.get("cloud.googleapis.com/location")
        return ("google_cloud_run_v2_job", {"id": f"projects/{meta.get('namespace')}/locations/{location}/jobs/"
                                                  f"{meta.get('name')}", "name": meta.get("name"), "labels": labels})

    def function(d):
        if d.get("buildConfig") or d.get("environment") == "GEN_2":
            return ("google_cloudfunctions2_function", {"id": d.get("name"), "name": _last(d.get("name")),
                                                        "labels": d.get("labels") or {},
                                                        "build_config": [{"runtime": (d.get("buildConfig") or {})
                                                                          .get("runtime")}]})
        return ("google_cloudfunctions_function", {"id": d.get("name"), "name": _last(d.get("name")),
                                                   "labels": d.get("labels") or {}, "runtime": d.get("runtime")})

    def trigger(d):
        parent = (d.get("resourceName") or "").rsplit("/triggers/", 1)[0]
        return ("google_cloudbuild_trigger", {"id": f"{parent}/triggers/{d.get('id')}", "name": d.get("name")})
    return [*(function(d) for d, _ in _of(items, "function")), *(run_job(d) for d, _ in _of(items, "run-job")),
            *(trigger(d) for d, _ in _of(items, "trigger")),
            *(("google_cloud_scheduler_job", {
                "name": d.get("name"), "schedule": d.get("schedule"),
                "http_target": [{"uri": d["httpTarget"].get("uri")}] if d.get("httpTarget") else [],
                "pubsub_target": [{"topic_name": d["pubsubTarget"].get("topicName")}] if d.get("pubsubTarget") else []})
              for d, _ in _of(items, "scheduler-job"))]


# GKE add-ons whose state is a `disabled` flag (absent = enabled); the others carry `enabled` (absent = off)
DISABLED_FLAG = frozenset(("httpLoadBalancing", "horizontalPodAutoscaling", "kubernetesDashboard",
                           "networkPolicyConfig", "cloudRunConfig", "istioConfig"))


def _clusters(items):
    def addon(name, state):
        flag = "disabled" if name in DISABLED_FLAG else "enabled"
        return _snake(name), [{flag: bool((state or {}).get(flag, False))}]

    def cluster(d):
        where = name_parts(_self(d))
        cid = f"projects/{where.get('projects')}/locations/{d.get('location')}/clusters/{d.get('name')}"
        return [("google_container_cluster", {
                    "id": cid, "name": d.get("name"), "master_version": d.get("currentMasterVersion"),
                    "node_locations": d.get("locations") or [], "resource_labels": d.get("resourceLabels") or {},
                    "addons_config": [dict(addon(k, v) for k, v in (d.get("addonsConfig") or {}).items())],
                    "workload_identity_config": [{"workload_pool": w}] if (w := (d.get("workloadIdentityConfig") or {})
                                                                           .get("workloadPool")) else [],
                    "secret_manager_config": [{"enabled": bool((d.get("secretManagerConfig") or {}).get("enabled"))}]}),
                *(("google_container_node_pool", {
                    "cluster": cid, "name": n.get("name"), "node_config": [{"machine_type": (n.get("config") or {})
                                                                            .get("machineType")}],
                    "autoscaling": [{"min_node_count": a.get("minNodeCount", a.get("totalMinNodeCount")),
                                     "max_node_count": a.get("maxNodeCount", a.get("totalMaxNodeCount"))}]
                    if (a := n.get("autoscaling") or {}).get("enabled") else []})
                  for n in d.get("nodePools") or ())]
    return [p for d, _ in _of(items, "cluster") for p in cluster(d)]


def _monitoring(items):
    def condition(c):
        return {"condition_threshold": [{"filter": c["conditionThreshold"].get("filter")}]
                if c.get("conditionThreshold") else [],
                "condition_matched_log": [{"filter": c["conditionMatchedLog"].get("filter")}]
                if c.get("conditionMatchedLog") else []}
    return [*(("google_pubsub_topic", {"id": d.get("name"), "name": _last(d.get("name")),
                                       "labels": d.get("labels") or {}}) for d, _ in _of(items, "topic")),
            *(("google_monitoring_notification_channel", {       # its configuration labels are never carried
                "name": d.get("name"), "type": d.get("type"), "display_name": d.get("displayName"),
                "user_labels": d.get("userLabels") or {}}) for d, _ in _of(items, "channel")),
            *(("google_logging_project_bucket_config", {"id": d.get("name"), "bucket_id": _last(d.get("name")),
                                                        "retention_days": d.get("retentionDays")})
              for d, _ in _of(items, "log-bucket")),
            *(("google_monitoring_alert_policy", {
                "name": d.get("name"), "display_name": d.get("displayName"),
                "conditions": [condition(c) for c in d.get("conditions") or ()],
                "notification_channels": d.get("notificationChannels") or [], "user_labels": d.get("userLabels") or {}})
              for d, _ in _of(items, "alert-policy")),
            *(("google_monitoring_uptime_check_config", {"name": d.get("name"), "display_name": d.get("displayName"),
                                                         "period": d.get("period"),
                                                         "user_labels": d.get("userLabels") or {}})
              for d, _ in _of(items, "uptime-check"))]


# ------------------------------------------------------------------ project numbers, scope, the importer
def _with_ids(v, ids):
    """v with project numbers in resource names (projects/<number>/...) and project fields read as project IDs."""
    if isinstance(v, str):
        return _NUMBERED.sub(lambda m: f"projects/{ids.get(m.group(1), m.group(1))}", v)
    if isinstance(v, dict):
        return {k: (ids.get(x, x) if k == "project" and isinstance(x, str) else _with_ids(x, ids))
                for k, x in v.items()}
    if isinstance(v, list):
        return [_with_ids(x, ids) for x in v]
    return v


def _project_ids(pairs, items):
    """(pairs with project IDs, notices naming numbers no project output resolves)."""
    ids = {str(d.get("projectNumber")): d.get("projectId") for d, _ in _of(items, "project")}
    named = [(t, _with_ids(a, ids)) for t, a in pairs]
    left = sorted({m.group(1) for _, a in named for m in _NUMBERED.finditer(repr(a))} |
                  {a["project"] for _, a in named if str(a.get("project") or "").isdigit()})
    return named, tuple(f"project number {n} in resource names: add `gcloud projects describe <project> --format=json` "
                        "to read it as the project ID" for n in left)


def _scoped(pairs):
    """(pairs, notices): subnetworks and instances of the listed networks only, when any are listed."""
    networks = {a["id"] for t, a in pairs if t == "google_compute_network"}
    if not networks:
        return pairs, ()
    outside = [(t, a) for t, a in pairs
               if (t == "google_compute_subnetwork" and a.get("network") and a["network"] not in networks)
               or (t == "google_compute_instance" and a["network_interface"][0].get("network")
                   and a["network_interface"][0]["network"] not in networks)]
    counted = Counter(t for t, _ in outside)
    return ([p for p in pairs if p not in outside],
            tuple(f"{t} ({n}): outside the listed networks ({', '.join(sorted(_last(x) for x in networks))}); not read"
                  for t, n in sorted(counted.items())))


def cli_resources(texts, at=None):
    """(resources, notices) of an environment's Cloud Asset Inventory and gcloud outputs ({path within the folder:
    text}); at dates Policy Troubleshooter's verdicts among them (the import's time)."""
    items, unknown = _items(texts)
    pairs, number_notices = _project_ids([*_networks(items), *_instances(items), *_firewalls(items),
                                          *_load_balancing(items), *_egress(items), *_compute_groups(items),
                                          *_references(items), *_automation(items), *_clusters(items),
                                          *_monitoring(items), *iam_pairs(items, at),
                                          *(sink_attributes(d, sink_parent(p)) for d, p in _of(items, "log-sink")),
                                          *(sql_instance(d) for d, _ in _of(items, "database")),
                                          *(("google_compute_disk", disk_attributes(d)) for d, _ in _of(items, "disk")),
                                          *(("google_compute_resource_policy", policy_attributes(d))
                                            for d, _ in _of(items, "resource-policy")),
                                          *(backup_attributes(kind, d) for kind, _ in BACKUP_ASSETS
                                            for d, _ in _of(items, kind)),
                                          *network_pairs(lambda kind: _of(items, kind))], items)
    pairs, scope_notices = _scoped(pairs)
    resources, notices = pairs_resources(pairs)
    return resources, (*unknown, *number_notices, *scope_notices, *notices)


def read_cli_inventory(files, d, patterns, at=None):
    """Imported: each environment's servers and bindings from the Cloud Asset Inventory and gcloud outputs under
    <cloud>/<env>/."""
    return layout_import(files, d, PROVIDER, "Google Cloud", lambda texts: cli_resources(texts, at),
                         (".json", ".jsonl"), "Cloud Asset Inventory or gcloud output", "assets.json",
                         summarize=ACCOUNT_WIDE)


CLI_INVENTORY = Importer("cli-inventory", "Cloud Asset Inventory (gcloud asset list/export --content-type=resource) "
                                          "and gcloud … --format=json outputs under <cloud>/<env>/, as the "
                                          "environment's servers and bindings", read_cli_inventory)
