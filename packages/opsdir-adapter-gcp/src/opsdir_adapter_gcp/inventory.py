"""What Google Cloud says an environment runs, as the record's neutral resources (opsdir.core.inventory). Pure.

From Terraform state (terraform.tfstate, format version 4, hashicorp/google), managed resources and data sources
alike; resource names (projects/<p>/...) are the provider refs, self links read as the names they end with:

  google_compute_network                      -> network (role network)
  google_compute_subnetwork                   -> subnet: its range
  google_compute_instance                     -> server: its address, zone, machine type, boot image, subnetwork; role
                                                 and product from metadata ciam-role / ciam-product (exact), else its
                                                 labels role / product; hostname from its hostname
  google_compute_firewall (ingress allow)     -> firewall rules, by the rule name their descriptions end with
                                                 ("... (fw-name)", the rule named ciam-<env>-fw-name) else their name;
                                                 the target role is that of the instances carrying the target tag,
                                                 else the tag's ciam-<env>- suffix;
                                                 priority; port ranges, all ports, tag and service account sources and
                                                 deny rules are named, not recorded; rules admitting only Google
                                                 Cloud's health-check probes belong to load balancers: left out
  google_compute_forwarding_rule (+ region    -> service: the DNS name of the Cloud DNS record holding its address, its
    backend service, instance groups,            managed zone, ports, the role most of its instances have, its address
    google_dns_record_set)
  google_compute_router_nat (+ addresses)     -> egress: its static addresses
  google_secret_manager_secret, _regional_    -> secret reference gcp-sm://projects/<p>/[locations/<l>/]secrets/<name>,
    secret                                       automatic rotation when it has a rotation period; never a value
  google_kms_crypto_key                       -> key reference gcp-kms://<name>: protection level, rotation
  google_storage_bucket                       -> storage gs://<bucket>
  google_cloudfunctions2_function,            -> job bindings: runtime, and the schedules of the Cloud Scheduler jobs
    google_cloudfunctions_function,              whose target names them
    google_cloud_run_v2_job,
    google_cloudbuild_trigger
  google_compute_(region_)instance_group_     -> compute group: the role its template's labels name, size (autoscaler
    manager (+ autoscaler, template)             min/max else target size), zones, the template's image and type
  google_container_cluster (+ node pools)     -> cluster: version, enabled add-ons, node pools, zones
  google_pubsub_topic                         -> stream carrier: topic
  google_monitoring_notification_channel      -> alert channel: its type (pagerduty: paging-service, email, pubsub:
                                                 topic, webhook)
  google_logging_project_bucket_config        -> log destination: its retention in days
  google_monitoring_alert_policy              -> alarm: the metric its first condition filters on, the channels it
                                                 notifies, the alert rule it realizes (label realizes)
  google_monitoring_uptime_check_config       -> synthetic check: its period, the canary it realizes
  google_sql_database_instance               -> database (kind database, ciamDatabase): engine, version, edition,
                                                 DNS name, tier, disk, zone, availability, TLS, backups, flags,
                                                 deletion protection, its key as a role; never its root password:
                                                 see databases.py
  IAM: service accounts and members' grants, deny policies, organization policies, IAP tunnels: see iam.py
Roles of resources the record doesn't have come from their labels role (or bindingrole); label values are lowercase,
as the record's roles are. A compute group's binding role is label bindingrole, else compute-<label role>; a
cluster's bindingrole or role, else cluster; an alarm's or check's, else alarm-<realizes> or canary-<realizes>.
"""
import re
from collections import Counter

from opsdir.core.contract import Importer
from opsdir_adapter_gcp.edge_inventory import (FORWARDING, backend_of, dns_resources, edge_services, ref_key,
                                               proxy_subnets, service_dns, service_facts)
from opsdir_adapter_gcp.health_checks import is_probe_rule
from opsdir.core.inventory import (cluster_role, compute_roles, duration_text, layout_import, of_types, per_file,
                                   realization_roles, resource, tagged_role)
from opsdir_format_terraform.state import blocks, first_block, read_state
from .databases import database_resources
from .iam import iam_resources
from .names import name_parts, resource_id
from .network_inventory import google_apis_endpoint, network_resources

PROVIDER = "gcp"

SKIPPED = ("google_secret_manager_secret_version", "google_secret_manager_regional_secret_version", "random_password",
           "tls_private_key", "google_service_account_key", "google_sql_user")
_RULE_NAME = re.compile(r"\(([A-Za-z0-9._-]+)\)\s*$")
PROTECTION = {"SOFTWARE": "software", "HSM": "hsm", "HSM_SINGLE_TENANT": "managed-hsm", "EXTERNAL": "external",
              "EXTERNAL_VPC": "external"}
CHANNEL_KINDS = (("pagerduty", "paging-service"), ("email", "email"), ("pubsub", "topic"), ("webhook", "webhook"))


def _labels(a):
    """A resource's own labels: user_labels where the provider names them so (monitoring keeps its configuration
    in labels), else labels or GKE's resource_labels."""
    return a.get("user_labels") or a.get("labels") or a.get("resource_labels") or {}


def _tags(a):
    """A resource's labels as the core's tag names (Role, BindingRole, Realizes)."""
    labels = _labels(a)
    return {k: labels[low] for k, low in (("Role", "role"), ("BindingRole", "bindingrole"), ("Realizes", "realizes"))
            if labels.get(low)}


def _role(a):
    return tagged_role(_tags(a))


def _metadata(a):
    return a.get("metadata") or {}


def _networks(found):
    return tuple(resource("network", resource_id(a.get("id")), {}, name=a.get("name"), role=_role(a) or "network")
                 for a in of_types(found, "google_compute_network") if a.get("id"))


def _subnets(found):
    return tuple(resource("subnet", resource_id(a.get("id")), {"ciamCidr": a.get("ip_cidr_range")},
                          name=a.get("name"), role=_role(a))
                 for a in of_types(found, "google_compute_subnetwork") if a.get("id"))


def _server_role(a):
    return _metadata(a).get("ciam-role") or _labels(a).get("role")


def _servers(found):
    def server(a):
        nic = first_block(a.get("network_interface"))
        image = first_block(first_block(a.get("boot_disk")).get("initialize_params")).get("image")
        return resource("server", resource_id(a.get("id")), {
            "ciamPrivateIp": nic.get("network_ip"), "ciamZone": a.get("zone"),
            "ciamInstanceSize": (a.get("machine_type") or "").rsplit("/", 1)[-1] or None,
            "ciamImageRef": resource_id(image), "ciamHostname": a.get("hostname"),
            "ciamProductVersion": _metadata(a).get("ciam-product")},
            links={"ciamSubnet": resource_id(nic.get("subnetwork"))}, name=a.get("name"), role=_server_role(a))
    return tuple(server(a) for a in of_types(found, "google_compute_instance") if a.get("id"))


# ------------------------------------------------------------------ firewall rules
def _tag_roles(found):
    """{network tag: role} from the instances carrying each tag."""
    return {tag: _server_role(a) for a in of_types(found, "google_compute_instance") if _server_role(a)
            for tag in a.get("tags") or ()}


def _target_role(rule, tag_roles):
    tags = rule.get("target_tags") or ()
    known = Counter(tag_roles[t] for t in tags if t in tag_roles)
    if known:
        return known.most_common(1)[0][0]
    return next((t.split("-", 2)[2] for t in tags if t.startswith("ciam-") and t.count("-") >= 2), None)


def _ports(rule):
    """(single ports, why not for the others) of a rule's allow blocks."""
    allowed = blocks(rule.get("allow"))
    singles = sorted({p for b in allowed for p in b.get("ports") or () if "-" not in str(p)}, key=int)
    why = [*(f"port range {p}" for b in allowed for p in b.get("ports") or () if "-" in str(p)),
           *("all ports" for b in allowed if not b.get("ports"))]
    return singles, why


def _firewall(found):
    """(firewall rules, notices): ingress allow rules, named by their descriptions' (fw-name) when their name is the
    rendered ciam-<env>-<fw-name> (a description that just ends in parentheses names nothing), else their name; rules
    admitting only Google Cloud's health-check probes, or only a proxy-only subnet, belong to load balancers and are
    left out."""
    tag_roles, proxies = _tag_roles(found), proxy_subnets(found)
    rules = [r for r in of_types(found, "google_compute_firewall")
             if r.get("name") and not is_probe_rule(r.get("source_ranges"))
             and not (r.get("source_ranges") and set(r.get("source_ranges")) <= proxies)]

    def name(r):
        m = _RULE_NAME.search(r.get("description") or "")
        return m.group(1) if m and r["name"].endswith(f"-{m.group(1)}") else r.get("name")
    ingress = [r for r in rules if (r.get("direction") or "INGRESS") == "INGRESS" and blocks(r.get("allow"))]
    notices = (*(f"firewall rule {name(r)}: {why}, not a single port; not recorded"
                 for r in ingress for why in dict.fromkeys(_ports(r)[1])),
               *(f"firewall rule {name(r)}: source {kind} {v} is not an address range; not recorded"
                 for r in ingress for kind, key in (("network tag", "source_tags"),
                                                    ("service account", "source_service_accounts"))
                 for v in r.get(key) or ()),
               *(f"firewall rule {name(r)}: {'a deny rule' if blocks(r.get('deny')) else 'an egress rule'}; "
                 "not recorded" for r in rules if r not in ingress))
    return tuple(resource("firewall", name(r), {
        "ciamSourceCidr": sorted(r.get("source_ranges") or ()), "ciamPort": _ports(r)[0],
        "ciamProtocol": next((b.get("protocol") for b in blocks(r.get("allow")) if b.get("protocol") in ("tcp", "udp")),
                             None),
        "ciamTargetRole": _target_role(r, tag_roles), "ciamRulePriority": r.get("priority")},
        name=name(r), role=None) for r in ingress), notices


# ------------------------------------------------------------------ services and egress
def _rule_ports(fr):
    """A forwarding rule's ports: its ports, else a port range of one port ("1636-1636"); none for wider ranges or
    all ports."""
    low, _, high = str(fr.get("port_range") or "").partition("-")
    return fr.get("ports") or ((low,) if low.isdigit() and high in ("", low) else ())


def _services(found):
    """A service per forwarding rule (regional or global): the Cloud DNS name holding its address (its TTL and weighted
    routing), its ports (a one-port range read as its port; none from wider ranges or a rule forwarding all ports), its
    instances' role, and what its edge runs."""
    groups = {resource_id(g.get("id")): g for g in of_types(found, "google_compute_instance_group")}
    roles = {resource_id(a.get("id")): _server_role(a) for a in of_types(found, "google_compute_instance")}

    def one_rule(fr):
        backend = backend_of(found, fr)[0] or {}
        members = [resource_id(i) for b in blocks(backend.get("backend"))
                   for i in (groups.get(resource_id(b.get("group"))) or {}).get("instances") or ()]
        found_roles = Counter(roles[i] for i in members if roles.get(i))
        ip = fr.get("ip_address")
        dns, record, _ = service_dns(found, ip)
        facts, settings = service_facts(found, fr)
        return resource("service", resource_id(fr.get("id")), {
            "ciamFqdn": (record or {}).get("name", "").rstrip(".") or None,
            "ciamDnsZoneRef": (record or {}).get("managed_zone"),
            "ciamPort": sorted({str(p) for p in _rule_ports(fr)}, key=int),
            "ciamTargetRole": found_roles.most_common(1)[0][0] if found_roles else None,
            "ciamFrontendIp": ip, "ciamEdgeFact": facts, "ciamEdgeSetting": settings, **dns},
            name=fr.get("name"), role=_role(fr))
    return tuple(one_rule(fr) for fr in of_types(found, *FORWARDING) if fr.get("id") and not google_apis_endpoint(fr))


def _edge(found):
    """The edge services, zones, records and forwarders, and notices for the other environments' answers."""
    rules = [fr for fr in of_types(found, *FORWARDING) if fr.get("id")]
    served = {key: resource_id(fr.get("id")) for fr in rules for b in (backend_of(found, fr)[0],) if b
              for key in (ref_key(b.get("id")), ref_key(b.get("self_link"))) if key}
    answers = [(fr.get("ip_address"), service_dns(found, fr.get("ip_address"))) for fr in rules]
    zones, records, forwarders = dns_resources(found, {id(r) for _, (_, r, _) in answers if r is not None})
    return ((*edge_services(found, served), *zones, *records, *forwarders),
            tuple(f"Cloud DNS answer {a} answers for another environment of the name {ip} serves: not recorded here"
                  for ip, (_, _, others) in answers for a in others))


ALLOCATION = {"MANUAL_ONLY": "static", "AUTO_ONLY": "automatic"}


def _egress(found):
    """Cloud NAT: its static addresses; whether they are fixed (MANUAL_ONLY) or Google's to pick (AUTO_ONLY)."""
    addresses = {resource_id(a.get("id")): a.get("address") for a in of_types(found, "google_compute_address")}
    return tuple(resource("egress", resource_id(a.get("id")), {
        "ciamCidr": [f"{addresses[resource_id(n)]}/32" for n in a.get("nat_ips") or ()
                     if addresses.get(resource_id(n))],
        "ciamNatAllocation": ALLOCATION.get(a.get("nat_ip_allocate_option"))}, name=a.get("name"), role=_role(a))
        for a in of_types(found, "google_compute_router_nat") if a.get("id"))


# ------------------------------------------------------------------ secrets, keys, storage
def _secret_ref(a, regional):
    where = f"locations/{a.get('location')}/" if regional else ""
    return f"gcp-sm://projects/{a.get('project')}/{where}secrets/{a.get('secret_id')}"


def _secrets(found):
    return tuple(resource("secret", resource_id(a.get("id")), {
        "ciamRefUri": _secret_ref(a, regional),
        "ciamAutoRotate": "TRUE" if first_block(a.get("rotation")).get("rotation_period") else None},
        name=a.get("secret_id"), role=_role(a))
        for t, regional in (("google_secret_manager_secret", False), ("google_secret_manager_regional_secret", True))
        for a in of_types(found, t) if a.get("secret_id") and a.get("project"))


def _keys(found):
    return tuple(resource("key", resource_id(a.get("id")), {
        "ciamRefUri": f"gcp-kms://{resource_id(a.get('id'))}",
        "ciamProtectionLevel": PROTECTION.get(first_block(a.get("version_template")).get("protection_level")),
        "ciamAutoRotate": "TRUE" if a.get("rotation_period") else "FALSE"}, name=a.get("name"), role=_role(a))
        for a in of_types(found, "google_kms_crypto_key") if a.get("id"))


def _storage(found):
    return tuple(resource("storage", a.get("name"), {"ciamStorageRef": f"gs://{a.get('name')}"}, name=a.get("name"),
                          role=_role(a)) for a in of_types(found, "google_storage_bucket") if a.get("name"))


# ------------------------------------------------------------------ automation, compute, clusters, streams
JOB_TYPES = ("google_cloudfunctions2_function", "google_cloudfunctions_function", "google_cloud_run_v2_job",
             "google_cloudbuild_trigger")


def _runtime(a):
    return first_block(a.get("build_config")).get("runtime") or a.get("runtime")


def _jobs(found):
    """Functions, Cloud Run jobs and build triggers, each with the Cloud Scheduler schedules whose target names it."""
    targets = [((first_block(s.get("http_target")).get("uri") or "") + " " +
                (first_block(s.get("pubsub_target")).get("topic_name") or ""), s.get("schedule"))
               for s in of_types(found, "google_cloud_scheduler_job") if s.get("schedule")]

    def schedules(name):
        return sorted({when for where, when in targets if name and name in where})
    return tuple(resource("job", resource_id(a.get("id")), {"ciamRuntime": _runtime(a),
                                                            "ciamSchedule": schedules(a.get("name"))},
                          name=a.get("name"), role=_role(a))
                 for t in JOB_TYPES for a in of_types(found, t) if a.get("id"))


def _compute(found):
    """Managed instance groups as compute groups, with their autoscaler's bounds and their template's settings."""
    templates = {k: t for t in of_types(found, "google_compute_instance_template",
                                        "google_compute_region_instance_template")
                 for k in (resource_id(t.get("id")), resource_id(t.get("self_link")), t.get("name")) if k}
    scalers = {resource_id(s.get("target")): first_block(s.get("autoscaling_policy"))
               for s in of_types(found, "google_compute_autoscaler", "google_compute_region_autoscaler")}

    def group(a):
        template = templates.get(resource_id(first_block(a.get("version")).get("instance_template"))) or \
            templates.get(resource_id(a.get("instance_template"))) or {}
        policy = scalers.get(resource_id(a.get("id"))) or scalers.get(resource_id(a.get("self_link"))) or {}
        binding, target = compute_roles(_tags(template))
        return resource("compute", resource_id(a.get("id")), {
            "ciamTargetRole": target,
            "ciamImageRef": resource_id(first_block(template.get("disk")).get("source_image")),
            "ciamInstanceSize": template.get("machine_type"), "ciamDesiredSize": a.get("target_size"),
            "ciamMinSize": policy.get("min_replicas"), "ciamMaxSize": policy.get("max_replicas"),
            "ciamSpansZone": sorted(a.get("distribution_policy_zones") or ((a.get("zone"),) if a.get("zone") else ()))},
            name=a.get("name"), role=binding)
    return tuple(group(a) for a in of_types(found, "google_compute_region_instance_group_manager",
                                            "google_compute_instance_group_manager") if a.get("id"))


def _addons(c):
    config = first_block(c.get("addons_config"))
    disabled = {k for k, v in config.items() if first_block(v).get("disabled") is True}
    enabled = {k for k, v in config.items() if first_block(v).get("enabled") is True}
    return sorted({*(k for k in config if first_block(config[k]) and k not in disabled and
                     "disabled" in first_block(config[k])), *enabled,
                   *(("workload-identity",) if first_block(c.get("workload_identity_config")) else ()),
                   *(("secret-manager",) if first_block(c.get("secret_manager_config")).get("enabled") else ())})


def _clusters(found):
    """GKE clusters, their node pools and enabled add-ons."""
    def pool(n):
        scale = first_block(n.get("autoscaling"))
        return (f"{n.get('name')}: {first_block(n.get('node_config')).get('machine_type') or '?'}, "
                f"{scale.get('min_node_count', '?')}-{scale.get('max_node_count', '?')}")

    def cluster(c):
        name = c.get("name")
        return resource("cluster", resource_id(c.get("id")), {
            "ciamClusterVersion": c.get("master_version") or c.get("min_master_version"),
            "ciamClusterAddon": _addons(c),
            "ciamNodePool": sorted(pool(n) for n in of_types(found, "google_container_node_pool")
                                   if resource_id(n.get("cluster")) in (resource_id(c.get("id")), name)),
            "ciamSpansZone": sorted(c.get("node_locations") or ())}, name=name, role=cluster_role(_tags(c)))
    return tuple(cluster(c) for c in of_types(found, "google_container_cluster") if c.get("id"))


def _streams(found):
    return tuple(resource("stream", resource_id(a.get("id")), {"ciamStreamKind": "topic"}, name=a.get("name"),
                          role=_role(a)) for a in of_types(found, "google_pubsub_topic") if a.get("id"))


# ------------------------------------------------------------------ monitoring
def _channels(found):
    def kind(t):
        return next((k for prefix, k in CHANNEL_KINDS if (t or "").startswith(prefix)), "other")
    return tuple(resource("channel", resource_id(a.get("name") or a.get("id")),
                          {"ciamChannelKind": kind(a.get("type"))}, name=a.get("display_name"), role=_role(a))
                 for a in of_types(found, "google_monitoring_notification_channel") if a.get("name") or a.get("id"))


def _log_destinations(found):
    return tuple(resource("logs", resource_id(a.get("id")), {"ciamDestinationKind": "log-group",
                                                            "ciamRetentionDays": a.get("retention_days")},
                          name=a.get("bucket_id"), role=_role(a))
                 for a in of_types(found, "google_logging_project_bucket_config") if a.get("id"))


_METRIC = re.compile(r'metric\.type\s*=\s*"([^"]+)"')


def _metric(policy):
    condition = first_block(policy.get("conditions"))
    query = first_block(condition.get("condition_threshold")).get("filter") or ""
    m = _METRIC.search(query)
    return m.group(1) if m else ("log query" if first_block(condition.get("condition_matched_log")) else None)


def _alarms(found):
    def alarm(a):
        role, realizes = realization_roles(_tags(a), "alarm")
        return resource("alarm", resource_id(a.get("name") or a.get("id")), {
            "ciamMetric": _metric(a), "ciamRealizes": realizes,
            "ciamNotifies": sorted(resource_id(c) for c in a.get("notification_channels") or ())},
            name=a.get("display_name"), role=role)
    return tuple(alarm(a) for a in of_types(found, "google_monitoring_alert_policy") if a.get("name") or a.get("id"))


def _canaries(found):
    def canary(a):
        role, realizes = realization_roles(_tags(a), "canary")
        period = int(str(a.get("period") or "0s").rstrip("s") or 0)
        return resource("canary", resource_id(a.get("name") or a.get("id")), {
            "ciamInterval": duration_text(period), "ciamRealizes": realizes}, name=a.get("display_name"), role=role)
    return tuple(canary(a) for a in of_types(found, "google_monitoring_uptime_check_config")
                 if a.get("name") or a.get("id"))


def pairs_resources(pairs):
    """(resources, notices) of (Terraform resource type, attributes) pairs: what every Google Cloud source is read into
    (Terraform state as it is; inventories normalized to the same attribute names)."""
    rules, rule_notices = _firewall(pairs)
    iam, iam_notices = iam_resources(pairs)
    edge, edge_notices = _edge(pairs)
    instances = {key: _server_role(a) for a in of_types(pairs, "google_compute_instance") if _server_role(a)
                 for key in (resource_id(a.get("id")), str(a.get("instance_id") or "")) if key}
    network, network_notices = network_resources(pairs, instances, _tag_roles(pairs), proxy_subnets(pairs))
    return ((*_networks(pairs), *_subnets(pairs), *_servers(pairs), *_services(pairs), *rules, *_secrets(pairs),
             *_keys(pairs), *_storage(pairs), *_egress(pairs), *_jobs(pairs), *_compute(pairs), *_clusters(pairs),
             *_streams(pairs), *_channels(pairs), *_log_destinations(pairs), *_alarms(pairs), *_canaries(pairs),
             *iam, *edge, *network, *database_resources(pairs)),
            (*rule_notices, *iam_notices, *edge_notices, *network_notices))


def state_resources(text):
    """(resources, notices) of a Google Cloud Terraform state."""
    found, problem = read_state(text)
    if problem:
        return (), (problem,)
    pairs = [(r.type, r.attributes) for r in found]
    skipped = Counter(t for t, _ in pairs if t in SKIPPED)
    resources, notices = pairs_resources(pairs)
    return (resources, (*notices, *(f"{t} ({n}): not read (holds secret values, or isn't modeled yet)"
                                    for t, n in sorted(skipped.items()))))


# ------------------------------------------------------------------ the importer
def read_terraform_state(files, d, patterns, at=None):
    """Imported: each environment's servers and bindings from the Google Cloud Terraform states under
    <cloud>/<env>/."""
    return layout_import(files, d, PROVIDER, "Google Cloud", per_file(state_resources), ".tfstate", "Terraform state",
                         "terraform.tfstate", summarize=("identity",))   # groups, users, service agents: counted


TERRAFORM_STATE = Importer("terraform-state", "Google Cloud Terraform state (terraform.tfstate) under <cloud>/<env>/, "
                                              "as the environment's servers and bindings", read_terraform_state)
