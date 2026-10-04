"""Google Cloud read back from Terraform state: each resource type as the record's neutral resources (servers with
their exact role and product from metadata, firewall rules grouped by the name their descriptions end with, a
passthrough load balancer as a service named by its Cloud DNS record, secrets and keys as references, compute groups,
clusters, jobs, streams and monitoring), what can't be recorded named, and an environment's drift imported."""
import json

from opsdir.connectors.importing import preview_import
from opsdir.core.directory import get, one
from opsdir.core.interchange.ldif import parse
from opsdir_adapter_gcp.adapter import ADAPTER
from opsdir_adapter_gcp.inventory import resource_id, state_resources
from support import REGISTRY, build_directory

P = "projects/ciam-prod"
NET = "projects/host-net"
API = "https://www.googleapis.com/compute/v1"
ENV = "env=prod,cloud=gcp,ou=environments,dc=ciam-ops"


def _entry(dn, oc, **attrs):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: {oc}\n" + "".join(f"{k}: {v}\n" for k, v in attrs.items())


# the record the drift is imported into: the environment, its network and subnetwork, two directory servers
RECORDS = "\n".join((
    "dn: dc=ciam-ops\nobjectClass: top\nobjectClass: domain\ndc: ciam-ops\n",
    "dn: ou=environments,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: environments\n",
    _entry("cloud=gcp,ou=environments,dc=ciam-ops", "ciamCloud", cloud="gcp", ciamCloudProvider="gcp",
           ciamRegion="us-central1"),
    _entry(ENV, "ciamEnvironment", env="prod"),
    _entry(f"ou=bindings,{ENV}", "organizationalUnit", ou="bindings"),
    _entry(f"cn=vpc,ou=bindings,{ENV}", "ciamNetwork", cn="vpc", ciamBindingRole="network", ciamCidr="10.30.0.0/16",
           ciamProviderRef=f"{NET}/global/networks/ciam-vpc"),
    _entry(f"cn=subnet-ds,ou=bindings,{ENV}", "ciamSubnetBinding", cn="subnet-ds", ciamBindingRole="subnet-ds",
           ciamCidr="10.30.1.0/24", ciamProviderRef=f"{NET}/regions/us-central1/subnetworks/ciam-ds"),
    *(_entry(f"cn={cn},{ENV}", "ciamServer", cn=cn, ciamServerRole="ds", ciamHostname=f"{cn}.gcp.example.test",
             ciamPrivateIp=ip, ciamZone=zone, ciamInstanceSize="n2-standard-4",
             ciamSubnet=f"cn=subnet-ds,ou=bindings,{ENV}")
      for cn, ip, zone in (("ds-1", "10.30.1.11", "us-central1-a"), ("ds-2", "10.30.1.12", "us-central1-b")))))


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/google"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


def _instance(cn, ip, zone, size="n2-standard-4"):
    return ("google_compute_instance", cn, {
        "id": f"{P}/zones/{zone}/instances/{cn}", "name": cn, "zone": zone, "hostname": f"{cn}.gcp.example.test",
        "machine_type": f"{API}/{P}/zones/{zone}/machineTypes/{size}",
        "tags": ["ciam-prod-ds"], "labels": {"role": "ds", "product": "pingds-8-0-1"},
        "metadata": {"ciam-role": "ds", "ciam-product": "PingDS 8.0.1"},
        "boot_disk": [{"initialize_params": [{"image": f"{P}/global/images/ciam-ds-2026"}]}],
        "network_interface": [{"network_ip": ip,
                               "subnetwork": f"{API}/{NET}/regions/us-central1/subnetworks/ciam-ds"}]})


STATE = _state(
    ("google_compute_network", "main", {"id": f"{NET}/global/networks/ciam-vpc", "name": "ciam-vpc"}),
    ("google_compute_subnetwork", "ds", {"id": f"{NET}/regions/us-central1/subnetworks/ciam-ds", "name": "ciam-ds",
                                         "ip_cidr_range": "10.30.1.0/24"}),
    _instance("ds-1", "10.30.1.11", "us-central1-a", size="n2-standard-8"),          # resized in the console
    _instance("ds-2", "10.30.1.12", "us-central1-b"),
    ("google_compute_firewall", "ldaps", {
        "name": "ciam-prod-fw-ldaps", "description": "fw-ldaps (fw-ldaps)", "direction": "INGRESS", "priority": 900,
        "allow": [{"protocol": "tcp", "ports": ["1636"]}], "source_ranges": ["10.40.0.0/16", "10.41.0.0/16"],
        "target_tags": ["ciam-prod-ds"]}),
    ("google_compute_firewall", "wide", {
        "name": "ciam-prod-temp", "description": "opened for a vendor (temporary)",     # names no record rule
        "direction": "INGRESS", "priority": 1500, "source_tags": ["bastion"],
        "allow": [{"protocol": "tcp", "ports": ["8000-8100", "22"]}], "target_tags": ["ciam-prod-pf-engine"]}),
    ("google_compute_firewall", "probes", {
        "name": "ciam-prod-svc-ldaps-health-checks", "description": "Google Cloud health checks for svc-ldaps",
        "direction": "INGRESS", "allow": [{"protocol": "tcp", "ports": ["1636"]}],
        "source_ranges": ["35.191.0.0/16"], "target_tags": ["ciam-prod-ds"]}),
    ("google_compute_firewall", "deny", {"name": "ciam-prod-deny-all", "direction": "INGRESS",
                                         "deny": [{"protocol": "all"}]}),
    ("google_compute_instance_group", "a", {"id": f"{P}/zones/us-central1-a/instanceGroups/ldaps-a",
                                            "instances": [f"{P}/zones/us-central1-a/instances/ds-1"]}),
    ("google_compute_region_backend_service", "ldaps", {
        "id": f"{P}/regions/us-central1/backendServices/ldaps",
        "backend": [{"group": f"{P}/zones/us-central1-a/instanceGroups/ldaps-a"}]}),
    ("google_compute_forwarding_rule", "ldaps", {
        "id": f"{P}/regions/us-central1/forwardingRules/ciam-prod-svc-ldaps", "name": "ciam-prod-svc-ldaps",
        "ip_address": "10.30.1.100", "ports": ["1636"],
        "backend_service": f"{P}/regions/us-central1/backendServices/ldaps"}),
    ("google_dns_record_set", "ldaps", {"name": "ldaps.gcp.example.test.", "type": "A", "managed_zone": "ciam-private",
                                        "rrdatas": ["10.30.1.100"]}),
    ("google_compute_address", "nat", {"id": f"{P}/regions/us-central1/addresses/nat-1", "address": "34.1.2.3"}),
    ("google_compute_router_nat", "nat", {"id": f"{P}/us-central1/ciam-router/ciam-nat", "name": "ciam-nat",
                                          "nat_ips": [f"{P}/regions/us-central1/addresses/nat-1"]}),
    ("google_secret_manager_secret", "root", {"id": f"{P}/secrets/ds-root-password", "secret_id": "ds-root-password",
                                              "project": "ciam-prod", "labels": {"role": "ds-root-password"},
                                              "rotation": [{"rotation_period": "2592000s"}]}),
    ("google_secret_manager_regional_secret", "tls", {"id": f"{P}/locations/us-central1/secrets/ds-tls",
                                                      "secret_id": "ds-tls", "project": "ciam-prod",
                                                      "location": "us-central1"}),
    ("google_secret_manager_secret_version", "root", {"secret_data": "hunter2"}),
    ("google_kms_crypto_key", "disk", {"id": f"{P}/locations/us-central1/keyRings/ciam/cryptoKeys/disk",
                                       "name": "disk", "rotation_period": "7776000s",
                                       "version_template": [{"protection_level": "HSM"}]}),
    ("google_storage_bucket", "backups", {"name": "ciam-prod-ds-backups", "labels": {"role": "backup-target"}}),
    ("google_cloudfunctions2_function", "rotate", {"id": f"{P}/locations/us-central1/functions/ciam-rotate",
                                                   "name": "ciam-rotate", "build_config": [{"runtime": "python312"}],
                                                   "labels": {"role": "rotate-function"}}),
    ("google_cloud_scheduler_job", "nightly", {"schedule": "0 2 * * *", "http_target": [{
        "uri": "https://us-central1-ciam-prod.cloudfunctions.net/ciam-rotate"}]}),
    ("google_compute_instance_template", "pf", {"id": f"{P}/global/instanceTemplates/pf-engine-1",
                                                "name": "pf-engine-1", "machine_type": "n2-standard-2",
                                                "labels": {"role": "pf-engine"},
                                                "disk": [{"source_image": f"{P}/global/images/ciam-pf-2026"}]}),
    ("google_compute_region_instance_group_manager", "pf", {
        "id": f"{P}/regions/us-central1/instanceGroupManagers/pf-engine", "name": "pf-engine", "target_size": 2,
        "version": [{"instance_template": f"{P}/global/instanceTemplates/pf-engine-1"}],
        "distribution_policy_zones": ["us-central1-a", "us-central1-b"]}),
    ("google_compute_region_autoscaler", "pf", {
        "target": f"{P}/regions/us-central1/instanceGroupManagers/pf-engine",
        "autoscaling_policy": [{"min_replicas": 2, "max_replicas": 6}]}),
    ("google_container_cluster", "gke", {
        "id": f"{P}/locations/us-central1/clusters/ciam", "name": "ciam", "master_version": "1.33.4-gke.1000",
        "node_locations": ["us-central1-a", "us-central1-b"],
        "addons_config": [{"http_load_balancing": [{"disabled": False}], "gcp_filestore_csi_driver_config":
                           [{"enabled": False}]}],
        "workload_identity_config": [{"workload_pool": "ciam-prod.svc.id.goog"}]}),
    ("google_container_node_pool", "default", {"cluster": f"{P}/locations/us-central1/clusters/ciam", "name": "default",
                                               "node_config": [{"machine_type": "e2-standard-4"}],
                                               "autoscaling": [{"min_node_count": 1, "max_node_count": 3}]}),
    ("google_pubsub_topic", "audit", {"id": f"{P}/topics/ciam-audit", "name": "ciam-audit",
                                      "labels": {"role": "audit-events"}}),
    ("google_monitoring_notification_channel", "page", {"name": f"{P}/notificationChannels/123", "type": "pagerduty",
                                                        "display_name": "ciam-page", "labels": {"service_key": "x"},
                                                        "user_labels": {"role": "alerts-page"}}),
    ("google_logging_project_bucket_config", "audit", {"id": f"{P}/locations/global/buckets/ciam-audit",
                                                       "bucket_id": "ciam-audit", "retention_days": 400,
                                                       "labels": {"role": "audit-logs"}}),
    ("google_monitoring_alert_policy", "lag", {
        "name": f"{P}/alertPolicies/9", "display_name": "ds-replication-lag",
        "conditions": [{"condition_threshold": [
            {"filter": 'metric.type="custom.googleapis.com/ds/replication_delay"'}]}],
        "notification_channels": [f"{P}/notificationChannels/123"], "user_labels": {"realizes": "replication-lag"}}),
    ("google_monitoring_uptime_check_config", "login", {"name": f"{P}/uptimeCheckConfigs/login", "period": "300s",
                                                        "display_name": "sso-login",
                                                        "user_labels": {"realizes": "sso-login"}}))


def _of(kind):
    return {r.ref: r for r in state_resources(STATE)[0] if r.kind == kind}


def test_self_links_read_as_resource_names():
    assert resource_id(f"{API}/projects/p/zones/z/instances/i") == "projects/p/zones/z/instances/i"
    assert resource_id("projects/p/global/networks/n") == "projects/p/global/networks/n"
    assert resource_id("https://compute.googleapis.com/compute/beta/projects/p/global/networks/n") == \
        "projects/p/global/networks/n"
    assert resource_id("https://container.googleapis.com/v1/projects/p/locations/l/clusters/c") == \
        "projects/p/locations/l/clusters/c"
    assert resource_id("//compute.googleapis.com/projects/p/zones/z/instances/i") == "projects/p/zones/z/instances/i"


def test_servers_carry_their_exact_role_and_product():
    s = _of("server")[f"{P}/zones/us-central1-b/instances/ds-2"]
    assert (s.role, s.attrs["ciamProductVersion"], s.attrs["ciamInstanceSize"], s.attrs["ciamPrivateIp"]) == (
        "ds", ("PingDS 8.0.1",), ("n2-standard-4",), ("10.30.1.12",))
    assert s.links == {"ciamSubnet": f"{NET}/regions/us-central1/subnetworks/ciam-ds"}


def test_firewall_rules_by_name_with_what_cant_be_recorded_named():
    resources, notices = state_resources(STATE)
    rules = {r.name: r for r in resources if r.kind == "firewall"}
    assert rules["fw-ldaps"].attrs == {"ciamSourceCidr": ("10.40.0.0/16", "10.41.0.0/16"), "ciamPort": ("1636",),
                                       "ciamProtocol": ("tcp",), "ciamTargetRole": ("ds",),
                                       "ciamRulePriority": ("900",)}
    assert rules["ciam-prod-temp"].attrs["ciamTargetRole"] == ("pf-engine",)     # from the tag: no instance carries it
    assert {"firewall rule ciam-prod-temp: port range 8000-8100, not a single port; not recorded",
            "firewall rule ciam-prod-temp: source network tag bastion is not an address range; not recorded",
            "firewall rule ciam-prod-deny-all: a deny rule; not recorded",
            "google_secret_manager_secret_version (1): not read (holds secret values, or isn't modeled yet)"} \
        <= set(notices)
    assert "hunter2" not in repr(resources)
    assert not any("health-checks" in n for n in (*rules, *notices))       # a load balancer's, not a record rule


def test_a_forwarding_rule_is_a_service_named_by_its_dns_record():
    (svc,) = _of("service").values()
    assert svc.attrs == {"ciamFqdn": ("ldaps.gcp.example.test",), "ciamDnsZoneRef": ("ciam-private",),
                         "ciamPort": ("1636",), "ciamTargetRole": ("ds",), "ciamFrontendIp": ("10.30.1.100",),
                         "ciamEdgeFact": ("tls-mode passthrough",)}


def test_references_egress_and_storage():
    secrets, keys = _of("secret"), _of("key")
    assert {r.attrs["ciamRefUri"][0] for r in secrets.values()} == {
        "gcp-sm://projects/ciam-prod/secrets/ds-root-password",
        "gcp-sm://projects/ciam-prod/locations/us-central1/secrets/ds-tls"}
    assert secrets[f"{P}/secrets/ds-root-password"].attrs["ciamAutoRotate"] == ("TRUE",)
    (key,) = keys.values()
    assert (key.attrs["ciamProtectionLevel"], key.attrs["ciamAutoRotate"]) == (("hsm",), ("TRUE",))
    assert [r.attrs["ciamCidr"] for r in _of("egress").values()] == [("34.1.2.3/32",)]
    assert [r.attrs["ciamStorageRef"] for r in _of("storage").values()] == [("gs://ciam-prod-ds-backups",)]


def test_jobs_compute_clusters_streams():
    (job,) = _of("job").values()
    assert (job.role, job.attrs) == ("rotate-function", {"ciamRuntime": ("python312",), "ciamSchedule": ("0 2 * * *",)})
    (group,) = _of("compute").values()
    assert (group.role, group.attrs) == ("compute-pf-engine", {
        "ciamTargetRole": ("pf-engine",), "ciamImageRef": (f"{P}/global/images/ciam-pf-2026",),
        "ciamInstanceSize": ("n2-standard-2",), "ciamDesiredSize": ("2",), "ciamMinSize": ("2",),
        "ciamMaxSize": ("6",), "ciamSpansZone": ("us-central1-a", "us-central1-b")})
    (gke,) = _of("cluster").values()
    assert gke.attrs["ciamClusterAddon"] == ("http_load_balancing", "workload-identity")
    assert gke.attrs["ciamNodePool"] == ("default: e2-standard-4, 1-3",) and gke.role == "cluster"
    assert [(r.role, r.attrs) for r in _of("stream").values()] == [("audit-events", {"ciamStreamKind": ("topic",)})]


def test_monitoring():
    (channel,), (logs,) = _of("channel").values(), _of("logs").values()
    assert (channel.role, channel.attrs) == ("alerts-page", {"ciamChannelKind": ("paging-service",)})
    assert logs.attrs == {"ciamDestinationKind": ("log-group",), "ciamRetentionDays": ("400",)}
    (alarm,), (canary,) = _of("alarm").values(), _of("canary").values()
    assert (alarm.role, alarm.attrs) == ("alarm-replication-lag", {
        "ciamMetric": ("custom.googleapis.com/ds/replication_delay",), "ciamRealizes": ("replication-lag",),
        "ciamNotifies": (f"{P}/notificationChannels/123",)})
    assert (canary.role, canary.attrs) == ("canary-sso-login",
                                           {"ciamInterval": ("5m",), "ciamRealizes": ("sso-login",)})


def test_an_environments_drift_is_imported():
    d = build_directory(REGISTRY, tuple(parse(RECORDS)))
    changes, notices = preview_import(d, "gcp/terraform-state", {"gcp/prod/terraform.tfstate": STATE}, (ADAPTER,))
    after = build_directory(REGISTRY, tuple(parse(RECORDS)), changes)
    assert one(get(after, f"cn=ds-1,{ENV}"), "ciamInstanceSize") == "n2-standard-8"
    assert one(get(after, f"cn=ds-2,{ENV}"), "ciamInstanceSize") == "n2-standard-4"
    assert preview_import(after, "gcp/terraform-state", {"gcp/prod/terraform.tfstate": STATE}, (ADAPTER,))[0] == ()
