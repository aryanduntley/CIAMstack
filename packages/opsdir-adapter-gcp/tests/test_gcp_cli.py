"""Google Cloud read from Cloud Asset Inventory and gcloud: assets recognized by type and gcloud items by kind or shape,
normalized into the mapping Terraform state uses (so both read the same environment the same way), project numbers
read as IDs, backend membership from get-health, record sets' zones from their file names, what can't be read named,
values never carried, and an environment's drift imported."""
import json

from opsdir.connectors.importing import preview_import
from opsdir.core.directory import get, one
from opsdir.core.interchange.ldif import parse
from opsdir_adapter_gcp.adapter import ADAPTER
from opsdir_adapter_gcp.cli import cli_resources, kind_of
from support import REGISTRY, build_directory

P = "projects/ciam-prod"
NET = "projects/host-net"
API = "https://www.googleapis.com/compute/v1"
ENV = "env=prod,cloud=gcp,ou=environments,dc=ciam-ops"
NUMBER = "123456789012"


def _entry(dn, oc, **attrs):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: {oc}\n" + "".join(f"{k}: {v}\n" for k, v in attrs.items())


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


def _asset(asset_type, data, name=None, key="assetType"):
    """One Cloud Asset Inventory asset as `gcloud asset export --content-type=resource` writes it."""
    name = name or f"//{asset_type.split('/')[0]}/{data.get('selfLink', data.get('name', '')).split('/v1/')[-1]}"
    return {"name": name, key: asset_type, "resource": {"version": "v1", "data": data}}


def _exported(instance):
    """An instance as Cloud Asset Inventory holds it: metadata only for a few platform keys."""
    return {**instance, "metadata": {"items": [{"key": "enable-oslogin", "value": "TRUE"}]}}


def _instance(cn, ip, zone, size="n2-standard-4", network="ciam-vpc"):
    return {"kind": "compute#instance", "name": cn, "selfLink": f"{API}/{P}/zones/{zone}/instances/{cn}",
            "zone": f"{API}/{P}/zones/{zone}", "machineType": f"{API}/{P}/zones/{zone}/machineTypes/{size}",
            "hostname": f"{cn}.gcp.example.test", "tags": {"items": ["ciam-prod-ds"]},
            "labels": {"role": "ds", "product": "pingds-8-0-1"},
            "metadata": {"items": [{"key": "ciam-role", "value": "ds"},
                                   {"key": "ciam-product", "value": "PingDS 8.0.1"},
                                   {"key": "startup-script", "value": "export DS_PASS=hunter2"}]},
            "disks": [{"boot": True, "source": f"{API}/{P}/zones/{zone}/disks/{cn}"}],
            "networkInterfaces": [{"networkIP": ip, "network": f"{API}/{NET}/global/networks/{network}",
                                   "subnetwork": f"{API}/{NET}/regions/us-central1/subnetworks/ciam-ds"}]}


def _disk(cn, zone):
    return {"kind": "compute#disk", "name": cn, "selfLink": f"{API}/{P}/zones/{zone}/disks/{cn}",
            "sourceImage": f"{API}/{P}/global/images/ciam-ds-2026"}


# gcloud asset export --content-type=resource (JSON lines): the network, subnetwork, instances and their disks
EXPORT = "\n".join(json.dumps(a) for a in (
    _asset("compute.googleapis.com/Network", {"kind": "compute#network", "name": "ciam-vpc",
                                              "selfLink": f"{API}/{NET}/global/networks/ciam-vpc"}),
    _asset("compute.googleapis.com/Subnetwork", {
        "kind": "compute#subnetwork", "name": "ciam-ds", "ipCidrRange": "10.30.1.0/24",
        "network": f"{API}/{NET}/global/networks/ciam-vpc",
        "selfLink": f"{API}/{NET}/regions/us-central1/subnetworks/ciam-ds"}),
    _asset("compute.googleapis.com/Instance", _exported(_instance("ds-1", "10.30.1.11", "us-central1-a",
                                                                  "n2-standard-8"))),
    _asset("compute.googleapis.com/Instance", _exported(_instance("ds-2", "10.30.1.12", "us-central1-b"))),
    _asset("compute.googleapis.com/Instance", _exported(_instance("bastion", "10.99.0.5", "us-central1-a",
                                                                  network="other"))),
    _asset("compute.googleapis.com/Disk", _disk("ds-1", "us-central1-a"), key="asset_type"),     # either spelling
    _asset("compute.googleapis.com/Disk", _disk("ds-2", "us-central1-b")),
    _asset("dns.googleapis.com/ResourceRecordSet", {"name": "sso.example.test.", "type": "A", "ttl": 300,
                                                    "rrdatas": ["34.120.10.10"]},
           name=f"//dns.googleapis.com/{P}/managedZones/ciam-public/rrsets/sso.example.test./A"),
    _asset("container.googleapis.com/NodePool", {"name": "default"}),
    _asset("iam.googleapis.com/ServiceAccount", {"email": "ciam@ciam-prod.iam.gserviceaccount.com"})))

GROUP = f"{API}/{P}/zones/us-central1-a/instanceGroups/ciam-prod-svc-ldaps-us-central1-a"
FILES = {
    "assets.jsonl": EXPORT,
    "instances.json": json.dumps([_instance("ds-2", "10.30.1.12", "us-central1-b")]),     # gcloud: full metadata
    "firewall-rules.json": json.dumps([
        {"kind": "compute#firewall", "name": "ciam-prod-fw-ldaps", "description": "LDAPS clients (fw-ldaps)",
         "direction": "INGRESS", "priority": 900, "sourceRanges": ["10.40.0.0/16", "10.41.0.0/16"],
         "targetTags": ["ciam-prod-ds"], "allowed": [{"IPProtocol": "tcp", "ports": ["1636"]}]},
        {"kind": "compute#firewall", "name": "ciam-prod-svc-ldaps-health-checks", "direction": "INGRESS",
         "priority": 1000, "sourceRanges": ["35.191.0.0/16"], "targetTags": ["ciam-prod-ds"],
         "allowed": [{"IPProtocol": "tcp", "ports": ["1636"]}]}]),
    "forwarding-rules.json": json.dumps([{
        "kind": "compute#forwardingRule", "name": "ciam-prod-svc-ldaps", "IPAddress": "10.30.1.100",
        "ports": ["1636"], "loadBalancingScheme": "INTERNAL", "region": f"{API}/{P}/regions/us-central1",
        "selfLink": f"{API}/{P}/regions/us-central1/forwardingRules/ciam-prod-svc-ldaps",
        "backendService": f"{API}/{P}/regions/us-central1/backendServices/ciam-prod-svc-ldaps"}, {
        "kind": "compute#forwardingRule", "name": "ciam-prod-svc-sso", "IPAddress": "34.120.10.10",
        "portRange": "443-443", "loadBalancingScheme": "EXTERNAL",
        "selfLink": f"{API}/{P}/regions/us-central1/forwardingRules/ciam-prod-svc-sso"}]),
    "backend-services.json": json.dumps([{
        "kind": "compute#backendService", "name": "ciam-prod-svc-ldaps", "region": f"{API}/{P}/regions/us-central1",
        "selfLink": f"{API}/{P}/regions/us-central1/backendServices/ciam-prod-svc-ldaps",
        "backends": [{"group": GROUP}]}]),
    "health/ldaps.json": json.dumps([{"backend": GROUP, "status": {"kind": "compute#backendServiceGroupHealth",
                                                                    "healthStatus": [{
                                                                        "instance": f"{API}/{P}/zones/us-central1-a/"
                                                                                    "instances/ds-1",
                                                                        "ipAddress": "10.30.1.11", "port": 1636,
                                                                        "healthState": "HEALTHY"}]}}]),
    "dns/ciam-private.json": json.dumps([{"kind": "dns#resourceRecordSet", "name": "ldaps.gcp.example.test.",
                                          "type": "A", "ttl": 300, "rrdatas": ["10.30.1.100"]}]),
    "routers.json": json.dumps([{"kind": "compute#router", "name": "ciam-router",
                                 "selfLink": f"{API}/{P}/regions/us-central1/routers/ciam-router",
                                 "nats": [{"name": "ciam-nat",
                                           "natIps": [f"{API}/{P}/regions/us-central1/addresses/nat-1"]}]}]),
    "addresses.json": json.dumps([{"kind": "compute#address", "name": "nat-1", "address": "34.1.2.3",
                                   "selfLink": f"{API}/{P}/regions/us-central1/addresses/nat-1"}]),
    "secrets.json": json.dumps([
        {"name": f"projects/{NUMBER}/secrets/ds-root-password", "labels": {"role": "ds-root-password"},
         "rotation": {"rotationPeriod": "2592000s"}},
        {"name": f"projects/{NUMBER}/locations/us-central1/secrets/ds-tls"}]),
    "project.json": json.dumps({"projectId": "ciam-prod", "projectNumber": NUMBER, "name": "ciam-prod"}),
    "keys.json": json.dumps([{"name": f"{P}/locations/us-central1/keyRings/ciam/cryptoKeys/disk", "purpose":
                              "ENCRYPT_DECRYPT", "rotationPeriod": "7776000s",
                              "versionTemplate": {"protectionLevel": "HSM",
                                                  "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"}}]),
    "buckets.json": json.dumps([{"name": "ciam-prod-ds-backups", "storage_url": "gs://ciam-prod-ds-backups/",
                                 "labels": {"role": "backup-target"}}]),
    "functions.json": json.dumps([{"name": f"{P}/locations/us-central1/functions/ciam-rotate", "environment": "GEN_2",
                                   "buildConfig": {"runtime": "python312"}, "labels": {"role": "rotate-function"}}]),
    "scheduler.json": json.dumps([{"name": f"{P}/locations/us-central1/jobs/nightly", "schedule": "0 2 * * *",
                                   "httpTarget": {
                                       "uri": "https://us-central1-ciam-prod.cloudfunctions.net/ciam-rotate"}}]),
    "run-jobs.json": json.dumps([{"apiVersion": "run.googleapis.com/v1", "kind": "Job",
                                  "metadata": {"name": "ds-export", "namespace": NUMBER,
                                               "labels": {"cloud.googleapis.com/location": "us-central1",
                                                          "role": "ds-export-job"}}}]),
    "compute-groups.json": json.dumps([
        {"kind": "compute#instanceGroupManager", "name": "pf-engine", "targetSize": 2,
         "region": f"{API}/{P}/regions/us-central1",
         "selfLink": f"{API}/{P}/regions/us-central1/instanceGroupManagers/pf-engine",
         "versions": [{"instanceTemplate": f"{API}/{P}/global/instanceTemplates/pf-engine-1"}],
         "distributionPolicy": {"zones": [{"zone": f"{API}/{P}/zones/us-central1-a"},
                                          {"zone": f"{API}/{P}/zones/us-central1-b"}]}},
        {"kind": "compute#instanceTemplate", "name": "pf-engine-1",
         "selfLink": f"{API}/{P}/global/instanceTemplates/pf-engine-1",
         "properties": {"machineType": "n2-standard-2", "labels": {"role": "pf-engine"},
                        "disks": [{"boot": True, "initializeParams": {
                            "sourceImage": f"{API}/{P}/global/images/ciam-pf-2026"}}]}},
        {"kind": "compute#autoscaler", "name": "pf-engine", "region": f"{API}/{P}/regions/us-central1",
         "target": f"{API}/{P}/regions/us-central1/instanceGroupManagers/pf-engine",
         "autoscalingPolicy": {"minNumReplicas": 2, "maxNumReplicas": 6}}]),
    "clusters.json": json.dumps([{
        "name": "ciam", "location": "us-central1", "currentMasterVersion": "1.33.4-gke.1000",
        "locations": ["us-central1-a", "us-central1-b"],
        "selfLink": "https://container.googleapis.com/v1/projects/ciam-prod/locations/us-central1/clusters/ciam",
        "addonsConfig": {"httpLoadBalancing": {}, "horizontalPodAutoscaling": {"disabled": True},
                         "gcpFilestoreCsiDriverConfig": {"enabled": True}, "gcePersistentDiskCsiDriverConfig": {}},
        "workloadIdentityConfig": {"workloadPool": "ciam-prod.svc.id.goog"},
        "nodePools": [{"name": "default", "config": {"machineType": "e2-standard-4"},
                       "autoscaling": {"enabled": True, "minNodeCount": 1, "maxNodeCount": 3}}]}]),
    "monitoring.json": json.dumps([
        {"name": f"{P}/topics/ciam-audit", "labels": {"role": "audit-events"}},
        {"name": f"{P}/notificationChannels/123", "type": "pagerduty", "displayName": "ciam-page",
         "labels": {"service_key": "pd-integration-key-1234"}, "userLabels": {"role": "alerts-page"}},
        {"name": f"{P}/locations/global/buckets/ciam-audit", "retentionDays": 400},
        {"name": f"{P}/alertPolicies/9", "displayName": "ds-replication-lag",
         "conditions": [{"conditionThreshold": {"filter": 'metric.type="custom.googleapis.com/ds/replication_delay"'}}],
         "notificationChannels": [f"{P}/notificationChannels/123"], "userLabels": {"realizes": "replication-lag"}},
        {"name": f"{P}/uptimeCheckConfigs/login", "displayName": "sso-login", "period": "300s",
         "userLabels": {"realizes": "sso-login"}}]),
    "search.json": json.dumps([{"name": f"//compute.googleapis.com/{P}/zones/us-central1-a/instances/ds-1",
                                "assetType": "compute.googleapis.com/Instance", "project": f"projects/{NUMBER}"}]),
    "notes.json": "not json at all",
    "other.json": json.dumps([{"hello": "world"}]),
}


def _of(kind, files=FILES):
    return {r.ref: r for r in cli_resources(files)[0] if r.kind == kind}


def test_items_are_recognized_by_asset_type_kind_or_shape():
    asset = {"assetType": "compute.googleapis.com/Firewall", "resource": {"data": {"name": "x"}}}
    assert kind_of(asset)[0] == "firewall"
    assert kind_of({**asset, "assetType": "container.googleapis.com/NodePool"})[0] == "covered"
    assert kind_of({"assetType": "compute.googleapis.com/Instance", "name": "//x"})[0] == "search"
    assert kind_of({"kind": "compute#router"})[0] == "router"
    assert kind_of({"name": f"{P}/locations/l/jobs/j", "schedule": "* * * * *"})[0] == "scheduler-job"
    assert kind_of({"name": f"{P}/locations/l/jobs/j", "template": {}})[0] == "run-job"
    assert kind_of({"hello": "world"})[0] is None


def test_servers_and_rules_read_as_state_reads_them():
    servers = _of("server")
    assert sum(r.kind == "server" for r in cli_resources(FILES)[0]) == 2       # ds-2 exported and listed: once
    assert set(servers) == {f"{P}/zones/us-central1-a/instances/ds-1", f"{P}/zones/us-central1-b/instances/ds-2"}
    s = servers[f"{P}/zones/us-central1-b/instances/ds-2"]      # exported and listed: read once, gcloud's
    assert (s.role, s.attrs["ciamProductVersion"], s.attrs["ciamInstanceSize"], s.attrs["ciamZone"],
            s.attrs["ciamImageRef"]) == ("ds", ("PingDS 8.0.1",), ("n2-standard-4",), ("us-central1-b",),
                                         (f"{P}/global/images/ciam-ds-2026",))
    assert s.links == {"ciamSubnet": f"{NET}/regions/us-central1/subnetworks/ciam-ds"}
    exported = servers[f"{P}/zones/us-central1-a/instances/ds-1"]               # from the asset export: label role
    assert exported.role == "ds" and "ciamProductVersion" not in exported.attrs
    assert exported.attrs["ciamImageRef"] == (f"{P}/global/images/ciam-ds-2026",)
    rules = {r.name: r for r in _of("firewall").values()}
    assert set(rules) == {"fw-ldaps"}                                           # the probe rule is the service's
    assert rules["fw-ldaps"].attrs["ciamRulePriority"] == ("900",)


def test_a_service_from_its_forwarding_rule_backends_health_and_zone_file():
    services = {r.name: r for r in _of("service").values()}
    sso = services["ciam-prod-svc-sso"]                                         # a one-port range; an exported record
    assert (sso.attrs["ciamPort"], sso.attrs["ciamFqdn"], sso.attrs["ciamDnsZoneRef"]) == (
        ("443",), ("sso.example.test",), ("ciam-public",))
    svc = services["ciam-prod-svc-ldaps"]
    assert svc.attrs == {"ciamFqdn": ("ldaps.gcp.example.test",), "ciamDnsZoneRef": ("ciam-private",),
                         "ciamPort": ("1636",), "ciamTargetRole": ("ds",), "ciamFrontendIp": ("10.30.1.100",)}


def test_references_with_project_numbers_read_as_ids():
    assert {r.attrs["ciamRefUri"][0] for r in _of("secret").values()} == {
        "gcp-sm://projects/ciam-prod/secrets/ds-root-password",
        "gcp-sm://projects/ciam-prod/locations/us-central1/secrets/ds-tls"}
    (key,) = _of("key").values()
    assert (key.attrs["ciamProtectionLevel"], key.attrs["ciamAutoRotate"]) == (("hsm",), ("TRUE",))
    assert [r.attrs["ciamCidr"] for r in _of("egress").values()] == [("34.1.2.3/32",)]
    assert [r.attrs["ciamStorageRef"] for r in _of("storage").values()] == [("gs://ciam-prod-ds-backups",)]
    without = {p: t for p, t in FILES.items() if p != "project.json"}
    notices = cli_resources(without)[1]
    assert any(n.startswith(f"project number {NUMBER} in resource names") for n in notices)


def test_jobs_compute_clusters_monitoring():
    jobs = {r.name: r for r in _of("job").values()}
    assert jobs["ciam-rotate"].attrs == {"ciamRuntime": ("python312",), "ciamSchedule": ("0 2 * * *",)}
    assert f"{P}/locations/us-central1/jobs/ds-export" in _of("job")      # the namespace's number read as the ID
    (group,) = _of("compute").values()
    assert (group.role, group.attrs["ciamMinSize"], group.attrs["ciamMaxSize"], group.attrs["ciamImageRef"]) == (
        "compute-pf-engine", ("2",), ("6",), (f"{P}/global/images/ciam-pf-2026",))
    (gke,) = _of("cluster").values()
    # httpLoadBalancing {} is on (no disabled flag), gcePersistentDiskCsiDriverConfig {} off (no enabled flag)
    assert gke.attrs["ciamClusterAddon"] == ("gcp_filestore_csi_driver_config", "http_load_balancing",
                                             "workload-identity")
    assert gke.attrs["ciamNodePool"] == ("default: e2-standard-4, 1-3",)
    (channel,) = _of("channel").values()
    assert (channel.role, channel.attrs) == ("alerts-page", {"ciamChannelKind": ("paging-service",)})
    (alarm,), (canary,) = _of("alarm").values(), _of("canary").values()
    assert alarm.attrs["ciamMetric"] == ("custom.googleapis.com/ds/replication_delay",)
    assert canary.attrs["ciamInterval"] == ("5m",)


def test_what_cant_be_read_is_named_and_no_value_is_carried():
    resources, notices = cli_resources(FILES)
    assert {"notes.json: not JSON; not read",
            "other.json: 1 item(s) that aren't Cloud Asset Inventory or gcloud output this importer reads; not read",
            "iam.googleapis.com/ServiceAccount (1): Cloud Asset Inventory assets of a type not read",
            "google_compute_instance (1): outside the listed networks (ciam-vpc); not read"} <= set(notices)
    assert any(n.startswith("search.json: 1 Cloud Asset Inventory search result(s)") for n in notices)
    assert "hunter2" not in repr(resources) and "pd-integration-key" not in repr(resources)
    assert not any("NodePool" in n for n in notices)                         # read from its cluster


def test_an_environments_drift_is_imported():
    files = {f"gcp/prod/{p}": t for p, t in FILES.items()}
    other = (_entry("cloud=other,ou=environments,dc=ciam-ops", "ciamCloud", cloud="other", ciamCloudProvider="aws"),
             _entry("env=prod,cloud=other,ou=environments,dc=ciam-ops", "ciamEnvironment", env="prod"))
    changes, notices = preview_import(build_directory(REGISTRY, tuple(parse("\n".join((RECORDS, *other))))),
                                      "gcp/cli-inventory", {**files, "other/prod/assets.json": "[]"}, (ADAPTER,))
    assert "other/prod: not a Google Cloud environment in the record; not imported" in notices
    d = build_directory(REGISTRY, tuple(parse(RECORDS)))
    changes, notices = preview_import(d, "gcp/cli-inventory", files, (ADAPTER,))
    after = build_directory(REGISTRY, tuple(parse(RECORDS)), changes)
    assert one(get(after, f"cn=ds-1,{ENV}"), "ciamInstanceSize") == "n2-standard-8"
    assert one(get(after, f"cn=ds-2,{ENV}"), "ciamInstanceSize") == "n2-standard-4"
    assert preview_import(after, "gcp/cli-inventory", files, (ADAPTER,))[0] == ()
