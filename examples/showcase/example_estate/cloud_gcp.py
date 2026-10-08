"""What Google Cloud reports the standby environment runs (pure: builds text), from the same fixture data as the
record, with the drift planted here (`opsdir import --dry-run` shows it).

  standby/prod, Cloud Asset Inventory (an export, JSON lines) and gcloud output (--format=json):
    - ds-2 resized in the console (n2-standard-4 -> n2-standard-8; the instance list carries it)
    - an SSH rule for IAP opened by hand (35.235.240.0/20 to port 22): named, not recorded (no role)
    - Secret Manager names secrets by project number; `gcloud projects describe` reads them as the project ID
    - IAM as the inventory exports it (iam-policy, by project number), the service accounts and the pipeline's pool
      provider: as recorded, but for a service account nobody recorded (ciam-servers): counted
  Its network depth as the stack's own Terraform made it: the network firewall policy (the record's rules by secure
  tag, probe rules, the egress allowlist), its tag values, the network's enforcement order and the Private Service
  Connect endpoint for Google's APIs.
"""
import json
import re

from opsdir.core.jsondata import indented
from opsdir.domains.data.storage import parse_lifecycle
from opsdir.domains.network.stack import sites_by_port

from .access import GCP_IDENTITIES, GITHUB, PRINCIPAL_ROWS
from .cloud_common import edge_subnets, hex_id, listed, rows_of, servers_of
from .infrastructure import HOST, PROJECT, SECRET_ROLES, STANDBY
from .observability import MONITORING
from .estate import SECURITY

# ------------------------------------------------------------------ standby/prod: Cloud Asset Inventory and gcloud
GAPI = "https://www.googleapis.com/compute/v1"
NUMBER = "481516234200"                                  # the standby project's number (Secret Manager names by it)
REGION_URL = f"{GAPI}/{PROJECT}/regions/us-central1"


def _asset(asset_type, data, name=None):
    """One asset as `gcloud asset export --content-type=resource` writes it (a line of JSON)."""
    service = asset_type.split("/")[0]
    return {"name": name or f"//{service}/{(data.get('selfLink') or data['name']).split('/v1/')[-1]}",
            "assetType": asset_type, "resource": {"version": "v1", "data": data}}


def _label(v):
    return re.sub(r"[^a-z0-9_-]", "-", (v or "").lower())[:63]


def _gcp_instance(server, full, resized):
    """An instance as Compute Engine reports it: Cloud Asset Inventory keeps only platform metadata keys (full=False),
    `gcloud compute instances list` all of them."""
    cn, role, host, ip, zone, size, image, subnet, version = server
    subnets = {name: ref for name, _, ref, _, _ in STANDBY["subnets"]}
    metadata = [{"key": "enable-oslogin", "value": "TRUE"},
                *(({"key": "ciam-role", "value": role}, {"key": "ciam-product", "value": version}) if full else ())]
    return {"kind": "compute#instance", "name": cn, "selfLink": f"{GAPI}/{PROJECT}/zones/{zone}/instances/{cn}",
            "zone": f"{GAPI}/{PROJECT}/zones/{zone}",
            "machineType": f"{GAPI}/{PROJECT}/zones/{zone}/machineTypes/{resized.get(cn, size)}",
            "hostname": host, "tags": {"items": [f"ciam-prod-{role}"]},
            "labels": {"role": _label(role), "product": _label(version), "managed_by": "opsdir"},
            "metadata": {"items": metadata},
            "disks": [{"boot": True, "source": f"{GAPI}/{PROJECT}/zones/{zone}/disks/{cn}"}],
            "networkInterfaces": [{"networkIP": ip, "network": f"{GAPI}/{STANDBY['net'][1]}",
                                   "subnetwork": f"{GAPI}/{subnets[subnet]}"}]}


def _probe_ranges(ip):
    return ["35.191.0.0/16"] if ip.startswith("10.") else ["35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"]


def _gcp_firewalls(p):
    """The rendered rules (pinned priorities, '(name)' descriptions) and each service's health-check probe rule (in the
    network firewall policy instead under the policy model: _gcp_policy), and the rule opened by hand."""
    network = f"{GAPI}/{p['net'][1]}"
    policy = p.get("firewall_model") == "policy"
    return [*(() if policy else ({"kind": "compute#firewall", "name": f"ciam-prod-{cn}", "description": f"{role} ({cn})",
               "network": network, "direction": "INGRESS", "priority": 100 + 10 * i, "sourceRanges": cidrs,
               "targetTags": [f"ciam-prod-{trole}"], "allowed": [{"IPProtocol": "tcp", "ports": [str(x) for x in ports]}]}
              for i, (cn, role, cidrs, ports, trole, _, _) in enumerate(p["fw"]))),
            *(() if policy else ({"kind": "compute#firewall", "name": f"ciam-prod-{cn}-health-checks",
                                  "network": network, "description": f"Google Cloud health checks for {cn}",
                                  "direction": "INGRESS", "priority": 1000, "sourceRanges": _probe_ranges(ip),
                                  "targetTags": [f"ciam-prod-{trole}"],
                                  "allowed": [{"IPProtocol": "tcp", "ports": [str(ports[0])]}]}
                                 for cn, _, _, _, _, trole, ports, ip, _, _ in p["services"])),
            {"kind": "compute#firewall", "name": "allow-iap-ssh", "description": "IAP SSH for the vendor (temporary)",
             "network": network, "direction": "INGRESS", "priority": 900, "sourceRanges": ["35.235.240.0/20"],
             "targetTags": ["ciam-prod-ds"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}]


def _tag_value(p, role):
    """The tag value (tagValues/...) the standby's servers of a role are bound to."""
    return f"tagValues/{int(hex_id('tag', role, n=6), 16)}"


def _gcp_policy(p):
    """The network firewall policy (in the host project) as gcloud describes it: the record's rules and the probe
    rules by secure tag, the egress allowlist with everything else to the internet denied; the tag values per role."""
    (_, _, _, policy), = [x for x in p["network"] if x[0] == "ciamFirewallPolicy"]
    (proxy,) = [a for oc, _, _, a in p["network"] if oc == "ciamProxy"]
    roles = sorted({s[1] for s in p["servers"]})
    every = [{"name": _tag_value(p, r)} for r in roles]
    ingress = [{"priority": 100 + 10 * i, "direction": "INGRESS", "action": "allow", "ruleName": cn,
                "description": role, "targetSecureTags": [{"name": _tag_value(p, trole)}],
                "match": {"srcIpRanges": cidrs, "layer4Configs": [{"ipProtocol": "tcp", "ports": [str(x) for x in ports]}]}}
               for i, (cn, role, cidrs, ports, trole, _, _) in enumerate(p["fw"])]
    probes = [{"priority": 70000 + i, "direction": "INGRESS", "action": "allow",
               "description": f"Google Cloud health checks for {cn}", "targetSecureTags": [{"name": _tag_value(p, trole)}],
               "match": {"srcIpRanges": _probe_ranges(ip), "layer4Configs": [{"ipProtocol": "tcp", "ports": [str(ports[0])]}]}}
              for i, (cn, _, _, _, _, trole, ports, ip, _, _) in enumerate(p["services"])]
    egress = [*({"priority": 80000 + i, "direction": "EGRESS", "action": "allow", "targetSecureTags": every,
                 "match": {"destFqdns": hosts, "layer4Configs": [{"ipProtocol": "tcp", "ports": [str(port)]}]}}
                for i, (port, hosts) in enumerate(sites_by_port(proxy["ciamAllowedDestination"]))),
              {"priority": 2147483000, "direction": "EGRESS", "action": "deny", "targetSecureTags": every,
               "match": {"destIpRanges": ["0.0.0.0/0"], "layer4Configs": [{"ipProtocol": "all"}]}}]
    return [_asset("compute.googleapis.com/NetworkFirewallPolicy", {
                "kind": "compute#firewallPolicy", "name": policy["ciamProviderRef"].rsplit("/", 1)[1],
                "selfLink": f"{GAPI}/{policy['ciamProviderRef']}", "rules": [*ingress, *probes, *egress],
                "associations": [{"name": "ciam-prod-fw-policy", "attachmentTarget": f"{GAPI}/{p['net'][1]}"}]}),
            *(_asset("cloudresourcemanager.googleapis.com/TagValue",
                     {"name": _tag_value(p, r), "shortName": r, "parent": "tagKeys/281474976710656"},
                     name=f"//cloudresourcemanager.googleapis.com/{_tag_value(p, r)}") for r in roles)]


def _gcp_google_apis(p):
    """The Private Service Connect endpoint for Google's APIs and the private services access range (the landing
    zone's), in the host project."""
    (role, a), = [(r, a) for oc, _, r, a in p["network"] if oc == "ciamPrivateEndpoint"
                  and a["ciamPrivateEndpointKind"] == "all-apis"]
    peered = [(r, a) for oc, _, r, a in p["network"] if oc == "ciamPrivateEndpoint"
              and a["ciamPrivateEndpointKind"] == "peered-service"]
    address = f"{GAPI}/{HOST}/global/addresses/ciam-prod-psc-apis"
    return [*(_asset("compute.googleapis.com/GlobalAddress", {
                "kind": "compute#address", "name": x["ciamProviderRef"].rsplit("/", 1)[1],
                "address": x["ciamCidr"].split("/")[0], "prefixLength": int(x["ciamCidr"].split("/")[1]),
                "purpose": "VPC_PEERING", "addressType": "INTERNAL", "network": f"{GAPI}/{p['net'][1]}",
                "selfLink": f"{GAPI}/{x['ciamProviderRef']}", "labels": {"role": r, "managed_by": "opsdir"}})
              for r, x in peered),
            _asset("compute.googleapis.com/GlobalAddress", {
                "kind": "compute#address", "name": "ciam-prod-psc-apis", "address": a["ciamFrontendIp"],
                "purpose": "PRIVATE_SERVICE_CONNECT", "addressType": "INTERNAL", "selfLink": address,
                "labels": {"role": role, "managed_by": "opsdir"}}),
            _asset("compute.googleapis.com/GlobalForwardingRule", {
                "kind": "compute#forwardingRule", "name": a["ciamProviderRef"].rsplit("/", 1)[1], "target": "all-apis",
                "IPAddress": a["ciamFrontendIp"], "network": f"{GAPI}/{p['net'][1]}",
                "selfLink": f"{GAPI}/{a['ciamProviderRef']}"})]


def _gcp_services(p):
    """(forwarding rules, backend services, record sets, get-health outputs by service) of the service names."""
    servers = p["servers"]
    rules, backends, records, health = [], [], [], {}
    for cn, _, fqdn, _, zref, trole, ports, ip, _, _ in p["services"]:
        name, targets = f"ciam-prod-{cn}", [s for s in servers if s[1] == trole]
        groups = {zone: f"{GAPI}/{PROJECT}/zones/{zone}/instanceGroups/{name}-{zone}" for zone in sorted({s[4] for s in targets})}
        backend = f"{REGION_URL}/backendServices/{name}"
        rules.append({"kind": "compute#forwardingRule", "name": name, "region": REGION_URL, "IPAddress": ip,
                      "ports": [str(x) for x in ports], "IPProtocol": "TCP", "backendService": backend,
                      "loadBalancingScheme": "INTERNAL" if ip.startswith("10.") else "EXTERNAL",
                      "selfLink": f"{REGION_URL}/forwardingRules/{name}", "labels": {"managed_by": "opsdir"}})
        backends.append({"kind": "compute#backendService", "name": name, "region": REGION_URL, "selfLink": backend,
                         "backends": [{"group": g, "balancingMode": "CONNECTION"} for g in groups.values()]})
        records.append(_asset("dns.googleapis.com/ResourceRecordSet",
                              {"name": f"{fqdn}.", "type": "A", "ttl": 300, "rrdatas": [ip]},
                              name=f"//dns.googleapis.com/{HOST}/managedZones/{zref}/rrsets/{fqdn}./A"))
        health[name] = [{"backend": g, "status": {"kind": "compute#backendServiceGroupHealth", "healthStatus": [
            {"instance": f"{GAPI}/{PROJECT}/zones/{zone}/instances/{s[0]}", "ipAddress": s[3], "port": ports[0],
             "healthState": "HEALTHY"} for s in targets if s[4] == zone]}} for zone, g in groups.items()]
    return rules, backends, records, health


def _gcp_references(p):
    """Secrets (named by project number), the disk key, the backup bucket, the audit topic and the engines' group."""
    key = p["key"][0].split("://", 1)[1]
    (mig, _, target, ref, image, size, least, runs, most, zones, _), = p["compute"]
    template = f"{GAPI}/{PROJECT}/global/instanceTemplates/{ref.rsplit('/', 1)[1]}-1"
    return [*(_asset("secretmanager.googleapis.com/Secret", {"name": f"projects/{NUMBER}/secrets/{role}",
                                                             "labels": {"role": role},
                                                             "replication": {"automatic": {}}})
              for role in SECRET_ROLES),
            _asset("cloudkms.googleapis.com/CryptoKey", {"name": key, "purpose": "ENCRYPT_DECRYPT",
                                                         "rotationPeriod": "7776000s", "labels": {"role": "disk-encryption"},
                                                         "versionTemplate": {"protectionLevel": "HSM",
                                                                             "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"}}),
            _asset("storage.googleapis.com/Bucket", _gcp_backup(p), name=f"//storage.googleapis.com/{p['backup'][5:]}"),
            *(_asset("pubsub.googleapis.com/Topic", {"name": sref, "labels": {"role": role}})
              for _, role, sref, _ in p["streams"]),
            *(_asset("pubsub.googleapis.com/Topic", {"name": a["ciamProviderRef"], "labels": {"role": role}})
              for oc, _, role, a in SECURITY["standby"] if oc == "ciamStreamBinding"),
            _asset("compute.googleapis.com/InstanceGroupManager", {
                "kind": "compute#instanceGroupManager", "name": ref.rsplit("/", 1)[1], "region": REGION_URL,
                "selfLink": f"{GAPI}/{ref}", "targetSize": runs, "versions": [{"instanceTemplate": template}],
                "distributionPolicy": {"zones": [{"zone": f"{GAPI}/{PROJECT}/zones/{z}"} for z in zones]}}),
            _asset("compute.googleapis.com/InstanceTemplate", {
                "kind": "compute#instanceTemplate", "name": template.rsplit("/", 1)[1], "selfLink": template,
                "properties": {"machineType": size, "labels": {"role": target},
                               "disks": [{"boot": True, "initializeParams": {"sourceImage": f"{GAPI}/{image}"}}]}}),
            _asset("compute.googleapis.com/Autoscaler", {
                "kind": "compute#autoscaler", "name": ref.rsplit("/", 1)[1], "region": REGION_URL,
                "selfLink": f"{REGION_URL}/autoscalers/{ref.rsplit('/', 1)[1]}", "target": f"{GAPI}/{ref}",
                "autoscalingPolicy": {"minNumReplicas": least, "maxNumReplicas": most}})]


_CLASSES = {"cool": "NEARLINE", "cold": "COLDLINE", "archive": "ARCHIVE"}


def _gcp_backup(p):
    """The backup bucket as Cloud Asset Inventory exports it, with its settings."""
    a = p["backup_depth"]

    def rule(noncurrent, days, act):
        return {"action": {"type": "Delete"} if act == "delete" else
                {"type": "SetStorageClass", "storageClass": _CLASSES[act]},
                "condition": {"daysSinceNoncurrentTime": days, "isLive": False} if noncurrent else {"age": days}}
    return {"kind": "storage#bucket", "name": p["backup"][5:], "location": "US-CENTRAL1",
            "labels": {"role": "backup-target", "managed_by": "opsdir"}, "versioning": {"enabled": True},
            "retentionPolicy": {"retentionPeriod": str(int(a["ciamStorageLockDays"]) * 86400), "isLocked": True},
            "encryption": {"defaultKmsKeyName": p["key"][0].split("://", 1)[1]},
            "iamConfiguration": {"publicAccessPrevention": "enforced", "uniformBucketLevelAccess": {"enabled": True}},
            "lifecycle": {"rule": [rule(*parse_lifecycle(v)) for v in a["ciamStorageLifecycle"]]}}


DATA_ACCESS = (("data-read", "DATA_READ"), ("data-write", "DATA_WRITE"))


def _audit_configs():
    """The project's Data Access audit configs (its IAM policy's auditConfigs) the standby's audit trail records."""
    events = [e for oc, _, _, a in MONITORING["standby"] if oc == "ciamAuditTrail" for e in a["ciamAuditEvents"]]
    logs = [{"logType": log} for e, log in DATA_ACCESS if e in events]
    return [{"service": "allServices", "auditLogConfigs": logs}] if logs else []


def _gcp_monitoring():
    """What Cloud Monitoring and Logging run, from the standby's monitoring bindings: the audit trail as the sink
    exporting Cloud Audit Logs, and the bucket keeping them with its locked retention policy."""
    numbered = PROJECT.replace(PROJECT.split("/")[1], NUMBER)
    stores = {role: a for oc, _, role, a in MONITORING["standby"] if oc == "ciamObjectStore"}

    def asset(oc, attrs):
        ref = attrs["ciamProviderRef"]
        if oc == "ciamObjectStore":
            return _asset("storage.googleapis.com/Bucket", {
                "kind": "storage#bucket", "name": ref, "location": "US-CENTRAL1",
                "labels": {"role": "audit-archive", "managed_by": "opsdir"},
                "retentionPolicy": {"retentionPeriod": str(int(attrs["ciamStorageLockDays"]) * 86400),
                                    "isLocked": attrs["ciamStorageImmutability"] == "compliance"},
                "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}}},
                name=f"//storage.googleapis.com/{ref}")
        if oc == "ciamAuditTrail":
            name = ref.rsplit("/", 1)[1]
            bucket = stores[attrs["ciamLogDestinationRole"]]["ciamStorageRef"][len("gs://"):]
            return _asset("logging.googleapis.com/LogSink", {
                "name": name, "destination": f"storage.googleapis.com/{bucket}",
                "filter": 'logName:"cloudaudit.googleapis.com"',
                "writerIdentity": f"serviceAccount:service-{NUMBER}@gcp-sa-logging.iam.gserviceaccount.com"},
                name=f"//logging.googleapis.com/{numbered}/sinks/{name}")
        if oc == "ciamAlertChannel":
            return _asset("monitoring.googleapis.com/NotificationChannel", {
                "name": ref, "type": "pagerduty", "displayName": "ciam-page", "labels": {"service_key": "**********"},
                "userLabels": {"role": "alerts-page"}})
        if oc == "ciamLogDestination":
            return _asset("logging.googleapis.com/LogBucket", {"name": ref, "retentionDays": attrs["ciamRetentionDays"],
                                                               "lifecycleState": "ACTIVE"})
        if oc == "ciamAlarmBinding":
            condition = ({"conditionMatchedLog": {"filter": 'logName:"pingfederate" AND "AUTHN_ATTEMPT" AND "FAILURE"'}}
                         if attrs["ciamMetric"] == "log query" else
                         {"conditionThreshold": {"filter": f'metric.type="{attrs["ciamMetric"]}" AND '
                                                           'resource.type="gce_instance"'}})
            return _asset("monitoring.googleapis.com/AlertPolicy", {
                "name": ref, "displayName": ref.rsplit("/", 1)[1], "conditions": [condition],
                "notificationChannels": [attrs["ciamNotifies"]], "userLabels": {"realizes": attrs["ciamRealizes"]}})
        return _asset("monitoring.googleapis.com/UptimeCheckConfig", {
            "name": ref, "displayName": "sso-login", "period": "300s", "userLabels": {"realizes": attrs["ciamRealizes"]}})
    return [asset(oc, attrs) for oc, _, _, attrs in MONITORING["standby"]]


def _gcp_databases(p):
    """The managed databases as Cloud Asset Inventory exports them (sqladmin.googleapis.com/Instance): never a
    password."""
    return [_asset("sqladmin.googleapis.com/Instance", {
        "kind": "sql#instance", "name": cn, "project": PROJECT.split("/")[1], "region": "us-central1",
        "databaseVersion": f"POSTGRES_{a['ciamDbEngineVersion']}", "dnsName": a["ciamFqdn"] + ".",
        "selfLink": f"https://sqladmin.googleapis.com/sql/v1beta4/{a['ciamProviderRef']}",
        "diskEncryptionConfiguration": {"kmsKeyName": p["key"][0].split("://", 1)[1]},
        "settings": {
            "tier": a["ciamInstanceSize"], "dataDiskSizeGb": a["ciamDbStorageGb"],
            "availabilityType": "REGIONAL" if a["ciamDbHighAvailability"] == "zone-redundant" else "ZONAL",
            "deletionProtectionEnabled": a["ciamDbDeletionProtection"] == "TRUE",
            "userLabels": {"role": role, "managed_by": "opsdir"},
            "locationPreference": {"zone": a["ciamZone"]},
            "backupConfiguration": {"enabled": True, "pointInTimeRecoveryEnabled": True,
                                    "backupRetentionSettings": {"retainedBackups": int(a["ciamRetentionDays"]),
                                                                "retentionUnit": "COUNT"}},
            "ipConfiguration": {"ipv4Enabled": False, "privateNetwork": f"{GAPI}/{p['net'][1]}",
                                "sslMode": "ENCRYPTED_ONLY"},
            "databaseFlags": [{"name": k, "value": v} for k, v in (x.split("=", 1) for x in a["ciamDbParameter"])]}},
        name=f"//sqladmin.googleapis.com/{a['ciamProviderRef']}")
        for _, cn, role, a in p["databases"]]


_PD = {"standard": "pd-standard", "ssd": "pd-ssd", "provisioned": "hyperdisk-balanced"}


def _gcp_volumes(p):
    """The disks as Cloud Asset Inventory exports them: each data volume of a role a disk on each of its instances, in
    its zone, encrypted with the disk key, labelled with its volume, role, server and snapshot policy and following
    the policy's snapshot schedule; each snapshot policy a resource policy with a daily (or hourly) schedule from its
    hour, its retention and its storage location."""
    key = p["key"][0].split("://", 1)[1]
    policies = {role: f"{REGION_URL}/resourcePolicies/ciam-prod-{cn}"
                for cn, role, _ in rows_of(p.get("volumes") or (), "ciamSnapshotPolicy")}
    disks = [_asset("compute.googleapis.com/Disk", {
                "kind": "compute#disk", "name": f"{s[0]}-{cn}", "sizeGb": a["ciamVolumeSizeGb"],
                "zone": f"{GAPI}/{PROJECT}/zones/{s[4]}", "type": f"{GAPI}/{PROJECT}/zones/{s[4]}/diskTypes/"
                                                                  f"{_PD[a['ciamVolumeClass']]}",
                "selfLink": f"{GAPI}/{PROJECT}/zones/{s[4]}/disks/{s[0]}-{cn}",
                **({"provisionedIops": a["ciamIops"]} if a.get("ciamIops") else {}),
                **({"provisionedThroughput": a["ciamThroughputMb"]} if a.get("ciamThroughputMb") else {}),
                "diskEncryptionKey": {"kmsKeyName": f"{key}/cryptoKeyVersions/1"},
                "users": [f"{GAPI}/{PROJECT}/zones/{s[4]}/instances/{s[0]}"],
                "resourcePolicies": [policies[a["ciamSnapshotPolicyRole"]]] if a.get("ciamSnapshotPolicyRole") else [],
                "labels": {"volume": _label(cn), "role": _label(role), "server": _label(s[0]),
                           **({"snapshot_policy": _label(a["ciamSnapshotPolicyRole"])}
                              if a.get("ciamSnapshotPolicyRole") else {}), "managed_by": "opsdir"}})
             for cn, role, a in rows_of(p.get("volumes") or (), "ciamVolume") for s in servers_of(p, a["ciamTargetRole"])]
    schedules = [_asset("compute.googleapis.com/ResourcePolicy", {
                    "kind": "compute#resourcePolicy", "name": f"ciam-prod-{cn}", "region": REGION_URL,
                    "selfLink": policies[role], "status": "READY", "snapshotSchedulePolicy": {
                        "schedule": {"dailySchedule": {"daysInCycle": 1, "startTime": a["ciamSnapshotAt"]}}
                        if int(a["ciamSnapshotEveryHours"]) == 24 else
                        {"hourlySchedule": {"hoursInCycle": int(a["ciamSnapshotEveryHours"]),
                                            "startTime": a["ciamSnapshotAt"]}},
                        "retentionPolicy": {"maxRetentionDays": int(a["ciamRetentionDays"]),
                                            "onSourceDiskDelete": "KEEP_AUTO_SNAPSHOTS"},
                        "snapshotProperties": {"storageLocations": [a["ciamCopyRegion"]] if a.get("ciamCopyRegion")
                                               else [], "guestFlush": a["ciamSnapshotConsistency"] == "application",
                                               "labels": {"policy": _label(cn), "role": _label(role),
                                                          "managed_by": "opsdir"}}}})
                 for cn, role, a in rows_of(p.get("volumes") or (), "ciamSnapshotPolicy")]
    return [*schedules, *disks]


def _gcp_backups(p):
    """Backup and DR as Cloud Asset Inventory exports it: each vault (its minimum enforced retention, in its plans'
    copy region), each plan (in the standby's region, for disks: retention, a daily schedule from its hour and the
    default window) and an association per disk of the roles it protects."""
    rows = p.get("volumes") or ()
    root = f"{PROJECT}/locations"
    regions = {a["ciamBackupVaultRole"]: (listed(a.get("ciamCopyRegion")) or ["us-central1"])[0]
               for _, _, a in rows_of(rows, "ciamBackupPlan")}          # a vault is where its plans copy to
    vaults = {role: f"{root}/{regions[role]}/backupVaults/ciam-prod-{cn}"
              for cn, role, _ in rows_of(rows, "ciamBackupVault") if role in regions}
    found = [_asset("backupdr.googleapis.com/BackupVault", {
                 "name": vaults[role], "state": "ACTIVE",
                 "backupMinimumEnforcedRetentionDuration": f"{int(a.get('ciamStorageLockDays') or 1) * 86400}s",
                 "labels": {"name": _label(cn), "role": _label(role), "managed_by": "opsdir"}})
             for cn, role, a in rows_of(rows, "ciamBackupVault") if role in vaults]
    for cn, role, a in rows_of(rows, "ciamBackupPlan"):
        plan = f"{root}/us-central1/backupPlans/{cn}"
        hour = int(a["ciamBackupAt"][:2])
        found += [_asset("backupdr.googleapis.com/BackupPlan", {
                      "name": plan, "state": "ACTIVE", "resourceType": "compute.googleapis.com/Disk",
                      "backupVault": vaults[a["ciamBackupVaultRole"]],
                      "backupRules": [{"ruleId": "ciam", "backupRetentionDays": int(a["ciamRetentionDays"]),
                                       "standardSchedule": {"recurrenceType": "DAILY", "timeZone": "UTC",
                                                            "backupWindow": {"startHourOfDay": hour,
                                                                             "endHourOfDay": min(hour + 6, 24)}}}]}),
                  *(_asset("backupdr.googleapis.com/BackupPlanAssociation", {
                      "name": f"{root}/us-central1/backupPlanAssociations/{s[0]}-{vcn}", "state": "ACTIVE",
                      "resource": f"{PROJECT}/zones/{s[4]}/disks/{s[0]}-{vcn}",
                      "resourceType": "compute.googleapis.com/Disk", "backupPlan": plan})
                    for vcn, vrole, v in rows_of(rows, "ciamVolume") if vrole in listed(a["ciamProtectsRole"])
                    for s in servers_of(p, v["ciamTargetRole"]))]
    return found


def standby_inventory():
    """{file name: text} of the standby environment's Cloud Asset Inventory export and gcloud output, with the planted
    drift."""
    p = STANDBY
    resized = {"ds-2": "n2-standard-8"}
    rules, backends, records, health = _gcp_services(p)
    nat, address = p["egress"][0].split("/"), p["egress"][1][:-3]
    exported = [*(_asset("compute.googleapis.com/Instance", _gcp_instance(s, False, {})) for s in p["servers"]),
                *(_asset("compute.googleapis.com/Disk", {"kind": "compute#disk", "name": s[0], "sourceImage": f"{GAPI}/{s[6]}",
                                                         "selfLink": f"{GAPI}/{PROJECT}/zones/{s[4]}/disks/{s[0]}"})
                  for s in p["servers"]),
                *(_asset("compute.googleapis.com/Firewall", fw) for fw in _gcp_firewalls(p)),
                *(_asset("compute.googleapis.com/ForwardingRule", r) for r in rules),
                *(_asset("compute.googleapis.com/RegionBackendService", b) for b in backends),
                _asset("compute.googleapis.com/Address", {"kind": "compute#address", "name": "ciam-standby-nat-1",
                                                          "address": address, "region": REGION_URL,
                                                          "selfLink": f"{REGION_URL}/addresses/ciam-standby-nat-1"}),
                _asset("compute.googleapis.com/Router", {"kind": "compute#router", "name": nat[2], "region": REGION_URL,
                                                         "selfLink": f"{REGION_URL}/routers/{nat[2]}",
                                                         "nats": [{"name": nat[3], "natIpAllocateOption": "MANUAL_ONLY",
                                                                   "natIps": [f"{REGION_URL}/addresses/ciam-standby-nat-1"]}]}),
                *_gcp_references(p), *_gcp_monitoring(), *_gcp_databases(p), *_gcp_volumes(p),
                *_gcp_backups(p),
                _asset("iam.googleapis.com/ServiceAccount", {"name": f"{PROJECT}/serviceAccounts/ciam-servers@"
                                                                     "example-aero-ciam-standby.iam.gserviceaccount.com"})]
    host = [_asset("compute.googleapis.com/Network", {"kind": "compute#network", "name": p["net"][1].rsplit("/", 1)[1],
                                                      "selfLink": f"{GAPI}/{p['net'][1]}",
                                                      "networkFirewallPolicyEnforcementOrder": "BEFORE_CLASSIC_FIREWALL"}),
            *_gcp_policy(p), *_gcp_google_apis(p),
            *(_asset("compute.googleapis.com/Subnetwork", {"kind": "compute#subnetwork", "name": ref.rsplit("/", 1)[1],
                                                           "ipCidrRange": cidr, "network": f"{GAPI}/{p['net'][1]}",
                                                           "region": f"{GAPI}/{HOST}/regions/us-central1",
                                                           "selfLink": f"{GAPI}/{ref}",
                                                           **({"purpose": "REGIONAL_MANAGED_PROXY"}
                                                              if role == "subnet-edge" else {})})
              for _, role, ref, cidr, _ in (*p["subnets"], *edge_subnets(p))),
            *records]
    iam, providers = _gcp_iam()
    return {"assets.jsonl": "".join(json.dumps(a, sort_keys=False) + "\n" for a in exported),
            "iam-policies.jsonl": "".join(json.dumps(a, sort_keys=False) + "\n" for a in iam),
            "pool-providers.json": indented(providers),
            "host-network.json": indented(host),
            "project.json": indented({"projectId": PROJECT.split("/")[1], "projectNumber": NUMBER,
                                    "name": PROJECT.split("/")[1], "lifecycleState": "ACTIVE"}),
            "instances.json": indented([_gcp_instance(s, True, resized) for s in p["servers"]]),
            **{f"health/{name}.json": indented(doc) for name, doc in health.items()}}


def _gcp_iam():
    """The standby's IAM policies as `gcloud asset export --content-type=iam-policy` writes them (by project number),
    its service accounts and the pipeline's pool provider: as the record holds them."""
    numbered = PROJECT.replace(PROJECT.split("/")[1], NUMBER)
    prefix = {"service-account": "serviceAccount", "federated": "serviceAccount", "group": "group", "user": "user"}

    def full(resource):
        if resource.startswith("projects/_/buckets/"):
            return f"//storage.googleapis.com/{resource.rsplit('/', 1)[1]}", "storage.googleapis.com/Bucket"
        if "/keyRings/" in resource:
            return f"//cloudkms.googleapis.com/{resource.replace(PROJECT, numbered)}", "cloudkms.googleapis.com/KeyRing"
        return f"//cloudresourcemanager.googleapis.com/{numbered}", "cloudresourcemanager.googleapis.com/Project"
    bindings = {}
    for cn, kind, ref, _, grants in GCP_IDENTITIES:
        for role, _, resource in (g.partition(" on ") for g in grants):
            bindings.setdefault(resource, {}).setdefault(role, []).append(f"{prefix[kind]}:{ref}")
    shown = {role: f"{cn} ({role})" for cn, _, role, *_ in PRINCIPAL_ROWS}
    accounts = [(cn, ref) for cn, kind, ref, _, _ in GCP_IDENTITIES if kind in ("service-account", "federated")]
    pool = f"projects/{NUMBER}/locations/global/workloadIdentityPools/ciam-prod-ci"
    ci = next((ref, trusted[0].split(" ", 1)[1]) for cn, _, ref, trusted, _ in GCP_IDENTITIES if cn == "identity-ci")
    project = f"//cloudresourcemanager.googleapis.com/{numbered}"
    granted = [{"name": full(r)[0], "assetType": full(r)[1],
                "iamPolicy": {"bindings": [{"role": role, "members": members} for role, members in roles.items()]}}
               for r, roles in bindings.items()]
    policies = [*granted, *([{"name": project, "assetType": "cloudresourcemanager.googleapis.com/Project",
                              "iamPolicy": {"bindings": []}}]
                            if _audit_configs() and not any(x["name"] == project for x in granted) else [])]
    return ([*({**x, "iamPolicy": {**x["iamPolicy"], "auditConfigs": _audit_configs()}} if x["name"] == project
               and _audit_configs() else x for x in policies),
             {"name": f"//iam.googleapis.com/{numbered}/serviceAccounts/{ci[0]}",
              "assetType": "iam.googleapis.com/ServiceAccount",
              "iamPolicy": {"bindings": [{"role": "roles/iam.workloadIdentityUser",
                                          "members": [f"principal://iam.googleapis.com/{pool}/subject/{ci[1]}"]}]}},
             *(_asset("iam.googleapis.com/ServiceAccount", {"email": ref, "name": f"{PROJECT}/serviceAccounts/{ref}",
                                                            "displayName": shown.get(cn)}) for cn, ref in accounts)],
            [{"name": f"{pool}/providers/github", "oidc": {"issuerUri": GITHUB}}])
