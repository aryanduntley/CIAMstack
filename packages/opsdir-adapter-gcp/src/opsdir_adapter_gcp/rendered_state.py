"""Google Cloud: what applying an environment's rendered Terraform would record, so gcp/terraform-state reads the render
back (the round trip, milestone 5.5c). Pure.

Each rendered root (terraform/, terraform/landing-zone/, ...) becomes a Terraform state (opsdir_format_terraform.
state_builder): what its blocks configure, and what Google Cloud would assign, which this module gives from the record
the render was made from:
  - a resource realizing a binding the record holds (REALIZES; opsdir_format_terraform.realized) gets that binding's
    provider reference as the importers read it: its id, and for the kinds named by what Google assigns (an alert
    policy's number: NAMED_BY_REF) its name, a service account's its email;
  - any other resource the id the google provider gives it (ID_TEMPLATES: projects/{project}/regions/{region}/
    subnetworks/{name}, ...; the importers read ids by their collections), in the project, region and zone it names
    or the root's provider's, and what Google assigns its type (ASSIGNS: a service account's email and unique id);
  - effective_labels: the provider's default_labels under the resource's labels, as the provider records them;
  - data sources the same ids, so a lookup by name finds what the record holds, and what the record holds of what
    they find (RECORDED: a service name's address); the project's number.
"""
import uuid
from types import MappingProxyType

from opsdir.core.directory import one
from opsdir.core.environment import env_dn, env_model
from opsdir_format_terraform.realized import realized
from opsdir_format_terraform.state_builder import root_states, synthetic

# Resource types realizing a binding the record matches by its provider reference -> the binding's object class
REALIZES = MappingProxyType({
    "google_monitoring_alert_policy": "ciamAlarmBinding", "google_monitoring_notification_channel": "ciamAlertChannel",
    "google_monitoring_uptime_check_config": "ciamCanaryBinding", "google_service_account": "ciamIdentityBinding",
    "google_logging_project_sink": "ciamAuditTrail", "google_logging_project_bucket_config": "ciamLogDestination",
    "google_cloud_asset_project_feed": "ciamStreamBinding", "google_pubsub_topic": "ciamStreamBinding",
    "google_scc_v2_project_notification_config": "ciamSecurityService",
    "google_data_loss_prevention_discovery_config": "ciamDataDiscovery",
    "google_backup_dr_backup_vault": "ciamBackupVault", "google_backup_dr_backup_plan": "ciamBackupPlan",
    "google_compute_resource_policy": "ciamSnapshotPolicy", "google_dns_managed_zone": "ciamDnsForwarder",
    "google_sql_database_instance": "ciamDatabase", "google_container_cluster": "ciamCluster",
    "google_compute_region_instance_group_manager": "ciamComputeGroup",
    "google_compute_global_address": "ciamPrivateEndpoint",
    "google_compute_global_forwarding_rule": "ciamPrivateEndpoint",
    "google_compute_network_firewall_policy": "ciamFirewallPolicy", "google_billing_budget": "ciamBudget",
    "google_compute_address": "ciamServiceName"})
# What the record holds of what Google assigned a realized binding's resource (or what a data source finds):
# {type: {state attribute: record attribute}}
RECORDED = MappingProxyType({"google_compute_address": {"address": "ciamFrontendIp"}})
# Types whose name is the full resource name Google gives them (the importers read them by it): name = id
FULL_NAME = frozenset(("google_scc_v2_project_notification_config",))
# Types whose name Google assigns (projects/p/alertPolicies/2001): a realized one's reference is its name too
NAMED_BY_REF = frozenset(("google_monitoring_alert_policy", "google_monitoring_notification_channel",
                          "google_monitoring_uptime_check_config", "google_billing_budget",
                          "google_scc_v2_project_notification_config"))
# The id the google provider gives a resource of a type: {project}, {region}, {zone}, {location}, {name}
ID_TEMPLATES = MappingProxyType({
    "google_compute_network": "projects/{project}/global/networks/{name}",
    "google_compute_subnetwork": "projects/{project}/regions/{region}/subnetworks/{name}",
    "google_compute_instance": "projects/{project}/zones/{zone}/instances/{name}",
    "google_compute_instance_group": "projects/{project}/zones/{zone}/instanceGroups/{name}",
    "google_compute_disk": "projects/{project}/zones/{zone}/disks/{name}",
    "google_compute_address": "projects/{project}/regions/{region}/addresses/{name}",
    "google_compute_global_address": "projects/{project}/global/addresses/{name}",
    "google_compute_firewall": "projects/{project}/global/firewalls/{name}",
    "google_compute_network_firewall_policy": "projects/{project}/global/firewallPolicies/{name}",
    "google_compute_forwarding_rule": "projects/{project}/regions/{region}/forwardingRules/{name}",
    "google_compute_global_forwarding_rule": "projects/{project}/global/forwardingRules/{name}",
    "google_compute_region_backend_service": "projects/{project}/regions/{region}/backendServices/{name}",
    "google_compute_region_health_check": "projects/{project}/regions/{region}/healthChecks/{name}",
    "google_compute_region_security_policy": "projects/{project}/regions/{region}/securityPolicies/{name}",
    "google_compute_region_ssl_policy": "projects/{project}/regions/{region}/sslPolicies/{name}",
    "google_compute_region_url_map": "projects/{project}/regions/{region}/urlMaps/{name}",
    "google_compute_region_target_https_proxy": "projects/{project}/regions/{region}/targetHttpsProxies/{name}",
    "google_compute_router": "projects/{project}/regions/{region}/routers/{name}",
    "google_compute_route": "projects/{project}/global/routes/{name}",
    "google_compute_resource_policy": "projects/{project}/regions/{region}/resourcePolicies/{name}",
    "google_compute_region_instance_group_manager": "projects/{project}/regions/{region}/instanceGroupManagers/{name}",
    "google_container_cluster": "projects/{project}/locations/{location}/clusters/{name}",
    "google_service_account": "projects/{project}/serviceAccounts/{account_id}@{project}.iam.gserviceaccount.com",
    "google_secret_manager_secret": "projects/{project}/secrets/{secret_id}",
    "google_logging_project_sink": "projects/{project}/sinks/{name}",
    "google_logging_project_bucket_config": "projects/{project}/locations/{location}/buckets/{bucket_id}",
    "google_pubsub_topic": "projects/{project}/topics/{name}",
    "google_dns_managed_zone": "projects/{project}/managedZones/{name}",
    "google_sql_database_instance": "projects/{project}/instances/{name}",
    "google_cloud_asset_project_feed": "projects/{project}/feeds/{feed_id}",
    "google_backup_dr_backup_vault": "projects/{project}/locations/{location}/backupVaults/{backup_vault_id}",
    "google_backup_dr_backup_plan": "projects/{project}/locations/{location}/backupPlans/{backup_plan_id}",
    "google_kms_key_ring": "projects/{project}/locations/{location}/keyRings/{name}",
    "google_iam_workload_identity_pool": "projects/{project}/locations/global/workloadIdentityPools/"
                                         "{workload_identity_pool_id}",
    "google_scc_v2_project_notification_config": "projects/{project}/locations/{location}/notificationConfigs/"
                                                 "{config_id}",
    "google_compute_router_nat": "{project}/{region}/{router}/{name}",
    "google_storage_bucket": "{name}"})
_NAMESPACE = uuid.UUID("0c4b8a2e-9d61-4f3e-a5b7-c1d2e3f4a5b6")       # synthetic numbers and ids: stable per resource


def number(*parts):
    """A stable synthetic number for what Google assigns (a project number, a unique id)."""
    return str(uuid.uuid5(_NAMESPACE, "/".join(str(p) for p in parts)).int % 10 ** 12)


# What Google Cloud assigns a resource of a type beyond its id: (configured, project) -> attributes
ASSIGNS = MappingProxyType({
    "google_service_account": lambda configured, project: {
        "email": f"{configured.get('account_id')}@{project}.iam.gserviceaccount.com",
        "name": f"projects/{project}/serviceAccounts/{configured.get('account_id')}@{project}.iam.gserviceaccount.com",
        "unique_id": number("account", configured.get("account_id")),
        "member": f"serviceAccount:{configured.get('account_id')}@{project}.iam.gserviceaccount.com"},
    "google_iam_workload_identity_pool": lambda configured, project: {
        "name": f"projects/{number('project', project)}/locations/global/workloadIdentityPools/"
                f"{configured.get('workload_identity_pool_id')}"}})


def _literal(v, defaults):
    named = v[6:-1] if isinstance(v, str) and v.startswith("${var.") else None
    return defaults.get(named, "") if named else (v if isinstance(v, str) else "")


def provider_facts(blocks):
    """(project, region, default labels) of a rendered root's google provider: literals, or the defaults of the
    variables they name."""
    body = next((b.body for b in blocks if b.kind == "provider" and b.labels == ("google",)), ())
    defaults = {b.labels[0]: v for b in blocks if b.kind == "variable" and b.labels for k, v in b.body
                if k == "default"}
    given = dict((k, v) for k, v in body if k != "#")
    labels = given.get("default_labels") if isinstance(given.get("default_labels"), dict) else {}
    return (_literal(given.get("project", ""), defaults), _literal(given.get("region", ""), defaults),
            {k.strip('"'): v for k, v in labels.items()})


def resource_id(type_, name, index, configured, project, region):
    """The id the google provider gives a resource of a type (ID_TEMPLATES), in the project, region and zone it names
    or the root's; a type this module doesn't place gets a synthetic one, unique in the root."""
    fields = {k: str(v) for k, v in configured.items() if isinstance(v, (str, int))}
    named = fields.get("name") or name
    values = {**fields, "name": named + (f"-{index}" if index is not None else ""),
              "project": fields.get("project") or project, "region": fields.get("region") or region,
              "zone": fields.get("zone") or f"{region}-a", "location": fields.get("location") or region}
    template = ID_TEMPLATES.get(type_)
    try:
        return template.format(**values) if template else \
            f"projects/{values['project']}/opsdirSynthetic/{type_[7:]}/{values['name']}"
    except KeyError:
        return f"projects/{values['project']}/opsdirSynthetic/{type_[7:]}/{values['name']}"


def gcp_assigned(m, blocks):
    """assigned() for one rendered root of environment m (see opsdir_format_terraform.state_builder.tf_state)."""
    project, region, default_labels = provider_facts(blocks)
    region = region or one(m.cloud, "ciamRegion") or ""

    def assigned(mode, type_, name, index, configured):
        rid = resource_id(type_, name, index, configured, project, region)
        made = {"id": rid, **({"name": rid} if type_ in FULL_NAME else {})}
        binding = realized(m, REALIZES, type_, name)
        held = {attr: one(binding, held_as) for attr, held_as in RECORDED.get(type_, {}).items()
                if binding is not None and one(binding, held_as)}
        if mode == "data":
            answered = {"number": number("project", project), "project_id": project} \
                if type_ == "google_project" else {}
            return {**synthetic(mode, type_, name, index, configured), **made, **answered, **held}
        ref = one(binding, "ciamProviderRef") if binding is not None else None
        extra = ASSIGNS[type_](configured, project or region) if type_ in ASSIGNS else {}
        labelled = {"effective_labels": {**default_labels, **configured.get("labels", {})}} if default_labels else {}
        given = ({"email": ref} if type_ == "google_service_account" else
                 {"id": ref, **({"name": ref} if type_ in NAMED_BY_REF else {})}) if ref else {}
        return {**made, **extra, **labelled, **held, **given}
    return assigned


def rendered_states(files, d, environment):
    """The ReadBack's prepare: the rendered Terraform roots of an environment ({<cloud>/<env>/...tf: text}) as the
    states applying them would record ({<cloud>/<env>/<root>.tfstate: text}), what Google assigns from record d."""
    m = env_model(d, env_dn(environment))
    return root_states(files, environment, lambda blocks: gcp_assigned(m, blocks))
