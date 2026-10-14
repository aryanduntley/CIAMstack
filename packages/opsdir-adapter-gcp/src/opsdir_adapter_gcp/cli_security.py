"""What gcloud (and Cloud Asset Inventory) report about Security Command Center, the scanning APIs and asset feeds,
normalized to the hashicorp/google attribute names opsdir_adapter_gcp.security reads. Items are recognized by their
resource names. Pure.

  gcloud scc notifications list --project=P|--organization=O [--location=global]
        projects|organizations/<id>/[locations/<l>/]notificationConfigs/<id>
        -> google_scc_[v2_]project|organization_notification_config (a folder's isn't read: no state type reads one)
  gcloud services list --enabled --project=P (or the assets serviceusage.googleapis.com/Service)
        projects/<p>/services/<api> -> google_project_service (enabled ones)
  gcloud asset feeds list --project=P|--folder=F|--organization=O
        projects|folders|organizations/<id>/feeds/<id> -> google_cloud_asset_project|folder|organization_feed
  gcloud compliance-manager framework-deployments list --organization=O --location=global
        organizations/<o>/locations/<l>/frameworkDeployments/<id>
        -> google_cloud_security_compliance_framework_deployment (description, framework, target)
"""
import re

NOTIFICATION = re.compile(r"^(projects|organizations)/[^/]+/(locations/[^/]+/)?notificationConfigs/[^/]+$")
SERVICE = re.compile(r"^projects/([^/]+)/services/([^/]+)$")
FEED = re.compile(r"^(projects|folders|organizations)/[^/]+/feeds/[^/]+$")
DEPLOYMENT = re.compile(r"^organizations/[^/]+/locations/[^/]+/frameworkDeployments/[^/]+$")
NOTIFICATION_TYPES = {("projects", True): "google_scc_v2_project_notification_config",
                      ("projects", False): "google_scc_project_notification_config",
                      ("organizations", True): "google_scc_v2_organization_notification_config",
                      ("organizations", False): "google_scc_notification_config"}
FEED_TYPES = {"projects": "google_cloud_asset_project_feed", "folders": "google_cloud_asset_folder_feed",
              "organizations": "google_cloud_asset_organization_feed"}


def security_shape(item):
    """What a security item is by its resource name, else None."""
    name = item.get("name") or ""
    return ("notification-config" if NOTIFICATION.match(name) else "service" if SERVICE.match(name)
            else "feed" if FEED.match(name) else "framework-deployment" if DEPLOYMENT.match(name) else None)


def _last(name):
    return (name or "").rsplit("/", 1)[-1] or None


def _notification(d):
    found = NOTIFICATION.match(d.get("name") or "")
    return (NOTIFICATION_TYPES[(found.group(1), bool(found.group(2)))], {
        "name": d.get("name"), "config_id": _last(d.get("name")), "description": d.get("description"),
        "pubsub_topic": d.get("pubsubTopic"),
        "streaming_config": [{"filter": (d.get("streamingConfig") or {}).get("filter")}]})


def _service(d):
    found = SERVICE.match(d.get("name") or "")
    api = (d.get("config") or {}).get("name") or found.group(2)
    return ("google_project_service", {"project": found.group(1), "service": api})


def _feed(d):
    return (FEED_TYPES[(d.get("name") or "").split("/", 1)[0]], {
        "name": d.get("name"), "feed_id": _last(d.get("name")), "content_type": d.get("contentType"),
        "asset_types": d.get("assetTypes") or [],
        "feed_output_config": [{"pubsub_destination": [{"topic": ((d.get("feedOutputConfig") or {})
                                                                  .get("pubsubDestination") or {}).get("topic")}]}]})


def _deployment(d):
    fw = d.get("framework") or {}
    target = d.get("targetResourceConfig") or {}
    return ("google_cloud_security_compliance_framework_deployment", {
        "name": d.get("name"), "framework_deployment_id": _last(d.get("name")), "description": d.get("description"),
        "framework": [{"framework": fw.get("framework"), "major_revision_id": fw.get("majorRevisionId")}],
        "target_resource_config": [{"existing_target_resource": target.get("existingTargetResource")}],
        "computed_target_resource": d.get("computedTargetResource")})


def security_pairs(of):
    """The (google type, attributes) pairs of the notification configs, enabled services, asset feeds and framework
    deployments."""
    return [*(_notification(d) for d, _ in of("notification-config")),
            *(_service(d) for d, _ in of("service") if SERVICE.match(d.get("name") or "")
              and (d.get("state") or "ENABLED") == "ENABLED"),
            *(_feed(d) for d, _ in of("feed")),
            *(_deployment(d) for d, _ in of("framework-deployment"))]
