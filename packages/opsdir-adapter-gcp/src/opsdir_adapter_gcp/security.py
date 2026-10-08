"""Cloud security services on Google Cloud (core estate: ciamSecurityService) as Security Command Center, Cloud Asset
Inventory and the scanning APIs. Pure.

Security Command Center is activated for an organization (or a project) at a tier, and its services (Event Threat
Detection, Container Threat Detection, VM Threat Detection, Security Health Analytics, Web Security Scanner) are turned
on there, by the organization's administrators: the google provider has no resource for either. Its compliance
frameworks are Compliance Manager deployments, and FedRAMP, IL and ITAR regimes are Assured Workloads folders, both on
the organization. So for each service the platform team keeps (no ciamManagedBy; one someone else keeps is named in a
comment) this renders what a project can hold and names the rest as a request:

  threat-detection        a comment naming the tier and the services its areas need: Event Threat Detection
                          (control-plane, identity, network, storage, databases), Container Threat Detection
                          (containers), VM Threat Detection (compute), Cloud Run Threat Detection (applications); no
                          service watches key vaults on their own
  vulnerability-scanning  google_project_service for Artifact Analysis container scanning (containers) and OS Config
                          (compute: VM Manager's vulnerability reports, once the instances' enable-osconfig metadata
                          is set, a comment), merged across services; applications: Web Security Scanner (a comment)
  config-recording        Cloud Asset Inventory keeps 35 days of resource history itself; a
                          google_cloud_asset_project_feed of every resource's changes to the Pub/Sub topic its
                          ciamFindingsRole names exports it
  posture                 Security Health Analytics (part of the tier, a comment); frameworks and the gcp-default
                          baseline as the request above; other clouds' baselines named in a comment

Findings of threat detection, vulnerability scanning and posture go where ciamFindingsRole says through a
google_scc_v2_project_notification_config streaming the finding class (THREAT, VULNERABILITY, MISCONFIGURATION) to the
Pub/Sub topic its binding names (ciamProviderRef projects/<p>/topics/<t>; Security Command Center's service agent must
be able to publish, a comment); any other binding is a NOTE. Security Command Center covers every region.

Read back from Terraform state: SCC notification configs (project or organization, v1 or v2) -> a security service per
finding class their filter streams (no class: threat detection), organization scope for an organization's;
google_project_service containerscanning / osconfig -> vulnerability scanning over containers / compute; asset feeds
(project, folder, organization) -> configuration recording (35 days); each with its topic as where findings go.
"""
import re

from opsdir.core.directory import get, one, rdn_value, values
from opsdir.core.inventory import of_types, resource
from opsdir.domains.estate.security import findings_destination, security_services
from opsdir_format_terraform.hcl import Block, block, ref, tf_name

NOTIFICATION = "google_scc_v2_project_notification_config"
NOTIFICATIONS = (("google_scc_v2_project_notification_config", "account"), ("google_scc_project_notification_config",
                                                                              "account"),
                 ("google_scc_v2_organization_notification_config", "organization"),
                 ("google_scc_notification_config", "organization"))
FEED = "google_cloud_asset_project_feed"
FEEDS = (("google_cloud_asset_project_feed", "account"), ("google_cloud_asset_folder_feed", "organization"),
         ("google_cloud_asset_organization_feed", "organization"))
PROJECT = ref("var.project_id")
CLASSES = {"threat-detection": "THREAT", "vulnerability-scanning": "VULNERABILITY", "posture": "MISCONFIGURATION"}
DETECTORS = (("Event Threat Detection", ("control-plane", "identity", "network", "storage", "databases")),
             ("Container Threat Detection", ("containers",)), ("VM Threat Detection", ("compute",)),
             ("Cloud Run Threat Detection", ("applications",)))
SCANNING = {"containers": "containerscanning.googleapis.com", "compute": "osconfig.googleapis.com"}
APIS = {v: k for k, v in SCANNING.items()}
BASELINE = "gcp-default"
NATIVE_DAYS = 35                     # Cloud Asset Inventory's own resource history


def _topic(m, s):
    """The Pub/Sub topic (projects/<p>/topics/<t>) a service's findings go to, or None."""
    dest = findings_destination(m, s)
    pref = one(dest, "ciamProviderRef") if dest is not None else None
    return pref if pref and "/topics/" in pref else None


def _no_topic(m, s, what):
    dest = findings_destination(m, s)
    return (f"# NOTE: {rdn_value(s)}'s {what} to {one(s, 'ciamFindingsRole')}: not rendered: {rdn_value(dest)} names "
            "no Pub/Sub topic (ciamProviderRef projects/<p>/topics/<t>)",) if dest is not None else ()


def _notification(m, s, kind):
    cn, topic = rdn_value(s), _topic(m, s)
    if kind not in CLASSES:
        return ()
    if topic is None:
        return _no_topic(m, s, "findings")
    return (block("resource", [NOTIFICATION, tf_name(f"{cn}_findings")], [
        ("#", "Security Command Center's service agent must be able to publish to the topic"),
        ("config_id", f"{cn}-findings"), ("project", PROJECT), ("location", "global"),
        ("description", f"{cn}'s findings to {one(s, 'ciamFindingsRole')}"), ("pubsub_topic", topic),
        ("streaming_config", Block((("filter", f'finding_class="{CLASSES[kind]}" AND state="ACTIVE"'),)))]),)


def _request(cn, what):
    return f"# {cn}: {what}: a request to the organization's administrators (not rendered)"


def _detection(m, s):
    cn, areas = rdn_value(s), values(s, "ciamSecurityCoverage")
    services = [name for name, watched in DETECTORS if set(watched) & set(areas)] or ["Event Threat Detection"]
    return (_request(cn, f"Security Command Center (Premium or Enterprise) activated with {', '.join(services)}"),
            *((f"# {cn}: no Security Command Center service watches key vaults on their own (Event Threat Detection "
               "sees Cloud KMS use in the audit logs)",) if "key-vaults" in areas else ()))


def _scanning(m, s):
    cn, areas = rdn_value(s), values(s, "ciamSecurityCoverage") or ("compute",)
    return (*((f"# {cn}: VM Manager reports vulnerabilities once the instances carry metadata enable-osconfig=TRUE "
               "(not rendered here)",) if "compute" in areas else ()),
            *((_request(cn, "Web Security Scanner (Security Command Center) for applications"),)
              if "applications" in areas else ()))


def _recording(m, s):
    cn, topic = rdn_value(s), _topic(m, s)
    native = f"# {cn}: Cloud Asset Inventory keeps {NATIVE_DAYS} days of resource history itself"
    if topic is None:
        return (native, *_no_topic(m, s, "configuration changes"))
    return (native, block("resource", [FEED, tf_name(cn)], [
        ("project", PROJECT), ("feed_id", cn), ("content_type", "RESOURCE"), ("asset_types", [".*"]),
        ("feed_output_config", Block((("pubsub_destination", Block((("topic", topic),))),)))]))


def _posture(m, s):
    cn = rdn_value(s)
    frameworks = values(s, "ciamComplianceStandard")
    others = [b for b in values(s, "ciamSecurityBaseline") if b != BASELINE]
    return (_request(cn, "Security Command Center (Premium or Enterprise) activated with Security Health Analytics"),
            *((_request(cn, f"{', '.join(frameworks)} assessed by Compliance Manager framework deployments (FedRAMP, "
                            "IL and ITAR regimes held by an Assured Workloads folder)"),) if frameworks else ()),
            *((f"# {cn}: {', '.join(others)}: another cloud's baseline, not Google Cloud's (not rendered)",)
              if others else ()))


_RENDER = {"threat-detection": _detection, "vulnerability-scanning": _scanning, "config-recording": _recording,
           "posture": _posture}


def _service(m, s):
    cn, kind, keeper = rdn_value(s), one(s, "ciamSecurityKind"), one(s, "ciamManagedBy")
    if keeper:
        holder = get(m.d, keeper)
        return (f"# Security service {cn} ({kind}): kept by {rdn_value(holder) if holder is not None else keeper}, "
                "not rendered here",)
    return (*_RENDER[kind](m, s), *_notification(m, s, kind),
            *((_request(cn, "organization-wide (Security Command Center and its notification at the organization)"),)
              if one(s, "ciamAuditScope") == "organization" else ()))


def _apis(m):
    """The scanning APIs the kept vulnerability-scanning services need, once each."""
    kept = [s for s in security_services(m, "vulnerability-scanning") if not one(s, "ciamManagedBy")]
    return tuple(dict.fromkeys(SCANNING[a] for s in kept for a in (values(s, "ciamSecurityCoverage") or ("compute",))
                               if a in SCANNING))


def render_security(m):
    """HCL (and comments) for environment m's security services: the scanning APIs once, then each service."""
    return (*(block("resource", ["google_project_service", tf_name(api.split(".")[0])], [
                ("project", PROJECT), ("service", api), ("disable_on_destroy", False)]) for api in _apis(m)),
            *(x for s in security_services(m) for x in _service(m, s)))


# ------------------------------------------------------------------ read back
_CLASS = re.compile(r'finding_class\s*=\s*"?([A-Z_]+)"?')


def _kinds(filter_):
    """The kinds of service a notification filter streams the findings of (no class named: threat detection)."""
    named = set(_CLASS.findall(filter_ or ""))
    return tuple(k for k, c in CLASSES.items() if c in named) if named else ("threat-detection",)


def _filter(a):
    cfg = a.get("streaming_config")
    cfg = cfg[0] if isinstance(cfg, list) and cfg else cfg if isinstance(cfg, dict) else {}
    return cfg.get("filter")


def _feed_topic(a):
    out = a.get("feed_output_config")
    out = out[0] if isinstance(out, list) and out else out if isinstance(out, dict) else {}
    dest = out.get("pubsub_destination")
    dest = dest[0] if isinstance(dest, list) and dest else dest if isinstance(dest, dict) else {}
    return dest.get("topic")


def security_resources(pairs):
    """Security services of (google type, attributes) pairs."""
    notified = [(kind, scope, a) for t, scope in NOTIFICATIONS for a in of_types(pairs, t)
                for kind in _kinds(_filter(a)) if a.get("name") or a.get("id")]
    every = {"ciamAllRegions": "TRUE"}
    scanned = tuple(dict.fromkeys(APIS[a.get("service")] for a in of_types(pairs, "google_project_service")
                                  if a.get("service") in APIS))
    vuln_topic = next((a.get("pubsub_topic") for k, _, a in notified if k == "vulnerability-scanning"), None)
    found = [*(resource("security", a.get("name") or a.get("id"), {
                  "ciamSecurityKind": kind, "ciamAuditScope": scope, **every,
                  **({"ciamSecurityCoverage": scanned} if kind == "vulnerability-scanning" else {})},
                  links={"ciamFindingsRole": a.get("pubsub_topic")},
                  name=(a.get("config_id") or (a.get("name") or "").rsplit("/", 1)[-1]))
               for kind, scope, a in notified),
             *(resource("security", f"scanning:{'+'.join(scanned)}", {
                   "ciamSecurityKind": "vulnerability-scanning", "ciamSecurityCoverage": scanned,
                   "ciamAuditScope": "account", **every}, links={"ciamFindingsRole": vuln_topic},
                   name="vulnerability-scanning")
               for _ in (1,) if scanned and not any(k == "vulnerability-scanning" for k, _, _ in notified)),
             *(resource("security", a.get("name") or a.get("id"), {
                   "ciamSecurityKind": "config-recording", "ciamAuditScope": scope,
                   "ciamRetentionDays": NATIVE_DAYS, **every},
                   links={"ciamFindingsRole": _feed_topic(a)}, name=a.get("feed_id"))
               for t, scope in FEEDS for a in of_types(pairs, t) if a.get("feed_id"))]
    return tuple(found)
