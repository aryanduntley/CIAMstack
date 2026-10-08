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

Findings at or above a service's ciamIncidentSeverity also go to the incident process (its ciamIncidentRole) through a
second notification config whose filter adds the Security Command Center severities at or above it (severity="HIGH"
OR severity="CRITICAL"), to the incident role's Pub/Sub topic; an asset feed has no severity (a NOTE).

Read back from Terraform state: SCC notification configs (project or organization, v1 or v2) -> a security service per
finding class their filter streams (no class: threat detection), organization scope for an organization's;
google_project_service containerscanning / osconfig -> vulnerability scanning over containers / compute; asset feeds
(project, folder, organization) -> configuration recording (35 days); each with its topic as where findings go. A
notification config whose filter names severities is the incident route of its class's service (its topic, the least
severity it lets through).
"""
import re

from opsdir.core.directory import get, one, rdn_value, values
from opsdir.core.inventory import of_types, resource
from opsdir.domains.estate.incidents import incident_routes
from opsdir.domains.estate.naming import SEVERITIES
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


def severity_filter(kind, severity):
    """The notification filter streaming a kind's active findings at or above a severity."""
    levels = " OR ".join(f'severity="{x.upper()}"' for x in reversed(SEVERITIES[SEVERITIES.index(severity):]))
    return f'finding_class="{CLASSES[kind]}" AND state="ACTIVE" AND ({levels})'


def _incident_notification(m, s, kind):
    """The notification config sending a service's findings at or above its incident severity to the incident
    process's Pub/Sub topic (its ciamIncidentRole), or a note."""
    route = next((r for r in incident_routes(m) if r.service.dn == s.dn), None)
    if route is None or route.binding is None:
        return ()
    cn = rdn_value(s)
    if kind not in CLASSES:
        return (f"# NOTE: {cn}'s incidents to {route.role}: not rendered: an asset feed's changes have no severity",)
    topic = one(route.binding, "ciamProviderRef")
    if not topic or "/topics/" not in topic:
        return (f"# NOTE: {cn}'s incidents to {route.role}: not rendered: {rdn_value(route.binding)} names no Pub/Sub "
                "topic (ciamProviderRef projects/<p>/topics/<t>)",)
    return (block("resource", [NOTIFICATION, tf_name(f"{cn}_incidents")], [
        ("#", "Security Command Center's service agent must be able to publish to the topic"),
        ("config_id", f"{cn}-incidents"), ("project", PROJECT), ("location", "global"),
        ("description", f"{cn}'s {route.severity} and worse findings to {route.role} (incident process)"),
        ("pubsub_topic", topic), ("streaming_config", Block((("filter", severity_filter(kind, route.severity)),)))]),)


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
    return (*_RENDER[kind](m, s), *_notification(m, s, kind), *_incident_notification(m, s, kind),
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
_SEVERITY = re.compile(r'(?<![a-z_])severity\s*=\s*"?([A-Z_]+)"?')


def _least(filter_):
    """The least severity a notification filter lets through, or None when it names none."""
    known = [x.lower() for x in _SEVERITY.findall(filter_ or "") if x.lower() in SEVERITIES]
    return min(known, key=SEVERITIES.index) if known else None


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
    notified = [(kind, scope, a, _least(_filter(a))) for t, scope in NOTIFICATIONS for a in of_types(pairs, t)
                for kind in _kinds(_filter(a)) if a.get("name") or a.get("id")]
    routes = [(kind, scope, a) for kind, scope, a, least in notified if least is None]
    incidents = [((kind, scope), (a.get("pubsub_topic"), least)) for kind, scope, a, least in notified
                 if least is not None]
    incident = {k: next(v for key, v in incidents if key == k) for k in dict.fromkeys(k for k, _ in incidents)}
    # a kind (and scope) whose findings only go to the incident process is read from that notification config
    only = [(kind, scope, a) for kind, scope, a, least in notified if least is not None
            and not any((k, s) == (kind, scope) for k, s, _ in routes)]
    services = [*routes, *[n for i, n in enumerate(only) if all(o[:2] != n[:2] for o in only[:i])]]
    every = {"ciamAllRegions": "TRUE"}
    scanned = tuple(dict.fromkeys(APIS[a.get("service")] for a in of_types(pairs, "google_project_service")
                                  if a.get("service") in APIS))
    vuln_topic = next((a.get("pubsub_topic") for k, _, a in routes if k == "vulnerability-scanning"), None)

    def incident_of(kind, scope):
        topic, least = incident.get((kind, scope), (None, None))
        return {"ciamIncidentSeverity": least} if least else {}, {"ciamIncidentRole": topic} if topic else {}

    found = [*(resource("security", a.get("name") or a.get("id"), {
                  "ciamSecurityKind": kind, "ciamAuditScope": scope, **every,
                  **({"ciamSecurityCoverage": scanned} if kind == "vulnerability-scanning" else {}),
                  **incident_of(kind, scope)[0]},
                  links={"ciamFindingsRole": a.get("pubsub_topic") if (kind, scope, a) in routes else None,
                         **incident_of(kind, scope)[1]},
                  name=(a.get("config_id") or (a.get("name") or "").rsplit("/", 1)[-1]))
               for kind, scope, a in services),
             *(resource("security", f"scanning:{'+'.join(scanned)}", {
                   "ciamSecurityKind": "vulnerability-scanning", "ciamSecurityCoverage": scanned,
                   "ciamAuditScope": "account", **every}, links={"ciamFindingsRole": vuln_topic},
                   name="vulnerability-scanning")
               for _ in (1,) if scanned and not any(k == "vulnerability-scanning" for k, _, _ in services)),
             *(resource("security", a.get("name") or a.get("id"), {
                   "ciamSecurityKind": "config-recording", "ciamAuditScope": scope,
                   "ciamRetentionDays": NATIVE_DAYS, **every},
                   links={"ciamFindingsRole": _feed_topic(a)}, name=a.get("feed_id"))
               for t, scope in FEEDS for a in of_types(pairs, t) if a.get("feed_id"))]
    return tuple(found)
