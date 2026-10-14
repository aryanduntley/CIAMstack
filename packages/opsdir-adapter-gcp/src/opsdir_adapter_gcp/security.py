"""Cloud security services on Google Cloud (core estate: ciamSecurityService) as Security Command Center, Cloud Asset
Inventory, the scanning APIs and Compliance Manager. Pure.

Security Command Center is activated for an organization (or a project) at a tier, and its services (Event Threat
Detection, Container Threat Detection, VM Threat Detection, Security Health Analytics, Web Security Scanner) are turned
on there, by the organization's administrators: the google provider has no resource for either. Its compliance
frameworks are Compliance Manager framework deployments (compliance.py), and FedRAMP and IL regimes Assured Workloads
folders. So for each service the platform team keeps (no ciamManagedBy; one someone else keeps is named in a comment)
this renders what a project can hold and names the rest as a request:

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
  posture                 Security Health Analytics (part of the tier, a request); each framework and the gcp-default
                          baseline (Security Essentials) a google_cloud_security_compliance_framework_deployment from
                          the framework catalog (compliance.py: on the project, or organization-wide on the
                          organization, kept with the landing zone), else a request saying why; frameworks Google
                          doesn't offer and other clouds' baselines named in a comment

Findings of threat detection, vulnerability scanning and posture go where ciamFindingsRole says through a
google_scc_v2_project_notification_config streaming the finding class (THREAT, VULNERABILITY, MISCONFIGURATION) to the
Pub/Sub topic its binding names (ciamProviderRef projects/<p>/topics/<t>; Security Command Center's service agent must
be able to publish, a comment); any other binding is a blocker. Security Command Center covers every region.

Findings at or above a service's ciamIncidentSeverity also go to the incident process (its ciamIncidentRole) through a
second notification config whose filter adds the Security Command Center severities at or above it (severity="HIGH"
OR severity="CRITICAL"), to the incident role's Pub/Sub topic; an asset feed has no severity (an action). Each is a
render note (security_notes, flow 43), written as its comment.

Read back from Terraform state (and from gcloud and Cloud Asset Inventory, normalized to the same names:
cli_security.py): SCC notification configs (project or organization, v1 or v2) -> a security service per
finding class their filter streams (no class: threat detection), organization scope for an organization's;
google_project_service containerscanning / osconfig -> vulnerability scanning over containers / compute; asset feeds
(project, folder, organization) -> configuration recording (35 days); each with its topic as where findings go;
framework deployments -> the frameworks and baseline a posture service assesses (compliance.deployment_keys), folded
into the posture service the notification configs give (else one of their own, organization-wide when one targets
the organization). A
notification config whose filter names severities is the incident route of its class's service (its topic, the least
severity it lets through).
"""
import re

from opsdir.core.directory import get, one, rdn_value, values
from opsdir.core.inventory import of_types, resource
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.estate.incidents import incident_routes
from opsdir.domains.estate.naming import SEVERITIES
from opsdir.domains.estate.security import findings_destination, security_services
from opsdir.domains.governance.keepers import organization_line, organization_wide
from opsdir_format_terraform.hcl import Block, TfBlock, comment, from_entry, mentions, ref, tf_block, tf_name
from .account import ORGANIZATION, organization_variable
from .compliance import BASELINE, deployment, deployment_keys, deployment_note, request_note

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
NATIVE_DAYS = 35                     # Cloud Asset Inventory's own resource history


def _topic(m, s):
    """The Pub/Sub topic (projects/<p>/topics/<t>) a service's findings go to, or None."""
    dest = findings_destination(m, s)
    pref = one(dest, "ciamProviderRef") if dest is not None else None
    return pref if pref and "/topics/" in pref else None


TOPIC_HOW = "Pub/Sub topic (ciamProviderRef projects/<p>/topics/<t>)"


def topic_note(m, s, what):
    """The render note of a service's findings or configuration changes (what) whose ciamFindingsRole binding names
    no Pub/Sub topic (a blocker: they go nowhere), or None (a topic, or no binding)."""
    dest = findings_destination(m, s)
    if dest is None or _topic(m, s) is not None:
        return None
    return note("Security", "blocker", f"{rdn_value(s)}'s {what} to {one(s, 'ciamFindingsRole')}",
                f"not rendered: {rdn_value(dest)} names no Pub/Sub topic (ciamProviderRef projects/<p>/topics/<t>)",
                (f"Record {rdn_value(dest)}'s {TOPIC_HOW}, {RECORD}",), s.dn, m.label)


def _no_topic(m, s, what):
    found = topic_note(m, s, what)
    return (comment(note_comment(found)),) if found is not None else ()


def _notification(m, s, kind):
    cn, topic = rdn_value(s), _topic(m, s)
    if kind not in CLASSES:
        return ()
    if topic is None:
        return _no_topic(m, s, "findings")
    return (tf_block("resource", [NOTIFICATION, tf_name(f"{cn}_findings")], [
        ("#", note_comment(publish_note(m, s, "findings", one(s, "ciamFindingsRole"), topic))),
        ("config_id", f"{cn}-findings"), ("project", PROJECT), ("location", "global"),
        ("description", f"{cn}'s findings to {one(s, 'ciamFindingsRole')}"), ("pubsub_topic", topic),
        ("streaming_config", Block((("filter", f'finding_class="{CLASSES[kind]}" AND state="ACTIVE"'),)))]),)


def severity_filter(kind, severity):
    """The notification filter streaming a kind's active findings at or above a severity."""
    levels = " OR ".join(f'severity="{x.upper()}"' for x in reversed(SEVERITIES[SEVERITIES.index(severity):]))
    return f'finding_class="{CLASSES[kind]}" AND state="ACTIVE" AND ({levels})'


def _route(m, s):
    return next((r for r in incident_routes(m) if r.service.dn == s.dn), None)


def incident_note(m, s, kind):
    """The render note of a service's incident route this render doesn't make, or None: an asset feed's changes have
    no severity (an action: route them another way), or the route's binding names no Pub/Sub topic (a blocker)."""
    route = _route(m, s)
    if route is None or route.binding is None:
        return None
    subject = f"{rdn_value(s)}'s incidents to {route.role}"
    if kind not in CLASSES:
        return note("Security", "action", subject, "not rendered: an asset feed's changes have no severity",
                    (f"Pick the changes that are incidents another way (a subscription on the feed's topic filtering "
                     f"them) and send them to {route.role}",
                     f"Or remove the service's ciamIncidentRole, {RECORD}"), s.dn, m.label)
    topic = one(route.binding, "ciamProviderRef")
    if topic and "/topics/" in topic:
        return None
    return note("Security", "blocker", subject, f"not rendered: {rdn_value(route.binding)} names no Pub/Sub topic "
                "(ciamProviderRef projects/<p>/topics/<t>)", (f"Record {rdn_value(route.binding)}'s {TOPIC_HOW}, "
                                                              f"{RECORD}",), s.dn, m.label)


def security_notes(m):
    """The render notes of environment m's security services (render_security writes their comments): each one's
    findings (or, recording configuration, its changes') and incident routes'."""
    def of(s):
        kind, route = one(s, "ciamSecurityKind"), _route(m, s)
        what = "configuration changes" if kind == "config-recording" else "findings" if kind in CLASSES else None
        published = (*((publish_note(m, s, "findings", one(s, "ciamFindingsRole"), _topic(m, s)),)
                       if kind in CLASSES and _topic(m, s) else ()),
                     *((publish_note(m, s, "incidents", route.role, one(route.binding, "ciamProviderRef")),)
                       if route is not None and route.binding is not None and incident_note(m, s, kind) is None
                       else ()))
        return (*request_notes(m, s), topic_note(m, s, what) if what else None, incident_note(m, s, kind),
                *published)
    return tuple(n for s in security_services(m) for n in of(s) if n is not None)


def _incident_notification(m, s, kind):
    """The notification config sending a service's findings at or above its incident severity to the incident
    process's Pub/Sub topic (its ciamIncidentRole), or its note's comment (incident_note)."""
    route = _route(m, s)
    if route is None or route.binding is None:
        return ()
    cn, found = rdn_value(s), incident_note(m, s, kind)
    if found is not None:
        return (comment(note_comment(found)),)
    topic = one(route.binding, "ciamProviderRef")
    return (tf_block("resource", [NOTIFICATION, tf_name(f"{cn}_incidents")], [
        ("#", note_comment(publish_note(m, s, "incidents", route.role, topic))),
        ("config_id", f"{cn}-incidents"), ("project", PROJECT), ("location", "global"),
        ("description", f"{cn}'s {route.severity} and worse findings to {route.role} (incident process)"),
        ("pubsub_topic", topic), ("streaming_config", Block((("filter", severity_filter(kind, route.severity)),)))]),)


def _request(m, s, what):
    return comment(note_comment(request_note(m, s, what)))


def publish_note(m, s, what, role, topic):
    """The render note (an action) of a rendered notification config sending a service's findings or incidents (what)
    to topic: Security Command Center's service agent must be able to publish to it."""
    return note("Security", "action", f"{rdn_value(s)}'s {what} to {role}", "Security Command Center's service agent "
                "must be able to publish to the topic",
                (f"Grant Security Command Center's notification service agent roles/pubsub.publisher on {topic} (its "
                 "owner)",), s.dn, m.label)


# Security Command Center's activation has no Terraform resource, and enabling its services has only google-beta's
# (google_scc_management_*_security_center_service): the build stays GA-only (decision 2789)
BETA_ONLY = "activation has no Terraform resource and enabling its services only a google-beta one"


def _activation(s):
    """What a threat-detection service asks the organization's administrators to activate."""
    areas = values(s, "ciamSecurityCoverage")
    services = [name for name, watched in DETECTORS if set(watched) & set(areas)] or ["Event Threat Detection"]
    return f"Security Command Center (Premium or Enterprise) activated with {', '.join(services)} ({BETA_ONLY})"


POSTURE = f"Security Command Center (Premium or Enterprise) activated with Security Health Analytics ({BETA_ONLY})"
SCANNER = "Web Security Scanner (Security Command Center) for applications"
WIDE = "organization-wide (Security Command Center and its notification at the organization)"


def _detection(m, s):
    cn, areas = rdn_value(s), values(s, "ciamSecurityCoverage")
    return (_request(m, s, _activation(s)),
            *((comment(f"{cn}: no Security Command Center service watches key vaults on their own (Event Threat "
                       "Detection sees Cloud KMS use in the audit logs)"),) if "key-vaults" in areas else ()))


def _scanning(m, s):
    cn, areas = rdn_value(s), values(s, "ciamSecurityCoverage") or ("compute",)
    return (*((tf_block("resource", ["google_compute_project_metadata_item", tf_name(f"{cn}_osconfig")], [
                  ("#", "VM Manager reports the instances' vulnerabilities once they run the OS Config agent"),
                  ("project", PROJECT), ("key", "enable-osconfig"), ("value", "TRUE")]),)
              if "compute" in areas else ()),
            *((_request(m, s, SCANNER),) if "applications" in areas else ()))


def _recording(m, s):
    cn, topic = rdn_value(s), _topic(m, s)
    native = comment(f"{cn}: Cloud Asset Inventory keeps {NATIVE_DAYS} days of resource history itself")
    if topic is None:
        return (native, *_no_topic(m, s, "configuration changes"))
    return (native, tf_block("resource", [FEED, tf_name(cn)], [
        ("project", PROJECT), ("feed_id", cn), ("content_type", "RESOURCE"), ("asset_types", [".*"]),
        ("feed_output_config", Block((("pubsub_destination", Block((("topic", topic),))),)))]))


def _posture(m, s):
    baselines = values(s, "ciamSecurityBaseline")
    others = [b for b in baselines if b != BASELINE]
    deployed = tuple(x for k in _posture_keys(s) for x in deployment(m, s, k))
    return (_request(m, s, POSTURE),
            *deployed,
            *((comment(organization_line(m, s)),)
              if organization_wide(s) and any(isinstance(x, TfBlock) for x in deployed) else ()),
            *((comment(note_comment(baseline_note(m, s))),) if others else ()))


def _posture_keys(s):
    baselines = values(s, "ciamSecurityBaseline")
    return (*values(s, "ciamComplianceStandard"), *((BASELINE,) if BASELINE in baselines else ()))


def baseline_note(m, s):
    """The render note (a plain note) of a posture service's baselines that are other clouds', not Google Cloud's, or
    None."""
    others = [b for b in values(s, "ciamSecurityBaseline") if b != BASELINE]
    return note("Security", "note", rdn_value(s), f"{', '.join(others)}: another cloud's baseline, not Google "
                "Cloud's (not rendered)", (), s.dn, m.label) if others else None


def request_notes(m, s):
    """The render notes of service s that only the organization's administrators can turn on (each a request_note,
    in the order _service writes them), the posture frameworks' deployment notes and its other clouds' baselines."""
    kind = one(s, "ciamSecurityKind")
    areas = values(s, "ciamSecurityCoverage") or ("compute",)
    own = ((request_note(m, s, _activation(s)),) if kind == "threat-detection" else
           (request_note(m, s, SCANNER),) if kind == "vulnerability-scanning" and "applications" in areas else
           (request_note(m, s, POSTURE), *(deployment_note(m, s, k) for k in _posture_keys(s)), baseline_note(m, s))
           if kind == "posture" else ())
    return (*own, *((request_note(m, s, WIDE),) if one(s, "ciamAuditScope") == "organization" else ()))


_RENDER = {"threat-detection": _detection, "vulnerability-scanning": _scanning, "config-recording": _recording,
           "posture": _posture}


def _service(m, s):
    kind = one(s, "ciamSecurityKind")
    return (*_RENDER[kind](m, s), *_notification(m, s, kind), *_incident_notification(m, s, kind),
            *((_request(m, s, WIDE),) if one(s, "ciamAuditScope") == "organization" else ()))


def _apis(m):
    """((API, origin), ...): the scanning APIs the vulnerability-scanning services need, once each, with the entry of
    the first service needing it (the API is placed with that entry's keeper)."""
    found = ((SCANNING[a], s.dn) for s in security_services(m, "vulnerability-scanning")
             for a in (values(s, "ciamSecurityCoverage") or ("compute",)) if a in SCANNING)
    return tuple({api: origin for api, origin in reversed(tuple(found))}.items())[::-1]


def render_security(m):
    """HCL (and comments) for environment m's security services (whoever keeps each): the scanning APIs once, then
    each service, stamped with its entry (an API with the first service needing it; an organization-wide framework
    deployment with its organization origin) so the render places it by keeper; the organization input once, when a
    deployment is made in the organization."""
    out = (*(x for api, origin in _apis(m) for x in from_entry(origin, (
               tf_block("resource", ["google_project_service", tf_name(api.split(".")[0])], [
                   ("project", PROJECT), ("service", api), ("disable_on_destroy", False)]),))),
           *(x for s in security_services(m) for x in from_entry(s.dn, _service(m, s))))
    return ((organization_variable(m, "The organization the compliance frameworks are deployed in"),)
            if mentions(out, f"var.{ORGANIZATION}") else ()) + out


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
    return _assessed(tuple(found), deployment_keys(pairs), every)


def _assessed(found, keys, every):
    """The security services with the frameworks and baseline the framework deployments assess folded into the first
    posture service (else one of their own)."""
    if not keys:
        return found
    attrs = {"ciamComplianceStandard": tuple(dict.fromkeys(k for k, _ in keys if k != BASELINE)),
             "ciamSecurityBaseline": tuple(dict.fromkeys(k for k, _ in keys if k == BASELINE))}
    first = next((i for i, r in enumerate(found) if r.attrs.get("ciamSecurityKind") == ("posture",)), None)
    if first is None:
        return (*found, resource("security", "compliance-manager", {
            "ciamSecurityKind": "posture", "ciamAuditScope": "organization" if any(w for _, w in keys) else "account",
            **every, **attrs}, name="posture"))
    r = found[first]
    return (*found[:first], r._replace(attrs={**r.attrs, **{k: v for k, v in attrs.items() if v}}), *found[first + 1:])
