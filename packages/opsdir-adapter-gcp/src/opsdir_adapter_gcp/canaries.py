"""Synthetic checks on Google Cloud (core observability: domains/observability/canaries) as Cloud Monitoring uptime
checks. Pure.

Each canary the environment can run whose request the record describes (canary_specs), for the flows one GET answers
(canaries.GET_FLOWS: health, login-page, saml-sso), as a google_monitoring_uptime_check_config named as its canary
binding: an HTTPS GET of its URL's path (and query) on its port (any 2xx answer passes), every 1, 5, 10 or 15 minutes
(its interval, raised to the next), with user labels realizes and bindingrole so the inventory reads it back.
- An internet-facing service name: on the monitored resource uptime_url of its host in the root's project, the TLS
  certificate validated.
- An internal one: a private uptime check (checker_type VPC_CHECKERS) of a Service Directory service (one namespace for
  the environment's checks, ciam-<env>-checks in the root's region; a service per check, its endpoint the service
  name's frontend address on its port in the network, named by its project's number), its Host header the service
  name's host. Google's private checkers don't validate certificates, whatever the check says (research 2848): said
  in a comment. The Monitoring service agent (service-<number>@gcp-sa-monitoring-notification) may view the project's
  Service Directory and reach the network through it (roles/servicedirectory.viewer, .pscAuthorizedService on the
  network's project), and a firewall rule admits the private checkers (35.199.192.0/19) to the service's servers on
  its port (a network firewall policy rule under the policy model); importers leave it out. Outside the regions where
  Google reports a regional internal load balancer's checks, its load balancer needs global access: said in a comment.

Not rendered, and said so: what canary_specs names; a service name whose exposure isn't recorded, or an internal one
without a frontend address; any uptime check where the environment is an Assured Workloads workload (a compliance
regime: Google supports neither uptime checks nor synthetic monitors there, and their requests may come from any
uptime region). The checks no GET makes (oidc-token, ldap-bind) are synthetic monitors (synthetic_monitors). A check
someone else keeps, or an overlay inherits from its base, is named with its keeper.
"""
import re
from urllib.parse import urlsplit

from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import one_role
from opsdir.domains.network.stack import firewall_model
from opsdir.domains.observability.canaries import GET_FLOWS, canary_specs
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from .account import regime
from .firewall_policy import health_check_rule
from .health_checks import PRIVATE_CHECKERS
from .names import NETWORK, label, network_tag

CHECK = "google_monitoring_uptime_check_config"
NAMESPACE = "google_service_directory_namespace.checks"
PERIODS = (60, 300, 600, 900)
AGENT = ("serviceAccount:service-${data.google_project.checks.number}"
         "@gcp-sa-monitoring-notification.iam.gserviceaccount.com")
NETWORK_PATH = ("projects/${data.google_project.checks_network.number}/locations/global/networks/"
                "${data.google_compute_network.main.name}")
# the regions where Google reports a regional internal load balancer's private checks without global access
REPORTED = ("us-east4", "us-central1", "us-west1", "europe-west1", "southamerica-east1", "asia-southeast1")


def check_name(name):
    """A name Google Cloud takes for a Service Directory service or a function: lowercase letters, digits and -,
    starting with a letter, at most 63."""
    safe = re.sub(r"-+", "-", re.sub(r"[^a-z0-9-]", "-", name.lower())).strip("-")
    return (safe if safe[:1].isalpha() else f"c-{safe}")[:63].rstrip("-")


def period(every):
    """An uptime check's period for an interval in seconds: the next Google offers, at most 15 minutes."""
    return f"{next((p for p in PERIODS if p >= every), PERIODS[-1])}s"


def assured(m):
    """Why environment m renders no uptime check or synthetic monitor (an Assured Workloads workload), else None."""
    r = regime(m)
    return (f"the environment is an Assured Workloads workload ({r}), where Google supports neither uptime checks nor "
            "synthetic monitors (their requests may come from any uptime region)") if r else None


def labels(spec):
    """The user labels the inventory reads a check back by: the canary it realizes, its binding's role."""
    cn = rdn_value(spec.canary)
    return {"realizes": label(cn),
            "bindingrole": label(one(spec.binding, "ciamBindingRole") if spec.binding is not None else f"canary-{cn}")}


def standard(spec):
    """Whether an uptime check makes a check: a flow one GET answers (public or private)."""
    return spec.flow in GET_FLOWS


def _why(m, spec):
    svc = one_role(m, one(spec.canary, "ciamCheckedService"))
    if spec.why:
        return spec.why
    if assured(m):
        return assured(m)
    if spec.exposure is None:
        return (f"service name {rdn_value(svc)} records neither a frontend address nor its exposure: whether its "
                "check is public or private is unknown")
    if spec.exposure == "internal" and not one(svc, "ciamFrontendIp"):
        return (f"service name {rdn_value(svc)} is internal and records no frontend address (ciamFrontendIp) for its "
                "private uptime check's Service Directory endpoint")
    return None


def _target(url):
    return url.path + (f"?{url.query}" if url.query else "")


def _public(spec, url):
    return (("http_check", Block((("path", _target(url)), ("port", url.port or 443), ("use_ssl", True),
                                  ("validate_ssl", True), ("request_method", "GET")))),
            ("monitored_resource", Block((("type", "uptime_url"),
                                          ("labels", {"host": url.hostname, "project_id": ref("var.project_id")})))))


def _private(m, spec, url, n):
    svc = one_role(m, one(spec.canary, "ciamCheckedService"))
    return (
        tf_block("resource", ["google_service_directory_service", n], [
            ("service_id", check_name(spec.name)), ("namespace", ref(f"{NAMESPACE}.id"))]),
        tf_block("resource", ["google_service_directory_endpoint", n], [
            ("endpoint_id", "frontend"), ("service", ref(f"google_service_directory_service.{n}.id")),
            ("address", one(svc, "ciamFrontendIp")), ("port", url.port or 443), ("network", NETWORK_PATH)]),
        comment(f"{spec.name}: Google's private uptime checkers don't validate TLS certificates, whatever validate_ssl "
                "says: this check proves the service answers, not its certificate"),
        *((comment(f"{spec.name}: outside {', '.join(REPORTED)}, a regional internal load balancer's private checks "
                   f"are reported only with global access on: turn it on for {rdn_value(svc)}'s load balancer"),)
          if one(m.cloud, "ciamRegion") not in REPORTED else ())), (
        ("checker_type", "VPC_CHECKERS"),
        ("http_check", Block((("path", _target(url)), ("port", url.port or 443), ("use_ssl", True),
                              ("validate_ssl", False), ("request_method", "GET"),
                              ("headers", {"Host": url.netloc}), ("mask_headers", False)))),
        ("monitored_resource", Block((("type", "servicedirectory_service"), ("labels", {
            "project_id": ref("var.project_id"), "location": ref("var.region"),
            "namespace_name": ref(f"{NAMESPACE}.namespace_id"),
            "service_name": ref(f"google_service_directory_service.{n}.service_id")})))))


def _check(m, spec, why):
    cn = rdn_value(spec.canary)
    if why:
        return (comment(f"NOTE: canary {cn}: not rendered: {why}"),)
    if spec.keeper is not None:
        return (comment(f"Uptime check {spec.name} ({cn}): kept by {spec.keeper}, not rendered here"),)
    url, n = urlsplit(spec.url), tf_name(spec.name)
    before, body = _private(m, spec, url, n) if spec.exposure == "internal" else ((), _public(spec, url))
    return (*before, tf_block("resource", [CHECK, n], [
        ("display_name", spec.name), ("timeout", "10s"), ("period", period(spec.every)), *body,
        ("user_labels", labels(spec))]))


def _admit(m, svc, port):
    """The firewall rule admitting the private uptime checkers to a service name's servers on its port."""
    n, role = tf_name(rdn_value(svc)), one(svc, "ciamTargetRole")
    if firewall_model(m) == "policy":
        return health_check_rule(m, svc, n, PRIVATE_CHECKERS, port, "uptime_checkers")
    return tf_block("resource", ["google_compute_firewall", f"{n}_uptime_checkers"], [
        ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(svc)}-uptime-checkers"),
        ("description", f"Private uptime checkers for {rdn_value(svc)}"),
        ("network", NETWORK), ("direction", "INGRESS"), ("allow", Block((("protocol", "tcp"), ("ports", [port])))),
        ("source_ranges", list(PRIVATE_CHECKERS)), ("target_tags", [network_tag(m, role)])])


def _shared(m, private):
    """What the private checks share: the namespace, the projects' numbers, the agent's grants, the firewall rules."""
    services = {one_role(m, one(s.canary, "ciamCheckedService")).dn: s for s in private}
    return (tf_block("data", ["google_project", "checks"], [("project_id", ref("var.project_id"))]),
            tf_block("data", ["google_project", "checks_network"], [
                ("project_id", ref("data.google_compute_network.main.project"))]),
            tf_block("resource", ["google_service_directory_namespace", "checks"], [
                ("namespace_id", f"ciam-{rdn_value(m.env)}-checks"), ("location", ref("var.region")),
                ("labels", {"managed_by": "opsdir"})]),
            tf_block("resource", ["google_project_iam_member", "uptime_checkers_viewer"], [
                ("project", ref("var.project_id")), ("role", "roles/servicedirectory.viewer"), ("member", AGENT)]),
            tf_block("resource", ["google_project_iam_member", "uptime_checkers_network"], [
                ("project", ref("data.google_compute_network.main.project")),
                ("role", "roles/servicedirectory.pscAuthorizedService"), ("member", AGENT)]),
            *(_admit(m, one_role(m, one(s.canary, "ciamCheckedService")), str(urlsplit(s.url).port or 443))
              for s in services.values()))


def render_checks(m, endpoints):
    """HCL (and comments) for environment m's uptime checks of the flows one GET answers (the NOTEs of what
    canary_specs doesn't render; the other checks are synthetic_monitors'), and what the private ones share."""
    specs = tuple(s for s in canary_specs(m, endpoints) if s.why or standard(s))
    done = tuple((s, _why(m, s)) for s in specs)
    private = tuple(s for s, why in done if why is None and s.keeper is None and s.exposure == "internal")
    return (*(x for s, why in done for x in (from_entry(s.binding.dn, _check(m, s, why)) if s.binding is not None
                                              else _check(m, s, why))),
            *(_shared(m, private) if private else ()))
