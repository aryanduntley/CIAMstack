"""Synthetic checks on Google Cloud (core observability: domains/observability/canaries) as Cloud Monitoring uptime
checks. Pure.

Each canary the environment can run whose request the record describes (canary_specs), for the flows one GET answers
(health, login-page), as a google_monitoring_uptime_check_config named as its canary binding: an HTTPS GET of its URL's
path on its port (the TLS certificate validated; any 2xx answer passes), on the monitored resource uptime_url of its
host in the root's project, every 1, 5, 10 or 15 minutes (its interval, raised to the next), with user labels realizes
and bindingrole so the inventory reads it back.

Not rendered, and said so: what canary_specs names; an oidc-token check (an uptime check could only hold the client's
secret in its configuration); a service name that isn't internet-facing (public uptime checks reach only public
endpoints). A check someone else keeps, or an overlay inherits from its base, is named with its keeper.
"""
from urllib.parse import urlsplit

from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import one_role
from opsdir.domains.edge.exposure import service_exposure
from opsdir.domains.observability.canaries import canary_specs
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .names import label

CHECK = "google_monitoring_uptime_check_config"
PERIODS = (60, 300, 600, 900)
GET_FLOWS = ("health", "login-page")


def _why(m, spec):
    if spec.why:
        return spec.why
    if spec.flow not in GET_FLOWS:
        return "an uptime check could only hold an oidc-token check's client secret in its configuration"
    svc = one_role(m, one(spec.canary, "ciamCheckedService"))
    if service_exposure(svc) != "internet":
        return f"service name {rdn_value(svc)} isn't recorded as internet-facing: uptime checks reach public endpoints"
    return None


def _check(m, spec):
    cn, why = rdn_value(spec.canary), _why(m, spec)
    if why:
        return (f"# NOTE: canary {cn}: not rendered: {why}",)
    if spec.keeper is not None:
        return (f"# Uptime check {spec.name} ({cn}): kept by {spec.keeper}, not rendered here",)
    url, period = urlsplit(spec.url), next((p for p in PERIODS if p >= spec.every), PERIODS[-1])
    return (block("resource", [CHECK, tf_name(spec.name)], [
        ("display_name", spec.name), ("timeout", "10s"), ("period", f"{period}s"),
        ("http_check", Block((("path", url.path), ("port", url.port or 443), ("use_ssl", True),
                              ("validate_ssl", True), ("request_method", "GET")))),
        ("monitored_resource", Block((("type", "uptime_url"),
                                      ("labels", {"host": url.hostname, "project_id": ref("var.project_id")})))),
        ("user_labels", {"realizes": label(cn),
                         "bindingrole": label(one(spec.binding, "ciamBindingRole") if spec.binding is not None
                                              else f"canary-{cn}")})]),)


def render_checks(m, endpoints):
    """HCL (and comments) for environment m's uptime checks."""
    return tuple(x for s in canary_specs(m, endpoints) for x in _check(m, s))
