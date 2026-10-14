"""Synthetic checks on Google Cloud (core observability: domains/observability/canaries) as Cloud Monitoring uptime
checks. Pure.

Each canary the environment can run whose request the record describes (canary_specs), for the flows one GET answers
(canaries.GET_FLOWS: health, login-page, saml-sso) of an internet-facing service name, as a
google_monitoring_uptime_check_config named as its canary binding: an HTTPS GET of its URL's path (and query) on its
port (any 2xx answer passes), the TLS certificate validated, on the monitored resource uptime_url of its host in the
root's project, every 1, 5, 10 or 15 minutes (its interval, raised to the next), with user labels realizes and
bindingrole so the inventory reads it back.

A check of an internal service name, whatever its flow, is a synthetic monitor (synthetic_monitors), not a private
uptime check (decision 2859): Google's private uptime checks don't support endpoints that redirect (a SAML start or a
login page does), never validate certificates, and send the Service Directory endpoint's address as the Host header;
the probes follow redirects and verify certificates, as the other clouds' checks do. The checks no GET makes
(oidc-token, ldap-bind) are synthetic monitors too.

Not rendered, and said so: what canary_specs names; a service name whose exposure isn't recorded; any uptime check where
the environment is an Assured Workloads workload (a compliance regime: Google supports neither uptime checks nor
synthetic monitors there, and their requests may come from any uptime region). A check someone else keeps, or an
overlay inherits from its base, is named with its keeper. What isn't rendered is a render note (uptime_notes, core
observability unrendered_note: why and how to handle it; flow 43), written as its comment.
"""
import re
from urllib.parse import urlsplit

from opsdir.core.directory import one, rdn_value
from opsdir.core.notes import note_comment
from opsdir.domains.observability.canaries import GET_FLOWS, Reason, canary_specs, unknown_exposure, unrendered_note
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from .account import regime
from .names import label

CHECK = "google_monitoring_uptime_check_config"
PERIODS = (60, 300, 600, 900)
# what to do instead where Google runs no checks (an Assured Workloads workload)
ASSURED_HOW = (
    "Run the same check from inside the boundary: a scheduled job on the environment's own compute (a Kubernetes "
    "CronJob, or a timer on a server) running the probe, its result written as a Cloud Monitoring custom metric with "
    "an alert policy on it",
    "Or alert on what the products log: log-based alert policies on failed sign-ins, LDAP binds or SAML errors",
    "Or run the check from a monitoring project outside the Assured Workloads folder, only if the authorizing official "
    "accepts check requests and results crossing the boundary")


def check_name(name):
    """A name Google Cloud takes for a Cloud Run function: lowercase letters, digits and -, starting with a letter,
    at most 63."""
    safe = re.sub(r"-+", "-", re.sub(r"[^a-z0-9-]", "-", name.lower())).strip("-")
    return (safe if safe[:1].isalpha() else f"c-{safe}")[:63].rstrip("-")


def period(every):
    """An uptime check's period for an interval in seconds: the next Google offers, at most 15 minutes."""
    return f"{next((p for p in PERIODS if p >= every), PERIODS[-1])}s"


def assured(m):
    """The Reason environment m renders no uptime check or synthetic monitor (an Assured Workloads workload, with what
    to do instead), else None."""
    r = regime(m)
    return Reason(f"the environment is an Assured Workloads workload ({r}), where Google supports neither uptime "
                  "checks nor synthetic monitors (their requests may come from any uptime region)",
                  ASSURED_HOW) if r else None


def labels(spec):
    """The user labels the inventory reads a check back by: the canary it realizes, its binding's role."""
    cn = rdn_value(spec.canary)
    return {"realizes": label(cn),
            "bindingrole": label(one(spec.binding, "ciamBindingRole") if spec.binding is not None else f"canary-{cn}")}


def standard(spec):
    """Whether an uptime check makes a check: a flow one GET answers, of a service name not recorded internal (an
    internal one's check is a synthetic monitor)."""
    return spec.flow in GET_FLOWS and spec.exposure != "internal"


def _reason(m, spec):
    """Why an uptime check isn't rendered (a Reason; the spec's own why first), else None."""
    if spec.why:
        return Reason(spec.why, spec.how)
    if assured(m):
        return assured(m)
    return unknown_exposure(m, spec) if spec.exposure is None else None


def _target(url):
    return url.path + (f"?{url.query}" if url.query else "")


def _check(m, spec, reason):
    cn = rdn_value(spec.canary)
    if reason:
        return (comment(note_comment(unrendered_note(m, spec, reason))),)
    if spec.keeper is not None:
        return (comment(f"Uptime check {spec.name} ({cn}): kept by {spec.keeper}, not rendered here"),)
    url = urlsplit(spec.url)
    return (tf_block("resource", [CHECK, tf_name(spec.name)], [
        ("display_name", spec.name), ("timeout", "10s"), ("period", period(spec.every)),
        ("http_check", Block((("path", _target(url)), ("port", url.port or 443), ("use_ssl", True),
                              ("validate_ssl", True), ("request_method", "GET")))),
        ("monitored_resource", Block((("type", "uptime_url"),
                                      ("labels", {"host": url.hostname, "project_id": ref("var.project_id")})))),
        ("user_labels", labels(spec))]),)


def render_checks(m, endpoints):
    """HCL (and comments) for environment m's uptime checks of the flows one GET answers of internet-facing service
    names (and the NOTEs of what canary_specs doesn't render; the other checks are synthetic_monitors')."""
    done = _done(m, endpoints)
    return tuple(x for s, reason in done for x in (from_entry(s.binding.dn, _check(m, s, reason))
                                                    if s.binding is not None else _check(m, s, reason)))


def _done(m, endpoints):
    return tuple((s, _reason(m, s)) for s in canary_specs(m, endpoints) if s.why or standard(s))


def uptime_notes(m, endpoints):
    """The render notes of environment m's uptime checks it doesn't render (render_checks writes their comments)."""
    return tuple(unrendered_note(m, s, reason) for s, reason in _done(m, endpoints) if reason)
