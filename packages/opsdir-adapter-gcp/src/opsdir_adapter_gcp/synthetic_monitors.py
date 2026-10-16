"""Scripted synthetic checks on Google Cloud (core observability: domains/observability/canaries) as Cloud Monitoring
synthetic monitors: the checks no uptime check makes (canaries.standard): an oidc-token check (it reads its
credentials when it runs) and an ldap-bind check (not HTTP), of a public or an internal service name, and every check
of an internal service name, its GETs included (decision 2859: Google's private uptime checks don't follow redirects
or validate certificates; the probes do), and any check that must trust a private CA (an uptime check takes no CA
certificate): it is given the CA certificates the record holds for it (canary_specs' trust: their PEMs, public
material, in index.js, added to Node.js's own roots; CHECK_CA_PARTIAL when an intermediate CA is the anchor); a CA
rotation is a record change and a re-render. Decision 2833, research 2832, 2840, 2848, 2857. Pure.

Each is a 2nd gen Cloud Run function (google_cloudfunctions2_function named as its canary binding: lowercase letters,
digits and -) in Node.js (nodejs24, the newest GA runtime), its source opsdir renders (terraform/checks/<name>/:
index.js with its do-not-edit header, the shared probes of observability.probes NODE_PROBES and the handler below;
package.json naming @google-cloud/functions-framework and @google-cloud/synthetics-sdk-api at their current releases)
zipped by the archive provider into the Cloud Storage location its canary binding names (ciamStorageRef
gs://bucket[/prefix]: the location is the environment's, as AWS's canary artifacts) as <prefix>check-<name>.zip, the
function building from that object's generation, so a changed zip replaces the object and redeploys the function;
and the uptime check running it (synthetic_monitor, its period the next Google offers, its timeout 60s), user labels
realizes and bindingrole so the inventory reads it back. One instance at most, 60 seconds, 2 GiB and one CPU (Google
recommends at least 2 GiB for a synthetic monitor's function, research 2857; its own sample uses 256 MiB).

Its credentials, when it has some, are a Secret Manager secret (gcp-sm://projects/<p>/secrets/<name>, its JSON holding
client_id and client_secret, or bind_dn and password, as on the other clouds) the platform mounts as a file
(secret_volumes, CREDENTIALS, the latest version) the handler reads each time the check runs, so a rotated secret is
used at the next run (a secret environment variable is read only when an instance starts): never written anywhere
opsdir renders. A check of an internal
service name runs with Direct VPC egress (private ranges only) in the first subnet canary_specs gives it (its
binding's ciamSubnetRole, else those the firewall rules admit to the service).

One runtime service account for the checks (ciam-<env>-checks: Cloud Trace agent, as Google's synthetic monitors
document; Secret Manager Secret Accessor on each credentials secret) and one that builds them (ciam-<env>-check-build,
not the Compute Engine default: Logging Log Writer, Artifact Registry Writer, Storage Object Viewer on each source
bucket); Cloud Monitoring may invoke the functions by default. The functions wait for their grants.

Not rendered, and said so: what canary_specs names; a check in an Assured Workloads workload (canaries.assured); a
service name whose exposure isn't recorded; an internal one with no subnet to run from; no source location (no canary
binding, or one without a gs:// ciamStorageRef); credentials that aren't a global Secret Manager secret (the function's
secret volumes name one by project and name). A check someone else keeps, or an overlay inherits from
its base, is named with its keeper. What isn't rendered is a render note (monitor_notes: why and how; flow 43),
written as its comment.
"""
import json
import re

from opsdir.core.directory import one, rdn_value
from opsdir.core.formats import JAVASCRIPT
from opsdir.core.manifest import header
from opsdir.core.notes import note_comment
from opsdir.domains.observability.canaries import (RECORD, Reason, canary_specs, no_subnet, unknown_exposure,
                                                   unrendered_note)
from opsdir.domains.observability.probes import NODE_PROBES
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from .canaries import assured, check_name, labels, period, standard
from .names import NETWORK

FUNCTION, CHECK = "google_cloudfunctions2_function", "google_monitoring_uptime_check_config"
RUNTIME = "nodejs24"                # the newest GA Node.js runtime of Cloud Run functions (research 2848)
ENTRY = "SyntheticFunction"
# the packages a synthetic monitor's function needs, at their current releases (npm, 2026-10-14)
PACKAGES = {"@google-cloud/functions-framework": "^5.0.5", "@google-cloud/synthetics-sdk-api": "^0.7.0"}
SECRET = re.compile(r"^gcp-sm://projects/([^/]+)/secrets/([^/]+)$")
RUNTIME_SA, BUILD_SA = "google_service_account.checks", "google_service_account.checks_build"
BUILD_ROLES = ("roles/logging.logWriter", "roles/artifactregistry.writer")
# where the platform mounts a check's credentials secret (its latest version, fetched when the file is read)
MOUNT, CREDENTIALS_FILE = "/etc/secrets/check", "credentials"

# The function's handler, after the probes (observability.probes NODE_PROBES): the credentials read from the mounted
# secret at each run (null: none, an anonymous LDAP bind), the probe run trusting the CA certificates it is given
# besides Node.js's roots (null: none); a rejection fails the synthetic monitor.
HANDLER = '''
const fs = require("fs");
const functions = require("@google-cloud/functions-framework");
const {{runSyntheticHandler}} = require("@google-cloud/synthetics-sdk-api");

const CHECK_FLOW = {flow};
const CHECK_URL = {url};
const CREDENTIALS = {credentials};
const CHECK_CA = {ca};
const CHECK_CA_PARTIAL = {partial};

functions.http("{entry}", runSyntheticHandler(async ({{logger}}) => {{
  // The {flow_text} check of CHECK_URL: the probe rejects when it fails, failing the synthetic monitor.
  const creds = CREDENTIALS ? JSON.parse(fs.readFileSync(CREDENTIALS, "utf8")) : null;
  logger.info(`${{CHECK_URL}}: ${{await probe(CHECK_FLOW, CHECK_URL, creds, CHECK_CA, CHECK_CA_PARTIAL)}}`);
}}));
'''


def source_location(spec):
    """(bucket, prefix) of where a synthetic monitor's function source goes (its binding's gs:// ciamStorageRef; the
    prefix '' or ending in /), else None."""
    uri = one(spec.binding, "ciamStorageRef") if spec.binding is not None else None
    if not (uri or "").startswith("gs://"):
        return None
    bucket, _, prefix = uri[len("gs://"):].partition("/")
    return (bucket, prefix.strip("/") + "/" if prefix.strip("/") else "") if bucket else None


def _secret(spec):
    """(project, name) of the check's credentials when they are a global Secret Manager secret, else None."""
    match = SECRET.match(one(spec.secret, "ciamRefUri") or "") if spec.secret is not None else None
    return match.groups() if match else None


def index_js(m, spec):
    """The function's index.js, with its do-not-edit header."""
    return (header(m, f"Cloud Monitoring synthetic monitor {check_name(spec.name)} ({spec.flow})", JAVASCRIPT)
            + NODE_PROBES + HANDLER.format(
                flow=json.dumps(spec.flow), url=json.dumps(spec.url), entry=ENTRY, flow_text=spec.flow,
                credentials=json.dumps(f"{MOUNT}/{CREDENTIALS_FILE}" if spec.secret is not None else None),
                ca=json.dumps(spec.trust.pem if spec.trust is not None else None),
                partial=json.dumps(bool(spec.trust is not None and spec.trust.partial))))


def package_json(m, spec):
    """The function's package.json (JSON has no comments: its description says it is generated)."""
    return json.dumps({"name": check_name(spec.name), "version": "1.0.0", "private": True,
                       "description": f"Generated by opsdir from {m.dn}: synthetic monitor {spec.name} ({spec.flow}). "
                                      "Do not edit. Change the operations directory (under an approved change) and "
                                      "re-render.",
                       "main": "index.js", "engines": {"node": ">=24"}, "dependencies": PACKAGES}, indent=2) + "\n"


def scripted(specs):
    """The checks a synthetic monitor makes: those no uptime check's GET does and nothing stops canary_specs
    rendering."""
    return tuple(s for s in specs if not s.why and not standard(s))


def _reason(m, spec):
    """Why a synthetic monitor isn't rendered (a Reason with how to handle it), else None."""
    if assured(m):
        return assured(m)
    if spec.exposure is None:
        return unknown_exposure(m, spec)
    if spec.exposure == "internal" and not spec.subnets:
        return no_subnet(m, spec)
    if spec.keeper is None and source_location(spec) is None:
        where = "its canary binding" if spec.binding is None else rdn_value(spec.binding)
        return Reason("no place for its function's source: it has no canary binding" if spec.binding is None else
                      f"its canary binding {rdn_value(spec.binding)} records no Cloud Storage location for its "
                      "function's source (ciamStorageRef gs://bucket/prefix)",
                      (f"Record {where} with the Cloud Storage location its function's source goes to (ciamStorageRef "
                       f"gs://bucket/prefix), {RECORD}",))
    if spec.secret is not None and _secret(spec) is None:
        return Reason(f"its credentials ({rdn_value(spec.secret)}) aren't a global Secret Manager secret "
                      "(gcp-sm://projects/<p>/secrets/<name>)",
                      (f"Keep the check's credentials in a global Secret Manager secret and point "
                       f"{rdn_value(spec.secret)} at it (ciamRefUri gcp-sm://projects/<p>/secrets/<name>), {RECORD}",))
    return None


def rendered(m, endpoints):
    """(CanarySpec, Reason it isn't rendered or None) of environment m's synthetic monitors, given the products'
    Endpoints."""
    return tuple((s, _reason(m, s)) for s in scripted(canary_specs(m, endpoints)))


def monitor_notes(m, endpoints):
    """The render notes of environment m's synthetic monitors it doesn't render (render_monitors writes their
    comments)."""
    return tuple(unrendered_note(m, s, reason) for s, reason in rendered(m, endpoints) if reason)


def _grant(secret):
    return f"checks_{tf_name(secret[0])}_{tf_name(secret[1])}"


def _monitor(m, spec, reason):
    cn = rdn_value(spec.canary)
    if reason:
        return (comment(note_comment(unrendered_note(m, spec, reason))),)
    name = check_name(spec.name)
    if spec.keeper is not None:
        return (comment(f"Synthetic monitor {name} ({cn}): kept by {spec.keeper}, not rendered here"),)
    n, (bucket, prefix), secret = tf_name(name), source_location(spec), _secret(spec)
    zipped = f"check_{n}"
    subnet = tf_name(rdn_value(spec.subnets[0])) if spec.subnets else None
    vpc = (("direct_vpc_network_interface", Block((
               ("network", NETWORK), ("subnetwork", ref(f"data.google_compute_subnetwork.{subnet}.self_link"))))),
           ("direct_vpc_egress", "VPC_EGRESS_PRIVATE_RANGES_ONLY")) if spec.exposure == "internal" else ()
    return (
        tf_block("data", ["archive_file", zipped], [
            ("type", "zip"), ("source_dir", f"${{path.module}}/checks/{name}"),
            ("output_path", f"${{path.module}}/.build/check-{name}.zip")]),
        tf_block("resource", ["google_storage_bucket_object", zipped], [
            ("name", f"{prefix}check-{name}.zip"), ("bucket", bucket),
            ("source", ref(f"data.archive_file.{zipped}.output_path"))]),
        tf_block("resource", [FUNCTION, n], [
            ("name", name), ("location", ref("var.region")),
            ("description", f"Synthetic monitor {spec.name}: the {spec.flow} check of {spec.url}"),
            ("build_config", Block((
                ("runtime", RUNTIME), ("entry_point", ENTRY), ("service_account", ref(f"{BUILD_SA}.id")),
                ("source", Block((("storage_source", Block((
                    ("bucket", bucket), ("object", ref(f"google_storage_bucket_object.{zipped}.name")),
                    ("generation", ref(f"google_storage_bucket_object.{zipped}.generation"))))),)))))),
            ("service_config", Block((
                ("available_memory", "2Gi"), ("available_cpu", "1"), ("timeout_seconds", 60),
                ("max_instance_count", 1), ("service_account_email", ref(f"{RUNTIME_SA}.email")),
                *((("secret_volumes", Block((
                    ("mount_path", MOUNT), ("project_id", secret[0]), ("secret", secret[1]),
                    ("versions", Block((("version", "latest"), ("path", CREDENTIALS_FILE))))))),) if secret else ()),
                *vpc))),
            ("labels", {"realizes": labels(spec)["realizes"], "managed_by": "opsdir"}),
            ("depends_on", [ref("google_project_iam_member.checks_trace"),
                            *(ref(f"google_project_iam_member.checks_build_{i}") for i, _ in enumerate(BUILD_ROLES)),
                            ref(f"google_storage_bucket_iam_member.checks_build_{tf_name(bucket)}"),
                            *((ref(f"google_secret_manager_secret_iam_member.{_grant(secret)}"),)
                              if secret else ())])]),
        tf_block("resource", [CHECK, n], [
            ("display_name", spec.name), ("timeout", "60s"), ("period", period(spec.every)),
            ("synthetic_monitor", Block((("cloud_function_v2", Block((("name", ref(f"{FUNCTION}.{n}.id")),))),))),
            ("user_labels", labels(spec))]))


def _account_id(m, suffix):
    """A service account id (6-30 lowercase letters, digits and -) for the environment's checks."""
    base = re.sub(r"[^a-z0-9-]", "-", f"ciam-{rdn_value(m.env).lower()}")
    return f"{base[:29 - len(suffix)].rstrip('-')}-{suffix}"


def _accounts(m, live):
    """The checks' runtime and build service accounts and their grants."""
    runtime = f"serviceAccount:${{{RUNTIME_SA}.email}}"
    builder = f"serviceAccount:${{{BUILD_SA}.email}}"
    secrets = tuple(dict.fromkeys(_secret(s) for s in live if s.secret is not None))
    buckets = tuple(dict.fromkeys(source_location(s)[0] for s in live))
    return (tf_block("resource", ["google_service_account", "checks"], [
                ("account_id", _account_id(m, "checks")),
                ("display_name", f"CIAM synthetic monitors ({m.label}): runs the checks")]),
            tf_block("resource", ["google_service_account", "checks_build"], [
                ("account_id", _account_id(m, "check-build")),
                ("display_name", f"CIAM synthetic monitors ({m.label}): builds the checks' functions")]),
            tf_block("resource", ["google_project_iam_member", "checks_trace"], [
                ("project", ref("var.project_id")), ("role", "roles/cloudtrace.agent"), ("member", runtime)]),
            *(tf_block("resource", ["google_project_iam_member", f"checks_build_{i}"], [
                ("project", ref("var.project_id")), ("role", role), ("member", builder)])
              for i, role in enumerate(BUILD_ROLES)),
            *(tf_block("resource", ["google_storage_bucket_iam_member", f"checks_build_{tf_name(b)}"], [
                ("bucket", b), ("role", "roles/storage.objectViewer"), ("member", builder)]) for b in buckets),
            *(tf_block("resource", ["google_secret_manager_secret_iam_member", _grant(s)], [
                ("project", s[0]), ("secret_id", s[1]), ("role", "roles/secretmanager.secretAccessor"),
                ("member", runtime)]) for s in secrets))


def render_monitors(m, endpoints):
    """(HCL and comments, {path: source file}) of environment m's synthetic monitors."""
    done = rendered(m, endpoints)
    live = tuple(s for s, why in done if why is None and s.keeper is None)
    hcl = (*(x for s, why in done for x in (from_entry(s.binding.dn, _monitor(m, s, why))
                                             if s.binding is not None else _monitor(m, s, why))),
           *(_accounts(m, live) if live else ()))
    return hcl, {p: text for s in live for p, text in (
        (f"terraform/checks/{check_name(s.name)}/index.js", index_js(m, s)),
        (f"terraform/checks/{check_name(s.name)}/package.json", package_json(m, s)))}
