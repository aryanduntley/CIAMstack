"""Scripted synthetic checks on Azure (core observability: domains/observability/canaries) as Azure Container Apps
scheduled jobs: the checks an Application Insights standard web test can't make (canaries.standard: a GET of an
internet-facing service name): an oidc-token check (it reads its credentials when it runs), an ldap-bind check (not
HTTP), and any check of an internal service name (the test locations reach public endpoints only). Decision 2841.
Pure.

A Container Apps environment per subnet the checks run from (azurerm_container_app_environment checks_<subnet>,
cae-ciam-<env>-<subnet>, workload profiles, the Consumption profile; no charge for a job between executions; an
internal load balancer): each internal check is placed in one of the subnets it may run from (canary_specs: its canary
binding's ciamSubnetRole, else the subnets the firewall rules admit to the service): one an earlier check already
uses when it can, else its first of at least a /27 (research 2857: no check is left out for want of one shared
environment). Each subnet must be delegated to Microsoft.App/environments (the network's keeper delegates it: a render
note). Checks of internet-facing services run in the first of those environments, else in one outside any network
(azurerm_container_app_environment checks, cae-ciam-<env>-checks).

One job per check (azurerm_container_app_job named as its canary binding: lowercase letters, digits and -, at most 32),
on a schedule (a 5-field UTC cron from its interval, raised to the next that divides an hour or a day), one replica,
no retry (a failure is reported, not hidden). Every job runs the same runner (its do-not-edit header, the shared probes
of observability.probes and the reporter below), given only data in environment variables: its flow, URL, test name
and token audience (CHECK_FLOW, CHECK_URL, CHECK_TEST, CHECK_AUDIENCE); never code (decision 2877, research 2876).
How the runner gets there is the estate setting azure-check-delivery:
- image (the default): an image the organization's own pipeline builds, signs, verifies and pushes, from the build
  context opsdir renders (images/ciam-check/: a Dockerfile FROM the base image azure-check-image names, Microsoft's
  distroless non-root Python 3.12 by default, and the runner). Each canary binding records the image the job runs
  (ciamContainerImage check=<registry>/<repository>@sha256:<digest>); the job pulls it with its own identity (registry
  {server, identity}, AcrPull on the registry, an input per registry: registry_<host>_id). A job whose binding records
  no image isn't rendered (a render note says how to build and record it); one recorded by tag is, with a note to pin
  its digest. Container Apps doesn't verify image signatures (no admission control: research 2876), so the pipeline
  verifies before it promotes; and whoever may start a job can override its image, command and environment and use
  its identity and secrets (Microsoft's jobs page): a render note says to keep that right to trusted identities.
- script (a lab's choice): the job runs the base image and reads the runner from an environment variable
  (terraform/checks/check.py through file(), python3 -c exec): nothing is built, nothing signed.
A check of a service name whose certificate a private CA issued is given the CA certificates the record holds for it
(canary_specs' trust: their PEMs, public material, base64-encoded in CHECK_CA so the value is one line wherever it is
written, and CHECK_CA_PARTIAL true when an intermediate CA is the anchor), added to the image's trust store: data,
so the image is the same for every check; a CA rotation is a record change and a re-render, never a rebuild.
Its credentials, when it has some, are a Key Vault secret reference (azkv://<vault>/<name>, its JSON holding client_id
and client_secret, or bind_dn and password, as on AWS) read by the platform into an environment variable: never
written anywhere opsdir renders.

The reporter sends each result to Application Insights as an availability result (POST <IngestionEndpoint>/v2.1/track,
an AvailabilityData envelope, research 2840) from the connection string (the root's sensitive input
application_insights_connection_string), authenticated with an Entra token for the job's identity (audience
https://monitor.azure.com, Azure Government's https://monitor.azure.us), so it works with the resource's local
authentication disabled. The results sit with the standard tests' (application_insights_id input).

One user-assigned identity per job (azurerm_user_assigned_identity check_<job>, id-ciam-<env>-<job>; a system-assigned
one exists only once its job does, and a job is created with its Key Vault references resolved), so a job can read its
own credentials and no other check's (research 2857): Key Vault Secrets User on its credentials secret, Monitoring
Metrics Publisher on the Application Insights resource; the job waits for both. The identity and its grants go with
their job (its canary binding's origin: a keeper's root takes them along).

Not rendered, and said so: what canary_specs names; a service name whose exposure isn't recorded; an internal one with
no subnet to run from, or not run from the environment's; a subnet smaller than /27; credentials that aren't a Key
Vault secret; no image recorded (image delivery). A check someone else keeps, or an overlay inherits from its base, is
named with its keeper. Live validation (decision 2841, deferred 2846): Key Vault references and registry pulls from
Azure Government.
"""
import base64
import ipaddress
import re
from functools import reduce

from opsdir.core.contract import Setting
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.formats import DOCKERFILE, PYTHON
from opsdir.core.manifest import header
from opsdir.core.settings import setting_value
from opsdir.core.notes import note, note_comment
from opsdir.domains.observability.canaries import (RECORD, Reason, canary_specs, no_subnet, unknown_exposure,
                                                   unrendered_note)
from opsdir.domains.observability.probes import PYTHON_PROBES
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from .account import government, tagged
from .canaries import INPUT, insights_input, standard
from .identities import LOC, RG, scope

ENVIRONMENT, JOB = "azurerm_container_app_environment", "azurerm_container_app_job"
CONNECTION = "application_insights_connection_string"
VAULT = "azkv://"
PROFILE = "Consumption"
SMALLEST = 27                   # a workload-profiles environment's subnet: at least a /27
MINUTES = (1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30)
HOURS = (1, 2, 3, 4, 6, 8, 12, 24)
TIMEOUT = 120                   # seconds a run may take: the probe's and the report's 10-second timeouts, and start-up
AUDIENCE, GOV_AUDIENCE = "https://monitor.azure.com", "https://monitor.azure.us"
IMAGE = Setting("azure-check-image", "string", "mcr.microsoft.com/azurelinux/distroless/python:3.12-nonroot",
                "The Python 3 base image of the scripted synthetic checks (Azure Container Apps jobs; standard library "
                "only): what their image's Dockerfile builds FROM (pin it by digest; an estate may name a hardened "
                "image or a mirror in its own registry), and what the script form runs in")
DELIVERY = Setting("azure-check-delivery", "string", "image",
                   "How the scripted synthetic checks get their code: image (an image the organization builds, signs "
                   "and records on each canary binding) or script (a lab's choice: the runner read from an "
                   "environment variable, nothing built or signed)", choices=("image", "script"))
COMMAND = ["python3", "-c", "import os; exec(os.environ['CHECK_SCRIPT'])"]
CONTEXT = "images/ciam-check"           # the image's build context, in the render
RUNNER = "checks/check.py"              # the runner beside the Terraform root (script delivery)
DIGEST = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


def job_name(name):
    """A Container Apps job name (lowercase letters, digits and -, starting with a letter, at most 32)."""
    safe = re.sub(r"-+", "-", re.sub(r"[^a-z0-9-]", "-", name.lower())).strip("-")
    return (safe if safe[:1].isalpha() else f"c-{safe}")[:32].rstrip("-")


def cron(every):
    """The 5-field UTC cron running a check every `every` seconds, raised to the next interval that divides an hour
    (minutes) or a day (hours)."""
    minutes = max(1, -(-every // 60))
    if minutes < 60:
        n = next((x for x in MINUTES if x >= minutes), None)
        if n is not None:
            return "* * * * *" if n == 1 else f"*/{n} * * * *"
    hours = next((x for x in HOURS if x * 60 >= minutes), HOURS[-1])
    return "0 0 * * *" if hours == 24 else f"0 */{hours} * * *"


def cron_seconds(expression):
    """The interval in seconds a cron expression cron() writes runs at (*/n minutes, every minute, 0 */n hours,
    daily), else None."""
    fields = (expression or "").split()
    if len(fields) != 5 or fields[2:] != ["*", "*", "*"]:
        return None
    minute, hour = fields[:2]
    if hour == "*":
        return 60 if minute == "*" else 60 * int(minute[2:]) if minute.startswith("*/") and minute[2:].isdigit() \
            else None
    if minute != "0":
        return None
    return 86400 if hour == "0" else 3600 * int(hour[2:]) if hour.startswith("*/") and hour[2:].isdigit() else None


# The checks' runner, after the probes (observability.probes): which check it makes from the job's environment variables
# (data only: the CA certificates it trusts besides the image's too), its credentials from the one the platform fills
# from Key Vault (none: an anonymous LDAP bind), the result
# POSTed to Application Insights as an availability result with an Entra token for the job's identity, and the run
# failed when the check fails. The same text for every job: built into the image, or read from a variable.
REPORTER = '''
import datetime
import os
import time
import uuid

FLOW = os.environ["CHECK_FLOW"]
URL = os.environ["CHECK_URL"]
TEST = os.environ["CHECK_TEST"]
AUDIENCE = os.environ["CHECK_AUDIENCE"]
CA = base64.b64decode(os.environ["CHECK_CA"]).decode() if os.environ.get("CHECK_CA") else None
CA_PARTIAL = os.environ.get("CHECK_CA_PARTIAL") == "true"


def _connection():
    """(instrumentation key, ingestion endpoint) of the Application Insights connection string."""
    parts = dict(p.split("=", 1) for p in os.environ["APPLICATIONINSIGHTS_CONNECTION_STRING"].split(";") if "=" in p)
    return parts["InstrumentationKey"], parts["IngestionEndpoint"].rstrip("/")


def _token():
    """An Entra access token for the job's identity (the Container Apps identity endpoint)."""
    query = urllib.parse.urlencode({"resource": AUDIENCE, "api-version": "2019-08-01",
                                    "client_id": os.environ["AZURE_CLIENT_ID"]})
    request = urllib.request.Request(f"{os.environ['IDENTITY_ENDPOINT']}?{query}",
                                     headers={"X-IDENTITY-HEADER": os.environ["IDENTITY_HEADER"]})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.loads(response.read())["access_token"]


def _duration(seconds):
    """DD.HH:MM:SS.MMMMMM"""
    whole, micro = divmod(round(seconds * 1000000), 1000000)
    minutes, secs = divmod(whole, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    return f"{days:02d}.{hours:02d}:{minutes:02d}:{secs:02d}.{micro:06d}"


def report(success, message, seconds):
    """The result as an availability result in Application Insights."""
    key, endpoint = _connection()
    envelope = {"ver": 1, "name": "Microsoft.ApplicationInsights.Availability", "sampleRate": 100, "iKey": key,
                "time": datetime.datetime.now(datetime.timezone.utc).isoformat(), "flags": 0,
                "data": {"baseType": "AvailabilityData", "baseData": {
                    "ver": 2, "id": str(uuid.uuid4()), "name": TEST, "duration": _duration(seconds),
                    "success": success, "runLocation": os.environ.get("CHECK_LOCATION", ""), "message": message[:8192],
                    "properties": {"flow": FLOW, "url": URL}}}}
    request = urllib.request.Request(f"{endpoint}/v2.1/track", data=json.dumps(envelope).encode(), method="POST",
                                     headers={"Content-Type": "application/json",
                                              "Authorization": f"Bearer {_token()}"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.status


def main():
    """The check of URL (its flow FLOW): the probe raises when it fails, failing the run."""
    creds = json.loads(os.environ["CHECK_CREDENTIALS"]) if os.environ.get("CHECK_CREDENTIALS") else None
    start = time.monotonic()
    try:
        success, message = True, probe(FLOW, URL, creds, CA, CA_PARTIAL)
    except Exception as failure:
        success, message = False, f"{type(failure).__name__}: {failure}"
    report(success, message, time.monotonic() - start)
    print(f"{URL}: {'passed' if success else 'failed'}: {message}")
    if not success:
        raise SystemExit(1)


main()
'''


def runner(m):
    """The checks' Python runner (every job's), with its do-not-edit header."""
    return header(m, "Azure Container Apps check jobs' runner", PYTHON) + PYTHON_PROBES + REPORTER


def dockerfile(m, hosts=()):
    """The check image's Dockerfile: the build note (_build) as its comment, FROM the base image (azure-check-image),
    the runner, run as non-root; hosts: the registries the jobs record."""
    return (header(m, "The image the scripted synthetic checks run: build, sign, verify and push it with the "
                      "organization's pipeline, then record its digest on each canary binding", DOCKERFILE)
            + f"# {note_comment(_build(m, hosts))}\n"
            + f"FROM {setting_value(m.d, IMAGE)}\n"
            + 'LABEL org.opencontainers.image.title="ciam-check" \\\n'
            + '      org.opencontainers.image.description="CIAM synthetic checks (opsdir): one probe per run, its '
              'check given in environment variables"\n'
            + "COPY check.py /opt/ciam-check/check.py\n"
            + "USER nonroot\n"
            + 'ENTRYPOINT ["/usr/bin/python3", "/opt/ciam-check/check.py"]\n')


def delivery(m):
    """How environment m's check jobs get their code (azure-check-delivery): image or script."""
    return setting_value(m.d, DELIVERY)


def recorded_image(spec):
    """The image a check's canary binding records for its job (ciamContainerImage check=<image>), else None."""
    values_ = values(spec.binding, "ciamContainerImage") if spec.binding is not None else ()
    return next((v.split("=", 1)[1] for v in values_ if v.startswith("check=")), None)


def registry(image):
    """The registry host of an image reference."""
    return image.split("/", 1)[0]


def _registry_input(host):
    return f"registry_{tf_name(host)}_id"


def _identity(name):
    """The address of a job's user-assigned identity (name: the job's name)."""
    return f"azurerm_user_assigned_identity.check_{tf_name(name)}"


def _vault_secret(spec):
    """(vault, secret name) of the check's credentials when they are a Key Vault secret, else None."""
    uri = one(spec.secret, "ciamRefUri") if spec.secret is not None else None
    if not uri or not uri.startswith(VAULT) or "/" not in uri[len(VAULT):]:
        return None
    vault, name = uri[len(VAULT):].split("/", 1)
    return vault, name.split("/")[0]


def scripted(specs):
    """The checks a job makes: those no standard web test does and nothing stops canary_specs rendering."""
    return tuple(s for s in specs if not s.why and not standard(s))


def _fits(subnet):
    """Whether a subnet can hold a workload-profiles environment (at least a /27; a subnet recording no range may)."""
    return (_prefix(subnet) or 0) <= SMALLEST


def placed(specs):
    """{check name: the subnet binding its job's environment is in} for the internal checks among specs (each one an
    earlier check already uses when it can, else the first of at least a /27, else its first): one environment per
    subnet, as few as the checks allow."""
    def step(chosen, spec):
        fitting = tuple(x for x in spec.subnets if _fits(x))
        shared = next((x for x in fitting if any(x.dn == c.dn for c in chosen.values())), None)
        pick = shared or (fitting[0] if fitting else spec.subnets[0])
        return {**chosen, spec.name: pick}
    internal = tuple(s for s in specs if s.exposure == "internal" and s.subnets)
    return reduce(step, internal, {})


def subnets_used(placement):
    """The subnet bindings the environments are in, each once, in the order the checks were placed."""
    return tuple({x.dn: x for x in placement.values()}.values())


def _prefix(subnet):
    cidr = one(subnet, "ciamCidr")
    return ipaddress.ip_network(cidr, strict=False).prefixlen if cidr else None


def _reason(m, spec, subnet):
    """Why a check job isn't rendered (a Reason with how to handle it), else None; subnet: where it was placed."""
    if spec.exposure is None:
        return unknown_exposure(m, spec)
    if spec.exposure == "internal" and not spec.subnets:
        return no_subnet(m, spec)
    if spec.exposure == "internal" and not _fits(subnet):
        return Reason(f"subnet {rdn_value(subnet)} ({one(subnet, 'ciamCidr')}) is smaller than the /{SMALLEST} a "
                      "Container Apps environment with workload profiles needs",
                      (f"Have the network's keeper give the checks a subnet of /{SMALLEST} or larger, and name its "
                       f"subnet role on the canary binding (ciamSubnetRole), {RECORD}",))
    if spec.secret is not None and _vault_secret(spec) is None:
        return Reason(f"its credentials ({rdn_value(spec.secret)}) aren't a Key Vault secret (azkv://)",
                      (f"Keep the check's credentials in a Key Vault secret and point {rdn_value(spec.secret)} at it "
                       f"(ciamRefUri azkv://<vault>/<secret>), {RECORD}",))
    if delivery(m) == "image" and spec.keeper is None and recorded_image(spec) is None:
        return _no_image(spec)
    return None


def _no_image(spec):
    """The Reason a check isn't rendered when its canary binding records no image for it to run."""
    where = (f"its canary binding {rdn_value(spec.binding)}" if spec.binding is not None
             else "it has no canary binding: it")
    return Reason(f"{where} records no check image to run (azure-check-delivery image)",
                  (f"Build the check image from the render's {CONTEXT}/ with the organization's pipeline, sign it, "
                   "verify the signature, and push it to a registry the environment reaches",
                   f"Record it on {'its canary binding' if spec.binding is None else rdn_value(spec.binding)} by "
                   f"digest (ciamContainerImage check=<registry>/<repository>@sha256:<digest>), {RECORD}",
                   "Or, in a lab only, run the checks from a variable instead (setting azure-check-delivery script)"))


def rendered(m, endpoints):
    """((CanarySpec, Reason it isn't rendered or None), ...) of environment m's scripted checks, and {check name: the
    subnet binding its environment is in} (placed)."""
    specs = scripted(canary_specs(m, endpoints))
    placement = placed(specs)
    return tuple((s, _reason(m, s, placement.get(s.name))) for s in specs), placement


def _environments(placement, live):
    """{check name: the address name of its job's environment} of the jobs rendered: checks_<subnet> for an internal
    check's, the first of those for an internet-facing one's, else checks (outside any network)."""
    names = {x.dn: f"checks_{tf_name(rdn_value(x))}" for x in subnets_used(_live_placement(placement, live))}
    public = next(iter(names.values()), "checks")
    return {s.name: names[placement[s.name].dn] if s.name in placement else public for s in live}


def _live_placement(placement, live):
    return {s.name: placement[s.name] for s in live if s.name in placement}


def _delegation(m, subnet):
    """The action the network's keeper takes before the checks' environment can use its subnet."""
    return note("Network", "action", f"subnet {rdn_value(subnet)}",
                "must be delegated to Microsoft.App/environments and hold nothing else before the checks' Container "
                "Apps environment is applied",
                (f"Have the network's keeper delegate subnet {rdn_value(subnet)} to Microsoft.App/environments (and "
                 "move anything else out of it), then apply",), subnet.dn, f"virtual network of {m.label}")


def _first_runs(m):
    """What to expect of the check jobs' first runs: results refused while the identity's role propagates; the
    availability results' form not yet seen accepted by a live Application Insights."""
    return (note("Monitoring", "note", "check jobs",
                 "the first runs may fail to post their results (403) until Azure has propagated each job's "
                 "identity's Monitoring Metrics Publisher role (minutes)",
                 ("If the first runs' availability results are missing, wait for the role assignment to propagate; "
                  "nothing to change",), scope=f"Application Insights of {m.label}"),
            note("Monitoring", "note", "check jobs",
                 "their results are posted as Microsoft.ApplicationInsights.Availability items with an Entra token, "
                 "a form not yet confirmed against a live Application Insights" + (" in Azure Government"
                                                                                  if government(m) else ""),
                 ("After the first runs, confirm their results appear in Application Insights (availabilityResults); "
                  "if not, report it with the job's log",), scope=f"Application Insights of {m.label}"))


def _build(m, hosts):
    """The action for whoever runs the organization's image pipeline: build, sign, verify, push and record the check
    image (hosts: the registries the jobs record)."""
    return note("Monitoring", "action", "check image",
                f"build it from {CONTEXT}/ (FROM {setting_value(m.d, IMAGE)}), sign it, verify its signature before "
                "it is used (Container Apps doesn't verify signatures), push it, and record its digest on each canary "
                "binding",
                ("Build the image from this build context in the organization's pipeline (pin the base image by "
                 "digest: setting azure-check-image)",
                 "Sign it (the organization's signing, e.g. Notary Project signatures kept in the registry) and verify "
                 "the signature by digest before promoting it; Azure Container Apps pulls whatever the job names",
                 "Push it to a registry the environment's jobs reach (a private one: allow ARM audience tokens for "
                 "managed identity pulls, az acr config authentication-as-arm)",
                 "Record it on each canary binding (ciamContainerImage "
                 f"check=<registry>/<repository>@sha256:<digest>), "
                 f"{RECORD}; rebuild only when opsdir's probes change (this file's text)"),
                scope=f"image pipeline and registry of {m.label}" + (f" ({', '.join(hosts)})" if hosts else ""))


def _start_rights(m):
    """The action for whoever grants roles on the jobs: starting a job can run other code with its identity."""
    return note("Monitoring", "action", "check jobs",
                "whoever may start one can override its image, command and environment and use its identity and "
                "secrets (Microsoft's jobs documentation): keep that right to identities trusted with them; the "
                "built-in Container Apps Jobs Operator and Contributor roles can also read the jobs' secrets",
                ("Give operators a custom role with only Microsoft.App/jobs/read, jobs/start/action, jobs/stop/action, "
                 "jobs/stop/execution/action, jobs/executions/read, jobs/execution/read and "
                 "Microsoft.App/managedEnvironments/read (not the Microsoft.App/jobs/*/action wildcard), assigned "
                 "only to those trusted with the jobs' identities",), scope=f"role assignments on {m.label}'s jobs")


def _by_tag(m, spec):
    """The action for a job whose binding records its image by tag rather than digest."""
    return note("Monitoring", "action", f"check job {job_name(spec.name)}",
                f"runs {recorded_image(spec)} by tag: a tag can move to an image nobody signed or verified",
                (f"Record its digest instead (ciamContainerImage check=<registry>/<repository>@sha256:<digest> on "
                 f"{rdn_value(spec.binding)}), {RECORD}",), spec.binding.dn)


def job_notes(m, endpoints):
    """The render notes of environment m's scripted checks (render_jobs writes their comments): those it doesn't
    render; with image delivery the check image to build, sign, verify and record (while any check needs it) and the
    jobs recorded by tag; and, when it renders any, the subnet delegation the network's keeper does, who may start the
    jobs, and what to expect of the first runs."""
    done, placement = rendered(m, endpoints)
    live = tuple(s for s, reason in done if reason is None and s.keeper is None)
    return (*(unrendered_note(m, s, reason) for s, reason in done if reason),
            *_image_notes(m, done, live),
            *((*(_delegation(m, x) for x in subnets_used(_live_placement(placement, live))), _start_rights(m),
               *_first_runs(m)) if live else ()))


def _needs_image(m, done):
    """Whether image delivery needs the check image: a check it renders, or one waiting only for its image."""
    return delivery(m) == "image" and any(reason is None or reason.why.endswith("(azure-check-delivery image)")
                                          for _, reason in done)


def _image_notes(m, done, live):
    return ((*((_build(m, _hosts(m, live)),) if _needs_image(m, done) else ()),
             *(_by_tag(m, s) for s in live if not DIGEST.match(recorded_image(s)))) if delivery(m) == "image" else ())


def _job(m, spec, reason, environment="checks"):
    cn = rdn_value(spec.canary)
    if reason:
        return (comment(note_comment(unrendered_note(m, spec, reason))),)
    name = job_name(spec.name)
    if spec.keeper is not None:
        return (comment(f"Check job {name} ({cn}): kept by {spec.keeper}, not rendered here"),)
    secret, n, identity, image = _vault_secret(spec), tf_name(name), _identity(name), delivery(m) == "image"
    secrets = (("secret", Block((("name", "credentials"),
                                 ("key_vault_secret_id", f"${{data.azurerm_key_vault.{tf_name(secret[0])}.vault_uri}}"
                                                         f"secrets/{secret[1]}"),
                                 ("identity", ref(f"{identity}.id"))))),) if secret else ()
    env = (*((("CHECK_SCRIPT", ("value", ref(f'file("${{path.module}}/{RUNNER}")'))),) if not image else ()),
           ("CHECK_FLOW", ("value", spec.flow)), ("CHECK_URL", ("value", spec.url)),
           ("CHECK_TEST", ("value", spec.name)),
           ("CHECK_AUDIENCE", ("value", GOV_AUDIENCE if government(m) else AUDIENCE)),
           ("CHECK_LOCATION", ("value", LOC)),
           *((("CHECK_CA", ("value", base64.b64encode(spec.trust.pem.encode()).decode())),
              ("CHECK_CA_PARTIAL", ("value", "true" if spec.trust.partial else "false"))) if spec.trust else ()),
           ("AZURE_CLIENT_ID", ("value", ref(f"{identity}.client_id"))),
           ("APPLICATIONINSIGHTS_CONNECTION_STRING", ("secret_name", "appinsights")),
           *((("CHECK_CREDENTIALS", ("secret_name", "credentials")),) if secret else ()))
    grants = (("publisher", ref(f"var.{INPUT}"), "Monitoring Metrics Publisher"),
              *((("secret", scope(spec.secret)[0], "Key Vault Secrets User"),) if secret else ()),
              *((("pull", ref(f"var.{_registry_input(registry(recorded_image(spec)))}"), "AcrPull"),) if image else ()))
    tagged_only = image and not DIGEST.match(recorded_image(spec))
    return (*((comment(note_comment(_by_tag(m, spec))),) if tagged_only else ()),
            tf_block("resource", ["azurerm_user_assigned_identity", f"check_{n}"], [
                ("name", f"id-ciam-{rdn_value(m.env)}-{name}"), ("resource_group_name", RG), ("location", LOC),
                ("tags", tagged(m, {"ManagedBy": "opsdir"}))]),
            *(tf_block("resource", ["azurerm_role_assignment", f"check_{n}_{what}"], [
                ("scope", where), ("role_definition_name", role), ("principal_id", ref(f"{identity}.principal_id"))])
              for what, where, role in grants),
            tf_block("resource", [JOB, n], [
            ("name", name), ("resource_group_name", RG), ("location", LOC),
            ("container_app_environment_id", ref(f"{ENVIRONMENT}.{environment}.id")),
            ("workload_profile_name", PROFILE),
            ("replica_timeout_in_seconds", TIMEOUT), ("replica_retry_limit", 0),
            ("schedule_trigger_config", Block((("cron_expression", cron(spec.every)), ("parallelism", 1),
                                               ("replica_completion_count", 1)))),
            ("identity", Block((("type", "UserAssigned"), ("identity_ids", [ref(f"{identity}.id")])))),
            ("secret", Block((("name", "appinsights"), ("value", ref(f"var.{CONNECTION}"))))),
            *secrets,
            *((("registry", Block((("server", registry(recorded_image(spec))), ("identity", ref(f"{identity}.id"))))),)
              if image else ()),
            ("template", Block((("container", Block((
                ("name", "check"), ("image", recorded_image(spec) if image else setting_value(m.d, IMAGE)),
                ("cpu", 0.25), ("memory", "0.5Gi"),
                *((("command", COMMAND),) if not image else ()),
                *(("env", Block((("name", k), v))) for k, v in env)))),))),
            ("tags", tagged(m, {"Realizes": cn, "BindingRole": one(spec.binding, "ciamBindingRole")
                                if spec.binding is not None else f"canary-{cn}"})),
            ("depends_on", [ref(f"azurerm_role_assignment.check_{n}_{what}") for what, _, _ in grants])]))


def _environment_name(m, subnet):
    """An environment's Azure name: cae-ciam-<env>-<subnet>, or -checks outside any network; lowercase letters,
    digits and hyphens, at most 32 (the Container Apps names' rule)."""
    return job_name(f"cae-ciam-{rdn_value(m.env)}-{rdn_value(subnet) if subnet is not None else 'checks'}")


def _environment(m, subnet):
    """A checks' environment: in subnet (with its delegation note), else outside any network."""
    where = (comment(note_comment(_delegation(m, subnet))),) if subnet is not None else ()
    address = f"checks_{tf_name(rdn_value(subnet))}" if subnet is not None else "checks"
    return (*where, tf_block("resource", [ENVIRONMENT, address], [
        ("name", _environment_name(m, subnet)), ("resource_group_name", RG), ("location", LOC),
        *((("infrastructure_subnet_id", ref(f"data.azurerm_subnet.{tf_name(rdn_value(subnet))}.id")),
           ("internal_load_balancer_enabled", True)) if subnet is not None else ()),
        ("workload_profile", Block((("name", PROFILE), ("workload_profile_type", PROFILE)))),
        ("tags", tagged(m, {"ManagedBy": "opsdir"}))]))


def _vaults(m, live):
    """The Key Vaults the jobs' credentials are in (each once), and the notes on who may start the jobs and on their
    first runs as comments."""
    vaults = dict.fromkeys(_vault_secret(s)[0] for s in live if s.secret is not None)
    return (*(tf_block("data", ["azurerm_key_vault", tf_name(vault)], [("name", vault), ("resource_group_name", RG)])
              for vault in vaults),
            *(comment(note_comment(n)) for n in (_start_rights(m), *_first_runs(m))))


def _hosts(m, live):
    """The registries the jobs' recorded images are in (image delivery), each once."""
    return tuple(dict.fromkeys(registry(recorded_image(s)) for s in live)) if delivery(m) == "image" else ()


def _inputs(m, live):
    return (tf_block("variable", [CONNECTION], [
                ("description", "The connection string of the Application Insights resource the scripted checks report "
                                "to (the one application_insights_id names)"),
                ("type", ref("string")), ("sensitive", True)]),
            insights_input(),
            *(tf_block("variable", [_registry_input(host)], [
                ("description", f"The resource ID of the container registry {host} the check jobs pull their image "
                                "from (each job's identity gets AcrPull on it)"),
                ("type", ref("string"))]) for host in _hosts(m, live)))


def render_jobs(m, endpoints):
    """(HCL and comments, {path: text}) of environment m's scripted checks: the jobs and what they share, and the
    check image's build context (image delivery, while any check needs it) or the runner beside the root (script)."""
    done, placement = rendered(m, endpoints)
    live = tuple(s for s, why in done if why is None and s.keeper is None)
    where = _environments(placement, live)
    subnets = subnets_used(_live_placement(placement, live))
    jobs = ((s, _job(m, s, why, where.get(s.name, "checks"))) for s, why in done)
    hcl = (*(x for s, items in jobs for x in (from_entry(s.binding.dn, items) if s.binding is not None else items)),
           *((*(x for subnet in (subnets or (None,)) for x in _environment(m, subnet)), *_vaults(m, live),
              *_inputs(m, live)) if live else ()))
    if delivery(m) == "image":
        files = {f"{CONTEXT}/Dockerfile": dockerfile(m, _hosts(m, live)), f"{CONTEXT}/check.py": runner(m)} \
            if _needs_image(m, done) else {}
    else:
        files = {f"terraform/{RUNNER}": runner(m)} if live else {}
    return hcl, files
