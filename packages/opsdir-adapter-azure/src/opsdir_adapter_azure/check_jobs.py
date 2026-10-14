"""Scripted synthetic checks on Azure (core observability: domains/observability/canaries) as Azure Container Apps
scheduled jobs: the checks an Application Insights standard web test can't make (canaries.standard: a GET of an
internet-facing service name): an oidc-token check (it reads its credentials when it runs), an ldap-bind check (not
HTTP), and any check of an internal service name (the test locations reach public endpoints only). Decision 2841.
Pure.

One Container Apps environment for the environment's checks (azurerm_container_app_environment checks, workload
profiles, the Consumption profile; no charge for a job between executions): in the subnet the internal checks run from
(canary_specs: their canary binding's ciamSubnetRole, else the subnets the firewall rules admit to the service), with
an internal load balancer, when there is one; that subnet must be at least a /27 delegated to
Microsoft.App/environments (the network's keeper delegates it: said in a comment). Checks of an internal service the
environment's subnet isn't among the subnets of aren't rendered, and said so.

One job per check (azurerm_container_app_job named as its canary binding: lowercase letters, digits and -, at most 32),
on a schedule (a 5-field UTC cron from its interval, raised to the next that divides an hour or a day), one replica,
no retry (a failure is reported, not hidden), in the image the estate setting azure-check-image names (a Python 3
image, Microsoft's Azure Linux one by default: a Gov estate may name a mirror in its own registry). It runs its script
(terraform/checks/<job>/check.py: its do-not-edit header, the shared probes of observability.probes, and the reporter
below) from an environment variable (python3 -c exec), so no image is built. Its credentials, when it has some, are a
Key Vault secret reference (azkv://<vault>/<name>, its JSON holding client_id and client_secret, or bind_dn and
password, as on AWS) read by the platform into an environment variable: never written anywhere opsdir renders.

The reporter sends each result to Application Insights as an availability result (POST <IngestionEndpoint>/v2.1/track,
an AvailabilityData envelope, research 2840) from the connection string (the root's sensitive input
application_insights_connection_string), authenticated with an Entra token for the jobs' identity (audience
https://monitor.azure.com, Azure Government's https://monitor.azure.us), so it works with the resource's local
authentication disabled. The results sit with the standard tests' (application_insights_id input).

One user-assigned identity for the jobs (azurerm_user_assigned_identity checks; a system-assigned one exists only once
its job does, and a job is created with its Key Vault references resolved): Key Vault Secrets User on each credentials
secret, Monitoring Metrics Publisher on the Application Insights resource; the jobs wait for both.

Not rendered, and said so: what canary_specs names; a service name whose exposure isn't recorded; an internal one with
no subnet to run from, or not run from the environment's; a subnet smaller than /27; credentials that aren't a Key
Vault secret. A check someone else keeps, or an overlay inherits from its base, is named with its keeper. Live
validation (decision 2841): Key Vault references and MCR pulls from Azure Government, the script's size in a variable.
"""
import ipaddress
import re

from opsdir.core.contract import Setting
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import one_role
from opsdir.core.formats import PYTHON
from opsdir.core.manifest import header
from opsdir.core.settings import setting_value
from opsdir.domains.observability.canaries import canary_specs
from opsdir.domains.observability.probes import PYTHON_PROBES
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from .account import government, tagged
from .canaries import INPUT, insights_input, standard
from .identities import LOC, RG, scope

ENVIRONMENT, JOB = "azurerm_container_app_environment", "azurerm_container_app_job"
IDENTITY = "azurerm_user_assigned_identity.checks"
CONNECTION = "application_insights_connection_string"
VAULT = "azkv://"
PROFILE = "Consumption"
SMALLEST = 27                   # a workload-profiles environment's subnet: at least a /27
MINUTES = (1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30)
HOURS = (1, 2, 3, 4, 6, 8, 12, 24)
TIMEOUT = 120                   # seconds a run may take: the probe's and the report's 10-second timeouts, and start-up
AUDIENCE, GOV_AUDIENCE = "https://monitor.azure.com", "https://monitor.azure.us"
IMAGE = Setting("azure-check-image", "string", "mcr.microsoft.com/azurelinux/base/python:3.12",
                "The Python 3 container image the scripted synthetic checks opsdir renders run in (Azure Container "
                "Apps jobs; standard library only): a Gov estate may name a mirror in its own registry")
COMMAND = ["python3", "-c", "import os; exec(os.environ['CHECK_SCRIPT'])"]


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


# The check's reporter, after the probes (observability.probes): its credentials from the environment variable the
# platform fills from Key Vault (none: an anonymous LDAP bind), the result POSTed to Application Insights as an
# availability result with an Entra token for the jobs' identity, and the run failed when the check fails.
REPORTER = '''
import datetime
import os
import time
import uuid

FLOW = {flow!r}
URL = {url!r}
TEST = {test!r}
AUDIENCE = {audience!r}


def _connection():
    """(instrumentation key, ingestion endpoint) of the Application Insights connection string."""
    parts = dict(p.split("=", 1) for p in os.environ["APPLICATIONINSIGHTS_CONNECTION_STRING"].split(";") if "=" in p)
    return parts["InstrumentationKey"], parts["IngestionEndpoint"].rstrip("/")


def _token():
    """An Entra access token for the jobs' identity (the Container Apps identity endpoint)."""
    query = urllib.parse.urlencode({{"resource": AUDIENCE, "api-version": "2019-08-01",
                                    "client_id": os.environ["AZURE_CLIENT_ID"]}})
    request = urllib.request.Request(f"{{os.environ['IDENTITY_ENDPOINT']}}?{{query}}",
                                     headers={{"X-IDENTITY-HEADER": os.environ["IDENTITY_HEADER"]}})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.loads(response.read())["access_token"]


def _duration(seconds):
    """DD.HH:MM:SS.MMMMMM"""
    whole, micro = divmod(round(seconds * 1000000), 1000000)
    minutes, secs = divmod(whole, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    return f"{{days:02d}}.{{hours:02d}}:{{minutes:02d}}:{{secs:02d}}.{{micro:06d}}"


def report(success, message, seconds):
    """The result as an availability result in Application Insights."""
    key, endpoint = _connection()
    envelope = {{"ver": 1, "name": "Microsoft.ApplicationInsights.Availability", "sampleRate": 100, "iKey": key,
                "time": datetime.datetime.now(datetime.timezone.utc).isoformat(), "flags": 0,
                "data": {{"baseType": "AvailabilityData", "baseData": {{
                    "ver": 2, "id": str(uuid.uuid4()), "name": TEST, "duration": _duration(seconds),
                    "success": success, "runLocation": os.environ.get("CHECK_LOCATION", ""), "message": message[:8192],
                    "properties": {{"flow": FLOW, "url": URL}}}}}}}}
    request = urllib.request.Request(f"{{endpoint}}/v2.1/track", data=json.dumps(envelope).encode(), method="POST",
                                     headers={{"Content-Type": "application/json",
                                              "Authorization": f"Bearer {{_token()}}"}})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.status


def main():
    """{flow} check of URL: the probe raises when it fails, failing the run."""
    creds = json.loads(os.environ["CHECK_CREDENTIALS"]) if os.environ.get("CHECK_CREDENTIALS") else None
    start = time.monotonic()
    try:
        success, message = True, probe(FLOW, URL, creds)
    except Exception as failure:
        success, message = False, f"{{type(failure).__name__}}: {{failure}}"
    report(success, message, time.monotonic() - start)
    print(f"{{URL}}: {{'passed' if success else 'failed'}}: {{message}}")
    if not success:
        raise SystemExit(1)


main()
'''


def script(m, spec):
    """The check's Python script, with its do-not-edit header."""
    return (header(m, f"Azure Container Apps job {job_name(spec.name)} ({spec.flow})", PYTHON) + PYTHON_PROBES
            + REPORTER.format(flow=spec.flow, url=spec.url, test=spec.name,
                              audience=GOV_AUDIENCE if government(m) else AUDIENCE))


def _grant(secret):
    """The address name of the role assignment letting the jobs read a credentials secret (vault, name)."""
    return f"checks_{tf_name(secret[0])}_{tf_name(secret[1])}"


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


def home(specs):
    """The subnet binding the checks' environment is in: the first subnet of the first internal check, else None."""
    return next((s.subnets[0] for s in specs if s.exposure == "internal" and s.subnets), None)


def _prefix(subnet):
    cidr = one(subnet, "ciamCidr")
    return ipaddress.ip_network(cidr, strict=False).prefixlen if cidr else None


def _why(m, spec, subnet):
    svc = one_role(m, one(spec.canary, "ciamCheckedService"))
    if spec.exposure is None:
        return (f"service name {rdn_value(svc)} records neither a frontend address nor its exposure: whether its "
                "check runs in the virtual network is unknown")
    if spec.exposure == "internal" and not spec.subnets:
        return (f"service name {rdn_value(svc)} is internal and no subnet is named to run its check from: name one on "
                "its canary binding (ciamSubnetRole), or record a firewall rule admitting a subnet to "
                + one(svc, "ciamTargetRole") + (f" on {one(svc, 'ciamPort')}" if one(svc, "ciamPort") else ""))
    if spec.exposure == "internal" and subnet not in spec.subnets:
        return (f"the environment's checks run from subnet {rdn_value(subnet)} (one Container Apps environment), not "
                f"from {', '.join(rdn_value(s) for s in spec.subnets)}: name {one(subnet, 'ciamBindingRole')} on its "
                "canary binding (ciamSubnetRole), with a firewall rule admitting it")
    if spec.exposure == "internal" and (_prefix(subnet) or 0) > SMALLEST:
        return (f"subnet {rdn_value(subnet)} ({one(subnet, 'ciamCidr')}) is smaller than the /{SMALLEST} a Container "
                "Apps environment with workload profiles needs")
    if spec.secret is not None and _vault_secret(spec) is None:
        return f"its credentials ({rdn_value(spec.secret)}) aren't a Key Vault secret (azkv://)"
    return None


def rendered(m, endpoints):
    """(CanarySpec, why not or None) of environment m's scripted checks, and the subnet binding their environment is
    in (or None)."""
    specs = scripted(canary_specs(m, endpoints))
    subnet = home(specs)
    return tuple((s, _why(m, s, subnet)) for s in specs), subnet


def _path(spec):
    return f"checks/{job_name(spec.name)}/check.py"


def _job(m, spec, why):
    cn = rdn_value(spec.canary)
    if why:
        return (comment(f"NOTE: canary {cn}: not rendered: {why}"),)
    name = job_name(spec.name)
    if spec.keeper is not None:
        return (comment(f"Check job {name} ({cn}): kept by {spec.keeper}, not rendered here"),)
    secret = _vault_secret(spec)
    secrets = (("secret", Block((("name", "credentials"),
                                 ("key_vault_secret_id", f"${{data.azurerm_key_vault.{tf_name(secret[0])}.vault_uri}}"
                                                         f"secrets/{secret[1]}"),
                                 ("identity", ref(f"{IDENTITY}.id"))))),) if secret else ()
    env = (("CHECK_SCRIPT", ("value", ref(f'file("${{path.module}}/{_path(spec)}")'))),
           ("CHECK_LOCATION", ("value", LOC)),
           ("AZURE_CLIENT_ID", ("value", ref(f"{IDENTITY}.client_id"))),
           ("APPLICATIONINSIGHTS_CONNECTION_STRING", ("secret_name", "appinsights")),
           *((("CHECK_CREDENTIALS", ("secret_name", "credentials")),) if secret else ()))
    return (tf_block("resource", [JOB, tf_name(name)], [
            ("name", name), ("resource_group_name", RG), ("location", LOC),
            ("container_app_environment_id", ref(f"{ENVIRONMENT}.checks.id")), ("workload_profile_name", PROFILE),
            ("replica_timeout_in_seconds", TIMEOUT), ("replica_retry_limit", 0),
            ("schedule_trigger_config", Block((("cron_expression", cron(spec.every)), ("parallelism", 1),
                                               ("replica_completion_count", 1)))),
            ("identity", Block((("type", "UserAssigned"), ("identity_ids", [ref(f"{IDENTITY}.id")])))),
            ("secret", Block((("name", "appinsights"), ("value", ref(f"var.{CONNECTION}"))))),
            *secrets,
            ("template", Block((("container", Block((
                ("name", "check"), ("image", setting_value(m.d, IMAGE)), ("cpu", 0.25), ("memory", "0.5Gi"),
                ("command", COMMAND),
                *(("env", Block((("name", k), v))) for k, v in env)))),))),
            ("tags", tagged(m, {"Realizes": cn, "BindingRole": one(spec.binding, "ciamBindingRole")
                                if spec.binding is not None else f"canary-{cn}"})),
            ("depends_on", [ref("azurerm_role_assignment.checks_publisher"),
                            *((ref(f"azurerm_role_assignment.{_grant(secret)}"),) if secret else ())])]),)


def _environment(m, subnet):
    where = (comment(f"Subnet {rdn_value(subnet)} must be delegated to Microsoft.App/environments (the network's "
                     "keeper delegates it) and hold nothing else"),) if subnet is not None else ()
    return (*where, tf_block("resource", [ENVIRONMENT, "checks"], [
        ("name", f"cae-ciam-{rdn_value(m.env)}-checks"), ("resource_group_name", RG), ("location", LOC),
        *((("infrastructure_subnet_id", ref(f"data.azurerm_subnet.{tf_name(rdn_value(subnet))}.id")),
           ("internal_load_balancer_enabled", True)) if subnet is not None else ()),
        ("workload_profile", Block((("name", PROFILE), ("workload_profile_type", PROFILE)))),
        ("tags", tagged(m, {"ManagedBy": "opsdir"}))]))


def _identity(m, live):
    """The jobs' identity, its grants, and the Key Vaults their credentials are in (each once)."""
    secrets = {_vault_secret(s): s.secret for s in live if s.secret is not None}
    vaults = dict.fromkeys(vault for vault, _ in secrets)
    return (*(tf_block("data", ["azurerm_key_vault", tf_name(vault)], [("name", vault), ("resource_group_name", RG)])
              for vault in vaults),
            tf_block("resource", ["azurerm_user_assigned_identity", "checks"], [
                ("name", f"id-ciam-{rdn_value(m.env)}-checks"), ("resource_group_name", RG), ("location", LOC),
                ("tags", tagged(m, {"ManagedBy": "opsdir"}))]),
            tf_block("resource", ["azurerm_role_assignment", "checks_publisher"], [
                ("scope", ref(f"var.{INPUT}")), ("role_definition_name", "Monitoring Metrics Publisher"),
                ("principal_id", ref(f"{IDENTITY}.principal_id"))]),
            *(tf_block("resource", ["azurerm_role_assignment", _grant(secret)], [
                ("scope", scope(b)[0]), ("role_definition_name", "Key Vault Secrets User"),
                ("principal_id", ref(f"{IDENTITY}.principal_id"))]) for secret, b in secrets.items()))


def _inputs():
    return (tf_block("variable", [CONNECTION], [
                ("description", "The connection string of the Application Insights resource the scripted checks report "
                                "to (the one application_insights_id names)"),
                ("type", ref("string")), ("sensitive", True)]),
            insights_input())


def render_jobs(m, endpoints):
    """(HCL and comments, {path: script}) of environment m's scripted checks."""
    done, subnet = rendered(m, endpoints)
    live = tuple(s for s, why in done if why is None and s.keeper is None)
    hcl = (*(x for s, why in done for x in (from_entry(s.binding.dn, _job(m, s, why))
                                             if s.binding is not None else _job(m, s, why))),
           *((*_environment(m, subnet), *_identity(m, live), *_inputs()) if live else ()))
    return hcl, {f"terraform/{_path(s)}": script(m, s) for s in live}
