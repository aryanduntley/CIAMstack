"""Scripted synthetic checks on Azure rendered from the record as Container Apps scheduled jobs: an oidc-token check
reading its Key Vault secret when it runs, an LDAPS bind of an internal service from the subnet the firewall admits,
one environment and one identity for them, results reported to Application Insights; what can't run is named."""
import ast
import io
import json
import urllib.request

from opsdir.core.contract import Endpoint
from opsdir.domains.observability.naming import CANARIES
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_azure.check_jobs import cron, job_name, render_jobs
from network_fixtures import BETA, entry, model, rule

ENDPOINTS = (Endpoint("health", "/pf/heartbeat.ping", "web"), Endpoint("token", "/as/token.oauth2", "web"))


def _canary(cn, **attrs):
    return entry(CANARIES, cn, "ciamCanary", **attrs).replace("objectClass: ciamCanary",
                                                               "objectClass: ciamObject\nobjectClass: ciamCanary")


TREE = (f"dn: {CANARIES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: canaries\n",
        _canary("sso-alive", ciamCheckedService="sso", ciamCanaryFlow="health"),
        _canary("sso-token", ciamCheckedService="sso", ciamCanaryFlow="oidc-token", ciamUsesRole="client",
                ciamInterval="7m"))
BINDINGS = (entry(BETA, "svc-sso", "ciamServiceName", ciamBindingRole="sso", ciamFqdn="sso.example.test",
                  ciamTargetRole="web", ciamFrontendIp="203.0.113.10"),
            entry(BETA, "client", "ciamSecretRef", ciamBindingRole="client", ciamRefUri="azkv://kv-ciam/canary-client"),
            entry(BETA, "Token-Check", "ciamCanaryBinding", ciamBindingRole="canary-sso-token",
                  ciamRealizes="sso-token"))
LDAP = (_canary("directory", ciamCheckedService="ldaps", ciamCanaryFlow="ldap-bind", ciamUsesRole="client"),
        _canary("anonymous", ciamCheckedService="ldaps", ciamCanaryFlow="ldap-bind"))
INTERNAL = (entry(BETA, "svc-ldaps", "ciamServiceName", ciamBindingRole="ldaps", ciamFqdn="ldap.example.test",
                  ciamPort="1636", ciamTargetRole="ds", ciamFrontendIp="10.1.1.100"),
            rule(BETA, "fw-web-ds", "10.1.2.0/24", "1636", "ds"))


def _render(bindings=BINDINGS, tree=TREE, gov=False):
    _, _, beta = model(beta=bindings, tree=tree)
    if gov:
        beta = beta._replace(cloud=beta.cloud._replace(attrs={**beta.cloud.attrs, "ciamRegion": ("usgovvirginia",)}))
    hcl, scripts = as_text(render_jobs(beta, ENDPOINTS))
    return "\n".join(hcl), hcl, scripts


def test_a_token_check_runs_as_a_scheduled_job_reading_its_secret_from_key_vault():
    text, _, scripts = _render()
    assert 'resource "azurerm_container_app_job" "token_check" {' in text
    assert 'name                         = "token-check"' in text
    assert 'cron_expression          = "*/10 * * * *"' in text                     # 7m raised to 10m
    assert "replica_retry_limit          = 0" in text and 'workload_profile_name        = "Consumption"' in text
    assert ('    key_vault_secret_id = "${data.azurerm_key_vault.kv_ciam.vault_uri}secrets/canary-client"\n'
            '    identity            = azurerm_user_assigned_identity.checks.id\n') in text
    assert 'data "azurerm_key_vault" "kv_ciam" {' in text
    assert 'value = file("${path.module}/checks/token-check/check.py")' in text
    assert 'name        = "CHECK_CREDENTIALS"\n        secret_name = "credentials"' in text
    assert 'Realizes    = "sso-token"' in text and 'BindingRole = "canary-sso-token"' in text
    assert "sso-alive" not in text                                  # a standard web test's (canaries)
    script = scripts["terraform/checks/token-check/check.py"]
    assert "URL = 'https://sso.example.test/as/token.oauth2'" in script and "FLOW = 'oidc-token'" in script
    assert "AUDIENCE = 'https://monitor.azure.com'" in script
    ast.parse(script)


def test_one_environment_and_identity_with_the_grants_the_jobs_need():
    text, hcl, _ = _render()
    assert 'resource "azurerm_container_app_environment" "checks" {' in text
    assert "infrastructure_subnet_id" not in text                   # a public check: no virtual network
    assert ('resource "azurerm_role_assignment" "checks_kv_ciam_canary_client" {\n'
            '  scope                = "${data.azurerm_key_vault.kv_ciam.id}/secrets/canary-client"\n'
            '  role_definition_name = "Key Vault Secrets User"\n') in text
    assert ('  scope                = var.application_insights_id\n'
            '  role_definition_name = "Monitoring Metrics Publisher"\n') in text
    assert ("depends_on = [azurerm_role_assignment.checks_publisher, "
            "azurerm_role_assignment.checks_kv_ciam_canary_client]") in text
    assert any(x.startswith('variable "application_insights_connection_string"') and "sensitive   = true" in x
               for x in hcl)
    assert any(x.startswith('variable "application_insights_id"') for x in hcl)


def test_an_internal_ldap_check_runs_in_the_subnet_the_firewall_admits():
    text, _, scripts = _render((*BINDINGS, *INTERNAL), (*TREE, *LDAP))
    assert ("  infrastructure_subnet_id       = data.azurerm_subnet.subnet_web.id\n"
            "  internal_load_balancer_enabled = true\n") in text
    assert "# Subnet subnet-web must be delegated to Microsoft.App/environments" in text
    anonymous, bound = scripts["terraform/checks/anonymous/check.py"], scripts["terraform/checks/directory/check.py"]
    assert "URL = 'ldaps://ldap.example.test:1636'" in anonymous and "FLOW = 'ldap-bind'" in bound
    job = text[text.index('resource "azurerm_container_app_job" "anonymous"'):]
    job = job[:job.index("\n}\n")]
    assert "CHECK_CREDENTIALS" not in job and "key_vault_secret_id" not in job      # an anonymous bind


def test_what_a_job_cant_run_is_named():
    vault = tuple(b.replace("azkv://kv-ciam/canary-client", "vault://secret/canary") for b in BINDINGS)
    _, hcl, _ = _render(vault)
    assert hcl == ("# NOTE: canary sso-token: not rendered: its credentials (client) aren't a Key Vault secret "
                   "(azkv://)",)


def test_azure_government_checks_ask_its_own_monitor_audience():
    _, _, scripts = _render(gov=True)
    assert "AUDIENCE = 'https://monitor.azure.us'" in scripts["terraform/checks/token-check/check.py"]


def test_names_and_schedules():
    assert job_name("Token_Check") == "token-check" and job_name("7-up") == "c-7-up"
    assert len(job_name("x" * 40)) == 32
    assert [cron(s) for s in (30, 60, 300, 420, 3600, 5400, 86400, 172800)] == [
        "* * * * *", "* * * * *", "*/5 * * * *", "*/10 * * * *", "0 */1 * * *", "0 */2 * * *", "0 0 * * *",
        "0 0 * * *"]


class _Answer(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def test_the_script_reports_an_availability_result_with_an_entra_token(monkeypatch):
    _, _, scripts = _render()
    sent = []

    def urlopen(request, timeout=None):
        sent.append(request)
        url = request.full_url
        if url.startswith("http://identity"):
            return _Answer(json.dumps({"access_token": "entra"}).encode())
        if url.endswith("/token.oauth2"):
            return _Answer(json.dumps({"access_token": "issued"}).encode())
        return _Answer(b"{}")

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    for k, v in {"APPLICATIONINSIGHTS_CONNECTION_STRING": "InstrumentationKey=ik;IngestionEndpoint=https://in.test/",
                 "IDENTITY_ENDPOINT": "http://identity/token", "IDENTITY_HEADER": "h", "AZURE_CLIENT_ID": "cid",
                 "CHECK_LOCATION": "eastus",
                 "CHECK_CREDENTIALS": json.dumps({"client_id": "c", "client_secret": "s"})}.items():
        monkeypatch.setenv(k, v)
    exec(compile(scripts["terraform/checks/token-check/check.py"], "check.py", "exec"), {})
    track = sent[-1]
    assert track.full_url == "https://in.test/v2.1/track" and track.get_header("Authorization") == "Bearer entra"
    assert "client_id=cid" in sent[1].full_url and "monitor.azure.com" in sent[1].full_url
    envelope = json.loads(track.data)
    data = envelope["data"]["baseData"]
    assert envelope["iKey"] == "ik" and envelope["data"]["baseType"] == "AvailabilityData"
    assert (data["name"], data["success"], data["runLocation"]) == ("Token-Check", True, "eastus")
    assert data["message"] == "HTTP 200, access token issued" and data["duration"].startswith("00.00:00:")


def test_a_job_reads_back_as_the_canary_binding_it_realizes_from_state_cli_and_arm():
    from opsdir_adapter_azure.check_jobs import cron_seconds
    from opsdir_adapter_azure.cli_monitor import monitor_items
    from opsdir_adapter_azure.inventory import pairs_resources
    assert [cron_seconds(cron(s)) for s in (60, 300, 600, 3600, 7200, 86400)] == [60, 300, 600, 3600, 7200, 86400]
    assert cron_seconds("5 4 * * 1") is None and cron_seconds(None) is None
    tags = {"Realizes": "sso-token", "BindingRole": "canary-sso-token"}
    job_id = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.App/jobs/token-check"
    state = ("azurerm_container_app_job", {"id": job_id, "name": "token-check", "tags": tags,
                                            "schedule_trigger_config": [{"cron_expression": "*/10 * * * *"}]})
    other = ("azurerm_container_app_job", {"id": job_id + "-x", "name": "batch", "tags": {},
                                            "schedule_trigger_config": [{"cron_expression": "0 0 * * *"}]})
    flat = {"id": job_id, "name": "token-check", "type": "Microsoft.App/jobs", "tags": tags,
            "cronExpression": "*/10 * * * *"}
    nested = {"id": job_id, "name": "token-check", "type": "Microsoft.App/jobs", "tags": tags,
              "properties": {"configuration": {"scheduleTriggerConfig": {"cronExpression": "*/10 * * * *"}}}}
    cli = [p for item in (flat, nested) for p in monitor_items([("microsoft.app/jobs", item)])]
    assert cli == [state, state]
    canaries = [r for r in pairs_resources([state, other])[0] if r.kind == "canary"]
    assert [(r.ref, r.attrs, r.role) for r in canaries] == [
        (job_id, {"ciamInterval": ("10m",), "ciamRealizes": ("sso-token",)}, "canary-sso-token")]


def test_as_bicep_the_environment_is_native_and_the_jobs_stay_terraform_with_their_scripts(monkeypatch):
    from types import SimpleNamespace
    from opsdir_format_terraform.hcl import TfFile, ref, tf_block
    import opsdir_adapter_azure.terraform as terraform
    stub = SimpleNamespace(dn="env=prod,cloud=alpha,ou=environments,dc=ciam-ops", label="alpha/prod")
    _, _, beta = model(beta=(*BINDINGS, *INTERNAL), tree=(*TREE, *LDAP))
    hcl, scripts = render_jobs(beta, ENDPOINTS)
    root = TfFile("", (tf_block("data", ["azurerm_resource_group", "main"], [("name", "rg-a")]),
                       tf_block("data", ["azurerm_subnet", "subnet_web"], [
                           ("name", "snet-web"), ("virtual_network_name", "vnet-a"),
                           ("resource_group_name", ref("data.azurerm_resource_group.main.name"))]), *hcl))
    monkeypatch.setattr(terraform, "render_files", lambda m, services: {"terraform/main.tf": root, **scripts})
    files = terraform.render(stub, None, ("bicep",))
    assert "terraform/main.tf" not in files
    template = files["bicep/rg-a.bicep"]
    assert "resource container_app_environment_checks 'Microsoft.App/managedEnvironments@2026-07-01' = {" in template
    assert "infrastructureSubnetId: subnets_snet_web.id\n      internal: true" in template
    assert "'4633458b-17de-408a-b874-0445c86b69e6')" in template                 # Key Vault Secrets User
    side = files["bicep/terraform/main.tf"]
    assert "#   azurerm_container_app_job.token_check: its check script is read from a file beside the root" in side
    assert "container_app_environment_id = var.azurerm_container_app_environment_checks_id" in side
    assert "depends_on = [azurerm_role_assignment.checks_publisher]" in side      # the template's grant: applied
    assert {p for p in files if p.endswith("check.py")} == {f"bicep/terraform/checks/{n}/check.py"
                                                             for n in ("anonymous", "directory", "token-check")}
