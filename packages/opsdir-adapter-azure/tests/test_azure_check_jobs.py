"""Scripted synthetic checks on Azure rendered from the record as Container Apps scheduled jobs: every job runs the same
runner, given its check as data; by default from the image the organization builds from the rendered build context and
records on each canary binding by digest (pulled with the job's own identity), else (a lab's choice) read from a
variable; an oidc-token check reading its Key Vault secret when it runs, an LDAPS bind of an internal service from the
subnet the firewall admits, one environment and an identity per job, results reported to Application Insights; what
can't run, or needs a person, is a render note."""
import ast
import base64
import io
import json
import ssl
import urllib.request

import pytest

from opsdir.core.contract import Endpoint
from opsdir.domains.observability.naming import CANARIES
from opsdir_format_terraform.hcl import as_text, blocks_of
import opsdir_adapter_azure.check_jobs as check_jobs
from opsdir_adapter_azure.canaries import render_tests
from opsdir_adapter_azure.check_jobs import cron, job_name, render_jobs
from network_fixtures import BETA, entry, model, rule
from pki_samples import CA_PEM, CERTIFICATES, private_chain

ENDPOINTS = (Endpoint("health", "/pf/heartbeat.ping", "web"), Endpoint("token", "/as/token.oauth2", "web"))
DIGEST = "sha256:" + "0" * 63 + "1"
IMAGE = f"crciam.azurecr.io/ciam/check@{DIGEST}"


def _canary(cn, **attrs):
    return entry(CANARIES, cn, "ciamCanary", **attrs).replace("objectClass: ciamCanary",
                                                               "objectClass: ciamObject\nobjectClass: ciamCanary")


def _binding(cn, canary, image=IMAGE):
    return entry(BETA, cn, "ciamCanaryBinding", ciamBindingRole=f"canary-{canary}", ciamRealizes=canary,
                 **({"ciamContainerImage": f"check={image}"} if image else {}))


TREE = (f"dn: {CANARIES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: canaries\n",
        _canary("sso-alive", ciamCheckedService="sso", ciamCanaryFlow="health"),
        _canary("sso-token", ciamCheckedService="sso", ciamCanaryFlow="oidc-token", ciamUsesRole="client",
                ciamInterval="7m"))
BINDINGS = (entry(BETA, "svc-sso", "ciamServiceName", ciamBindingRole="sso", ciamFqdn="sso.example.test",
                  ciamTargetRole="web", ciamFrontendIp="203.0.113.10"),
            entry(BETA, "client", "ciamSecretRef", ciamBindingRole="client", ciamRefUri="azkv://kv-ciam/canary-client"),
            _binding("Token-Check", "sso-token"))
LDAP = (_canary("directory", ciamCheckedService="ldaps", ciamCanaryFlow="ldap-bind", ciamUsesRole="client"),
        _canary("anonymous", ciamCheckedService="ldaps", ciamCanaryFlow="ldap-bind"))
INTERNAL = (entry(BETA, "svc-ldaps", "ciamServiceName", ciamBindingRole="ldaps", ciamFqdn="ldap.example.test",
                  ciamPort="1636", ciamTargetRole="ds", ciamFrontendIp="10.1.1.100"),
            rule(BETA, "fw-web-ds", "10.1.2.0/24", "1636", "ds"),
            _binding("directory", "directory"), _binding("anonymous", "anonymous"))


def _model(bindings=BINDINGS, tree=TREE, gov=False):
    _, _, beta = model(beta=bindings, tree=tree)
    if gov:
        beta = beta._replace(cloud=beta.cloud._replace(attrs={**beta.cloud.attrs, "ciamRegion": ("usgovvirginia",)}))
    return beta


def _render(bindings=BINDINGS, tree=TREE, gov=False):
    hcl, files = as_text(render_jobs(_model(bindings, tree, gov), ENDPOINTS))
    return "\n".join(hcl), hcl, files


def _job(text, name):
    job = text[text.index(f'resource "azurerm_container_app_job" "{name}"'):]
    return job[:job.index("\n}\n")]


def test_a_job_runs_the_recorded_image_given_its_check_as_data():
    text, _, files = _render()
    job = _job(text, "token_check")
    assert 'name                         = "token-check"' in job
    assert 'cron_expression          = "*/10 * * * *"' in job                       # 7m raised to 10m
    assert "replica_retry_limit          = 0" in job and 'workload_profile_name        = "Consumption"' in job
    assert ("  registry {\n    server   = \"crciam.azurecr.io\"\n"
            "    identity = azurerm_user_assigned_identity.check_token_check.id\n  }\n") in job
    assert f'      image  = "{IMAGE}"' in job and "command" not in job and "CHECK_SCRIPT" not in job
    for name, value in (("CHECK_FLOW", "oidc-token"), ("CHECK_URL", "https://sso.example.test/as/token.oauth2"),
                        ("CHECK_TEST", "Token-Check"), ("CHECK_AUDIENCE", "https://monitor.azure.com")):
        assert f'        name  = "{name}"\n        value = "{value}"' in job                # data, never code
    assert ('    key_vault_secret_id = "${data.azurerm_key_vault.kv_ciam.vault_uri}secrets/canary-client"\n'
            '    identity            = azurerm_user_assigned_identity.check_token_check.id\n') in job
    assert 'name        = "CHECK_CREDENTIALS"\n        secret_name = "credentials"' in job
    assert 'Realizes    = "sso-token"' in job and 'BindingRole = "canary-sso-token"' in job
    assert "sso-alive" not in text                                  # a standard web test's (canaries)
    assert sorted(files) == ["images/ciam-check/Dockerfile", "images/ciam-check/check.py"]
    ast.parse(files["images/ciam-check/check.py"])


def test_the_build_context_builds_the_runner_from_the_base_image_as_non_root():
    _, _, files = _render()
    dockerfile = files["images/ciam-check/Dockerfile"]
    assert dockerfile.startswith("# Generated by opsdir from ")
    assert "\n# NOTE: check image: build it from " in dockerfile
    assert "FROM mcr.microsoft.com/azurelinux/distroless/python:3.12-nonroot\n" in dockerfile
    assert "COPY check.py /opt/ciam-check/check.py\nUSER nonroot\n" in dockerfile
    assert dockerfile.endswith('ENTRYPOINT ["/usr/bin/python3", "/opt/ciam-check/check.py"]\n')
    runner = files["images/ciam-check/check.py"]
    assert 'FLOW = os.environ["CHECK_FLOW"]' in runner and "sso.example.test" not in runner   # one image for all


def test_one_environment_and_an_identity_per_job_with_only_its_own_grants():
    text, hcl, _ = _render()
    assert 'resource "azurerm_container_app_environment" "checks" {' in text
    assert "infrastructure_subnet_id" not in text                   # a public check: no virtual network
    assert ('resource "azurerm_user_assigned_identity" "check_token_check" {\n'
            '  name                = "id-ciam-prod-token-check"\n') in text
    assert ('resource "azurerm_role_assignment" "check_token_check_secret" {\n'
            '  scope                = "${data.azurerm_key_vault.kv_ciam.id}/secrets/canary-client"\n'
            '  role_definition_name = "Key Vault Secrets User"\n'
            '  principal_id         = azurerm_user_assigned_identity.check_token_check.principal_id\n') in text
    assert ('resource "azurerm_role_assignment" "check_token_check_publisher" {\n'
            '  scope                = var.application_insights_id\n'
            '  role_definition_name = "Monitoring Metrics Publisher"\n') in text
    assert ('resource "azurerm_role_assignment" "check_token_check_pull" {\n'
            '  scope                = var.registry_crciam_azurecr_io_id\n'
            '  role_definition_name = "AcrPull"\n') in text
    assert ("depends_on = [azurerm_role_assignment.check_token_check_publisher, "
            "azurerm_role_assignment.check_token_check_secret, azurerm_role_assignment.check_token_check_pull]") in text
    assert text.count('role_definition_name = "Key Vault Secrets User"') == 1      # no other job reads the secret
    assert any(x.startswith('variable "application_insights_connection_string"') and "sensitive   = true" in x
               for x in hcl)
    assert any(x.startswith('variable "application_insights_id"') for x in hcl)
    assert any(x.startswith('variable "registry_crciam_azurecr_io_id"') for x in hcl)


def test_an_internal_ldap_check_runs_in_the_subnet_the_firewall_admits():
    text, _, _ = _render((*BINDINGS, *INTERNAL), (*TREE, *LDAP))
    assert ("  infrastructure_subnet_id       = data.azurerm_subnet.subnet_web.id\n"
            "  internal_load_balancer_enabled = true\n") in text
    assert "# NOTE: subnet subnet-web: must be delegated to Microsoft.App/environments" in text
    anonymous = _job(text, "anonymous")
    assert 'value = "ldaps://ldap.example.test:1636"' in anonymous and 'value = "ldap-bind"' in anonymous
    assert "CHECK_CREDENTIALS" not in anonymous and "key_vault_secret_id" not in anonymous   # an anonymous bind


def test_what_a_job_cant_run_is_a_note_and_the_image_is_still_to_build():
    vault = tuple(b.replace("azkv://kv-ciam/canary-client", "vault://secret/canary") for b in BINDINGS)
    _, hcl, files = _render(vault)
    assert hcl == ("# NOTE: canary sso-token: not rendered: its credentials (client) aren't a Key Vault secret "
                   "(azkv://)",) and files == {}
    unrecorded = (*BINDINGS[:2], _binding("Token-Check", "sso-token", image=None))
    _, hcl, files = _render(unrecorded)
    assert hcl == ("# NOTE: canary sso-token: not rendered: its canary binding Token-Check records no check image to "
                   "run (azure-check-delivery image)",)
    assert sorted(files) == ["images/ciam-check/Dockerfile", "images/ciam-check/check.py"]   # what to build it from


def test_an_image_recorded_by_tag_runs_with_a_note_to_pin_its_digest():
    tagged = (*BINDINGS[:2], _binding("Token-Check", "sso-token", image="crciam.azurecr.io/ciam/check:1.0"))
    text, _, _ = _render(tagged)
    assert ("# NOTE: check job token-check: runs crciam.azurecr.io/ciam/check:1.0 by tag: a tag can move to an image "
            "nobody signed or verified") in text
    assert 'image  = "crciam.azurecr.io/ciam/check:1.0"' in _job(text, "token_check")


def test_azure_government_checks_ask_its_own_monitor_audience():
    text, _, _ = _render(gov=True)
    assert '        name  = "CHECK_AUDIENCE"\n        value = "https://monitor.azure.us"' in text


def test_a_lab_may_run_the_runner_from_a_variable_instead(monkeypatch):
    monkeypatch.setattr(check_jobs, "delivery", lambda m: "script")
    text, hcl, files = _render()
    job = _job(text, "token_check")
    assert '= "mcr.microsoft.com/azurelinux/distroless/python:3.12-nonroot"' in job        # the base image
    assert '"import os; exec(os.environ[\'CHECK_SCRIPT\'])"' in job and "registry" not in job
    assert 'value = file("${path.module}/checks/check.py")' in job and "_pull" not in text
    assert sorted(files) == ["terraform/checks/check.py"] and not any("registry_" in x for x in hcl)


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


def test_the_runner_reports_an_availability_result_with_an_entra_token(monkeypatch):
    _, _, files = _render()
    sent = []

    def urlopen(request, timeout=None, context=None):
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
                 "CHECK_LOCATION": "eastus", "CHECK_FLOW": "oidc-token",
                 "CHECK_URL": "https://sso.example.test/as/token.oauth2", "CHECK_TEST": "Token-Check",
                 "CHECK_AUDIENCE": "https://monitor.azure.com",
                 "CHECK_CREDENTIALS": json.dumps({"client_id": "c", "client_secret": "s"})}.items():
        monkeypatch.setenv(k, v)
    exec(compile(files["images/ciam-check/check.py"], "check.py", "exec"), {})
    track = sent[-1]
    assert track.full_url == "https://in.test/v2.1/track" and track.get_header("Authorization") == "Bearer entra"
    assert "client_id=cid" in sent[1].full_url and "monitor.azure.com" in sent[1].full_url
    envelope = json.loads(track.data)
    data = envelope["data"]["baseData"]
    assert envelope["iKey"] == "ik" and envelope["data"]["baseType"] == "AvailabilityData"
    assert (data["name"], data["success"], data["runLocation"]) == ("Token-Check", True, "eastus")
    assert data["message"] == "HTTP 200, access token issued" and data["duration"].startswith("00.00:00:")


def test_a_job_reads_back_as_the_canary_binding_it_realizes_with_its_image_from_state_cli_and_arm():
    from opsdir_adapter_azure.check_jobs import cron_seconds
    from opsdir_adapter_azure.cli_monitor import monitor_items
    from opsdir_adapter_azure.inventory import pairs_resources
    assert [cron_seconds(cron(s)) for s in (60, 300, 600, 3600, 7200, 86400)] == [60, 300, 600, 3600, 7200, 86400]
    assert cron_seconds("5 4 * * 1") is None and cron_seconds(None) is None
    tags = {"Realizes": "sso-token", "BindingRole": "canary-sso-token"}
    job_id = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.App/jobs/token-check"
    state = ("azurerm_container_app_job", {"id": job_id, "name": "token-check", "tags": tags,
                                            "schedule_trigger_config": [{"cron_expression": "*/10 * * * *"}],
                                            "template": [{"container": [{"image": IMAGE}]}],
                                            "registry": [{"server": "crciam.azurecr.io"}]})
    other = ("azurerm_container_app_job", {"id": job_id + "-x", "name": "batch", "tags": {},
                                            "schedule_trigger_config": [{"cron_expression": "0 0 * * *"}]})
    flat = {"id": job_id, "name": "token-check", "type": "Microsoft.App/jobs", "tags": tags,
            "cronExpression": "*/10 * * * *", "image": IMAGE, "registries": ["crciam.azurecr.io"]}
    nested = {"id": job_id, "name": "token-check", "type": "Microsoft.App/jobs", "tags": tags,
              "properties": {"configuration": {"scheduleTriggerConfig": {"cronExpression": "*/10 * * * *"},
                                               "registries": [{"server": "crciam.azurecr.io", "identity": "x"}]},
                             "template": {"containers": [{"name": "check", "image": IMAGE}]}}}
    merged = {**{k: v for k, v in nested.items() if k != "properties"}, **nested["properties"]}   # the ARM reader's
    cli = [p for item in (flat, nested, merged) for p in monitor_items([("microsoft.app/jobs", item)])]
    assert cli == [state, state, state]
    canaries = [r for r in pairs_resources([state, other])[0] if r.kind == "canary"]
    assert [(r.ref, r.attrs, r.role) for r in canaries] == [
        (job_id, {"ciamInterval": ("10m",), "ciamRealizes": ("sso-token",),
                  "ciamContainerImage": (f"check={IMAGE}",)}, "canary-sso-token")]
    script_form = ("azurerm_container_app_job", {**state[1], "registry": []})          # the base image: not recorded
    assert "ciamContainerImage" not in [r for r in pairs_resources([script_form])[0] if r.kind == "canary"][0].attrs


def _root(m):
    """{path: TfFile | text} of environment m's check jobs in a Terraform root (with the lookups they read)."""
    from opsdir_format_terraform.hcl import TfFile, ref, tf_block
    hcl, files = render_jobs(m, ENDPOINTS)
    return {"terraform/main.tf": TfFile("", (
        tf_block("data", ["azurerm_resource_group", "main"], [("name", "rg-a")]),
        tf_block("data", ["azurerm_subnet", "subnet_web"], [
            ("name", "snet-web"), ("virtual_network_name", "vnet-a"),
            ("resource_group_name", ref("data.azurerm_resource_group.main.name"))]), *hcl)), **files}


def _native(monkeypatch, targets=("bicep",)):
    """The ARM render (targets) of the check jobs' root (_root)."""
    from types import SimpleNamespace
    import opsdir_adapter_azure.terraform as terraform
    stub = SimpleNamespace(dn="env=prod,cloud=alpha,ou=environments,dc=ciam-ops", label="alpha/prod")
    root = _root(_model((*BINDINGS, *INTERNAL), (*TREE, *LDAP)))
    monkeypatch.setattr(terraform, "render_files", lambda m, services: root)
    return terraform.render(stub, None, targets)


def test_as_bicep_the_jobs_and_their_grants_are_native(monkeypatch):
    """The environment, identities and jobs are template resources; each job's grants on the Application Insights
    resource and its registry (inputs naming them by ID) are modules at the group the ID names, one module file per
    role and target type, which the job waits for: nothing stays Terraform."""
    out = _native(monkeypatch)
    assert "terraform/main.tf" not in out and "bicep/terraform/main.tf" not in out
    template = out["bicep/rg-a.bicep"]
    assert ("resource container_app_environment_checks_subnet_web 'Microsoft.App/managedEnvironments@2026-07-01' = {"
            in template)
    assert "infrastructureSubnetId: subnets_snet_web.id\n      internal: true" in template
    assert "'4633458b-17de-408a-b874-0445c86b69e6')" in template                 # Key Vault Secrets User
    pull = template[template.index("module role_assignment_check_token_check_pull "):]
    assert pull[:pull.index("\n}\n")] == (
        "module role_assignment_check_token_check_pull './modules/role-assignments-registries.bicep' = {\n"
        "  name: 'role_assignment_check_token_check_pull'\n"
        "  scope: resourceGroup(split(registry_crciam_azurecr_io_id, '/')[2], "
        "split(registry_crciam_azurecr_io_id, '/')[4])\n"
        "  params: {\n"
        "    name: guid(registry_crciam_azurecr_io_id, 'azurerm_role_assignment.check_token_check_pull')\n"
        "    principalId: user_assigned_identity_check_token_check.properties.principalId\n"
        "    targetName: split(registry_crciam_azurecr_io_id, '/')[8]\n"
        "  }")
    job = template[template.index("resource container_app_job_token_check "):]
    assert "  dependsOn: [\n    role_assignment_check_token_check_publisher\n" in job[:job.index("\n}\n") + 2]
    registries = out["bicep/modules/role-assignments-registries.bicep"]
    assert "resource target 'Microsoft.ContainerRegistry/registries@2025-11-01' existing = {" in registries
    assert "'7f951dda-4ed3-4680-a7ca-43fe172d538d')" in registries                # AcrPull
    assert "'3913510d-42f4-4e42-8a64-420c390055eb')" in out["bicep/modules/role-assignments-components.bicep"]
    assert {p for p in out if p.endswith("check.py")} == {"images/ciam-check/check.py"}   # nothing read beside it


def test_a_job_s_native_form_and_its_arm_read_back(monkeypatch):
    """A job is Microsoft.App/jobs (image delivery): its identity, schedule, secrets (a value, a Key Vault secret read
    with its identity), registry and container; read back from the templates (its grants from their modules, at the
    group their input's ID names) it is the canary binding and the identity's grants the Terraform state gives."""
    from opsdir_adapter_azure.arm import arm_resources
    from opsdir_adapter_azure.rendered_state import rendered_deployments
    template = _native(monkeypatch)["bicep/rg-a.bicep"]
    job = template[template.index("resource container_app_job_token_check 'Microsoft.App/jobs@2026-07-01' = {"):]
    job = job[:job.index("\n}\n")]
    for part in ("triggerType: 'Schedule'", "replicaTimeout: 120", "cronExpression: '*/10 * * * *'",
                 "keyVaultUrl: '${vaults_kv_ciam.properties.vaultUri}secrets/canary-client'",
                 "identity: user_assigned_identity_check_token_check.id", "server: 'crciam.azurecr.io'",
                 "cpu: json('0.25')", "secretRef: 'appinsights'", f"image: '{IMAGE}'"):
        assert part in job, part
    from opsdir_format_terraform.hcl import written
    from opsdir_adapter_azure.inventory import pairs_resources, state_pairs
    from opsdir_adapter_azure.rendered_state import INPUT_GROUP, rendered_states
    model_ = _model((*BINDINGS, *INTERNAL), (*TREE, *LDAP))
    arm = _native(monkeypatch, ("arm",))
    texts = {f"alpha/prod/{p[len('arm/'):]}": t for p, t in arm.items() if p.startswith("arm/")}
    by_arm = arm_resources({p[len("alpha/prod/"):]: t for p, t in rendered_deployments(
        texts, model_.d, "alpha/prod").items()})[0]
    tf = {"alpha/prod/main.tf": written({"main.tf": _root(model_)["terraform/main.tf"]})["main.tf"]}
    by_terraform = pairs_resources([p for state in rendered_states(tf, model_.d, "alpha/prod").values()
                                    for p in state_pairs(state)[0]])[0]

    def read(resources, kind):                    # a managed identity's client id: Azure's at deployment, not held
        return {r.name: {a: v for a, v in r.attrs.items() if a != "ciamIdentityClientId"} for r in resources
                if r.kind == kind}
    assert read(by_arm, "canary") == read(by_terraform, "canary")
    assert read(by_arm, "canary")["token-check"]["ciamContainerImage"] == (f"check={IMAGE}",)
    assert read(by_arm, "identity") == read(by_terraform, "identity")
    grants = read(by_arm, "identity")["id-ciam-prod-token-check"]["ciamGrant"]
    assert {g.split(" on ")[0] for g in grants if f"/resourceGroups/{INPUT_GROUP}/" in g} == {
        "AcrPull", "Monitoring Metrics Publisher"}                     # on the inputs' resources, from the modules


@pytest.mark.bicep
def test_the_jobs_native_form_builds_to_its_arm_json_and_lints_clean(monkeypatch, tmp_path):
    """The jobs' render with its modules, checked by the pinned Bicep CLI (tools/bin/bicep; skipped without it): it
    builds to the ARM JSON rendered beside it (but for Bicep's generator stamps, its modules' too), and lints without
    an error."""
    import subprocess
    from pathlib import Path
    bicep = Path(__file__).resolve().parents[3] / "tools" / "bin" / "bicep"
    if not bicep.exists():
        pytest.skip("no tools/bin/bicep (opsdir/scripts/fetch-tools.sh)")
    out = _native(monkeypatch, ("bicep", "arm"))
    for p, text in out.items():
        if p.startswith("bicep/") and p.endswith(".bicep"):
            (tmp_path / p).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / p).write_text(text)
    path = tmp_path / "bicep" / "rg-a.bicep"
    built = subprocess.run([str(bicep), "build", str(path), "--stdout"], capture_output=True, text=True)
    assert built.returncode == 0, built.stderr

    def unstamped(doc):
        if isinstance(doc, list):
            return [unstamped(x) for x in doc]
        if not isinstance(doc, dict):
            return doc
        meta = {k: v for k, v in doc["metadata"].items() if k != "_generator"} \
            if isinstance(doc.get("metadata"), dict) else doc.get("metadata")
        return {k: unstamped(v) for k, v in {**doc, "metadata": meta}.items() if k != "metadata" or v}
    assert unstamped(json.loads(built.stdout)) == json.loads(out["arm/rg-a.json"])
    lint = subprocess.run([str(bicep), "lint", str(path)], capture_output=True, text=True)
    assert lint.returncode == 0 and " Error " not in lint.stderr, lint.stderr


def test_in_the_script_form_a_job_stays_terraform_for_its_file(monkeypatch):
    monkeypatch.setattr(check_jobs, "delivery", lambda m: "script")
    side = _native(monkeypatch)["bicep/terraform/main.tf"]
    assert ("#   azurerm_container_app_job.token_check: in the script form the check job reads its runner from a file "
            "beside the root (file())") in side


def test_the_jobs_notes_are_written_as_their_comments():
    from opsdir.core.notes import note_comment
    from opsdir_adapter_azure.check_jobs import job_notes
    text, _, files = _render((*BINDINGS, *INTERNAL), (*TREE, *LDAP))
    notes = job_notes(_model((*BINDINGS, *INTERNAL), (*TREE, *LDAP)), ENDPOINTS)
    written = text + files["images/ciam-check/Dockerfile"]
    assert all(f"# {note_comment(n)}" in written for n in notes)
    delegation = next(n for n in notes if n.area == "Network")
    assert (delegation.severity, delegation.subject) == ("action", "subnet subnet-web")
    assert delegation.how[0].startswith("Have the network's keeper delegate subnet subnet-web")
    build = next(n for n in notes if n.subject == "check image")
    assert build.severity == "action" and build.scope.endswith("(crciam.azurecr.io)")
    assert any("Notary Project" in step for step in build.how)
    start = next(n for n in notes if n.subject == "check jobs" and n.severity == "action")
    assert "jobs/start/action" in start.how[0]
    assert [n.severity for n in notes if n.subject == "check jobs"] == ["action", "note", "note"]


SUBNETS = (entry(BETA, "subnet-checks", "ciamSubnetBinding", ciamBindingRole="subnet-checks", ciamCidr="10.1.9.0/27"),
           entry(BETA, "subnet-tiny", "ciamSubnetBinding", ciamBindingRole="subnet-tiny", ciamCidr="10.1.8.0/28"),
           entry(BETA, "svc-admin", "ciamServiceName", ciamBindingRole="admin", ciamFqdn="admin.example.test",
                 ciamTargetRole="web", ciamFrontendIp="10.1.2.50"),
           _binding("admin-check", "admin-alive").replace("ciamRealizes: admin-alive\n",
                                                          "ciamRealizes: admin-alive\nciamSubnetRole: subnet-checks\n"))
ADMIN = (_canary("admin-alive", ciamCheckedService="admin", ciamCanaryFlow="health"),)


def test_each_subnet_the_checks_run_from_gets_its_own_environment():
    text, _, _ = _render((*BINDINGS, *INTERNAL, *SUBNETS), (*TREE, *LDAP, *ADMIN))
    assert text.count('resource "azurerm_container_app_environment"') == 2       # no check left out
    assert ('resource "azurerm_container_app_environment" "checks_subnet_web" {\n'
            '  name                           = "cae-ciam-prod-subnet-web"\n') in text
    assert ('resource "azurerm_container_app_environment" "checks_subnet_checks" {\n'
            '  name                           = "cae-ciam-prod-subnet-checks"\n') in text
    assert "container_app_environment_id = azurerm_container_app_environment.checks_subnet_checks.id" in _job(
        text, "admin_check")
    assert "container_app_environment_id = azurerm_container_app_environment.checks_subnet_web.id" in _job(
        text, "directory")
    assert "checks_subnet_checks.id" in _job(text, "token_check")      # a public check: the first one placed
    assert text.count("# NOTE: subnet subnet-") == 2 and "not run from" not in text


def test_a_check_runs_from_a_subnet_large_enough_else_it_is_named():
    from opsdir_adapter_azure.check_jobs import placed
    from opsdir.domains.observability.canaries import canary_specs
    tiny_first = tuple(b.replace("ciamSubnetRole: subnet-checks", "ciamSubnetRole: subnet-tiny\n"
                                 "ciamSubnetRole: subnet-checks") for b in SUBNETS)
    m = _model((*BINDINGS, *tiny_first), (*TREE, *ADMIN))
    spec = next(s for s in canary_specs(m, ENDPOINTS) if s.name == "admin-check")
    assert [x.dn.split(",")[0] for x in spec.subnets] == ["cn=subnet-tiny", "cn=subnet-checks"]
    assert placed((spec,))["admin-check"].dn.startswith("cn=subnet-checks,")     # the /28 skipped for the /27
    only_tiny = tuple(b.replace("ciamSubnetRole: subnet-checks", "ciamSubnetRole: subnet-tiny") for b in SUBNETS)
    _, hcl, _ = _render((*BINDINGS, *only_tiny), (*TREE, *ADMIN))
    assert ("# NOTE: canary admin-alive: not rendered: subnet subnet-tiny (10.1.8.0/28) is smaller than the /27 a "
            "Container Apps environment with workload profiles needs") in hcl


PRIVATE_SSO = BINDINGS[0].replace("ciamFrontendIp: 203.0.113.10\n",
                                  f"ciamFrontendIp: 203.0.113.10\nciamTlsCertificate: cn=svc-cert,{CERTIFICATES}\n")


def test_a_check_that_must_trust_a_private_ca_is_a_job_given_the_ca_as_data():
    bindings, tree = (PRIVATE_SSO, *BINDINGS[1:], _binding("SSO-Alive", "sso-alive")), (*TREE, *private_chain())
    text, _, files = _render(bindings, tree)
    job = _job(text, "sso_alive")                       # a GET of a public service, yet no standard web test takes a CA
    assert f'value = "{base64.b64encode(CA_PEM.encode()).decode()}"' in job and 'name  = "CHECK_CA"' in job
    assert 'name  = "CHECK_CA_PARTIAL"\n        value = "false"' in job
    assert "CHECK_CA" not in _job(_render()[0], "token_check")              # a public CA's service: the image's own
    assert not blocks_of(render_tests(_model(bindings, tree), ENDPOINTS), "resource")
    assert files["images/ciam-check/check.py"] == _render()[2]["images/ciam-check/check.py"]   # the same image


def test_the_runner_trusts_the_ca_it_is_given_besides_the_images(monkeypatch):
    _, _, files = _render()
    seen = []

    def urlopen(request, timeout=None, context=None):
        seen.append(context)
        return _Answer(json.dumps({"access_token": "t"}).encode())
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    for k, v in {"APPLICATIONINSIGHTS_CONNECTION_STRING": "InstrumentationKey=ik;IngestionEndpoint=https://in.test/",
                 "IDENTITY_ENDPOINT": "http://identity/token", "IDENTITY_HEADER": "h", "AZURE_CLIENT_ID": "cid",
                 "CHECK_FLOW": "health", "CHECK_URL": "https://sso.example.test/", "CHECK_TEST": "SSO-Alive",
                 "CHECK_AUDIENCE": "https://monitor.azure.com", "CHECK_CA_PARTIAL": "true",
                 "CHECK_CA": base64.b64encode(CA_PEM.encode()).decode()}.items():
        monkeypatch.setenv(k, v)
    exec(compile(files["images/ciam-check/check.py"], "check.py", "exec"), {})
    probe = seen[0]                                                         # the check's own request
    assert any("Example Aero CIAM Internal CA" in str(c["subject"]) for c in probe.get_ca_certs())
    assert probe.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
