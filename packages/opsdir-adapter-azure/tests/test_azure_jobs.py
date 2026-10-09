"""Azure jobs: a function app read as a job binding, with its runtime and the schedules of its timer-triggered
functions, from Terraform state, the CLI's outputs and an ARM template alike; its tag Role gives the binding role."""
import json

from opsdir_adapter_azure.arm import arm_resources
from opsdir_adapter_azure.cli import cli_resources
from opsdir_adapter_azure.inventory import state_resources

SUB, RG = "00000000-0000-0000-0000-000000000000", "rg-ciam-prod"
APP = f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/sites/fn-ciam-prod"
TIMER = {"bindings": [{"type": "timerTrigger", "name": "t", "schedule": "0 0 2 * * *"},
                      {"type": "blob", "name": "out", "path": "reports/{rand-guid}"}]}


def _jobs(resources):
    return {r.name: r for r in resources if r.kind == "job"}


def test_terraform_state():
    state = json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": a}]} for t, n, a in (
            ("azurerm_linux_function_app", "fn", {"id": APP, "name": "fn-ciam-prod",
                                                  "tags": {"Role": "report-function"},
                                                  "site_config": [{"application_stack": [{"python_version": "3.11",
                                                                                          "node_version": None}]}]}),
            ("azurerm_function_app_function", "nightly", {"id": f"{APP}/functions/nightly", "name": "nightly",
                                                          "function_app_id": APP, "config_json": json.dumps(TIMER)}))]})
    resources, _ = state_resources(state)
    job = _jobs(resources)["fn-ciam-prod"]
    assert (job.ref, job.role, job.attrs) == (APP, "report-function", {"ciamRuntime": ("python 3.11",),
                                                                        "ciamSchedule": ("0 0 2 * * *",)})


def test_cli_outputs():
    texts = {"functionapps.json": json.dumps([{"id": APP, "name": "fn-ciam-prod", "type": "Microsoft.Web/sites",
                                               "kind": "functionapp,linux", "tags": {"Role": "report-function"},
                                               "siteConfig": {"linuxFxVersion": "Python|3.11"}}]),
             "functions.json": json.dumps([{"id": f"{APP}/functions/nightly", "name": "fn-ciam-prod/nightly",
                                            "type": "Microsoft.Web/sites/functions", "config": TIMER}])}
    resources, _ = cli_resources(texts)
    job = _jobs(resources)["fn-ciam-prod"]
    assert (job.role, job.attrs) == ("report-function", {"ciamRuntime": ("python 3.11",),
                                                         "ciamSchedule": ("0 0 2 * * *",)})


def test_an_arm_template():
    template = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0", "resources": [
        {"type": "Microsoft.Web/sites", "name": "fn-ciam-prod", "kind": "functionapp,linux",
         "tags": {"Role": "report-function"},
         "properties": {"siteConfig": {"linuxFxVersion": "Python|3.11",
                                       "appSettings": [{"name": "TOKEN", "value": "not-read"}]}}},
        {"type": "Microsoft.Web/sites/functions", "name": "fn-ciam-prod/nightly", "properties": {"config": TIMER}}]}
    deployment = {"id": f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Resources/deployments/fn",
                  "properties": {"outputResources": [{"id": APP}, {"id": f"{APP}/functions/nightly"}]}}
    resources, _ = arm_resources({"fn/template.json": json.dumps(template),
                                  "fn/deployment.json": json.dumps(deployment)})
    job = _jobs(resources)["fn-ciam-prod"]
    assert (job.ref, job.role, job.attrs["ciamSchedule"]) == (APP, "report-function", ("0 0 2 * * *",))
    assert "not-read" not in repr(resources)
