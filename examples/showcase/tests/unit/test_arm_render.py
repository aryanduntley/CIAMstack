"""The showcase's Azure environment rendered as ARM (5.6 e3a, the azure render targets bicep and arm), before and after
the approved changes: every Terraform resource goes exactly one place (a template's resource, part of one, or the
Terraform root beside the templates, saying why), every rendered type is in the table (mapped, kept with a reason, or
without an ARM form), a template per deployment scope, children inline where the parent's PUT would remove them, and
the render declares the formats of its files."""
import pytest

from opsdir.connectors.registry import ADAPTERS, environment_specs, services
from opsdir.connectors.render import render_env, render_parts
from opsdir_adapter_azure.arm_types import KEPT, NO_NATIVE, TYPES, arm_translation
from opsdir_adapter_azure.terraform import WHAT, render_files
from opsdir_format_arm.bicep import as_bicep
from opsdir_format_terraform.hcl import TfBlock
from opsdir_format_terraform.translate import address, root_items, roots


def _azure(d):
    """(spec, model, Terraform files, translation) of each environment the azure adapter renders."""
    found = services(ADAPTERS)
    out = []
    for spec in environment_specs(d):
        m, adapters, _, _, _ = render_parts(d, spec)
        if any(a.name == "azure" for a in adapters):
            files = render_files(m, found)
            out.append((spec, m, files, arm_translation(m, files, WHAT)))
    return tuple(out)


@pytest.fixture(scope="module", params=["before", "after"])
def translated(request, estate):
    return _azure(estate[request.param])


def test_every_rendered_type_is_mapped_kept_or_without_an_arm_form(translated):
    assert {spec for spec, *_ in translated} == {"target/prod"}
    rendered = {b.labels[0] for _, _, files, _ in translated for root in roots(files).values()
                for b in root_items(root) if isinstance(b, TfBlock) and b.kind == "resource"}
    assert rendered - set(TYPES) - NO_NATIVE - set(KEPT) == set()


def test_every_terraform_resource_goes_exactly_one_place(translated):
    """Every resource, and every check (a data source with lifecycle conditions, which the side root keeps)."""
    for spec, _, files, t in translated:
        for directory, root in roots(files).items():
            blocks = tuple(b for b in root_items(root) if isinstance(b, TfBlock))
            placed = {address(b) for b in blocks if b.kind == "resource" or
                      (b.kind == "data" and any(k == "lifecycle" for k, _ in b.body))}
            assert set(t.placements[directory]) == placed, (spec, directory)


def test_a_template_per_deployment_scope_holds_its_placed_resources(translated):
    for spec, _, _, t in translated:
        for directory, places in t.placements.items():
            for a, p in places.items():
                if p.kind == "template":
                    template = next(x for (d, _), x in t.templates.items()
                                    if d == directory and as_bicep(x) and p.detail in {r.symbol for r in x.resources})
                    assert not next(r for r in template.resources if r.symbol == p.detail).existing, (spec, a)
                elif p.kind == "merged":
                    assert places[p.detail].kind == "template", (spec, a)
                else:
                    assert p.detail, (spec, a)
    scopes = {key for (_, key) in translated[0][3].templates}
    assert {("resourceGroup", "rg-ciam-prod"), ("resourceGroup", "rg-hub-net"),
            ("resourceGroup", ("var", "network_watcher_resource_group")), ("subscription", None),
            ("tenant", None)} <= scopes
    assert {x.scope for (_, key), x in translated[0][3].templates.items()} == {"resourceGroup", "subscription",
                                                                               "tenant"}


def test_rules_and_balancer_parts_are_inline_and_lookups_existing(translated):
    _, _, _, t = translated[0]
    resources = {r.symbol: r for x in t.templates.values() for r in x.resources}
    nsg = resources["network_security_group_ds"]
    assert [rule["name"] for rule in nsg.properties["securityRules"]][:2] == ["fw-admin", "fw-checks-ds"]
    lb = resources["lb_svc_ldaps"]
    assert {"frontendIPConfigurations", "backendAddressPools", "probes", "loadBalancingRules"} <= set(lb.properties)
    assert "Microsoft.Network/loadBalancers/backendAddressPools" not in {r.type for r in resources.values()}
    subnet = next(r for r in resources.values() if r.type == "Microsoft.Network/virtualNetworks/subnets")
    assert subnet.existing and resources[subnet.parent].existing


def test_kept_resources_say_why(translated):
    _, _, _, t = translated[0]
    why = {a: p.detail for places in t.placements.values() for a, p in places.items() if p.kind == "terraform"}
    assert why["azurerm_subnet_route_table_association.rt_private_snet_ds"].startswith(
        "a property of the landing zone's subnet")
    assert why["data.azurerm_key_vault_secrets.kv_ciam_prod"] == ("a check (its lifecycle conditions), which ARM "
                                                                  "can't make")
    key = "azurerm_data_protection_backup_vault_customer_managed_key.ciam_backups"     # the backups: after only
    assert key not in why or why[key].startswith(
        "part of azurerm_data_protection_backup_vault.ciam_backups natively, but waits for "
        "azurerm_role_assignment.ciam_backups_cmk, which reads it: a cycle there")
    jobs = [a for a in why if a.startswith("azurerm_container_app_job.")]       # the scripted checks (check_jobs)
    assert jobs and all(why[a] == f"waits for azurerm_role_assignment.check_{a.split('.')[1]}_publisher (depends_on), "
                        "which stays Terraform, applied after the template" for a in jobs)     # its grants, below
    publishers = [a for a in why if a.startswith("azurerm_role_assignment.check_") and a.endswith("_publisher")]
    pulls = [a for a in why if a.startswith("azurerm_role_assignment.check_") and a.endswith("_pull")]
    assert len(publishers) == len(pulls) == len(jobs)                   # each job's own identity's grants
    assert all(why[a].startswith("what names its ARM deployment scope") for a in (*publishers, *pulls))
    assert {a.split(".")[0] for a in why if a not in (*publishers, *pulls)} <= {
        "azurerm_data_protection_backup_vault_customer_managed_key", "azurerm_subnet_route_table_association",
        "azurerm_subnet_network_security_group_association", "azuread_conditional_access_policy",
        "azapi_data_plane_resource", "azurerm_container_app_job", "data"}


def test_role_assignments_scope_what_they_grant_and_name_built_in_roles(translated):
    _, _, _, t = translated[0]
    resources = {r.symbol: r for x in t.templates.values() for r in x.resources}
    secret = resources["role_assignment_identity_ds_read_secret_ds_root_password"]
    assert resources[secret.scope].type == "Microsoft.KeyVault/vaults/secrets" and resources[secret.scope].existing
    assert secret.properties["roleDefinitionId"].args == ("Microsoft.Authorization/roleDefinitions",
                                                          "4633458b-17de-408a-b874-0445c86b69e6")
    assert secret.name.function == "guid"
    server = resources["postgresql_flexible_server_psql_ciam_prod_pf_grants"]
    assert server.depends_on == ("role_assignment_psql_ciam_prod_pf_grants_cmk",)
    subscription = t.templates[("terraform", ("subscription", None))]
    assert {r.type for r in subscription.resources} >= {"Microsoft.Security/pricings",
                                                         "Microsoft.Authorization/policyAssignments"}


def test_a_render_choosing_bicep_and_arm_declares_its_files(estate):
    _, files = render_env(estate["before"], "target/prod", wanted={"azure": ("bicep", "arm")})
    assert not any(p.startswith("terraform/") for p in files)
    assert {"bicep/rg-ciam-prod.bicep", "arm/rg-ciam-prod.json", "bicep/terraform/main.tf",
            "bicep/landing-zone/network-security/rg-hub-net.bicep"} <= set(files)
    manifest = files["MANIFEST.json"]
    assert '"azure": [\n      "bicep",\n      "arm"\n    ]' in manifest
    assert '"bicep/rg-ciam-prod.bicep": {\n      "scope": "environment-specific",\n      "format": "bicep"' in manifest
    assert '"arm/landing-zone/rg-ciam-prod.json": {\n      "scope": "landing-zone",\n      "format": "arm-json"' \
        in manifest
