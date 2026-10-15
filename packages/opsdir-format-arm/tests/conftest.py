"""The writers' module sample (fixture module_sample): a template granting a role on a resource in another resource
group, named by an input id, through a module: two grants of one module template (a shared file), what depends on them
waiting for both."""
from types import SimpleNamespace

import pytest

from opsdir_format_arm.template import (ArmModule, ArmParameter, ArmResource, ArmTemplate, Call, Index, Member, Param,
                                        Prop)

REGISTRIES = "Microsoft.ContainerRegistry/registries"
ACR_PULL = "7f951dda-4ed3-4680-a7ca-43fe172d538d"
GRANT = ArmTemplate("resourceGroup", None, (
    ArmResource("target", REGISTRIES, "2025-04-01", Param("targetName"), existing=True),
    ArmResource("assignment", "Microsoft.Authorization/roleAssignments", "2022-04-01", Param("name"), scope="target",
                properties={"principalId": Param("principalId"), "principalType": "ServicePrincipal",
                            "roleDefinitionId": Call("subscriptionResourceId", (
                                "Microsoft.Authorization/roleDefinitions", ACR_PULL))})),
    (ArmParameter("name", "string"), ArmParameter("principalId", "string"), ArmParameter("targetName", "string")))


def part(i):
    """Element i of the input id split at '/' (2: its subscription, 4: its group, 8: its name)."""
    return Index(Call("split", (Param("registryId"), "/")), i)


def grant(sym):
    return ArmModule(sym, f"grant-{sym}", GRANT, part(2), part(4), {
        "name": Call("guid", (Param("registryId"), sym)), "principalId": Prop("identity", "principalId"),
        "targetName": part(8)}, "role-assignment-registries")


MODULES = ArmTemplate("resourceGroup", None, (
    ArmResource("identity", "Microsoft.ManagedIdentity/userAssignedIdentities", "2023-01-31", "id-x",
                fields={"location": Member(Call("resourceGroup", ()), "location")}),
    ArmResource("job", "Microsoft.App/jobs", "2026-07-01", "job",
                fields={"location": Member(Call("resourceGroup", ()), "location")},
                properties={"environmentId": "x"}, depends_on=("pull_a", "pull_b"))),
    (ArmParameter("registryId", "string"),), modules=(grant("pull_a"), grant("pull_b")))


@pytest.fixture(scope="session")
def module_sample():
    """The sample: MODULES (the template), GRANT (its modules' template), grant(symbol) (another module), ACR_PULL."""
    return SimpleNamespace(MODULES=MODULES, GRANT=GRANT, grant=grant, ACR_PULL=ACR_PULL)
