"""Container logs on AKS to Log Analytics: per cluster a data collection endpoint and the agent's ConfigMap (high
scale, multitenancy, pod labels); per cluster and route a ContainerLogV2Extension rule over the roles' namespaces to
the route's workspace, keeping a role's pods by label, a source's container (a sidecar by name, the main source the
rest) and the route's kinds; what can't ship named."""
import yaml

from opsdir.connectors.registry import services
from opsdir.core.contract import LogSource
from opsdir.domains.compute.naming import WORKLOADS, workload_dn
from opsdir.domains.observability.naming import LOG_ROUTES
from opsdir_adapter_azure.container_logs import container_log_notes, render_container_logs
from network_fixtures import ALPHA, entry, model

AKS = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks-ciam"
WS = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law-{}"
AM = LogSource("am", "kubernetes", None, "mixed", "debug",
               (("eventName", "AM-ACCESS", "access"), ("eventName", "", "audit")))
TAIL = LogSource("am", "kubernetes", None, "text", "audit", container="audit-tail")
OU = "dn: {}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {}\n"


def _route(cn, kinds, dest):
    return (f"dn: cn={cn},{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\n"
            f"cn: {cn}\n" + "".join(f"ciamLogKind: {k}\n" for k in kinds)
            + f"ciamPublishedBy: am\nciamLogDestinationRole: {dest}\n")


TREE = (OU.format(WORKLOADS, "workloads"),
        f"dn: {workload_dn('am')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: am\nciamWorkloadKind: deployment\n"
        "ciamTargetRole: am\nciamNamespace: ciam\nciamClusterRole: k8s\nciamWorkloadRole: am-workload\n",
        OU.format(LOG_ROUTES, "log-routes"), _route("audit-logs", ("audit",), "audit-logs"),
        _route("access-logs", ("access",), "ops-logs"), _route("to-siem", ("debug",), "siem"))
BINDINGS = (entry(ALPHA, "am", "ciamWorkloadBinding", ciamBindingRole="am-workload",
                  ciamContainerImage="openam=registry.example.test/am:7.5.1"),
            entry(ALPHA, "aks", "ciamCluster", ciamBindingRole="k8s", ciamProviderRef=AKS),
            *(entry(ALPHA, cn, "ciamLogDestination", ciamBindingRole=role, ciamDestinationKind="workspace",
                    ciamProviderRef=WS.format(cn)) for cn, role in (("audit", "audit-logs"), ("ops", "ops-logs"))),
            entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                  ciamProviderRef="splunk://ciam"))


def _render():
    _, alpha, _ = model(alpha=BINDINGS, tree=TREE)
    return alpha, render_container_logs(alpha, services()._replace(logs=lambda m: (AM, TAIL)))


def test_a_rule_per_route_keeps_its_roles_pods_containers_and_kinds():
    _, (blocks, files) = _render()
    hcl = "\n".join(blocks)
    assert hcl.count('resource "azurerm_monitor_data_collection_endpoint"') == 1
    assert 'kind                = "Linux"' in hcl
    assert hcl.count('resource "azurerm_monitor_data_collection_rule" ') == 2          # the SIEM route: none
    assert 'extension_name = "ContainerLogV2Extension"' in hcl
    assert 'extension_json = "{\\"dataCollectionSettings\\":{\\"namespaces\\":[\\"ciam\\"]}}"' in hcl
    assert 'streams        = ["Microsoft-ContainerLogV2-HighScale"]' in hcl
    role = 'tostring(KubernetesMetadata.podLabels[\\"opsdir.io/role\\"]) == \\"am\\"'
    event = 'tostring(parse_json(LogMessage)[\\"eventName\\"])'
    audit = next(line for line in hcl.splitlines() if 'ContainerName == \\"audit-tail' in line)
    assert f'({role} and ContainerName == \\"audit-tail\\")' in audit           # the sidecar: all its lines
    assert (f'({role} and ContainerName !in (\\"audit-tail\\") and (isnotempty({event}) and '
            f'not({event} startswith_cs \\"AM-ACCESS\\")))') in audit         # the main output: audit events only
    assert f'target_resource_id      = "{AKS}"' in hcl
    (config,) = files.values()
    data = next(d for d in yaml.safe_load_all(config) if d)["data"]
    assert "[log_collection_settings.multi_tenancy]" in data["log-data-collection-settings"]
    assert 'include_fields = ["podLabels"]' in data["log-data-collection-settings"]


def test_what_isnt_shipped_is_named():
    alpha, _ = _render()
    assert container_log_notes(alpha, services()._replace(logs=lambda m: (AM, TAIL))) == (
        "# NOTE: log route to-siem: role am's container output not shipped: its destination siem isn't a Log "
        "Analytics workspace (kind workspace, a workspace ID)",)
