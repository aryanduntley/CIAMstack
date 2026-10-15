"""What the deployment kits share (kits.py): a placement per namespace, the workload a component or product runs as,
the image it runs (by container name, else its own workload's only image, else UNBOUND) and the kit's listeners for
the roles placed."""
from opsdir.core.contract import Listener
from opsdir.core.directory import get
from opsdir.core.environment import UNBOUND, env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.compute.naming import WORKLOADS, workload_dn
from opsdir_adapter_kubernetes.kits import Placement, kit_image, kit_listeners, workload_of
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
AM_IMAGE, AMSTER_IMAGE, IDM_IMAGE = ("registry.example.test/am:8.0.2", "registry.example.test/amster:8.0.2",
                                     "registry.example.test/idm:8.0.1")


def _workload(name, role):
    return (f"dn: {workload_dn(name)}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: {name}\n"
            f"ciamWorkloadKind: deployment\nciamTargetRole: {role}\nciamClusterRole: k8s\nciamNamespace: identity\n"
            f"ciamWorkloadRole: {name}-workload\n")


def _binding(cn, oc, role, extra=""):
    return (f"dn: cn={cn},ou=bindings,{ALPHA}\nobjectClass: top\nobjectClass: {oc}\ncn: {cn}\n"
            f"ciamBindingRole: {role}\n{extra}")


RECORDS = (
    f"dn: {WORKLOADS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: workloads\n",
    _workload("am", "am"), _workload("idm", "idm"),
    _binding("k8s", "ciamCluster", "k8s", "ciamProviderRef: cluster-1\n"),
    _binding("am", "ciamWorkloadBinding", "am-workload",
             f"ciamContainerImage: am={AM_IMAGE}\nciamContainerImage: amster={AMSTER_IMAGE}\n"),
    _binding("idm", "ciamWorkloadBinding", "idm-workload", f"ciamContainerImage: openidm={IDM_IMAGE}\n"))


def model():
    return env_model(build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *RECORDS))))), "alpha/prod")


def _placement(m, *names):
    return Placement("identity", tuple((n, get(m.d, workload_dn(n))) for n in names))


def test_a_placement_without_parts_that_come_with_others_has_none_on():
    assert Placement("identity", ()).on == ()


def test_the_workload_a_placement_runs_a_name_as():
    m = model()
    p = _placement(m, "am")
    assert workload_of(p, "am").dn == workload_dn("am") and workload_of(p, "amster") is None


def test_an_image_by_container_name_else_the_only_image_else_unbound():
    m = model()
    p = _placement(m, "am", "idm")
    assert kit_image(m, p, "am", ("am",), "kit") == AM_IMAGE
    assert kit_image(m, p, "amster", ("amster",), "kit") == AMSTER_IMAGE       # comes with AM: its binding names it
    assert kit_image(m, p, "idm", ("idm",), "kit") == IDM_IMAGE                # its workload's only image
    assert kit_image(m, p, "login-ui", ("login-ui",), "kit") == f"{UNBOUND}kit-login-ui-image"


def test_listeners_for_the_roles_placed_only():
    m = model()
    ports = (("am", 8080, "http", ("ig",)), ("idm", 8080, "http", ()), ("ig", 8443, "https", ()))
    assert kit_listeners((_placement(m, "am", "idm"),), ports) == (
        Listener("am", 8080, "tcp", "http", ("ig",), "kubernetes"),
        Listener("idm", 8080, "tcp", "http", (), "kubernetes"))
    assert kit_listeners((), ports) == ()
